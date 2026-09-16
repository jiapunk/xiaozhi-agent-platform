package tts

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"xiaozhi-agent-platform/gateway/internal/speechcontract"
)

func TestFramedHTTPStreamsOpusPackets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer secret" {
			t.Error("missing authorization")
		}
		if request.Header.Get(speechcontract.Header) != speechcontract.TTSVersion {
			t.Error("missing TTS contract header")
		}
		var body synthesisRequest
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.Text != "hello" || body.Format != "opus" || body.SampleRate != 24000 ||
			body.Contract != speechcontract.TTSVersion ||
			body.SessionID != "s1" || body.RequestID != 7 ||
			request.Header.Get("Idempotency-Key") != "s1:7" {
			t.Errorf("unexpected request: %#v", body)
		}
		writer.Header().Set("Content-Type", framedContentType)
		writer.Header().Set(speechcontract.Header, speechcontract.TTSVersion)
		for _, frame := range [][]byte{{0x18, 0x00}, {0x0b, 0x03, 0, 0, 0}} {
			var header [4]byte
			binary.BigEndian.PutUint32(header[:], uint32(len(frame)))
			_, _ = writer.Write(header[:])
			_, _ = writer.Write(frame)
		}
	}))
	defer server.Close()

	client, err := NewFramedHTTP(FramedHTTPConfig{
		Endpoint: server.URL, BearerToken: "secret", Client: server.Client(),
		AllowInsecure: true, SampleRate: 24000, FrameDuration: 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	var frames [][]byte
	if err := client.Stream(context.Background(), Request{
		DeviceID: "d1", SessionID: "s1", RequestID: 7, Text: "hello",
	}, func(frame []byte) error {
		frames = append(frames, append([]byte(nil), frame...))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(frames) != 2 || len(frames[1]) != 5 || frames[1][1] != 3 {
		t.Fatalf("unexpected frames: %v", frames)
	}
}

func TestFramedHTTPRejectsMalformedStreams(t *testing.T) {
	cases := []struct {
		name        string
		contentType string
		body        []byte
	}{
		{"wrong type", "application/octet-stream", []byte{0, 0, 0, 1, 1}},
		{"empty", framedContentType, nil},
		{"zero frame", framedContentType, []byte{0, 0, 0, 0}},
		{"truncated", framedContentType, []byte{0, 0, 0, 2, 1}},
		{"wrong opus duration", framedContentType, []byte{0, 0, 0, 2, 0x08, 0}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", test.contentType)
				writer.Header().Set(speechcontract.Header, speechcontract.TTSVersion)
				_, _ = writer.Write(test.body)
			}))
			defer server.Close()
			client, err := NewFramedHTTP(FramedHTTPConfig{
				Endpoint: server.URL, BearerToken: "secret", Client: server.Client(),
				AllowInsecure: true, SampleRate: 24000, FrameDuration: 60,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := client.Stream(context.Background(), Request{
				DeviceID: "d1", SessionID: "s1", RequestID: 7, Text: "text",
			}, func([]byte) error { return nil }); err == nil {
				t.Fatal("expected malformed stream to fail")
			}
		})
	}
}

func TestFramedHTTPRejectsMissingContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", framedContentType)
		_, _ = writer.Write([]byte{0, 0, 0, 2, 0x18, 0})
	}))
	defer server.Close()
	client, err := NewFramedHTTP(FramedHTTPConfig{
		Endpoint: server.URL, BearerToken: "secret", Client: server.Client(),
		AllowInsecure: true, SampleRate: 24000, FrameDuration: 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Stream(context.Background(), Request{
		DeviceID: "d1", SessionID: "s1", RequestID: 7, Text: "text",
	}, func([]byte) error { return nil }); err == nil {
		t.Fatal("expected missing TTS contract rejection")
	}
}

func TestFramedHTTPStopsBufferedFramesImmediatelyAfterCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", framedContentType)
		writer.Header().Set(speechcontract.Header, speechcontract.TTSVersion)
		for range 3 {
			_, _ = writer.Write([]byte{0, 0, 0, 2, 0x18, 0})
		}
	}))
	defer server.Close()
	client, err := NewFramedHTTP(FramedHTTPConfig{
		Endpoint: server.URL, BearerToken: "secret", Client: server.Client(),
		AllowInsecure: true, SampleRate: 24000, FrameDuration: 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	frames := 0
	err = client.Stream(ctx, Request{
		DeviceID: "d1", SessionID: "s1", RequestID: 8, Text: "cancel",
	}, func([]byte) error {
		frames++
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Stream error = %v, want context cancellation", err)
	}
	if frames != 1 {
		t.Fatalf("emitted %d frames after cancellation, want exactly one", frames)
	}
}

func TestFramedHTTPEnforcesReservedOutputDuration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", framedContentType)
		writer.Header().Set(speechcontract.Header, speechcontract.TTSVersion)
		for range 2 {
			_, _ = writer.Write([]byte{0, 0, 0, 2, 0x18, 0})
		}
	}))
	defer server.Close()
	client, err := NewFramedHTTP(FramedHTTPConfig{
		Endpoint: server.URL, BearerToken: "secret", Client: server.Client(),
		AllowInsecure: true, SampleRate: 24000, FrameDuration: 60,
		MaxOutputAudioMS: 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	frames := 0
	err = client.Stream(context.Background(), Request{
		DeviceID: "d1", SessionID: "s1", RequestID: 9, Text: "bounded",
	}, func([]byte) error {
		frames++
		return nil
	})
	if err == nil || frames != 1 {
		t.Fatalf("duration bound err=%v frames=%d", err, frames)
	}
}

func TestFramedHTTPRequiresHTTPSByDefault(t *testing.T) {
	if _, err := NewFramedHTTP(FramedHTTPConfig{
		Endpoint: "http://example.test/tts", BearerToken: "secret",
		SampleRate: 24000, FrameDuration: 60,
	}); err == nil {
		t.Fatal("expected insecure URL to fail")
	}
	if _, err := NewFramedHTTP(FramedHTTPConfig{
		Endpoint: "https://speech.example.test/tts?token=leak", BearerToken: "secret",
		SampleRate: 24000, FrameDuration: 60,
	}); err == nil {
		t.Fatal("expected TTS query-string credential surface to fail")
	}
}

func TestFramedHTTPReadinessRequiresContract(t *testing.T) {
	for _, withContract := range []bool{true, false} {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.Header.Get(speechcontract.Header) != speechcontract.TTSVersion {
				t.Error("missing readiness request contract")
			}
			if withContract {
				writer.Header().Set(speechcontract.Header, speechcontract.TTSVersion)
			}
			writer.WriteHeader(http.StatusNoContent)
		}))
		client, err := NewFramedHTTP(FramedHTTPConfig{
			Endpoint: "http://example.test/tts", HealthURL: server.URL,
			BearerToken: "secret", Client: server.Client(), AllowInsecure: true,
			SampleRate: 24000, FrameDuration: 60,
		})
		if err != nil {
			server.Close()
			t.Fatal(err)
		}
		err = client.Ready(context.Background())
		server.Close()
		if (err == nil) != withContract {
			t.Fatalf("withContract=%v err=%v", withContract, err)
		}
	}
}
