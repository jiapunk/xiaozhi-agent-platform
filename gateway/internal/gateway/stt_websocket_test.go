package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"xiaozhi-agent-platform/gateway/internal/speechcontract"
)

type captureEmitter struct {
	stt      chan string
	failures chan error
}

func (emitter *captureEmitter) SendSTT(_ context.Context, text string) error {
	emitter.stt <- text
	return nil
}

func (*captureEmitter) SendJSON(context.Context, []byte) error { return nil }

func (emitter *captureEmitter) FailVoice(cause error) {
	select {
	case emitter.failures <- cause:
	default:
	}
}

func TestWebSocketSTTStreamsAndEmitsFinalText(t *testing.T) {
	var requestMu sync.Mutex
	var authorization string
	var contract string
	var ownerHeader string
	var tenantHeader string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestMu.Lock()
		authorization = request.Header.Get("Authorization")
		contract = request.Header.Get(speechcontract.Header)
		ownerHeader = request.Header.Get("Owner-Id")
		tenantHeader = request.Header.Get("Tenant-Id")
		requestMu.Unlock()
		writer.Header().Set(speechcontract.Header, speechcontract.STTVersion)
		socket, err := websocket.Accept(writer, request, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer socket.CloseNow()
		messageType, start, err := socket.Read(request.Context())
		if err != nil || messageType != websocket.MessageText {
			t.Errorf("invalid start: %v %v", messageType, err)
			return
		}
		var startMessage map[string]any
		if err := json.Unmarshal(start, &startMessage); err != nil ||
			startMessage["type"] != "start" ||
			startMessage["contract"] != speechcontract.STTVersion {
			t.Errorf("invalid start JSON: %s", start)
			return
		}
		messageType, audio, err := socket.Read(request.Context())
		if err != nil || messageType != websocket.MessageBinary ||
			string(audio) != string([]byte{0x18, 0x00}) {
			t.Errorf("invalid audio: %v %v %v", messageType, audio, err)
			return
		}
		_ = socket.Write(request.Context(), websocket.MessageText,
			[]byte(`{"type":"stt","text":"turn on","final":true}`))
		<-request.Context().Done()
	}))
	defer server.Close()

	backend, err := NewWebSocketSTT(WebSocketSTTConfig{
		Endpoint:    "ws" + strings.TrimPrefix(server.URL, "http"),
		BearerToken: "upstream-secret", HTTPClient: server.Client(),
		AllowInsecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	emitter := &captureEmitter{stt: make(chan string, 1), failures: make(chan error, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session, err := backend.Open(ctx, VoiceSessionConfig{
		DeviceID: "device-1", OwnerID: "user-1", TenantID: "tenant-1",
		ClientID: "client-1", SessionID: "voice:s1",
		SampleRate: 16000, FrameDuration: 60, ProtocolVersion: 1,
	}, emitter)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := session.HandleAudio(ctx, []byte{0x18, 0x00}); err != nil {
		t.Fatal(err)
	}
	select {
	case text := <-emitter.stt:
		if text != "turn on" {
			t.Fatalf("unexpected STT: %q", text)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for STT")
	}
	requestMu.Lock()
	defer requestMu.Unlock()
	if authorization != "Bearer upstream-secret" {
		t.Fatalf("unexpected authorization: %q", authorization)
	}
	if contract != speechcontract.STTVersion {
		t.Fatalf("unexpected contract: %q", contract)
	}
	if ownerHeader != "" || tenantHeader != "" {
		t.Fatalf("ownership identity leaked upstream: owner=%q tenant=%q",
			ownerHeader, tenantHeader)
	}
}

func TestWebSocketSTTRejectsMissingContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		socket, err := websocket.Accept(writer, request, nil)
		if err == nil {
			defer socket.CloseNow()
			<-request.Context().Done()
		}
	}))
	defer server.Close()
	backend, err := NewWebSocketSTT(WebSocketSTTConfig{
		Endpoint:    "ws" + strings.TrimPrefix(server.URL, "http"),
		BearerToken: "secret", HTTPClient: server.Client(), AllowInsecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	emitter := &captureEmitter{stt: make(chan string, 1), failures: make(chan error, 1)}
	if _, err := backend.Open(context.Background(), VoiceSessionConfig{
		DeviceID: "d", ClientID: "c", SessionID: "s", SampleRate: 16000,
		FrameDuration: 60, ProtocolVersion: 1,
	}, emitter); err == nil {
		t.Fatal("expected missing STT contract rejection")
	}
}

func TestWebSocketSTTRejectsWrongOpusDuration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set(speechcontract.Header, speechcontract.STTVersion)
		socket, err := websocket.Accept(writer, request, nil)
		if err != nil {
			return
		}
		defer socket.CloseNow()
		_, _, _ = socket.Read(request.Context())
		<-request.Context().Done()
	}))
	defer server.Close()
	backend, err := NewWebSocketSTT(WebSocketSTTConfig{
		Endpoint:    "ws" + strings.TrimPrefix(server.URL, "http"),
		BearerToken: "secret", HTTPClient: server.Client(), AllowInsecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	emitter := &captureEmitter{stt: make(chan string, 1), failures: make(chan error, 1)}
	session, err := backend.Open(ctx, VoiceSessionConfig{
		DeviceID: "d", ClientID: "c", SessionID: "s", SampleRate: 16000,
		FrameDuration: 60, ProtocolVersion: 1,
	}, emitter)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := session.HandleAudio(ctx, []byte{0x08, 0x00}); err == nil {
		t.Fatal("expected 20 ms uplink packet rejection")
	}
}

func TestWebSocketSTTRequiresSecureURL(t *testing.T) {
	if _, err := NewWebSocketSTT(WebSocketSTTConfig{
		Endpoint: "ws://example.test/stt", BearerToken: "secret",
	}); err == nil {
		t.Fatal("expected insecure STT URL to fail")
	}
	if _, err := NewWebSocketSTT(WebSocketSTTConfig{
		Endpoint: "wss://speech.example.test/stt?token=leak", BearerToken: "secret",
	}); err == nil {
		t.Fatal("expected STT query-string credential surface to fail")
	}
}

func TestWebSocketSTTReadinessRequiresContract(t *testing.T) {
	for _, withContract := range []bool{true, false} {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if request.Header.Get(speechcontract.Header) != speechcontract.STTVersion {
				t.Error("missing readiness request contract")
			}
			if withContract {
				writer.Header().Set(speechcontract.Header, speechcontract.STTVersion)
			}
			writer.WriteHeader(http.StatusNoContent)
		}))
		backend, err := NewWebSocketSTT(WebSocketSTTConfig{
			Endpoint: "ws://example.test/stt", HealthURL: server.URL,
			BearerToken: "secret", HTTPClient: server.Client(), AllowInsecure: true,
		})
		if err != nil {
			server.Close()
			t.Fatal(err)
		}
		err = backend.Ready(context.Background())
		server.Close()
		if (err == nil) != withContract {
			t.Fatalf("withContract=%v err=%v", withContract, err)
		}
	}
}
