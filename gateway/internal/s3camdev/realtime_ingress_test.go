package s3camdev

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestRealtimeIngressIsBoundedOrderedAndOwnsAudio(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue := newRealtimeIngressQueue(ctx, "test", 2)
	pcm := []byte{1, 2}
	if err := queue.push(realtimeIngressEvent{kind: "start"}); err != nil {
		t.Fatal(err)
	}
	if err := queue.push(realtimeIngressEvent{kind: "opus", data: pcm}); err != nil {
		t.Fatal(err)
	}
	pcm[0] = 99
	if err := queue.push(realtimeIngressEvent{kind: "abort"}); !errors.Is(err, errRealtimeIngressFull) {
		t.Fatalf("full queue did not explicitly fail: %v", err)
	}
	first, second := <-queue.events, <-queue.events
	queue.noteProcessed(first)
	queue.noteProcessed(second)
	if first.kind != "start" || second.kind != "opus" || second.data[0] != 1 {
		t.Fatal("ingress reordered frames or borrowed caller audio memory")
	}
	if queue.accepted.Load() != 2 || queue.processed.Load() != 2 ||
		queue.highWater.Load() != 2 || queue.overflows.Load() != 1 {
		t.Fatal("ingress integrity counters are inaccurate")
	}
	cancel()
	if err := queue.push(realtimeIngressEvent{}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled ingress accepted more input")
	}
}

func TestRealtimeSlowSetupDoesNotBlockDeviceMCPOrLoseLeadingAudio(t *testing.T) {
	ffmpeg, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg is unavailable")
	}
	setupStarted, allowSetup := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(allowSetup) }) }
	defer release()
	forwarded := make(chan struct{}, 1)
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(setupStarted)
		select {
		case <-allowSetup:
		case <-r.Context().Done():
			return
		}
		connection, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer connection.CloseNow()
		for {
			_, payload, err := connection.Read(r.Context())
			if err != nil {
				return
			}
			var event map[string]any
			if json.Unmarshal(payload, &event) == nil && event["type"] == "input_audio_buffer.append" {
				select {
				case forwarded <- struct{}{}:
				default:
				}
			}
		}
	}))
	defer upstreamServer.Close()
	realtime, err := NewOpenAIRealtimeGateway(OpenAIRealtimeConfig{
		APIKey: "local-test-key", URL: "ws" + strings.TrimPrefix(upstreamServer.URL, "http"),
		FFmpegPath: ffmpeg,
	})
	if err != nil {
		t.Fatal(err)
	}
	const deviceID = "20:6e:f1:b3:9c:c4"
	const token = "0123456789abcdef0123456789abcdef"
	gateway, err := New(Config{
		PublicWebSocketURL: "ws://127.0.0.1:8766/v1/device",
		ExpectedDeviceID:   deviceID, Token: token, Realtime: realtime,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway.Handler())
	defer server.Close()
	device := dialRealtimeTestDevice(t, server.URL, deviceID, token)
	defer device.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hello := readJSON(t, ctx, device)
	sessionID := hello["session_id"].(string)
	assertMCPMethod(t, readJSON(t, ctx, device), "initialize")
	writeJSON(t, ctx, device, map[string]any{
		"session_id": sessionID, "type": "listen", "state": "start", "mode": "realtime",
	})
	select {
	case <-setupStarted:
	case <-ctx.Done():
		t.Fatal("provider setup did not begin")
	}
	for index := range 3 {
		packet, err := base64.StdEncoding.DecodeString(testSpeechPacketsBase64[index])
		if err != nil {
			t.Fatal(err)
		}
		if err := device.Write(ctx, websocket.MessageBinary, packet); err != nil {
			t.Fatal(err)
		}
	}
	// This response is deliberately sent AFTER listen/start while the provider
	// handshake is held. The old synchronous Start path could not read it.
	writeMCPResult(t, ctx, device, sessionID, 1, map[string]any{})
	assertMCPMethod(t, readJSON(t, ctx, device), "tools/list")
	release()
	select {
	case <-forwarded:
	case <-ctx.Done():
		t.Fatal("leading microphone frames were lost during slow setup")
	}
}
