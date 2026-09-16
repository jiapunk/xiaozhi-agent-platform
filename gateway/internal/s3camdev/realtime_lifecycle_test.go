package s3camdev

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestRealtimeNewSpeechInvalidatesThinkingToolBatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	batchContext, cancelBatch := context.WithCancel(ctx)
	session := &openAIRealtimeSession{
		gateway: &OpenAIRealtimeGateway{config: OpenAIRealtimeConfig{Logger: slog.Default()}},
		device:  &deviceSession{server: &Server{}}, ctx: ctx, cancel: cancel,
		inputTurnGeneration: 7, responseGeneration: 9, responseProviderDone: true,
		retryResponseAfterActive: true,
		toolBatch: &realtimeToolBatch{inputGeneration: 7, sourceGeneration: 9,
			ctx: batchContext, cancel: cancelBatch, pending: 1},
	}
	if !session.beginSpeechCapture("replacement_question") {
		t.Fatal("thinking tool work was not treated as superseded output")
	}
	if batchContext.Err() != context.Canceled || session.toolBatch != nil ||
		session.inputTurnGeneration != 8 || session.retryResponseAfterActive {
		t.Fatal("new speech retained a stale batch, retry or input generation")
	}
	if session.inputStartedDuringReply {
		t.Fatal("thinking-only question was wrongly classified as playback overlap")
	}
}

type realtimeClosingWriter struct{ closing chan struct{} }

func (writer realtimeClosingWriter) Write(data []byte) (int, error) { return len(data), nil }
func (writer realtimeClosingWriter) Close() error {
	close(writer.closing)
	return nil
}

func TestRealtimeCancelledFlushDoesNotFailReplacementSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	responseContext, cancelResponse := context.WithCancel(ctx)
	closing := make(chan struct{})
	encoder := &realtimeOpusEncoder{
		stdin: realtimeClosingWriter{closing}, done: make(chan struct{}),
		doneErr: errors.New("signal: killed"),
	}
	session := &openAIRealtimeSession{
		gateway: &OpenAIRealtimeGateway{config: OpenAIRealtimeConfig{Logger: slog.Default()}},
		ctx:     ctx, cancel: cancel, responseID: "old", responseGeneration: 1,
		responseEncoder: encoder, responseContext: responseContext, responseCancel: cancelResponse,
		playback: make(chan realtimePlaybackEvent, 1),
	}
	session.finishAudioOutput("old")
	<-closing // encoder.Close is now flushing asynchronously.
	session.beginResponse("replacement")
	close(encoder.done) // simulate CommandContext's cancelled Wait result.
	deadline := time.After(time.Second)
	for session.obsoleteEncoderFinishes.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("cancelled encoder flush did not retire")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if session.IsClosed() || ctx.Err() != nil || len(session.playback) != 0 {
		t.Fatal("old flush failed or finished the replacement session")
	}
}

func TestRealtimeOldAudioDoneCannotCloseCurrentEncoder(t *testing.T) {
	encoder := &realtimeOpusEncoder{}
	session := &openAIRealtimeSession{responseID: "current", responseEncoder: encoder}
	session.finishAudioOutput("old")
	if session.responseEncoder != encoder {
		t.Fatal("stale audio.done detached the current response's encoder")
	}
}

func TestRealtimeEncoderCancellationReportsContext(t *testing.T) {
	ffmpeg, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg is unavailable")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	encoder, err := newRealtimeOpusEncoder(ctx, ffmpeg, func([]byte) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := encoder.WritePCM(make([]byte, realtimePCMFrameBytes*3)); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := encoder.Close(); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled ffmpeg exposed process failure instead of context: %v", err)
	}
}

func realtimeLifecycleSocketPair(t *testing.T) (*websocket.Conn, *websocket.Conn) {
	t.Helper()
	accepted := make(chan *websocket.Conn, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		accepted <- connection
		<-release
		connection.CloseNow()
	}))
	client, _, err := websocket.Dial(context.Background(),
		"ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	connection := <-accepted
	t.Cleanup(func() { client.CloseNow(); close(release); server.Close() })
	return connection, client
}

func TestRealtimePlaybackControlSurvivesResponseCancellation(t *testing.T) {
	connection, client := realtimeLifecycleSocketPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	responseContext, cancelResponse := context.WithCancel(ctx)
	cancelResponse()
	session := &openAIRealtimeSession{
		ctx: ctx, device: &deviceSession{connection: connection, sessionID: "device"},
		responseGeneration: 1,
	}
	// A cancelled response must not be passed into connection.Write: coder/
	// websocket closes the entire socket when Write receives that context.
	if err := session.startDevicePlayback(responseContext, 1); err != nil {
		t.Fatal(err)
	}
	if event := readJSON(t, ctx, client); event["state"] != "start" {
		t.Fatal(event)
	}
	if err := session.waitForDevicePlaybackDrain(responseContext, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("drain did not honor response cancellation: %v", err)
	}
	if event := readJSON(t, ctx, client); event["state"] != "finish" {
		t.Fatal(event)
	}
	session.responseGeneration = 2
	if err := session.writeDevicePlaybackControl(1, "stop"); !errors.Is(err, context.Canceled) {
		t.Fatalf("stale stop was not rejected: %v", err)
	}
	if err := session.writeDevicePlaybackControl(2, "start"); err != nil {
		t.Fatal(err)
	}
	if event := readJSON(t, ctx, client); event["state"] != "start" {
		t.Fatal(event)
	}
}

var _ io.WriteCloser = realtimeClosingWriter{}

func TestRealtimeCloseCancelsBeforeWaitingForStateLock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	session := &openAIRealtimeSession{ctx: ctx, cancel: cancel}
	// Model a socket/codec operation that owns stateMu until its lifetime is
	// cancelled. Close must break this dependency before trying to lock state.
	session.stateMu.Lock()
	done := make(chan struct{})
	go func() { session.Close(); close(done) }()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		session.stateMu.Unlock()
		t.Fatal("Close waited for state lock before cancelling blocked operation")
	}
	session.stateMu.Unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after blocked operation released state")
	}
}
