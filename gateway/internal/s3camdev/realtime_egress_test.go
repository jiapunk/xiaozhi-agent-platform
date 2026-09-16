package s3camdev

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"sync"
	"testing"
	"time"
)

func TestRealtimeEgressBoundsBytesAndEventsWithoutDroppingAcceptedAudio(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue := newRealtimeEgressQueue(ctx, 2, 6)
	first := realtimeEgressEvent{generation: 1, pcm: []byte{1, 2, 3, 4}}
	if err := queue.push(first); err != nil {
		t.Fatal(err)
	}
	if err := queue.push(first); !errors.Is(err, errRealtimeEgressFull) {
		t.Fatal("byte capacity was not enforced")
	}
	if err := queue.push(realtimeEgressEvent{generation: 1, finished: true}); err != nil {
		t.Fatal(err)
	}
	if err := queue.push(realtimeEgressEvent{generation: 1, finished: true}); !errors.Is(err, errRealtimeEgressFull) {
		t.Fatal("event capacity was not enforced")
	}
	one, two := <-queue.events, <-queue.events
	queue.take(one)
	queue.take(two)
	if !bytes.Equal(one.pcm, first.pcm) || !two.finished || queue.pendingBytes.Load() != 0 ||
		queue.accepted.Load() != 2 || queue.overflows.Load() != 2 {
		t.Fatal("accepted audio or finish ordering/counters changed on overflow")
	}
}

type realtimeRecordingPCMWriter struct {
	mu     sync.Mutex
	data   bytes.Buffer
	closed bool
}

func (writer *realtimeRecordingPCMWriter) Write(data []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.closed {
		return 0, errors.New("write after finish")
	}
	return writer.data.Write(data)
}

func (writer *realtimeRecordingPCMWriter) Close() error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	writer.closed = true
	return nil
}

func TestRealtimeEgressPreservesAllPCMAndFinishAcrossTurns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session := &openAIRealtimeSession{
		gateway: &OpenAIRealtimeGateway{config: OpenAIRealtimeConfig{Logger: slog.Default()}},
		ctx:     ctx, cancel: cancel, playback: make(chan realtimePlaybackEvent, 1),
		pcmEgress: newRealtimeEgressQueue(ctx, 16, 4096),
	}
	done := make(chan struct{})
	go func() { session.outputPCMLoop(); close(done) }()
	defer func() { cancel(); <-done }()
	for turn := range 5 {
		responseID := fmt.Sprintf("round_%d", turn)
		session.beginResponse(responseID)
		writer := &realtimeRecordingPCMWriter{}
		encoderDone := make(chan struct{})
		close(encoderDone)
		session.stateMu.Lock()
		session.responseEncoder = &realtimeOpusEncoder{stdin: writer, done: encoderDone}
		session.responseContext = ctx
		generation := session.responseGeneration
		session.stateMu.Unlock()
		want := []byte{byte(turn), 1, 2, 3, 4, 5, 6, 7}
		for _, pcm := range [][]byte{want[:2], want[2:6], want[6:]} {
			if err := session.handleAudioDelta(responseID, base64.StdEncoding.EncodeToString(pcm)); err != nil {
				t.Fatal(err)
			}
		}
		if err := session.enqueueAudioFinish(responseID); err != nil {
			t.Fatal(err)
		}
		select {
		case event := <-session.playback:
			if !event.finished || event.generation != generation {
				t.Fatal("finish belongs to wrong turn")
			}
		case <-time.After(time.Second):
			t.Fatal("finish did not follow queued audio")
		}
		writer.mu.Lock()
		got := append([]byte(nil), writer.data.Bytes()...)
		closed := writer.closed
		writer.mu.Unlock()
		if !bytes.Equal(got, want) || !closed {
			t.Fatalf("round %d lost/reordered PCM: %v", turn, got)
		}
	}
	if session.pcmEgress.acceptedBytes.Load() != 40 || session.pcmEgress.processedBytes.Load() != 40 ||
		session.pcmEgress.stale.Load() != 0 || session.pcmEgress.overflows.Load() != 0 {
		t.Fatal("completed output integrity counts differ")
	}
}

func TestRealtimeStalledEncoderCannotBlockProviderBargeIn(t *testing.T) {
	ffmpeg, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg is unavailable")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session := &openAIRealtimeSession{
		gateway: &OpenAIRealtimeGateway{config: OpenAIRealtimeConfig{Logger: slog.Default(), FFmpegPath: ffmpeg}},
		device:  &deviceSession{server: &Server{}}, ctx: ctx, cancel: cancel,
		playback:  make(chan realtimePlaybackEvent), // deliberately blocked downstream
		pcmEgress: newRealtimeEgressQueue(ctx, 16, 4*1024*1024),
	}
	done := make(chan struct{})
	go func() { session.outputPCMLoop(); close(done) }()
	defer func() { cancel(); <-done }()
	encoded := base64.StdEncoding.EncodeToString(make([]byte, realtimePCMFrameBytes*100))
	for round := range 3 {
		responseID := fmt.Sprintf("blocked_%d", round)
		session.beginResponse(responseID)
		if err := session.handleAudioDelta(responseID, encoded); err != nil {
			t.Fatal(err)
		}
		if err := session.enqueueAudioFinish(responseID); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(2 * time.Second)
		for {
			session.stateMu.Lock()
			encoder := session.responseEncoder
			session.stateMu.Unlock()
			if encoder != nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("encoder worker did not start")
			}
			time.Sleep(time.Millisecond)
		}
		started := time.Now()
		if err := session.handleEvent(openAIRealtimeEvent{
			Type: "input_audio_buffer.speech_started", ItemID: fmt.Sprintf("new_%d", round),
		}); err != nil {
			t.Fatal(err)
		}
		if time.Since(started) > 250*time.Millisecond {
			t.Fatal("provider speech_started waited behind blocked ffmpeg output")
		}
		if ctx.Err() != nil || session.IsClosed() {
			t.Fatal("barge-in killed persistent session")
		}
	}
}
