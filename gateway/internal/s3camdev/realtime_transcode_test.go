package s3camdev

import (
	"context"
	"encoding/base64"
	"errors"
	"os/exec"
	"testing"
	"time"
)

func TestRealtimeOpusDecoderEmitsPCMBeforeInputCloses(t *testing.T) {
	ffmpeg, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pcmFrames := make(chan []byte, 8)
	decoder, err := newRealtimeOpusDecoder(ctx, ffmpeg, func(pcm []byte) error {
		pcmFrames <- append([]byte(nil), pcm...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 2; index++ {
		packet, decodeErr := base64.StdEncoding.DecodeString(
			testSpeechPacketsBase64[index])
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if err := decoder.WritePacket(packet); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case pcm := <-pcmFrames:
		if len(pcm) != realtimePCMFrameBytes {
			t.Fatalf("unexpected PCM frame bytes: %d", len(pcm))
		}
	case <-ctx.Done():
		t.Fatal("decoder buffered audio until the input stream closed")
	}
	if err := decoder.Close(); err != nil && !errors.Is(err, context.Canceled) &&
		!errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	cancel()
}

func TestRealtimeOpusEncoderEmitsPacketBeforePCMCloses(t *testing.T) {
	ffmpeg, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	opusPackets := make(chan []byte, 16)
	encoder, err := newRealtimeOpusEncoder(ctx, ffmpeg, func(packet []byte) error {
		opusPackets <- append([]byte(nil), packet...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	pcm := make([]byte, realtimePCMFrameBytes)
	for index := range 3 {
		pcm[index*2] = byte(index + 1)
		if err := encoder.WritePCM(pcm); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case packet := <-opusPackets:
		if len(packet) == 0 {
			t.Fatal("encoder returned an empty Opus packet")
		}
	case <-encoder.done:
		t.Fatalf("encoder stopped before producing audio: %v", encoder.doneErr)
	case <-ctx.Done():
		t.Fatal("encoder buffered audio until the PCM stream closed")
	}
	if err := encoder.Close(); err != nil &&
		!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	cancel()
}
