package s3camdev

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

type transientTTSPipeline struct {
	attempts atomic.Int32
}

func (*transientTTSPipeline) Transcribe(context.Context, [][]byte) (string, error) {
	return "", nil
}

func (*transientTTSPipeline) Reply(context.Context, string) (string, error) {
	return "", nil
}

func (pipeline *transientTTSPipeline) Synthesize(
	context.Context, string) ([][]byte, error) {
	if pipeline.attempts.Add(1) < 3 {
		return nil, fmt.Errorf("provider status 429")
	}
	return [][]byte{{0x7f}}, nil
}

func TestTransientTTSRateLimitIsRetried(t *testing.T) {
	pipeline := &transientTTSPipeline{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	packets, err := synthesizeVoiceChunkWithRetry(ctx, pipeline, "測試")
	if err != nil || len(packets) != 1 || packets[0][0] != 0x7f ||
		pipeline.attempts.Load() != 3 {
		t.Fatalf("transient TTS retry failed: attempts=%d packets=%v err=%v",
			pipeline.attempts.Load(), packets, err)
	}
}

type orderedParallelSynthesisPipeline struct {
	firstStarted  chan struct{}
	secondStarted chan struct{}
	releaseFirst  chan struct{}
}

func (*orderedParallelSynthesisPipeline) Transcribe(
	context.Context, [][]byte) (string, error) {
	return "", nil
}

func (*orderedParallelSynthesisPipeline) Reply(
	context.Context, string) (string, error) {
	return "", nil
}

func (pipeline *orderedParallelSynthesisPipeline) Synthesize(
	ctx context.Context, text string) ([][]byte, error) {
	if text == "第一句。" {
		close(pipeline.firstStarted)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-pipeline.releaseFirst:
		}
		return [][]byte{{0x01}}, nil
	}
	close(pipeline.secondStarted)
	return [][]byte{{0x02}}, nil
}

func TestParallelSynthesisPreservesReplyOrder(t *testing.T) {
	pipeline := &orderedParallelSynthesisPipeline{
		firstStarted: make(chan struct{}), secondStarted: make(chan struct{}),
		releaseFirst: make(chan struct{}),
	}
	replies := make(chan VoiceReplyChunk, 2)
	replies <- VoiceReplyChunk{Text: "第一句。"}
	replies <- VoiceReplyChunk{Text: "第二句。"}
	close(replies)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	chunks, summaryChannel := synthesizeReplyStream(ctx, pipeline, replies)

	select {
	case <-pipeline.firstStarted:
	case <-ctx.Done():
		t.Fatal("first TTS did not start")
	}
	select {
	case <-pipeline.secondStarted:
	case <-ctx.Done():
		t.Fatal("second TTS did not run in parallel")
	}
	select {
	case chunk := <-chunks:
		t.Fatalf("later sentence bypassed unfinished first sentence: %+v", chunk)
	case <-time.After(40 * time.Millisecond):
	}
	close(pipeline.releaseFirst)

	var received []VoiceSynthesisChunk
	for chunk := range chunks {
		received = append(received, chunk)
	}
	summary := <-summaryChannel
	if summary.Err != nil {
		t.Fatal(summary.Err)
	}
	if len(received) != 2 || received[0].Text != "第一句。" ||
		received[1].Text != "第二句。" || received[0].Packets[0][0] != 0x01 ||
		received[1].Packets[0][0] != 0x02 {
		t.Fatalf("synthesis order changed: %+v", received)
	}
	if summary.Reply != "第一句。第二句。" || summary.FirstTextAt.IsZero() ||
		summary.CompletedAt.Before(summary.FirstTextAt) {
		t.Fatalf("invalid streaming summary: %+v", summary)
	}
}

func TestPrimeVoiceSynthesisWaitsForSecondChunk(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	input := make(chan VoiceSynthesisChunk, 2)
	input <- VoiceSynthesisChunk{Text: "第一句。", Packets: [][]byte{{1}}}
	output := primeVoiceSynthesis(ctx, input, 200*time.Millisecond)
	select {
	case chunk := <-output:
		t.Fatalf("first chunk escaped before the reserve was ready: %+v", chunk)
	case <-time.After(30 * time.Millisecond):
	}
	input <- VoiceSynthesisChunk{Text: "第二句。", Packets: [][]byte{{2}}}
	close(input)
	first := <-output
	second := <-output
	if first.Text != "第一句。" || second.Text != "第二句。" {
		t.Fatalf("startup reserve changed order: first=%+v second=%+v", first, second)
	}
}

func TestPrimeVoiceSynthesisTimeoutKeepsFirstAudioResponsive(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	input := make(chan VoiceSynthesisChunk, 1)
	input <- VoiceSynthesisChunk{Text: "唯一一句。", Packets: [][]byte{{1}}}
	started := time.Now()
	output := primeVoiceSynthesis(ctx, input, 35*time.Millisecond)
	chunk := <-output
	if chunk.Text != "唯一一句。" || time.Since(started) < 25*time.Millisecond {
		t.Fatalf("first chunk did not honor bounded priming: %+v", chunk)
	}
	close(input)
}
