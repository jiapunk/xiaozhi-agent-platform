package s3camdev

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	parallelTTSWorkers     = 2
	ttsStartupPrimeTimeout = 250 * time.Millisecond
	ttsRetryAttempts       = 3
	ttsRetryInitialBackoff = 350 * time.Millisecond
)

type voiceReplySummary struct {
	Reply       string
	FirstTextAt time.Time
	CompletedAt time.Time
	Err         error
}

type voiceSynthesisJob struct {
	index       int
	text        string
	textReadyAt time.Time
}

type indexedVoiceSynthesisChunk struct {
	index int
	chunk VoiceSynthesisChunk
}

// synthesizeReplyStream keeps at most two provider TTS requests in flight.
// Results are buffered by index, so a later sentence may finish first without
// ever being played before an earlier sentence.
func synthesizeReplyStream(ctx context.Context, pipeline VoicePipeline,
	replies <-chan VoiceReplyChunk) (<-chan VoiceSynthesisChunk,
	<-chan voiceReplySummary) {
	output := make(chan VoiceSynthesisChunk, parallelTTSWorkers)
	summaryOutput := make(chan voiceReplySummary, 1)
	jobs := make(chan voiceSynthesisJob, maxStreamingReplyChunks)
	results := make(chan indexedVoiceSynthesisChunk, parallelTTSWorkers)
	producerDone := make(chan voiceReplySummary, 1)
	workerContext, cancelWorkers := context.WithCancel(ctx)

	go func() {
		defer close(jobs)
		var builder strings.Builder
		summary := voiceReplySummary{}
		index := 0
		for event := range replies {
			if event.Err != nil {
				summary.Err = event.Err
				break
			}
			text := strings.TrimSpace(event.Text)
			if text == "" ||
				!utf8.ValidString(text) ||
				utf8.RuneCountInString(text) > maxSpokenReplyRunes ||
				utf8.RuneCountInString(builder.String())+
					utf8.RuneCountInString(text) > maxSpokenReplyRunes {
				summary.Err = fmt.Errorf("streaming Agent returned invalid spoken text")
				break
			}
			readyAt := time.Now()
			if summary.FirstTextAt.IsZero() {
				summary.FirstTextAt = readyAt
			}
			if needsSpokenSeparator(builder.String(), text) {
				builder.WriteByte(' ')
			}
			builder.WriteString(text)
			job := voiceSynthesisJob{
				index: index, text: text, textReadyAt: readyAt,
			}
			select {
			case <-workerContext.Done():
				summary.Err = workerContext.Err()
				summary.Reply = builder.String()
				summary.CompletedAt = time.Now()
				producerDone <- summary
				return
			case jobs <- job:
				index++
			}
		}
		summary.Reply = builder.String()
		summary.CompletedAt = time.Now()
		if summary.Err == nil && summary.Reply == "" {
			summary.Err = fmt.Errorf("streaming Agent returned no spoken reply")
		}
		producerDone <- summary
	}()

	var workers sync.WaitGroup
	workers.Add(parallelTTSWorkers)
	for worker := 0; worker < parallelTTSWorkers; worker++ {
		go func() {
			defer workers.Done()
			for job := range jobs {
				startedAt := time.Now()
				packets, err := synthesizeVoiceChunkWithRetry(
					workerContext, pipeline, job.text)
				completedAt := time.Now()
				result := indexedVoiceSynthesisChunk{
					index: job.index,
					chunk: VoiceSynthesisChunk{
						Text: job.text, Packets: packets, Err: err,
						TextReadyAt:          job.textReadyAt,
						SynthesisStartedAt:   startedAt,
						SynthesisCompletedAt: completedAt,
					},
				}
				select {
				case <-workerContext.Done():
					return
				case results <- result:
				}
			}
		}()
	}
	go func() {
		workers.Wait()
		close(results)
	}()

	go func() {
		defer close(output)
		defer close(summaryOutput)
		defer cancelWorkers()
		next := 0
		pending := make(map[int]VoiceSynthesisChunk)
		var synthesisErr error
		for result := range results {
			if synthesisErr != nil {
				continue
			}
			pending[result.index] = result.chunk
			for {
				chunk, exists := pending[next]
				if !exists {
					break
				}
				delete(pending, next)
				next++
				if chunk.Err != nil {
					synthesisErr = chunk.Err
					cancelWorkers()
					break
				}
				select {
				case <-ctx.Done():
					synthesisErr = ctx.Err()
					cancelWorkers()
				case output <- chunk:
				}
				if synthesisErr != nil {
					break
				}
			}
		}
		summary := <-producerDone
		if synthesisErr != nil {
			summary.Err = synthesisErr
		}
		if summary.Err != nil {
			select {
			case <-ctx.Done():
			default:
				output <- VoiceSynthesisChunk{Err: summary.Err}
			}
		}
		summaryOutput <- summary
	}()

	return output, summaryOutput
}

func synthesizeVoiceChunkWithRetry(ctx context.Context, pipeline VoicePipeline,
	text string) ([][]byte, error) {
	var lastErr error
	for attempt := 0; attempt < ttsRetryAttempts; attempt++ {
		packets, err := pipeline.Synthesize(ctx, text)
		if err == nil {
			return packets, nil
		}
		lastErr = err
		if !retryableTTSError(err) || attempt == ttsRetryAttempts-1 {
			break
		}
		delay := ttsRetryInitialBackoff << attempt
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, lastErr
}

func retryableTTSError(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	for _, status := range []string{"status 429", "status 500", "status 502", "status 503", "status 504"} {
		if strings.Contains(message, status) {
			return true
		}
	}
	return false
}

// primeVoiceSynthesis preserves the low-latency first-sentence TTS start while
// allowing one following sentence to finish before playback begins. That
// small reserve prevents a fast first sentence from outrunning the external
// TTS provider; the timeout keeps first audio responsive when the next
// sentence is slow or the answer contains only one sentence.
func primeVoiceSynthesis(ctx context.Context,
	input <-chan VoiceSynthesisChunk, maximumWait time.Duration) <-chan VoiceSynthesisChunk {
	output := make(chan VoiceSynthesisChunk, parallelTTSWorkers)
	go func() {
		defer close(output)
		var first VoiceSynthesisChunk
		var ok bool
		select {
		case <-ctx.Done():
			return
		case first, ok = <-input:
		}
		if !ok {
			return
		}
		primed := []VoiceSynthesisChunk{first}
		if first.Err == nil && maximumWait > 0 {
			timer := time.NewTimer(maximumWait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case second, open := <-input:
				timer.Stop()
				if open {
					primed = append(primed, second)
				}
			case <-timer.C:
			}
		}
		for _, chunk := range primed {
			select {
			case <-ctx.Done():
				return
			case output <- chunk:
			}
		}
		for chunk := range input {
			select {
			case <-ctx.Done():
				return
			case output <- chunk:
			}
		}
	}()
	return output
}

func needsSpokenSeparator(existing, next string) bool {
	if existing == "" || next == "" {
		return false
	}
	last, _ := utf8.DecodeLastRuneInString(existing)
	first, _ := utf8.DecodeRuneInString(next)
	return (last <= unicode.MaxASCII &&
		(unicode.IsLetter(last) || unicode.IsDigit(last) ||
			strings.ContainsRune(".!?;,:\"'", last))) &&
		(first <= unicode.MaxASCII &&
			(unicode.IsLetter(first) || unicode.IsDigit(first) ||
				strings.ContainsRune("\"'(", first)))
}
