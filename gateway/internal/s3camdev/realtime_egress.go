package s3camdev

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"
)

const (
	realtimePCMEgressCapacity     = 2048
	realtimePCMEgressMaximumBytes = 8 * 1024 * 1024
)

var errRealtimeEgressFull = errors.New("Realtime audio egress capacity exceeded")

type realtimeEgressEvent struct {
	generation uint64
	responseID string
	pcm        []byte
	finished   bool
	at         time.Time
}

// The provider can emit PCM faster than wall-clock playback. A dedicated
// worker owns ffmpeg writes; the provider reader must always remain free to
// receive speech_started, tools and cancellation even when playback stalls.
// Both bytes and event count are bounded. Only explicitly superseded response
// generations are discarded, with counters; current audio is never dropped.
type realtimeEgressQueue struct {
	ctx            context.Context
	events         chan realtimeEgressEvent
	maximumBytes   int64
	pendingBytes   atomic.Int64
	accepted       atomic.Uint64
	processed      atomic.Uint64
	acceptedBytes  atomic.Uint64
	processedBytes atomic.Uint64
	stale          atomic.Uint64
	staleBytes     atomic.Uint64
	overflows      atomic.Uint64
	highWater      atomic.Uint64
	byteHighWater  atomic.Uint64
	maxWaitUS      atomic.Uint64
}

func newRealtimeEgressQueue(ctx context.Context, capacity int, maximumBytes int64) *realtimeEgressQueue {
	return &realtimeEgressQueue{ctx: ctx, events: make(chan realtimeEgressEvent, capacity),
		maximumBytes: maximumBytes}
}

func (queue *realtimeEgressQueue) push(event realtimeEgressEvent) error {
	if err := queue.ctx.Err(); err != nil {
		return err
	}
	size := int64(len(event.pcm))
	for {
		previous := queue.pendingBytes.Load()
		if size > queue.maximumBytes-previous {
			queue.overflows.Add(1)
			return fmt.Errorf("%w: stage=provider_to_encoder byte_limit=%d", errRealtimeEgressFull, queue.maximumBytes)
		}
		if queue.pendingBytes.CompareAndSwap(previous, previous+size) {
			break
		}
	}
	event.at = time.Now()
	// handleAudioDelta owns the newly decoded byte slice. No other path may
	// mutate it once enqueued, avoiding a second large PCM allocation.
	select {
	case queue.events <- event:
		queue.accepted.Add(1)
		queue.acceptedBytes.Add(uint64(size))
		realtimeAtomicMaximum(&queue.highWater, uint64(len(queue.events)))
		realtimeAtomicMaximum(&queue.byteHighWater, uint64(queue.pendingBytes.Load()))
		return nil
	default:
		queue.pendingBytes.Add(-size)
		queue.overflows.Add(1)
		return fmt.Errorf("%w: stage=provider_to_encoder event_limit=%d", errRealtimeEgressFull, cap(queue.events))
	}
}

func (queue *realtimeEgressQueue) take(event realtimeEgressEvent) {
	queue.pendingBytes.Add(-int64(len(event.pcm)))
	wait := time.Since(event.at).Microseconds()
	if wait > 0 {
		realtimeAtomicMaximum(&queue.maxWaitUS, uint64(wait))
	}
}

func (queue *realtimeEgressQueue) log(logger *slog.Logger) {
	logger.Info("Realtime egress integrity", "stage", "provider_to_encoder",
		"accepted", queue.accepted.Load(), "processed", queue.processed.Load(),
		"accepted_pcm_bytes", queue.acceptedBytes.Load(), "processed_pcm_bytes", queue.processedBytes.Load(),
		"superseded_events", queue.stale.Load(), "superseded_pcm_bytes", queue.staleBytes.Load(),
		"pending_pcm_bytes", queue.pendingBytes.Load(), "overflows", queue.overflows.Load(),
		"queue_high_water", queue.highWater.Load(), "byte_high_water", queue.byteHighWater.Load(),
		"max_queue_wait_ms", queue.maxWaitUS.Load()/1000)
}

func (session *openAIRealtimeSession) enqueueAudioFinish(responseID string) error {
	session.stateMu.Lock()
	generation := session.responseGeneration
	active := !session.responseBlocked && (responseID == "" || session.responseID == "" || responseID == session.responseID)
	session.stateMu.Unlock()
	if !active {
		return nil
	}
	return session.pcmEgress.push(realtimeEgressEvent{
		generation: generation, responseID: responseID, finished: true,
	})
}

func (session *openAIRealtimeSession) outputPCMLoop() {
	queue := session.pcmEgress
	defer queue.log(session.gateway.config.Logger)
	for {
		select {
		case <-session.ctx.Done():
			return
		case event := <-queue.events:
			queue.take(event)
			if !session.responseOutputActive(event.generation, nil) {
				queue.stale.Add(1)
				queue.staleBytes.Add(uint64(len(event.pcm)))
				continue
			}
			if event.finished {
				session.finishAudioGeneration(event.generation, event.responseID)
				queue.processed.Add(1)
				queue.log(session.gateway.config.Logger)
				continue
			}
			encoder, _, responseContext, err := session.ensureAudioEncoder(event.generation)
			if err == nil {
				err = encoder.WritePCM(event.pcm)
			}
			if errors.Is(err, context.Canceled) || !session.responseOutputActive(event.generation, responseContext) {
				queue.stale.Add(1)
				queue.staleBytes.Add(uint64(len(event.pcm)))
				continue
			}
			if err != nil {
				session.fail(fmt.Errorf("encode queued Realtime PCM: %w", err))
				return
			}
			queue.processed.Add(1)
			queue.processedBytes.Add(uint64(len(event.pcm)))
		}
	}
}
