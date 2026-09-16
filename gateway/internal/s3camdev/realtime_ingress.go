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
	// 128 device events allow at most 7.68 seconds of 60 ms audio during
	// connection setup. PCM has a smaller 3.84-second bounded network cushion.
	// Neither stage drops frames or grows memory to hide a stalled provider.
	realtimeDeviceIngressCapacity = 128
	realtimePCMIngressCapacity    = 64
)

var errRealtimeIngressFull = errors.New("Realtime audio ingress capacity exceeded")

type realtimeIngressEvent struct {
	kind string
	data []byte
	text string
	at   time.Time
}

type realtimeIngressQueue struct {
	ctx       context.Context
	name      string
	events    chan realtimeIngressEvent
	accepted  atomic.Uint64
	processed atomic.Uint64
	completed atomic.Uint64
	failed    atomic.Uint64
	discarded atomic.Uint64
	overflows atomic.Uint64
	highWater atomic.Uint64
	maxWaitUS atomic.Uint64
}

func newRealtimeIngressQueue(ctx context.Context, name string, capacity int) *realtimeIngressQueue {
	return &realtimeIngressQueue{ctx: ctx, name: name,
		events: make(chan realtimeIngressEvent, capacity)}
}

func realtimeAtomicMaximum(value *atomic.Uint64, candidate uint64) {
	for previous := value.Load(); candidate > previous; previous = value.Load() {
		if value.CompareAndSwap(previous, candidate) {
			return
		}
	}
}

func (queue *realtimeIngressQueue) push(event realtimeIngressEvent) error {
	if err := queue.ctx.Err(); err != nil {
		return err
	}
	event.at = time.Now()
	event.data = append([]byte(nil), event.data...)
	select {
	case queue.events <- event:
		queue.accepted.Add(1)
		realtimeAtomicMaximum(&queue.highWater, uint64(len(queue.events)))
		return nil
	default:
		queue.overflows.Add(1)
		return fmt.Errorf("%w: stage=%s capacity=%d", errRealtimeIngressFull,
			queue.name, cap(queue.events))
	}
}

func (queue *realtimeIngressQueue) noteProcessed(event realtimeIngressEvent) {
	queue.processed.Add(1)
	wait := time.Since(event.at).Microseconds()
	if wait > 0 {
		realtimeAtomicMaximum(&queue.maxWaitUS, uint64(wait))
	}
}

func (queue *realtimeIngressQueue) log(logger *slog.Logger) {
	logger.Info("Realtime ingress integrity", "stage", queue.name,
		"accepted", queue.accepted.Load(), "dequeued", queue.processed.Load(),
		"completed", queue.completed.Load(), "failed", queue.failed.Load(),
		"discarded_after_failure_or_stop", queue.discarded.Load(),
		"pending", len(queue.events), "overflows", queue.overflows.Load(),
		"queue_high_water", queue.highWater.Load(),
		"max_queue_wait_ms", queue.maxWaitUS.Load()/1000)
}

// A single owner serializes listen/start, Opus, wake/VAD and manual abort in
// device order. Slow provider setup/FFmpeg can no longer block the websocket
// reader from delivering MCP, consent or playback-drained acknowledgements.
type realtimeDeviceIngress struct {
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	queue   *realtimeIngressQueue
	gateway *OpenAIRealtimeGateway
	device  *deviceSession
	enabled atomic.Bool
}

func newRealtimeDeviceIngress(ctx context.Context, gateway *OpenAIRealtimeGateway,
	device *deviceSession) *realtimeDeviceIngress {
	ctx, cancel := context.WithCancel(ctx)
	input := &realtimeDeviceIngress{ctx: ctx, cancel: cancel, done: make(chan struct{}),
		gateway: gateway, device: device,
		queue: newRealtimeIngressQueue(ctx, "device_to_decoder", realtimeDeviceIngressCapacity)}
	go input.run()
	return input
}

func (input *realtimeDeviceIngress) Enabled() bool {
	return input != nil && input.enabled.Load()
}

func (input *realtimeDeviceIngress) Start() error {
	input.enabled.Store(true)
	return input.queue.push(realtimeIngressEvent{kind: "start"})
}

func (input *realtimeDeviceIngress) Stop() error {
	input.enabled.Store(false)
	return input.queue.push(realtimeIngressEvent{kind: "stop"})
}

func (input *realtimeDeviceIngress) push(kind string, data []byte, text string) error {
	return input.queue.push(realtimeIngressEvent{kind: kind, data: data, text: text})
}

func (input *realtimeDeviceIngress) Close() {
	input.cancel()
	<-input.done
}

func (input *realtimeDeviceIngress) reportFailure(err error) {
	input.gateway.config.Logger.Error("Realtime device ingress failed", "error", err)
	input.queue.log(input.gateway.config.Logger)
	code := "realtime_unavailable"
	if errors.Is(err, errRealtimeIngressFull) {
		code = "audio_input_overflow"
	}
	// This error is a device-connection control frame, not cancelled response work.
	_ = input.device.writeJSON(input.ctx, map[string]any{
		"session_id": input.device.sessionID, "type": "error", "code": code,
	})
}

func (input *realtimeDeviceIngress) run() {
	defer close(input.done)
	defer input.queue.log(input.gateway.config.Logger)
	var live *openAIRealtimeSession
	defer func() {
		if live != nil {
			live.Close()
		}
	}()
	for {
		select {
		case <-input.ctx.Done():
			return
		case event := <-input.queue.events:
			input.queue.noteProcessed(event)
			if input.queue.processed.Load()%100 == 0 {
				input.queue.log(input.gateway.config.Logger)
			}
			var err error
			switch event.kind {
			case "start":
				if live != nil && !live.IsClosed() {
					input.queue.completed.Add(1)
					continue
				}
				if live != nil {
					live.Close()
				}
				started := time.Now()
				live, err = input.gateway.Start(input.ctx, input.device)
				input.gateway.config.Logger.Info("Realtime ingress setup completed",
					"success", err == nil, "setup_ms", time.Since(started).Milliseconds(),
					"buffered_events", len(input.queue.events))
				if err == nil {
					input.device.server.update(func(status *PublicStatus) {
						status.Microphone = "等待語音"
						status.LastEvent = "Realtime 全雙工語音已連線"
					})
				}
			case "stop":
				if live != nil {
					live.Close()
					live = nil
				}
			default:
				if live == nil || live.IsClosed() {
					input.queue.discarded.Add(1)
					continue
				}
				switch event.kind {
				case "opus":
					err = live.AppendOpus(event.data)
				case "wake":
					live.MarkWakeWord(event.text)
				case "speech_start":
					live.MarkDeviceVoiceActivity(true)
				case "speech_stop":
					live.MarkDeviceVoiceActivity(false)
				case "abort":
					err = live.InterruptByDevice()
				}
			}
			if err != nil {
				input.queue.failed.Add(1)
				input.enabled.Store(false)
				if !errors.Is(err, context.Canceled) {
					if live != nil {
						live.fail(err)
					} else {
						input.reportFailure(err)
					}
				}
				if live != nil {
					live.Close()
					live = nil
				}
			} else {
				input.queue.completed.Add(1)
			}
		}
	}
}

func (session *openAIRealtimeSession) inputPCMLoop() {
	queue := session.pcmIngress
	defer queue.log(session.gateway.config.Logger)
	for {
		select {
		case <-session.ctx.Done():
			return
		case event := <-queue.events:
			queue.noteProcessed(event)
			if err := session.sendInputPCM(event.data); err != nil {
				queue.failed.Add(1)
				if !errors.Is(err, context.Canceled) {
					session.fail(fmt.Errorf("forward queued Realtime PCM: %w", err))
				}
				return
			}
			queue.completed.Add(1)
			if queue.processed.Load()%100 == 0 {
				queue.log(session.gateway.config.Logger)
			}
		}
	}
}
