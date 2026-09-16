package gateway

import (
	"context"
	"errors"
	"sync"
	"time"

	"xiaozhi-agent-platform/gateway/internal/speechbudget"
)

type sttUsageMeter struct {
	ledger  speechbudget.Ledger
	pricing speechbudget.Pricing
	subject string
	metrics *Metrics

	mu          sync.Mutex
	reservation speechbudget.Reservation
	usedAudioMS int64
	timer       *time.Timer
	closed      bool
	failed      error
}

func newSTTUsageMeter(ledger speechbudget.Ledger, pricing speechbudget.Pricing,
	subject string, metrics *Metrics) *sttUsageMeter {
	if ledger == nil {
		return nil
	}
	return &sttUsageMeter{ledger: ledger, pricing: pricing,
		subject: subject, metrics: metrics}
}

// HandleAudio holds the reservation lock across the upstream write. That makes
// the order explicit: durable reserve, provider contact, then durable settle.
func (meter *sttUsageMeter) HandleAudio(ctx context.Context, frameDurationMS int,
	send func() error) error {
	if meter == nil {
		return send()
	}
	meter.mu.Lock()
	defer meter.mu.Unlock()
	if meter.closed || meter.failed != nil || frameDurationMS < 1 {
		return speechbudget.ErrUnavailable
	}
	frameMS := int64(frameDurationMS)
	if meter.reservation.ReservedMicrousd > 0 &&
		meter.usedAudioMS+frameMS > meter.pricing.STTReservationChunkAudioMS {
		if err := meter.settleLocked(ctx); err != nil {
			return err
		}
	}
	if meter.reservation.ReservedMicrousd == 0 {
		reservation, err := meter.ledger.Reserve(ctx, meter.subject,
			speechbudget.STTUsage(meter.pricing.STTReservationChunkAudioMS))
		if err != nil {
			if errors.Is(err, speechbudget.ErrBudgetExceeded) {
				meter.metrics.speechBudgetRejected.Add(1)
			} else {
				meter.metrics.speechUsageFailures.Add(1)
			}
			return err
		}
		meter.reservation = reservation
	}
	if err := send(); err != nil {
		meter.markUncertainLocked(context.Background())
		return err
	}
	meter.usedAudioMS += frameMS
	meter.armTimerLocked()
	if meter.usedAudioMS >= meter.pricing.STTReservationChunkAudioMS {
		return meter.settleLocked(ctx)
	}
	return nil
}

func (meter *sttUsageMeter) armTimerLocked() {
	if meter.timer != nil {
		meter.timer.Stop()
	}
	interval := meter.pricing.ReservationTTL / 2
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	meter.timer = time.AfterFunc(interval, meter.flush)
}

func (meter *sttUsageMeter) flush() {
	meter.mu.Lock()
	defer meter.mu.Unlock()
	if meter.closed || meter.failed != nil || meter.reservation.ReservedMicrousd == 0 {
		return
	}
	if err := meter.settleLocked(context.Background()); err != nil {
		meter.failed = err
	}
}

func (meter *sttUsageMeter) settleLocked(ctx context.Context) error {
	if meter.reservation.ReservedMicrousd == 0 {
		return nil
	}
	if meter.timer != nil {
		meter.timer.Stop()
		meter.timer = nil
	}
	reservation := meter.reservation
	used := meter.usedAudioMS
	if used == 0 {
		if err := meter.ledger.Release(ctx, reservation); err != nil {
			meter.metrics.speechUsageFailures.Add(1)
			return err
		}
	} else {
		settlement, err := meter.ledger.Settle(ctx, reservation,
			speechbudget.STTUsage(used))
		if err != nil {
			meter.metrics.speechUsageFailures.Add(1)
			return err
		}
		meter.metrics.speechSettledReservations.Add(1)
		meter.metrics.speechCommittedMicrousd.Add(settlement.CostMicrousd)
		meter.metrics.speechSTTAudioMS.Add(used)
	}
	meter.reservation = speechbudget.Reservation{}
	meter.usedAudioMS = 0
	return nil
}

func (meter *sttUsageMeter) markUncertainLocked(ctx context.Context) {
	if meter.reservation.ReservedMicrousd == 0 {
		return
	}
	if meter.timer != nil {
		meter.timer.Stop()
		meter.timer = nil
	}
	cost, err := meter.ledger.MarkUncertain(ctx, meter.reservation)
	if err != nil {
		meter.metrics.speechUsageFailures.Add(1)
		meter.failed = err
		return
	}
	meter.metrics.speechUncertainReservations.Add(1)
	meter.metrics.speechUncertainMicrousd.Add(cost)
	meter.reservation = speechbudget.Reservation{}
	meter.usedAudioMS = 0
}

func (meter *sttUsageMeter) Close() {
	if meter == nil {
		return
	}
	meter.mu.Lock()
	defer meter.mu.Unlock()
	if meter.closed {
		return
	}
	meter.closed = true
	if meter.failed != nil {
		meter.markUncertainLocked(context.Background())
		return
	}
	if err := meter.settleLocked(context.Background()); err != nil {
		meter.markUncertainLocked(context.Background())
	}
}

func (server *Server) reserveTTS(ctx context.Context, subject string,
	characters int64) (speechbudget.Reservation, error) {
	if server.config.SpeechUsageLedger == nil {
		return speechbudget.Reservation{}, nil
	}
	reservation, err := server.config.SpeechUsageLedger.Reserve(ctx, subject,
		speechbudget.TTSUsage(characters,
			server.config.SpeechPricing.TTSMaxOutputAudioMS))
	if err != nil {
		if errors.Is(err, speechbudget.ErrBudgetExceeded) {
			server.metrics.speechBudgetRejected.Add(1)
		} else {
			server.metrics.speechUsageFailures.Add(1)
		}
	}
	return reservation, err
}

func (server *Server) settleTTS(ctx context.Context,
	reservation speechbudget.Reservation, characters, outputAudioMS int64) error {
	if reservation.ReservedMicrousd == 0 {
		return nil
	}
	settlement, err := server.config.SpeechUsageLedger.Settle(ctx, reservation,
		speechbudget.TTSUsage(characters, outputAudioMS))
	if err != nil {
		server.metrics.speechUsageFailures.Add(1)
		return err
	}
	server.metrics.speechSettledReservations.Add(1)
	server.metrics.speechCommittedMicrousd.Add(settlement.CostMicrousd)
	server.metrics.speechTTSCharacters.Add(characters)
	server.metrics.speechTTSOutputAudioMS.Add(outputAudioMS)
	return nil
}

func (server *Server) releaseTTS(ctx context.Context,
	reservation speechbudget.Reservation) {
	if reservation.ReservedMicrousd == 0 {
		return
	}
	if err := server.config.SpeechUsageLedger.Release(ctx, reservation); err != nil {
		server.metrics.speechUsageFailures.Add(1)
	}
}

func (server *Server) uncertainTTS(ctx context.Context,
	reservation speechbudget.Reservation) {
	if reservation.ReservedMicrousd == 0 {
		return
	}
	cost, err := server.config.SpeechUsageLedger.MarkUncertain(ctx, reservation)
	if err != nil {
		server.metrics.speechUsageFailures.Add(1)
		return
	}
	server.metrics.speechUncertainReservations.Add(1)
	server.metrics.speechUncertainMicrousd.Add(cost)
}
