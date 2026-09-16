package actionconsent

import (
	"context"
	"errors"
	"fmt"
	"time"
)

type WakeSendDisposition uint8

const (
	WakeSendAccepted WakeSendDisposition = iota + 1
	WakeSendNoInstallation
	WakeSendRetry
)

type WakeRunResult uint8

const (
	WakeRunIdle WakeRunResult = iota
	WakeRunAccepted
	WakeRunNoInstallation
	WakeRunRetried
	WakeRunExpired
)

// WakeSender owns the selected APNs/FCM installation registry and provider
// transport. It receives only routing metadata plus the fixed content-free
// payload. Provider response bodies and credentials must not cross this API.
type WakeSender interface {
	SendWake(context.Context, Actor, string,
		[]byte) (WakeSendDisposition, error)
}

type WakeNotifier struct {
	outbox     WakeOutbox
	sender     WakeSender
	workerID   string
	lease      time.Duration
	retryAfter time.Duration
	now        func() time.Time
}

const (
	minimumWakePoll = 100 * time.Millisecond
	maximumWakePoll = 5 * time.Second
)

func NewWakeNotifier(outbox WakeOutbox, sender WakeSender, workerID string,
	lease, retryAfter time.Duration) (*WakeNotifier, error) {
	if outbox == nil || sender == nil || !validWakeWorker(workerID) ||
		!validWakeLease(lease) || !validWakeRetry(retryAfter) {
		return nil, ErrInvalid
	}
	return &WakeNotifier{
		outbox: outbox, sender: sender, workerID: workerID,
		lease: lease, retryAfter: retryAfter, now: time.Now,
	}, nil
}

// RunOnce claims at most one wake. Provider acceptance acknowledges only the
// outbox row and never the action; retry/no-installation cannot create a
// consent decision. The worker deliberately has no challenge-reading API.
func (notifier *WakeNotifier) RunOnce(ctx context.Context) (WakeRunResult, error) {
	if notifier == nil || notifier.outbox == nil || notifier.sender == nil ||
		ctx == nil {
		return WakeRunIdle, ErrInvalid
	}
	now := notifier.now().UTC()
	wake, found, err := notifier.outbox.ClaimWake(
		notifier.workerID, now, notifier.lease)
	if err != nil {
		return WakeRunIdle, err
	}
	if !found {
		return WakeRunIdle, nil
	}
	disposition, sendErr := notifier.sender.SendWake(
		ctx, wake.Target, WakeContract, CanonicalWakePayload())
	switch disposition {
	case WakeSendAccepted, WakeSendNoInstallation:
		if sendErr != nil {
			break
		}
		if err := notifier.outbox.AcknowledgeWake(
			notifier.workerID, wake.WakeID, notifier.now().UTC()); err != nil {
			return WakeRunIdle, err
		}
		if disposition == WakeSendAccepted {
			return WakeRunAccepted, nil
		}
		return WakeRunNoInstallation, nil
	case WakeSendRetry:
		// A provider may omit its internal diagnostic; the public result still
		// remains a bounded retry classification.
	default:
		if sendErr == nil {
			sendErr = errors.New("invalid wake provider disposition")
		}
	}
	err = notifier.outbox.RetryWake(
		notifier.workerID, wake.WakeID, notifier.now().UTC(),
		notifier.retryAfter)
	if errors.Is(err, ErrExpired) {
		return WakeRunExpired, nil
	}
	if err != nil {
		return WakeRunIdle, err
	}
	if sendErr == nil {
		sendErr = ErrUnavailable
	}
	return WakeRunRetried, fmt.Errorf("%w: wake provider retry", ErrUnavailable)
}

// Run polls the durable outbox serially until shutdown. It never overlaps
// provider sends for one worker identity and therefore cannot extend a lease by
// launching unbounded goroutines during a provider outage.
func (notifier *WakeNotifier) Run(ctx context.Context, poll time.Duration,
	observe func(WakeRunResult, error)) error {
	if notifier == nil || ctx == nil || poll < minimumWakePoll ||
		poll > maximumWakePoll {
		return ErrInvalid
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			result, err := notifier.RunOnce(ctx)
			if observe != nil && (result != WakeRunIdle || err != nil) {
				observe(result, err)
			}
			timer.Reset(poll)
		}
	}
}
