package actionconsent

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

type wakeSenderFixture struct {
	disposition WakeSendDisposition
	err         error
	calls       int
	target      Actor
	contract    string
	payload     []byte
}

func (sender *wakeSenderFixture) SendWake(_ context.Context, target Actor,
	contract string, payload []byte) (WakeSendDisposition, error) {
	sender.calls++
	sender.target = target
	sender.contract = contract
	sender.payload = bytes.Clone(payload)
	return sender.disposition, sender.err
}

func notifierFixture(t *testing.T, disposition WakeSendDisposition,
	sendErr error) (*Store, *WakeNotifier, *wakeSenderFixture, time.Time) {
	t.Helper()
	now := time.Now().UTC()
	store, _ := NewStore(8)
	if err := store.Register(testChallenge(now), now); err != nil {
		t.Fatal(err)
	}
	sender := &wakeSenderFixture{disposition: disposition, err: sendErr}
	notifier, err := NewWakeNotifier(
		store, sender, "notifier-1", 5*time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	notifier.now = func() time.Time { return now }
	return store, notifier, sender, now
}

func TestWakeNotifierSendsOnlyFixedPayloadAndAcknowledges(t *testing.T) {
	store, notifier, sender, now := notifierFixture(
		t, WakeSendAccepted, nil)
	result, err := notifier.RunOnce(context.Background())
	if err != nil || result != WakeRunAccepted || sender.calls != 1 ||
		sender.target != testActor() || sender.contract != WakeContract ||
		!bytes.Equal(sender.payload, CanonicalWakePayload()) {
		t.Fatalf("result=%v sender=%#v err=%v", result, sender, err)
	}
	if bytes.Contains(sender.payload, []byte(testRequest().ChallengeID)) {
		t.Fatal("challenge ID crossed the provider payload")
	}
	if _, found, err := store.ClaimWake(
		"notifier-2", now, time.Second); err != nil || found {
		t.Fatalf("accepted wake remained found=%t err=%v", found, err)
	}
}

func TestWakeNotifierNoInstallationIsSafeTerminalOutcome(t *testing.T) {
	store, notifier, _, now := notifierFixture(
		t, WakeSendNoInstallation, nil)
	result, err := notifier.RunOnce(context.Background())
	if err != nil || result != WakeRunNoInstallation {
		t.Fatalf("result=%v err=%v", result, err)
	}
	if _, found, _ := store.ClaimWake(
		"notifier-2", now, time.Second); found {
		t.Fatal("no-installation wake remained queued")
	}
	if _, found, err := store.Pending(testActor(), now); err != nil || !found {
		t.Fatalf("notification outcome changed consent found=%t err=%v", found, err)
	}
}

func TestWakeNotifierRetriesWithoutChangingConsent(t *testing.T) {
	store, notifier, _, now := notifierFixture(
		t, WakeSendRetry, errors.New("provider unavailable"))
	result, err := notifier.RunOnce(context.Background())
	if result != WakeRunRetried || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("result=%v err=%v", result, err)
	}
	if _, found, _ := store.ClaimWake(
		"notifier-2", now, time.Second); found {
		t.Fatal("retry escaped before available time")
	}
	if _, found, err := store.Pending(testActor(), now); err != nil || !found {
		t.Fatalf("retry changed consent found=%t err=%v", found, err)
	}
	notifier.now = func() time.Time { return now.Add(time.Second) }
	result, err = notifier.RunOnce(context.Background())
	if result != WakeRunRetried || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("second result=%v err=%v", result, err)
	}
}

func TestWakeNotifierRejectsInvalidProviderDisposition(t *testing.T) {
	_, notifier, _, _ := notifierFixture(t, WakeSendDisposition(99), nil)
	result, err := notifier.RunOnce(context.Background())
	if result != WakeRunRetried || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("result=%v err=%v", result, err)
	}
}

func TestWakeNotifierRunStopsWithContextAndDoesNotBusyLoop(t *testing.T) {
	_, notifier, sender, _ := notifierFixture(t, WakeSendAccepted, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	observed := make(chan WakeRunResult, 1)
	go func() {
		done <- notifier.Run(ctx, 100*time.Millisecond,
			func(result WakeRunResult, _ error) { observed <- result })
	}()
	select {
	case result := <-observed:
		if result != WakeRunAccepted {
			t.Fatalf("result=%v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("wake worker did not process initial item")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("wake worker did not stop")
	}
	if sender.calls != 1 {
		t.Fatalf("sender calls=%d", sender.calls)
	}
}
