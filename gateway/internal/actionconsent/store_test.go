package actionconsent

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testChallengeID = "MDEyMzQ1Njc4OWFiY2RlZg"

func testChallenge(now time.Time) Challenge {
	return Challenge{
		ChallengeID: testChallengeID,
		DeviceID:    "device-1", OwnerID: "user-1", TenantID: "tenant-1",
		OwnerRevision: 7, SessionID: "session-1", RequestID: 42,
		Action:    Action{IndicatorOn: true},
		ExpiresAt: now.Add(20 * time.Second),
	}
}

func testActor() Actor {
	return Actor{
		OwnerID: "user-1", TenantID: "tenant-1", DeviceID: "device-1",
		OwnerRevision: 7,
	}
}

func testRequest() Request {
	return Request{
		ChallengeID: testChallengeID, DeviceID: "device-1",
		OwnerRevision: 7, SessionID: "session-1", RequestID: 42,
		Action: Action{IndicatorOn: true}, Decision: DecisionApprove,
	}
}

func testDeviceRequest() DeviceRequest {
	return DeviceRequest{
		ChallengeID: testChallengeID, DeviceID: "device-1",
		OwnerRevision: 7, SessionID: "session-1", RequestID: 42,
		Action: Action{IndicatorOn: true},
	}
}

func TestStoreBindsExactActionAndIsOneUse(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	store, err := NewStore(8)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Register(testChallenge(now), now); err != nil {
		t.Fatal(err)
	}
	record, err := store.Decide(testActor(), testRequest(), now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if record.Decision != DecisionApprove || !record.Challenge.Action.IndicatorOn ||
		!record.DecidedAt.Equal(now.Add(time.Second)) {
		t.Fatalf("unexpected decision record: %#v", record)
	}
	if _, err := store.Decide(testActor(), testRequest(), now.Add(2*time.Second)); !errors.Is(err, ErrReplay) {
		t.Fatalf("decision replay error=%v, want replay", err)
	}
	consumed, err := store.Consume(testDeviceRequest(), now.Add(3*time.Second))
	if err != nil || consumed.Decision != DecisionApprove ||
		!consumed.ConsumedAt.Equal(now.Add(3*time.Second)) {
		t.Fatalf("consume decision: %#v %v", consumed, err)
	}
	if _, err := store.Consume(testDeviceRequest(), now.Add(4*time.Second)); !errors.Is(err, ErrReplay) {
		t.Fatalf("consume replay error=%v, want replay", err)
	}
}

func TestStoreDeviceConsumeFailsClosedAndDoesNotChooseDecision(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	store, _ := NewStore(8)
	if err := store.Register(testChallenge(now), now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Consume(testDeviceRequest(), now.Add(time.Second)); !errors.Is(err, ErrPending) {
		t.Fatalf("pending consume error=%v, want pending", err)
	}
	mutated := testDeviceRequest()
	mutated.Action.IndicatorOn = false
	if _, err := store.Consume(mutated, now.Add(2*time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatalf("mutated consume error=%v, want conflict", err)
	}
	request := testRequest()
	request.Decision = DecisionDeny
	if _, err := store.Decide(testActor(), request,
		now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	record, err := store.Consume(testDeviceRequest(), now.Add(4*time.Second))
	if err != nil || record.Decision != DecisionDeny {
		t.Fatalf("stored denial consume: %#v %v", record, err)
	}
}

func TestStorePendingInboxIsOwnerScopedStableAndNonConsuming(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	store, _ := NewStore(8)
	later := testChallenge(now)
	later.ChallengeID = "YWJjZGVmZ2hpamtsbW5vcA"
	later.SessionID = "session-2"
	later.RequestID = 43
	later.ExpiresAt = now.Add(25 * time.Second)
	if err := store.Register(later, now); err != nil {
		t.Fatal(err)
	}
	first := testChallenge(now)
	if err := store.Register(first, now); err != nil {
		t.Fatal(err)
	}
	for _, actor := range []Actor{
		{OwnerID: "user-2", TenantID: "tenant-1", DeviceID: "device-1", OwnerRevision: 7},
		{OwnerID: "user-1", TenantID: "tenant-2", DeviceID: "device-1", OwnerRevision: 7},
		{OwnerID: "user-1", TenantID: "tenant-1", DeviceID: "device-2", OwnerRevision: 7},
		{OwnerID: "user-1", TenantID: "tenant-1", DeviceID: "device-1", OwnerRevision: 8},
	} {
		if _, found, err := store.Pending(actor, now); err != nil || found {
			t.Fatalf("cross-owner inbox actor=%#v found=%t err=%v", actor, found, err)
		}
	}
	for attempt := 0; attempt < 2; attempt++ {
		record, found, err := store.Pending(testActor(), now.Add(time.Second))
		if err != nil || !found || record.Challenge.ChallengeID != testChallengeID {
			t.Fatalf("pending attempt=%d record=%#v found=%t err=%v",
				attempt, record, found, err)
		}
	}
	if _, err := store.Decide(testActor(), testRequest(), now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	record, found, err := store.Pending(testActor(), now.Add(3*time.Second))
	if err != nil || !found || record.Challenge.ChallengeID != later.ChallengeID {
		t.Fatalf("next pending record=%#v found=%t err=%v", record, found, err)
	}
	if _, found, err := store.Pending(testActor(), now.Add(26*time.Second)); err != nil || found {
		t.Fatalf("expired inbox found=%t err=%v", found, err)
	}
}

func TestStoreRejectsEveryBindingMutationWithoutConsuming(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	mutations := []struct {
		name  string
		actor Actor
		edit  func(*Request)
	}{
		{name: "owner", actor: Actor{OwnerID: "user-2", TenantID: "tenant-1", DeviceID: "device-1", OwnerRevision: 7}},
		{name: "tenant", actor: Actor{OwnerID: "user-1", TenantID: "tenant-2", DeviceID: "device-1", OwnerRevision: 7}},
		{name: "actor device", actor: Actor{OwnerID: "user-1", TenantID: "tenant-1", DeviceID: "device-2", OwnerRevision: 7}},
		{name: "actor revision", actor: Actor{OwnerID: "user-1", TenantID: "tenant-1", DeviceID: "device-1", OwnerRevision: 8}},
		{name: "body device", actor: testActor(), edit: func(r *Request) { r.DeviceID = "device-2" }},
		{name: "body revision", actor: testActor(), edit: func(r *Request) { r.OwnerRevision = 8 }},
		{name: "session", actor: testActor(), edit: func(r *Request) { r.SessionID = "session-2" }},
		{name: "request", actor: testActor(), edit: func(r *Request) { r.RequestID++ }},
		{name: "argument", actor: testActor(), edit: func(r *Request) { r.Action.IndicatorOn = false }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			store, _ := NewStore(8)
			if err := store.Register(testChallenge(now), now); err != nil {
				t.Fatal(err)
			}
			request := testRequest()
			if mutation.edit != nil {
				mutation.edit(&request)
			}
			if _, err := store.Decide(mutation.actor, request, now.Add(time.Second)); !errors.Is(err, ErrConflict) {
				t.Fatalf("mutation error=%v, want conflict", err)
			}
			if _, err := store.Decide(testActor(), testRequest(), now.Add(2*time.Second)); err != nil {
				t.Fatalf("mutation consumed challenge: %v", err)
			}
		})
	}
}

func TestStoreExpiryDuplicateAndCapacity(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	store, _ := NewStore(1)
	if err := store.Register(testChallenge(now), now); err != nil {
		t.Fatal(err)
	}
	if err := store.Register(testChallenge(now), now); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate error=%v, want conflict", err)
	}
	if _, err := store.Decide(testActor(), testRequest(), now.Add(20*time.Second)); !errors.Is(err, ErrExpired) {
		t.Fatalf("expiry error=%v, want expired", err)
	}
	second := testChallenge(now)
	second.ChallengeID = "YWJjZGVmZ2hpamtsbW5vcA"
	second.RequestID++
	if err := store.Register(second, now); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity error=%v, want capacity", err)
	}
	tooLong := testChallenge(now)
	tooLong.ChallengeID = "cXdlcnR5dWlvcGFzZGZnaA"
	tooLong.ExpiresAt = now.Add(MaximumLifetime + time.Second)
	other, _ := NewStore(2)
	if err := other.Register(tooLong, now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("long lifetime error=%v, want invalid", err)
	}
}

func TestStoreRejectsSecondChallengeForSameActionRequest(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	store, _ := NewStore(8)
	if err := store.Register(testChallenge(now), now); err != nil {
		t.Fatal(err)
	}
	duplicate := testChallenge(now)
	duplicate.ChallengeID = "YWJjZGVmZ2hpamtsbW5vcA"
	duplicate.Action.IndicatorOn = false
	if err := store.Register(duplicate, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate action request error=%v, want conflict", err)
	}
}

func TestStoreConcurrentDecisionHasOneWinner(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	store, _ := NewStore(8)
	if err := store.Register(testChallenge(now), now); err != nil {
		t.Fatal(err)
	}
	var winners atomic.Int32
	var wait sync.WaitGroup
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			request := testRequest()
			if index%2 != 0 {
				request.Decision = DecisionDeny
			}
			if _, err := store.Decide(testActor(), request, now.Add(time.Second)); err == nil {
				winners.Add(1)
			} else if !errors.Is(err, ErrReplay) {
				t.Errorf("concurrent decision error=%v", err)
			}
		}(index)
	}
	wait.Wait()
	if winners.Load() != 1 {
		t.Fatalf("decision winners=%d, want 1", winners.Load())
	}
}
