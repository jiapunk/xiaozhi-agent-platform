package databasequalification

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type fakeClock struct{ current time.Time }

func (clock *fakeClock) now() time.Time { return clock.current }

func (clock *fakeClock) pause(ctx context.Context, duration time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		clock.current = clock.current.Add(duration)
		return nil
	}
}

type fakeEventStore struct {
	role                  Role
	clock                 *fakeClock
	beforeBinding         string
	afterBinding          string
	failoverAt            time.Time
	neverFailover         bool
	unavailableAfterThree bool
	ambiguousSequence     uint64
	ambiguousReturned     bool
	events                []Event
}

func (store *fakeEventStore) Role() Role                         { return store.role }
func (store *fakeEventStore) Close() error                       { return nil }
func (store *fakeEventStore) VerifySchema(context.Context) error { return nil }

func (store *fakeEventStore) Snapshot(context.Context, []byte) (NodeSnapshot, error) {
	if store.unavailableAfterThree && len(store.events) >= 3 {
		return NodeSnapshot{}, ErrUnavailable
	}
	binding := store.beforeBinding
	if !store.neverFailover && !store.clock.current.Before(store.failoverAt) {
		binding = store.afterBinding
	}
	return NodeSnapshot{BindingSHA256: binding,
		DatabaseTime: store.clock.current, PostgresVersion: 170006}, nil
}

func (store *fakeEventStore) AppendEvent(_ context.Context, _ string, _ []byte,
	sequence uint64, phase Phase, payload string) (Event, error) {
	for _, existing := range store.events {
		if existing.Sequence == sequence {
			if existing.Phase != phase || existing.PayloadSHA256 != payload {
				return Event{}, ErrConflict
			}
			existing.Existing = true
			return existing, nil
		}
	}
	if store.unavailableAfterThree && sequence > 3 {
		return Event{}, ErrUnavailable
	}
	event := Event{Sequence: sequence, Phase: phase,
		PayloadSHA256: payload, CommittedAt: store.clock.current}
	store.events = append(store.events, event)
	if sequence == store.ambiguousSequence && !store.ambiguousReturned {
		store.ambiguousReturned = true
		return Event{}, ErrUnavailable
	}
	return event, nil
}

func (store *fakeEventStore) LoadEvents(context.Context, string, []byte) ([]Event, error) {
	return append([]Event(nil), store.events...), nil
}

func testFailoverConfig(clock *fakeClock) FailoverRunConfig {
	config := FailoverRunConfig{
		QualificationID: "m73-managed-db-qualification",
		Environment:     "staging", DevelopmentOnly: true,
		ConfigSHA256: strings.Repeat("a", 64),
		ToolSHA256:   strings.Repeat("b", 64),
		Nonce:        []byte("0123456789abcdef"), HeartbeatInterval: 100 * time.Millisecond,
		FailoverTimeout: 10 * time.Second,
		Candidates:      make([]DatabaseCandidate, 0, len(ExactRoles)),
	}
	for index, role := range ExactRoles {
		before := fmt.Sprintf("%064x", index+1)
		after := fmt.Sprintf("%064x", index+11)
		store := &fakeEventStore{role: role, clock: clock,
			beforeBinding: before, afterBinding: after,
			failoverAt: clock.current.Add(7 * time.Second)}
		if index == 0 {
			store.ambiguousSequence = 4
		}
		config.Candidates = append(config.Candidates, DatabaseCandidate{
			Role: role, ManagedClusterID: fmt.Sprintf("managed-cluster-%d", index+1),
			EndpointAuthoritySHA256: fmt.Sprintf("%064x", index+21), Store: store,
		})
	}
	config.RunBindingSHA256 = runBindingSHA256(config)
	config.SignalReady = func(signal ReadySignal) (string, error) {
		payload, err := CanonicalReadySignal(signal)
		return digestBytes(payload), err
	}
	return config
}

func TestFailoverRunnerReconcilesAmbiguousCommitAcrossThreeRoles(t *testing.T) {
	clock := &fakeClock{current: time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)}
	config := testFailoverConfig(clock)
	runner := &Runner{now: clock.now, pause: clock.pause}
	observation, err := runner.RunFailover(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	if len(observation.Databases) != 3 ||
		observation.Databases[0].AmbiguousCommitRecoveredCount != 1 ||
		observation.Databases[0].AvailabilityFailureCount != 1 {
		t.Fatalf("unexpected observation: %+v", observation)
	}
	for _, evidence := range observation.Databases {
		if !evidence.FailoverObserved || !evidence.AllAcknowledgedEventsDurable ||
			evidence.AcknowledgedEventCount < 5 ||
			evidence.BeforeNodeBindingSHA256 == evidence.AfterNodeBindingSHA256 {
			t.Fatalf("role did not prove failover durability: %+v", evidence)
		}
	}
	payload, err := CanonicalFailoverObservation(observation)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseFailoverObservation(payload)
	if err != nil || !failoverObservationsEqual(observation, parsed) {
		t.Fatalf("canonical round trip failed: %v", err)
	}
}

func TestFailoverRunnerDoesNotTreatOutageAsFailover(t *testing.T) {
	clock := &fakeClock{current: time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)}
	config := testFailoverConfig(clock)
	store := config.Candidates[0].Store.(*fakeEventStore)
	store.unavailableAfterThree = true
	runner := &Runner{now: clock.now, pause: clock.pause}
	_, err := runner.RunFailover(context.Background(), config)
	if err == nil || !strings.Contains(err.Error(), "not observed before timeout") {
		t.Fatalf("availability loss counted as failover: %v", err)
	}
}

func TestFailoverRunnerRequiresNodeIdentityChange(t *testing.T) {
	clock := &fakeClock{current: time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)}
	config := testFailoverConfig(clock)
	for _, candidate := range config.Candidates {
		candidate.Store.(*fakeEventStore).neverFailover = true
	}
	runner := &Runner{now: clock.now, pause: clock.pause}
	_, err := runner.RunFailover(context.Background(), config)
	if err == nil || !strings.Contains(err.Error(), "not observed before timeout") {
		t.Fatalf("unchanged primary counted as failover: %v", err)
	}
}

func TestEndpointAuthorityDigestExcludesCredentials(t *testing.T) {
	first, err := endpointAuthoritySHA256("postgresql://first:secret-one@db.example.com:5432/ownership?sslmode=verify-full")
	if err != nil {
		t.Fatal(err)
	}
	second, err := endpointAuthoritySHA256("postgresql://second:secret-two@db.example.com:5432/ownership?sslmode=verify-full")
	if err != nil || first != second {
		t.Fatalf("credential-free endpoint binding changed: %v", err)
	}
	third, err := endpointAuthoritySHA256("postgresql://second:secret-two@db.example.com:5432/account?sslmode=verify-full")
	if err != nil || first == third {
		t.Fatalf("database identity was not bound: %v", err)
	}
}

func TestFailoverErrorsDoNotExposeStoreDetails(t *testing.T) {
	err := roleFailure(RoleOwnership, "append", errors.New("password=hidden"))
	if strings.Contains(err.Error(), "hidden") {
		t.Fatalf("store details leaked: %v", err)
	}
}

func TestLoadedFailoverIdentityDoesNotRequireReadySinkUntilRun(t *testing.T) {
	clock := &fakeClock{current: time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)}
	config := testFailoverConfig(clock)
	config.SignalReady = nil
	if !validFailoverRunIdentity(config) || validFailoverRunConfig(config) {
		t.Fatal("load-time identity and run-time ready sink were not separated")
	}
}

func TestAvailabilityRetryReconcilesPostCommitReplyLoss(t *testing.T) {
	clock := &fakeClock{current: time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)}
	config := testFailoverConfig(clock)
	store := config.Candidates[0].Store.(*fakeEventStore)
	store.ambiguousSequence = 1
	state := failoverState{candidate: config.Candidates[0], nextSequence: 1}
	event, err := (&Runner{now: clock.now, pause: clock.pause}).
		appendWithAvailabilityRetry(context.Background(), config, &state,
			PhasePost, time.Second)
	if err != nil || !event.Existing || state.ambiguousRecovered != 1 ||
		len(state.expected) != 1 || state.availabilityErrors != 1 {
		t.Fatalf("ambiguous commit did not reconcile: event=%+v state=%+v err=%v",
			event, state, err)
	}
}

func testRestoreConfig(clock *fakeClock) RestoreRunConfig {
	marker := clock.current.Add(-8 * time.Second)
	exclusion := clock.current.Add(-3 * time.Second)
	config := RestoreRunConfig{
		QualificationID: "m73-managed-db-qualification",
		Environment:     "staging", DevelopmentOnly: true,
		ConfigSHA256:              strings.Repeat("c", 64),
		ToolSHA256:                strings.Repeat("d", 64),
		FailoverObservationSHA256: strings.Repeat("e", 64),
		RunBindingSHA256:          strings.Repeat("f", 64),
		Nonce:                     []byte("0123456789abcdef"),
		Candidates:                make([]RestoreDatabaseCandidate, 0, len(ExactRoles)),
	}
	for index, role := range ExactRoles {
		store := &fakeEventStore{role: role, clock: clock,
			beforeBinding: fmt.Sprintf("%064x", index+31),
			afterBinding:  fmt.Sprintf("%064x", index+41),
			failoverAt:    clock.current.Add(time.Hour)}
		store.events = []Event{
			{Sequence: 1, Phase: PhasePre,
				PayloadSHA256: eventPayloadSHA256(config.RunBindingSHA256,
					role, 1, PhasePre), CommittedAt: marker.Add(-time.Second)},
			{Sequence: 2, Phase: PhaseRestoreMarker,
				PayloadSHA256: eventPayloadSHA256(config.RunBindingSHA256,
					role, 2, PhaseRestoreMarker), CommittedAt: marker},
		}
		config.Candidates = append(config.Candidates, RestoreDatabaseCandidate{
			Role: role, ManagedClusterID: fmt.Sprintf("managed-cluster-%d", index+1),
			RestoreOperationID:             fmt.Sprintf("restore-operation-%d", index+1),
			RequestedRecoveryTarget:        marker.Add(2 * time.Second),
			SourceEndpointAuthoritySHA256:  fmt.Sprintf("%064x", index+51),
			RestoreEndpointAuthoritySHA256: fmt.Sprintf("%064x", index+61),
			MarkerCommittedAt:              marker, ExclusionCommittedAt: exclusion, Store: store,
		})
	}
	return config
}

func TestRestoreRunnerProvesExactPointInTimeBoundary(t *testing.T) {
	clock := &fakeClock{current: time.Date(2026, 8, 10, 13, 0, 0, 0, time.UTC)}
	config := testRestoreConfig(clock)
	observation, err := (&Runner{now: clock.now, pause: clock.pause}).
		RunRestore(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	for _, evidence := range observation.Databases {
		if evidence.RestoredEventCount != 2 || !evidence.RestoreMarkerPresent ||
			!evidence.RestoreExclusionAbsent || !evidence.HeartbeatEventsAbsent ||
			!evidence.PostFailoverEventAbsent {
			t.Fatalf("restore boundary was not proven: %+v", evidence)
		}
	}
	payload, err := CanonicalRestoreObservation(observation)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseRestoreObservation(payload)
	if err != nil || !restoreObservationsEqual(observation, parsed) {
		t.Fatalf("restore observation round trip failed: %v", err)
	}
}

func TestRestoreRunnerRejectsExclusionOrPostData(t *testing.T) {
	clock := &fakeClock{current: time.Date(2026, 8, 10, 13, 0, 0, 0, time.UTC)}
	config := testRestoreConfig(clock)
	store := config.Candidates[0].Store.(*fakeEventStore)
	store.events = append(store.events, Event{Sequence: 3,
		Phase: PhaseRestoreExclusion,
		PayloadSHA256: eventPayloadSHA256(config.RunBindingSHA256,
			RoleOwnership, 3, PhaseRestoreExclusion), CommittedAt: clock.current})
	_, err := (&Runner{now: clock.now, pause: clock.pause}).
		RunRestore(context.Background(), config)
	if err == nil || !strings.Contains(err.Error(), "boundary is invalid") {
		t.Fatalf("restore after exclusion was accepted: %v", err)
	}
}
