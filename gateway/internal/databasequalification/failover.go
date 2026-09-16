package databasequalification

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

const (
	minimumRestoreMarkerGap = 5 * time.Second
	minimumFailoverTimeout  = 10 * time.Second
	maximumFailoverTimeout  = 15 * time.Minute
)

type EventStore interface {
	Role() Role
	VerifySchema(context.Context) error
	Snapshot(context.Context, []byte) (NodeSnapshot, error)
	AppendEvent(context.Context, string, []byte, uint64, Phase, string) (Event, error)
	LoadEvents(context.Context, string, []byte) ([]Event, error)
	Close() error
}

type DatabaseCandidate struct {
	Role                    Role
	ManagedClusterID        string
	EndpointAuthoritySHA256 string
	Store                   EventStore
}

type FailoverRunConfig struct {
	QualificationID   string
	Environment       string
	DevelopmentOnly   bool
	ConfigSHA256      string
	ToolSHA256        string
	RunBindingSHA256  string
	Nonce             []byte
	Candidates        []DatabaseCandidate
	HeartbeatInterval time.Duration
	FailoverTimeout   time.Duration
	SignalReady       func(ReadySignal) (string, error)
}

type Runner struct {
	now   func() time.Time
	pause func(context.Context, time.Duration) error
}

type failoverState struct {
	candidate          DatabaseCandidate
	before             NodeSnapshot
	after              NodeSnapshot
	expected           []Event
	nextSequence       uint64
	marker             Event
	exclusion          Event
	post               Event
	detectedAt         time.Time
	failureStartedAt   time.Time
	maximumUnavailable time.Duration
	availabilityErrors uint64
	ambiguousRecovered uint64
}

func NewRunner() *Runner {
	return &Runner{now: time.Now, pause: pauseContext}
}

func pauseContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (runner *Runner) RunFailover(ctx context.Context,
	config FailoverRunConfig) (FailoverObservation, error) {
	if runner == nil || runner.now == nil || runner.pause == nil || ctx == nil ||
		!validFailoverRunConfig(config) {
		return FailoverObservation{}, fmt.Errorf("invalid managed database failover run configuration")
	}
	started := canonicalSecond(runner.now())
	states := make([]failoverState, len(config.Candidates))
	for index, candidate := range config.Candidates {
		states[index] = failoverState{candidate: candidate, nextSequence: 1}
		if err := candidate.Store.VerifySchema(ctx); err != nil {
			return FailoverObservation{}, roleFailure(candidate.Role, "schema verification", err)
		}
		snapshot, err := candidate.Store.Snapshot(ctx, config.Nonce)
		if err != nil {
			return FailoverObservation{}, roleFailure(candidate.Role, "initial node snapshot", err)
		}
		states[index].before = snapshot
		if _, err := runner.appendExpected(ctx, config, &states[index], PhasePre); err != nil {
			return FailoverObservation{}, err
		}
		marker, err := runner.appendExpected(ctx, config, &states[index], PhaseRestoreMarker)
		if err != nil {
			return FailoverObservation{}, err
		}
		states[index].marker = marker
	}
	if err := runner.waitForDatabaseGap(ctx, config, states); err != nil {
		return FailoverObservation{}, err
	}
	for index := range states {
		exclusion, err := runner.appendExpected(ctx, config, &states[index], PhaseRestoreExclusion)
		if err != nil {
			return FailoverObservation{}, err
		}
		if !exclusion.CommittedAt.After(states[index].marker.CommittedAt) {
			return FailoverObservation{}, fmt.Errorf("managed database restore marker window is not ordered")
		}
		states[index].exclusion = exclusion
	}
	readyAt := canonicalSecond(runner.now())
	signal := ReadySignal{Schema: 1, QualificationID: config.QualificationID,
		RunBindingSHA256: config.RunBindingSHA256,
		ConfigSHA256:     config.ConfigSHA256, Roles: append([]Role(nil), ExactRoles...),
		ReadyAt: readyAt.Format(time.RFC3339)}
	readyPayload, err := CanonicalReadySignal(signal)
	if err != nil {
		return FailoverObservation{}, err
	}
	readySHA, err := config.SignalReady(signal)
	if err != nil || readySHA != digestBytes(readyPayload) {
		return FailoverObservation{}, fmt.Errorf("managed database failover ready signal was not durably published")
	}
	if err := runner.observeFailover(ctx, config, readyAt, states); err != nil {
		return FailoverObservation{}, err
	}
	for index := range states {
		post, err := runner.appendWithAvailabilityRetry(ctx, config,
			&states[index], PhasePost, 30*time.Second)
		if err != nil {
			return FailoverObservation{}, err
		}
		if !post.CommittedAt.After(states[index].exclusion.CommittedAt) {
			return FailoverObservation{}, fmt.Errorf("managed database post-failover event is not ordered")
		}
		states[index].post = post
		actual, err := runner.loadEventsWithAvailabilityRetry(ctx, config,
			&states[index], 30*time.Second)
		if err != nil || !EventsMatch(actual, states[index].expected) {
			return FailoverObservation{}, roleFailure(states[index].candidate.Role,
				"durability reconciliation", err)
		}
	}
	finished := canonicalSecond(runner.now())
	observation := FailoverObservation{Schema: FailoverObservationSchema,
		QualificationID: config.QualificationID, Environment: config.Environment,
		DevelopmentOnly:  config.DevelopmentOnly,
		RunBindingSHA256: config.RunBindingSHA256, ConfigSHA256: config.ConfigSHA256,
		QualificationToolSHA256: config.ToolSHA256, ReadySignalSHA256: readySHA,
		Roles: append([]Role(nil), ExactRoles...), Databases: make([]RoleFailoverEvidence, 0, len(states)),
		ReadyAt: readyAt.Format(time.RFC3339), StartedAt: started.Format(time.RFC3339),
		FinishedAt: finished.Format(time.RFC3339), SecretFree: true}
	for _, state := range states {
		observation.Databases = append(observation.Databases, RoleFailoverEvidence{
			Role: state.candidate.Role, ManagedClusterID: state.candidate.ManagedClusterID,
			EndpointAuthoritySHA256: state.candidate.EndpointAuthoritySHA256,
			BeforeNodeBindingSHA256: state.before.BindingSHA256,
			AfterNodeBindingSHA256:  state.after.BindingSHA256,
			BeforePostgresVersion:   state.before.PostgresVersion,
			AfterPostgresVersion:    state.after.PostgresVersion,
			ProductSchemasVerified:  true, FailoverObserved: true,
			AllAcknowledgedEventsDurable:  true,
			RestoreMarkerSequence:         state.marker.Sequence,
			RestoreMarkerCommittedAt:      canonicalSecond(state.marker.CommittedAt).Format(time.RFC3339),
			RestoreExclusionSequence:      state.exclusion.Sequence,
			RestoreExclusionCommittedAt:   canonicalSecond(state.exclusion.CommittedAt).Format(time.RFC3339),
			PostFailoverSequence:          state.post.Sequence,
			PostFailoverCommittedAt:       canonicalSecond(state.post.CommittedAt).Format(time.RFC3339),
			AcknowledgedEventCount:        uint64(len(state.expected)),
			AmbiguousCommitRecoveredCount: state.ambiguousRecovered,
			AvailabilityFailureCount:      state.availabilityErrors,
			FailoverDetectionMS:           state.detectedAt.Sub(readyAt).Milliseconds(),
			MaximumUnavailableMS:          state.maximumUnavailable.Milliseconds(),
		})
	}
	if err := validateFailoverObservation(observation); err != nil {
		return FailoverObservation{}, err
	}
	return observation, nil
}

func (runner *Runner) waitForDatabaseGap(ctx context.Context,
	config FailoverRunConfig, states []failoverState) error {
	deadline := runner.now().Add(2 * minimumRestoreMarkerGap)
	for {
		allReady := true
		for index := range states {
			snapshot, err := states[index].candidate.Store.Snapshot(ctx, config.Nonce)
			if err != nil {
				return roleFailure(states[index].candidate.Role, "restore marker clock", err)
			}
			if snapshot.DatabaseTime.Sub(states[index].marker.CommittedAt) < minimumRestoreMarkerGap {
				allReady = false
			}
		}
		if allReady {
			return nil
		}
		if !runner.now().Before(deadline) {
			return fmt.Errorf("managed database restore marker window did not advance")
		}
		if err := runner.pause(ctx, 500*time.Millisecond); err != nil {
			return fmt.Errorf("managed database restore marker wait interrupted")
		}
	}
}

func (runner *Runner) observeFailover(ctx context.Context, config FailoverRunConfig,
	readyAt time.Time, states []failoverState) error {
	deadline := readyAt.Add(config.FailoverTimeout)
	remaining := len(states)
	for remaining > 0 {
		if !runner.now().Before(deadline) {
			return fmt.Errorf("managed database failover was not observed before timeout")
		}
		for index := range states {
			state := &states[index]
			if !state.detectedAt.IsZero() {
				continue
			}
			_, eventErr := runner.appendExpected(ctx, config, state, PhaseHeartbeat)
			if eventErr != nil {
				if errors.Is(eventErr, ErrUnavailable) {
					runner.recordUnavailable(state)
					continue
				}
				return eventErr
			}
			runner.recordAvailable(state)
			snapshot, snapshotErr := state.candidate.Store.Snapshot(ctx, config.Nonce)
			if snapshotErr != nil {
				if errors.Is(snapshotErr, ErrUnavailable) {
					runner.recordUnavailable(state)
					continue
				}
				return roleFailure(state.candidate.Role, "failover node snapshot", snapshotErr)
			}
			runner.recordAvailable(state)
			if snapshot.BindingSHA256 != state.before.BindingSHA256 {
				state.after = snapshot
				state.detectedAt = canonicalSecond(runner.now())
				remaining--
			}
		}
		if remaining > 0 {
			if err := runner.pause(ctx, config.HeartbeatInterval); err != nil {
				return fmt.Errorf("managed database failover observation interrupted")
			}
		}
	}
	for index := range states {
		runner.recordAvailable(&states[index])
	}
	return nil
}

func (runner *Runner) appendExpected(ctx context.Context, config FailoverRunConfig,
	state *failoverState, phase Phase) (Event, error) {
	sequence := state.nextSequence
	payloadSHA := eventPayloadSHA256(config.RunBindingSHA256,
		state.candidate.Role, sequence, phase)
	event, err := state.candidate.Store.AppendEvent(ctx, config.QualificationID,
		config.Nonce, sequence, phase, payloadSHA)
	if err != nil {
		return Event{}, roleFailure(state.candidate.Role, "append event", err)
	}
	if event.Sequence != sequence || event.Phase != phase ||
		event.PayloadSHA256 != payloadSHA || event.CommittedAt.IsZero() {
		return Event{}, fmt.Errorf("managed database event acknowledgment is invalid")
	}
	if event.Existing {
		state.ambiguousRecovered++
	}
	state.expected = append(state.expected, event)
	state.nextSequence++
	return event, nil
}

func (runner *Runner) appendWithAvailabilityRetry(ctx context.Context,
	config FailoverRunConfig, state *failoverState, phase Phase,
	timeout time.Duration) (Event, error) {
	deadline := runner.now().Add(timeout)
	for {
		event, err := runner.appendExpected(ctx, config, state, phase)
		if err == nil {
			runner.recordAvailable(state)
			return event, nil
		}
		if !errors.Is(err, ErrUnavailable) {
			return Event{}, err
		}
		runner.recordUnavailable(state)
		if !runner.now().Before(deadline) {
			return Event{}, roleFailure(state.candidate.Role,
				"append retry timeout", ErrUnavailable)
		}
		if err := runner.pause(ctx, config.HeartbeatInterval); err != nil {
			return Event{}, fmt.Errorf("managed database append retry interrupted")
		}
	}
}

func (runner *Runner) loadEventsWithAvailabilityRetry(ctx context.Context,
	config FailoverRunConfig, state *failoverState,
	timeout time.Duration) ([]Event, error) {
	deadline := runner.now().Add(timeout)
	for {
		events, err := state.candidate.Store.LoadEvents(ctx,
			config.QualificationID, config.Nonce)
		if err == nil {
			runner.recordAvailable(state)
			return events, nil
		}
		if !errors.Is(err, ErrUnavailable) {
			return nil, roleFailure(state.candidate.Role,
				"durability reconciliation", err)
		}
		runner.recordUnavailable(state)
		if !runner.now().Before(deadline) {
			return nil, roleFailure(state.candidate.Role,
				"durability retry timeout", ErrUnavailable)
		}
		if err := runner.pause(ctx, config.HeartbeatInterval); err != nil {
			return nil, fmt.Errorf("managed database durability retry interrupted")
		}
	}
}

func eventPayloadSHA256(runBinding string, role Role, sequence uint64,
	phase Phase) string {
	payload := fmt.Sprintf("XIAOZHI-M73-MANAGED-DATABASE-EVENT-V1\x00%s\x00%s\x00%d\x00%s",
		runBinding, role, sequence, phase)
	digest := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(digest[:])
}

func (runner *Runner) recordUnavailable(state *failoverState) {
	now := runner.now()
	state.availabilityErrors++
	if state.failureStartedAt.IsZero() {
		state.failureStartedAt = now
	}
}

func (runner *Runner) recordAvailable(state *failoverState) {
	if state.failureStartedAt.IsZero() {
		return
	}
	duration := runner.now().Sub(state.failureStartedAt)
	if duration > state.maximumUnavailable {
		state.maximumUnavailable = duration
	}
	state.failureStartedAt = time.Time{}
}

func validFailoverRunConfig(config FailoverRunConfig) bool {
	return config.SignalReady != nil && validFailoverRunIdentity(config)
}

func validFailoverRunIdentity(config FailoverRunConfig) bool {
	if !auth.ValidIdentifier(config.QualificationID, 64) ||
		(config.Environment != "staging" && config.Environment != "production") ||
		(config.DevelopmentOnly && config.Environment != "staging") ||
		!validSHA256(config.ConfigSHA256) || !validSHA256(config.ToolSHA256) ||
		!validSHA256(config.RunBindingSHA256) || len(config.Nonce) != 16 ||
		len(config.Candidates) != len(ExactRoles) ||
		config.HeartbeatInterval < 100*time.Millisecond ||
		config.HeartbeatInterval > 30*time.Second ||
		config.FailoverTimeout < minimumFailoverTimeout ||
		config.FailoverTimeout > maximumFailoverTimeout {
		return false
	}
	for index, candidate := range config.Candidates {
		if candidate.Role != ExactRoles[index] || candidate.Store == nil ||
			candidate.Store.Role() != candidate.Role ||
			!auth.ValidIdentifier(candidate.ManagedClusterID, 128) ||
			!validSHA256(candidate.EndpointAuthoritySHA256) {
			return false
		}
	}
	return runBindingSHA256(config) == config.RunBindingSHA256
}

func roleFailure(role Role, operation string, err error) error {
	if err == nil {
		return fmt.Errorf("managed database %s %s failed", role, operation)
	}
	if errors.Is(err, ErrUnavailable) {
		return fmt.Errorf("%w: managed database %s %s", ErrUnavailable, role, operation)
	}
	if errors.Is(err, ErrConflict) {
		return fmt.Errorf("%w: managed database %s %s", ErrConflict, role, operation)
	}
	return fmt.Errorf("managed database %s %s failed", role, operation)
}

func canonicalSecond(value time.Time) time.Time {
	return value.UTC().Truncate(time.Second)
}
