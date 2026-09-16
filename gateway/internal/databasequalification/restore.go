package databasequalification

import (
	"context"
	"fmt"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

type RestoreDatabaseCandidate struct {
	Role                           Role
	ManagedClusterID               string
	RestoreOperationID             string
	RequestedRecoveryTarget        time.Time
	SourceEndpointAuthoritySHA256  string
	RestoreEndpointAuthoritySHA256 string
	MarkerCommittedAt              time.Time
	ExclusionCommittedAt           time.Time
	Store                          EventStore
}

type RestoreRunConfig struct {
	QualificationID           string
	Environment               string
	DevelopmentOnly           bool
	ConfigSHA256              string
	ToolSHA256                string
	FailoverObservationSHA256 string
	RunBindingSHA256          string
	Nonce                     []byte
	Candidates                []RestoreDatabaseCandidate
}

func (runner *Runner) RunRestore(ctx context.Context,
	config RestoreRunConfig) (RestoreObservation, error) {
	if runner == nil || runner.now == nil || ctx == nil ||
		!validRestoreRunConfig(config) {
		return RestoreObservation{}, fmt.Errorf("invalid managed database restore run configuration")
	}
	started := canonicalSecond(runner.now())
	observation := RestoreObservation{Schema: RestoreObservationSchema,
		QualificationID: config.QualificationID, Environment: config.Environment,
		DevelopmentOnly:           config.DevelopmentOnly,
		RunBindingSHA256:          config.RunBindingSHA256,
		FailoverObservationSHA256: config.FailoverObservationSHA256,
		ConfigSHA256:              config.ConfigSHA256, QualificationToolSHA256: config.ToolSHA256,
		Roles:     append([]Role(nil), ExactRoles...),
		Databases: make([]RoleRestoreEvidence, 0, len(ExactRoles)),
		StartedAt: started.Format(time.RFC3339), SecretFree: true}
	for _, candidate := range config.Candidates {
		if err := candidate.Store.VerifySchema(ctx); err != nil {
			return RestoreObservation{}, roleFailure(candidate.Role,
				"restored schema verification", err)
		}
		snapshot, err := candidate.Store.Snapshot(ctx, config.Nonce)
		if err != nil {
			return RestoreObservation{}, roleFailure(candidate.Role,
				"restored node snapshot", err)
		}
		events, err := candidate.Store.LoadEvents(ctx, config.QualificationID,
			config.Nonce)
		if err != nil {
			return RestoreObservation{}, roleFailure(candidate.Role,
				"restored event read", err)
		}
		if !validRestoredEvents(events, config.RunBindingSHA256, candidate) {
			return RestoreObservation{}, fmt.Errorf("managed database restored event boundary is invalid")
		}
		observation.Databases = append(observation.Databases, RoleRestoreEvidence{
			Role: candidate.Role, ManagedClusterID: candidate.ManagedClusterID,
			RestoreOperationID:             candidate.RestoreOperationID,
			SourceEndpointAuthoritySHA256:  candidate.SourceEndpointAuthoritySHA256,
			RestoreEndpointAuthoritySHA256: candidate.RestoreEndpointAuthoritySHA256,
			RestoredNodeBindingSHA256:      snapshot.BindingSHA256,
			RestoredPostgresVersion:        snapshot.PostgresVersion,
			RequestedRecoveryTarget:        canonicalSecond(candidate.RequestedRecoveryTarget).Format(time.RFC3339),
			ProductSchemasVerified:         true, PreRestoreEventPresent: true,
			RestoreMarkerPresent: true, RestoreExclusionAbsent: true,
			HeartbeatEventsAbsent: true, PostFailoverEventAbsent: true,
			RestoredEventCount:       uint64(len(events)),
			RestoreMarkerCommittedAt: canonicalSecond(events[1].CommittedAt).Format(time.RFC3339),
		})
	}
	observation.FinishedAt = canonicalSecond(runner.now()).Format(time.RFC3339)
	if err := validateRestoreObservation(observation); err != nil {
		return RestoreObservation{}, err
	}
	return observation, nil
}

func validRestoredEvents(events []Event, runBinding string,
	candidate RestoreDatabaseCandidate) bool {
	if len(events) != 2 {
		return false
	}
	expectedPhases := []Phase{PhasePre, PhaseRestoreMarker}
	for index, event := range events {
		sequence := uint64(index + 1)
		if event.Sequence != sequence || event.Phase != expectedPhases[index] ||
			event.PayloadSHA256 != eventPayloadSHA256(runBinding, candidate.Role,
				sequence, expectedPhases[index]) || event.CommittedAt.IsZero() {
			return false
		}
	}
	return canonicalSecond(events[1].CommittedAt).Equal(
		canonicalSecond(candidate.MarkerCommittedAt)) &&
		candidate.RequestedRecoveryTarget.After(candidate.MarkerCommittedAt) &&
		candidate.RequestedRecoveryTarget.Before(candidate.ExclusionCommittedAt)
}

func validRestoreRunConfig(config RestoreRunConfig) bool {
	if !auth.ValidIdentifier(config.QualificationID, 64) ||
		(config.Environment != "staging" && config.Environment != "production") ||
		(config.DevelopmentOnly && config.Environment != "staging") ||
		!validSHA256(config.ConfigSHA256) || !validSHA256(config.ToolSHA256) ||
		!validSHA256(config.FailoverObservationSHA256) ||
		!validSHA256(config.RunBindingSHA256) || len(config.Nonce) != 16 ||
		len(config.Candidates) != len(ExactRoles) {
		return false
	}
	for index, candidate := range config.Candidates {
		if candidate.Role != ExactRoles[index] || candidate.Store == nil ||
			candidate.Store.Role() != candidate.Role ||
			!auth.ValidIdentifier(candidate.ManagedClusterID, 128) ||
			!auth.ValidIdentifier(candidate.RestoreOperationID, 128) ||
			!validSHA256(candidate.SourceEndpointAuthoritySHA256) ||
			!validSHA256(candidate.RestoreEndpointAuthoritySHA256) ||
			candidate.SourceEndpointAuthoritySHA256 == candidate.RestoreEndpointAuthoritySHA256 ||
			candidate.MarkerCommittedAt.IsZero() || candidate.ExclusionCommittedAt.IsZero() ||
			!candidate.RequestedRecoveryTarget.After(candidate.MarkerCommittedAt) ||
			!candidate.RequestedRecoveryTarget.Before(candidate.ExclusionCommittedAt) {
			return false
		}
	}
	return true
}
