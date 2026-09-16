package databasequalification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/strictjson"
)

const (
	FailoverObservationSchema = 1
	maximumFailoverRunTime    = 20 * time.Minute
)

type RoleFailoverEvidence struct {
	Role                          Role   `json:"role"`
	ManagedClusterID              string `json:"managed_cluster_id"`
	EndpointAuthoritySHA256       string `json:"endpoint_authority_sha256"`
	BeforeNodeBindingSHA256       string `json:"before_node_binding_sha256"`
	AfterNodeBindingSHA256        string `json:"after_node_binding_sha256"`
	BeforePostgresVersion         int    `json:"before_postgres_version"`
	AfterPostgresVersion          int    `json:"after_postgres_version"`
	ProductSchemasVerified        bool   `json:"product_schemas_verified"`
	FailoverObserved              bool   `json:"failover_observed"`
	AllAcknowledgedEventsDurable  bool   `json:"all_acknowledged_events_durable"`
	RestoreMarkerSequence         uint64 `json:"restore_marker_sequence"`
	RestoreMarkerCommittedAt      string `json:"restore_marker_committed_at"`
	RestoreExclusionSequence      uint64 `json:"restore_exclusion_sequence"`
	RestoreExclusionCommittedAt   string `json:"restore_exclusion_committed_at"`
	PostFailoverSequence          uint64 `json:"post_failover_sequence"`
	PostFailoverCommittedAt       string `json:"post_failover_committed_at"`
	AcknowledgedEventCount        uint64 `json:"acknowledged_event_count"`
	AmbiguousCommitRecoveredCount uint64 `json:"ambiguous_commit_recovered_count"`
	AvailabilityFailureCount      uint64 `json:"availability_failure_count"`
	FailoverDetectionMS           int64  `json:"failover_detection_ms"`
	MaximumUnavailableMS          int64  `json:"maximum_unavailable_ms"`
}

type FailoverObservation struct {
	Schema                  uint32                 `json:"schema"`
	QualificationID         string                 `json:"qualification_id"`
	Environment             string                 `json:"environment"`
	DevelopmentOnly         bool                   `json:"development_only"`
	RunBindingSHA256        string                 `json:"run_binding_sha256"`
	ConfigSHA256            string                 `json:"config_sha256"`
	QualificationToolSHA256 string                 `json:"qualification_tool_sha256"`
	ReadySignalSHA256       string                 `json:"ready_signal_sha256"`
	Roles                   []Role                 `json:"roles"`
	Databases               []RoleFailoverEvidence `json:"databases"`
	ReadyAt                 string                 `json:"ready_at"`
	StartedAt               string                 `json:"started_at"`
	FinishedAt              string                 `json:"finished_at"`
	SecretFree              bool                   `json:"secret_free"`
}

type ReadySignal struct {
	Schema           uint32 `json:"schema"`
	QualificationID  string `json:"qualification_id"`
	RunBindingSHA256 string `json:"run_binding_sha256"`
	ConfigSHA256     string `json:"config_sha256"`
	Roles            []Role `json:"roles"`
	ReadyAt          string `json:"ready_at"`
}

func LoadFailoverObservation(path string) (FailoverObservation, []byte, error) {
	payload, err := readRegular(path, maximumDocumentBytes, false)
	if err != nil {
		return FailoverObservation{}, nil,
			fmt.Errorf("database failover observation: %w", err)
	}
	observation, err := ParseFailoverObservation(payload)
	if err != nil {
		return FailoverObservation{}, nil, err
	}
	return observation, payload, nil
}

func ParseFailoverObservation(payload []byte) (FailoverObservation, error) {
	if err := strictjson.RejectDuplicateFields(payload); err != nil {
		return FailoverObservation{}, fmt.Errorf("database failover observation is ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var observation FailoverObservation
	if err := decoder.Decode(&observation); err != nil {
		return FailoverObservation{}, fmt.Errorf("database failover observation JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return FailoverObservation{}, fmt.Errorf("database failover observation has trailing JSON")
	}
	canonical, err := CanonicalFailoverObservation(observation)
	if err != nil || !bytes.Equal(canonical, payload) {
		return FailoverObservation{}, fmt.Errorf("database failover observation is not canonical JSON")
	}
	if err := validateFailoverObservation(observation); err != nil {
		return FailoverObservation{}, err
	}
	return observation, nil
}

func CanonicalFailoverObservation(observation FailoverObservation) ([]byte, error) {
	payload, err := json.Marshal(observation)
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}

func CanonicalReadySignal(signal ReadySignal) ([]byte, error) {
	if signal.Schema != 1 || !auth.ValidIdentifier(signal.QualificationID, 64) ||
		!validSHA256(signal.RunBindingSHA256) ||
		!validSHA256(signal.ConfigSHA256) || !equalRoles(signal.Roles) {
		return nil, fmt.Errorf("database failover ready signal is invalid")
	}
	ready, err := parseCanonicalTime(signal.ReadyAt)
	if err != nil || ready.Nanosecond() != 0 {
		return nil, fmt.Errorf("database failover ready signal time is invalid")
	}
	payload, err := json.Marshal(signal)
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}

func LoadReadySignal(path string) (ReadySignal, []byte, error) {
	payload, err := readRegular(path, maximumDocumentBytes, false)
	if err != nil {
		return ReadySignal{}, nil, fmt.Errorf("database failover ready signal: %w", err)
	}
	if err := strictjson.RejectDuplicateFields(payload); err != nil {
		return ReadySignal{}, nil, fmt.Errorf("database failover ready signal is ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var signal ReadySignal
	if err := decoder.Decode(&signal); err != nil {
		return ReadySignal{}, nil, fmt.Errorf("database failover ready signal JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ReadySignal{}, nil, fmt.Errorf("database failover ready signal has trailing JSON")
	}
	canonical, err := CanonicalReadySignal(signal)
	if err != nil || !bytes.Equal(canonical, payload) {
		return ReadySignal{}, nil, fmt.Errorf("database failover ready signal is not canonical JSON")
	}
	return signal, payload, nil
}

func validateFailoverObservation(observation FailoverObservation) error {
	if observation.Schema != FailoverObservationSchema ||
		!auth.ValidIdentifier(observation.QualificationID, 64) ||
		(observation.Environment != "staging" && observation.Environment != "production") ||
		(observation.DevelopmentOnly && observation.Environment != "staging") ||
		!validSHA256(observation.RunBindingSHA256) ||
		!validSHA256(observation.ConfigSHA256) ||
		!validSHA256(observation.QualificationToolSHA256) ||
		!validSHA256(observation.ReadySignalSHA256) ||
		!equalRoles(observation.Roles) || len(observation.Databases) != len(ExactRoles) ||
		!observation.SecretFree {
		return fmt.Errorf("database failover observation fields are invalid")
	}
	for index, evidence := range observation.Databases {
		if evidence.Role != ExactRoles[index] || !validRoleEvidence(evidence) {
			return fmt.Errorf("database failover role evidence is invalid")
		}
	}
	started, err := parseCanonicalTime(observation.StartedAt)
	if err != nil {
		return fmt.Errorf("database failover observation start time is invalid")
	}
	ready, err := parseCanonicalTime(observation.ReadyAt)
	if err != nil || ready.Before(started) {
		return fmt.Errorf("database failover observation ready time is invalid")
	}
	finished, err := parseCanonicalTime(observation.FinishedAt)
	if err != nil || finished.Before(ready) ||
		finished.Sub(started) > maximumFailoverRunTime {
		return fmt.Errorf("database failover observation finish time is invalid")
	}
	return nil
}

func validRoleEvidence(evidence RoleFailoverEvidence) bool {
	if !evidence.Role.Valid() ||
		!auth.ValidIdentifier(evidence.ManagedClusterID, 128) ||
		!validSHA256(evidence.EndpointAuthoritySHA256) ||
		!validSHA256(evidence.BeforeNodeBindingSHA256) ||
		!validSHA256(evidence.AfterNodeBindingSHA256) ||
		evidence.BeforeNodeBindingSHA256 == evidence.AfterNodeBindingSHA256 ||
		evidence.BeforePostgresVersion < minimumPostgresVersion ||
		evidence.AfterPostgresVersion < minimumPostgresVersion ||
		!evidence.ProductSchemasVerified || !evidence.FailoverObserved ||
		!evidence.AllAcknowledgedEventsDurable ||
		evidence.RestoreMarkerSequence != 2 ||
		evidence.RestoreExclusionSequence != 3 ||
		evidence.PostFailoverSequence <= evidence.RestoreExclusionSequence ||
		evidence.AcknowledgedEventCount < 5 ||
		evidence.AcknowledgedEventCount > maximumEventSequence ||
		evidence.AmbiguousCommitRecoveredCount > evidence.AcknowledgedEventCount ||
		evidence.AvailabilityFailureCount > maximumEventSequence ||
		evidence.FailoverDetectionMS < 0 ||
		evidence.FailoverDetectionMS > maximumFailoverRunTime.Milliseconds() ||
		evidence.MaximumUnavailableMS < 0 ||
		evidence.MaximumUnavailableMS > maximumFailoverRunTime.Milliseconds() {
		return false
	}
	marker, markerErr := parseCanonicalTime(evidence.RestoreMarkerCommittedAt)
	exclusion, exclusionErr := parseCanonicalTime(evidence.RestoreExclusionCommittedAt)
	post, postErr := parseCanonicalTime(evidence.PostFailoverCommittedAt)
	return markerErr == nil && exclusionErr == nil && postErr == nil &&
		exclusion.After(marker) && post.After(exclusion)
}

func failoverObservationsEqual(left, right FailoverObservation) bool {
	return reflect.DeepEqual(left, right)
}

func parseCanonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Format(time.RFC3339) != value {
		return time.Time{}, fmt.Errorf("invalid canonical time")
	}
	return parsed, nil
}
