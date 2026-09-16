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
	RestoreObservationSchema = 1
	maximumRestoreRunTime    = 5 * time.Minute
)

type RoleRestoreEvidence struct {
	Role                           Role   `json:"role"`
	ManagedClusterID               string `json:"managed_cluster_id"`
	RestoreOperationID             string `json:"restore_operation_id"`
	SourceEndpointAuthoritySHA256  string `json:"source_endpoint_authority_sha256"`
	RestoreEndpointAuthoritySHA256 string `json:"restore_endpoint_authority_sha256"`
	RestoredNodeBindingSHA256      string `json:"restored_node_binding_sha256"`
	RestoredPostgresVersion        int    `json:"restored_postgres_version"`
	RequestedRecoveryTarget        string `json:"requested_recovery_target"`
	ProductSchemasVerified         bool   `json:"product_schemas_verified"`
	PreRestoreEventPresent         bool   `json:"pre_restore_event_present"`
	RestoreMarkerPresent           bool   `json:"restore_marker_present"`
	RestoreExclusionAbsent         bool   `json:"restore_exclusion_absent"`
	HeartbeatEventsAbsent          bool   `json:"heartbeat_events_absent"`
	PostFailoverEventAbsent        bool   `json:"post_failover_event_absent"`
	RestoredEventCount             uint64 `json:"restored_event_count"`
	RestoreMarkerCommittedAt       string `json:"restore_marker_committed_at"`
}

type RestoreObservation struct {
	Schema                    uint32                `json:"schema"`
	QualificationID           string                `json:"qualification_id"`
	Environment               string                `json:"environment"`
	DevelopmentOnly           bool                  `json:"development_only"`
	RunBindingSHA256          string                `json:"run_binding_sha256"`
	FailoverObservationSHA256 string                `json:"failover_observation_sha256"`
	ConfigSHA256              string                `json:"config_sha256"`
	QualificationToolSHA256   string                `json:"qualification_tool_sha256"`
	Roles                     []Role                `json:"roles"`
	Databases                 []RoleRestoreEvidence `json:"databases"`
	StartedAt                 string                `json:"started_at"`
	FinishedAt                string                `json:"finished_at"`
	SecretFree                bool                  `json:"secret_free"`
}

func LoadRestoreObservation(path string) (RestoreObservation, []byte, error) {
	payload, err := readRegular(path, maximumDocumentBytes, false)
	if err != nil {
		return RestoreObservation{}, nil, fmt.Errorf("database restore observation: %w", err)
	}
	observation, err := ParseRestoreObservation(payload)
	if err != nil {
		return RestoreObservation{}, nil, err
	}
	return observation, payload, nil
}

func ParseRestoreObservation(payload []byte) (RestoreObservation, error) {
	if err := strictjson.RejectDuplicateFields(payload); err != nil {
		return RestoreObservation{}, fmt.Errorf("database restore observation is ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var observation RestoreObservation
	if err := decoder.Decode(&observation); err != nil {
		return RestoreObservation{}, fmt.Errorf("database restore observation JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return RestoreObservation{}, fmt.Errorf("database restore observation has trailing JSON")
	}
	canonical, err := CanonicalRestoreObservation(observation)
	if err != nil || !bytes.Equal(canonical, payload) {
		return RestoreObservation{}, fmt.Errorf("database restore observation is not canonical JSON")
	}
	if err := validateRestoreObservation(observation); err != nil {
		return RestoreObservation{}, err
	}
	return observation, nil
}

func CanonicalRestoreObservation(observation RestoreObservation) ([]byte, error) {
	payload, err := json.Marshal(observation)
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}

func validateRestoreObservation(observation RestoreObservation) error {
	if observation.Schema != RestoreObservationSchema ||
		!auth.ValidIdentifier(observation.QualificationID, 64) ||
		(observation.Environment != "staging" && observation.Environment != "production") ||
		(observation.DevelopmentOnly && observation.Environment != "staging") ||
		!validSHA256(observation.RunBindingSHA256) ||
		!validSHA256(observation.FailoverObservationSHA256) ||
		!validSHA256(observation.ConfigSHA256) ||
		!validSHA256(observation.QualificationToolSHA256) ||
		!equalRoles(observation.Roles) || len(observation.Databases) != len(ExactRoles) ||
		!observation.SecretFree {
		return fmt.Errorf("database restore observation fields are invalid")
	}
	for index, evidence := range observation.Databases {
		if evidence.Role != ExactRoles[index] || !validRoleRestoreEvidence(evidence) {
			return fmt.Errorf("database restore role evidence is invalid")
		}
	}
	started, startErr := parseCanonicalTime(observation.StartedAt)
	finished, finishErr := parseCanonicalTime(observation.FinishedAt)
	if startErr != nil || finishErr != nil || finished.Before(started) ||
		finished.Sub(started) > maximumRestoreRunTime {
		return fmt.Errorf("database restore observation time is invalid")
	}
	return nil
}

func validRoleRestoreEvidence(evidence RoleRestoreEvidence) bool {
	if !evidence.Role.Valid() || !auth.ValidIdentifier(evidence.ManagedClusterID, 128) ||
		!auth.ValidIdentifier(evidence.RestoreOperationID, 128) ||
		!validSHA256(evidence.SourceEndpointAuthoritySHA256) ||
		!validSHA256(evidence.RestoreEndpointAuthoritySHA256) ||
		evidence.SourceEndpointAuthoritySHA256 == evidence.RestoreEndpointAuthoritySHA256 ||
		!validSHA256(evidence.RestoredNodeBindingSHA256) ||
		evidence.RestoredPostgresVersion < minimumPostgresVersion ||
		!evidence.ProductSchemasVerified || !evidence.PreRestoreEventPresent ||
		!evidence.RestoreMarkerPresent || !evidence.RestoreExclusionAbsent ||
		!evidence.HeartbeatEventsAbsent || !evidence.PostFailoverEventAbsent ||
		evidence.RestoredEventCount != 2 {
		return false
	}
	target, targetErr := parseCanonicalTime(evidence.RequestedRecoveryTarget)
	marker, markerErr := parseCanonicalTime(evidence.RestoreMarkerCommittedAt)
	return targetErr == nil && markerErr == nil && target.After(marker)
}

func restoreObservationsEqual(left, right RestoreObservation) bool {
	return reflect.DeepEqual(left, right)
}
