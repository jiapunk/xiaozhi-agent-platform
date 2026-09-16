package databasequalification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/strictjson"
)

const (
	LiveAuditProvider    = "managed-postgresql-audit-authority"
	FixtureAuditProvider = "fixture"
	maximumRecoverySLO   = int64(3600)
)

type DatabaseAuditBinding struct {
	Role                    Role   `json:"role"`
	ManagedClusterID        string `json:"managed_cluster_id"`
	FailoverOperationID     string `json:"failover_operation_id"`
	AutomatedBackupID       string `json:"automated_backup_id"`
	RestoreOperationID      string `json:"restore_operation_id"`
	RequestedRecoveryTarget string `json:"requested_recovery_target"`
	ObservedRPOSeconds      int64  `json:"observed_rpo_seconds"`
	FailoverRTOSeconds      int64  `json:"failover_rto_seconds"`
	RestoreRTOSeconds       int64  `json:"restore_rto_seconds"`
}

type AuditDocument struct {
	Schema                             uint32                 `json:"schema"`
	QualificationID                    string                 `json:"qualification_id"`
	Environment                        string                 `json:"environment"`
	DevelopmentOnly                    bool                   `json:"development_only"`
	Provider                           string                 `json:"provider"`
	WORMRecordID                       string                 `json:"worm_record_id"`
	FailoverStartedAt                  string                 `json:"failover_started_at"`
	FailoverCompletedAt                string                 `json:"failover_completed_at"`
	RestoreCompletedAt                 string                 `json:"restore_completed_at"`
	RPOTargetSeconds                   int64                  `json:"rpo_target_seconds"`
	RTOTargetSeconds                   int64                  `json:"rto_target_seconds"`
	Databases                          []DatabaseAuditBinding `json:"databases"`
	ManagedServiceControlPlaneVerified bool                   `json:"managed_service_control_plane_verified"`
	FailoverOperatorEventVerified      bool                   `json:"failover_operator_event_verified"`
	AutomatedBackupsVerified           bool                   `json:"automated_backups_verified"`
	PointInTimeRestoreVerified         bool                   `json:"point_in_time_restore_verified"`
	EncryptionAtRestVerified           bool                   `json:"encryption_at_rest_verified"`
	RestoreIsolationVerified           bool                   `json:"restore_isolation_verified"`
	WORMRetentionVerified              bool                   `json:"worm_retention_verified"`
}

func LoadAuditDocument(path string) (AuditDocument, []byte, error) {
	payload, err := readRegular(path, maximumDocumentBytes, false)
	if err != nil {
		return AuditDocument{}, nil, fmt.Errorf("managed database audit evidence rejected")
	}
	if err := strictjson.RejectDuplicateFields(payload); err != nil {
		return AuditDocument{}, nil, fmt.Errorf("managed database audit evidence is ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var document AuditDocument
	if err := decoder.Decode(&document); err != nil {
		return AuditDocument{}, nil, fmt.Errorf("managed database audit evidence JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return AuditDocument{}, nil, fmt.Errorf("managed database audit evidence has trailing JSON")
	}
	canonical, err := CanonicalAuditDocument(document)
	if err != nil || !bytes.Equal(canonical, payload) {
		return AuditDocument{}, nil, fmt.Errorf("managed database audit evidence is not canonical JSON")
	}
	if err := validateAuditDocument(document); err != nil {
		return AuditDocument{}, nil, err
	}
	return document, payload, nil
}

func CanonicalAuditDocument(document AuditDocument) ([]byte, error) {
	payload, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}

func validateAuditDocument(document AuditDocument) error {
	if document.Schema != 1 || !auth.ValidIdentifier(document.QualificationID, 64) ||
		(document.Environment != "staging" && document.Environment != "production") ||
		(document.DevelopmentOnly && document.Environment != "staging") ||
		!auth.ValidIdentifier(document.WORMRecordID, 128) ||
		document.RPOTargetSeconds < 1 || document.RPOTargetSeconds > maximumRecoverySLO ||
		document.RTOTargetSeconds < 1 || document.RTOTargetSeconds > maximumRecoverySLO ||
		len(document.Databases) != len(ExactRoles) {
		return fmt.Errorf("managed database audit evidence fields are invalid")
	}
	started, startErr := parseCanonicalTime(document.FailoverStartedAt)
	failoverCompleted, failoverErr := parseCanonicalTime(document.FailoverCompletedAt)
	restoreCompleted, restoreErr := parseCanonicalTime(document.RestoreCompletedAt)
	if startErr != nil || failoverErr != nil || restoreErr != nil ||
		failoverCompleted.Before(started) || restoreCompleted.Before(failoverCompleted) ||
		restoreCompleted.Sub(started) > 24*time.Hour {
		return fmt.Errorf("managed database audit evidence time is invalid")
	}
	for index, binding := range document.Databases {
		if binding.Role != ExactRoles[index] ||
			!auth.ValidIdentifier(binding.ManagedClusterID, 128) ||
			!auth.ValidIdentifier(binding.FailoverOperationID, 128) ||
			!auth.ValidIdentifier(binding.AutomatedBackupID, 128) ||
			!auth.ValidIdentifier(binding.RestoreOperationID, 128) ||
			binding.ObservedRPOSeconds < 0 ||
			binding.ObservedRPOSeconds > document.RPOTargetSeconds ||
			binding.FailoverRTOSeconds < 0 ||
			binding.FailoverRTOSeconds > document.RTOTargetSeconds ||
			binding.RestoreRTOSeconds < 0 ||
			binding.RestoreRTOSeconds > document.RTOTargetSeconds {
			return fmt.Errorf("managed database audit role evidence is invalid")
		}
		if _, err := parseCanonicalTime(binding.RequestedRecoveryTarget); err != nil {
			return fmt.Errorf("managed database audit recovery target is invalid")
		}
	}
	verified := document.ManagedServiceControlPlaneVerified &&
		document.FailoverOperatorEventVerified && document.AutomatedBackupsVerified &&
		document.PointInTimeRestoreVerified && document.EncryptionAtRestVerified &&
		document.RestoreIsolationVerified && document.WORMRetentionVerified
	if document.DevelopmentOnly {
		if document.Provider != FixtureAuditProvider ||
			document.ManagedServiceControlPlaneVerified ||
			document.FailoverOperatorEventVerified ||
			document.AutomatedBackupsVerified ||
			document.PointInTimeRestoreVerified ||
			document.EncryptionAtRestVerified ||
			document.RestoreIsolationVerified ||
			document.WORMRetentionVerified {
			return fmt.Errorf("fixture managed database audit overstates live evidence")
		}
	} else if document.Provider != LiveAuditProvider || !verified {
		return fmt.Errorf("live managed database audit evidence fields are invalid")
	}
	return nil
}
