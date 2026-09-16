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
	DatabaseAttestationSchema        = 1
	LiveDatabaseAttestationResult    = "LIVE_MANAGED_POSTGRESQL_CONTROL_PLANE_PASS"
	FixtureDatabaseAttestationResult = "FIXTURE_MANAGED_POSTGRESQL_ATTESTATION_PASS"
	maximumDatabaseAttestationLife   = 24 * time.Hour
	maximumDatabaseEvidenceDelay     = 10 * time.Minute
	databaseClockSkew                = 30 * time.Second
)

var databaseAttestationSignatureDomain = []byte(
	"XIAOZHI-MANAGED-DATABASE-ATTESTATION-V1\x00")

type DatabaseAttestation struct {
	Schema                             uint32                 `json:"schema"`
	QualificationID                    string                 `json:"qualification_id"`
	Result                             string                 `json:"result"`
	Environment                        string                 `json:"environment"`
	DevelopmentOnly                    bool                   `json:"development_only"`
	AttestationProvider                string                 `json:"attestation_provider"`
	RunBindingSHA256                   string                 `json:"run_binding_sha256"`
	FailoverObservationSHA256          string                 `json:"failover_observation_sha256"`
	RestoreObservationSHA256           string                 `json:"restore_observation_sha256"`
	ProviderAuditEvidenceSHA256        string                 `json:"provider_audit_evidence_sha256"`
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
	VerifiedAt                         string                 `json:"verified_at"`
	ExpiresAt                          string                 `json:"expires_at"`
	SigningKeyID                       string                 `json:"signing_key_id"`
	SignatureAlgorithm                 string                 `json:"signature_algorithm"`
	SignatureB64URL                    string                 `json:"signature_b64url"`
}

type DatabaseAttestationInput struct {
	Failover                  FailoverObservation
	Restore                   RestoreObservation
	FailoverObservationSHA256 string
	RestoreObservationSHA256  string
	Audit                     AuditDocument
	ProviderAuditSHA256       string
	VerifiedAt                time.Time
	ExpiresAt                 time.Time
}

type DatabaseAttestationVerifyOptions struct {
	TrustedPublicKey            string
	ExpectedSigningKeyID        string
	ExpectedProvider            string
	ExpectedProviderAuditSHA256 string
	EvaluationTime              time.Time
	RequireLive                 bool
}

func SignDatabaseAttestation(input DatabaseAttestationInput, privateKeyPath,
	signingKeyID string) ([]byte, error) {
	if !databaseAuditMatchesObservations(input.Audit, input.Failover, input.Restore) ||
		!validSHA256(input.FailoverObservationSHA256) ||
		!validSHA256(input.RestoreObservationSHA256) ||
		!validSHA256(input.ProviderAuditSHA256) || input.VerifiedAt.IsZero() ||
		input.Restore.FailoverObservationSHA256 != input.FailoverObservationSHA256 ||
		input.ExpiresAt.IsZero() || input.VerifiedAt.Nanosecond() != 0 ||
		input.ExpiresAt.Nanosecond() != 0 {
		return nil, fmt.Errorf("managed database attestation input is invalid")
	}
	result := LiveDatabaseAttestationResult
	if input.Audit.DevelopmentOnly {
		result = FixtureDatabaseAttestationResult
	}
	attestation := DatabaseAttestation{Schema: DatabaseAttestationSchema,
		QualificationID: input.Audit.QualificationID, Result: result,
		Environment: input.Audit.Environment, DevelopmentOnly: input.Audit.DevelopmentOnly,
		AttestationProvider:                input.Audit.Provider,
		RunBindingSHA256:                   input.Failover.RunBindingSHA256,
		FailoverObservationSHA256:          input.FailoverObservationSHA256,
		RestoreObservationSHA256:           input.RestoreObservationSHA256,
		ProviderAuditEvidenceSHA256:        input.ProviderAuditSHA256,
		WORMRecordID:                       input.Audit.WORMRecordID,
		FailoverStartedAt:                  input.Audit.FailoverStartedAt,
		FailoverCompletedAt:                input.Audit.FailoverCompletedAt,
		RestoreCompletedAt:                 input.Audit.RestoreCompletedAt,
		RPOTargetSeconds:                   input.Audit.RPOTargetSeconds,
		RTOTargetSeconds:                   input.Audit.RTOTargetSeconds,
		Databases:                          append([]DatabaseAuditBinding(nil), input.Audit.Databases...),
		ManagedServiceControlPlaneVerified: input.Audit.ManagedServiceControlPlaneVerified,
		FailoverOperatorEventVerified:      input.Audit.FailoverOperatorEventVerified,
		AutomatedBackupsVerified:           input.Audit.AutomatedBackupsVerified,
		PointInTimeRestoreVerified:         input.Audit.PointInTimeRestoreVerified,
		EncryptionAtRestVerified:           input.Audit.EncryptionAtRestVerified,
		RestoreIsolationVerified:           input.Audit.RestoreIsolationVerified,
		WORMRetentionVerified:              input.Audit.WORMRetentionVerified,
		VerifiedAt:                         input.VerifiedAt.UTC().Format(time.RFC3339),
		ExpiresAt:                          input.ExpiresAt.UTC().Format(time.RFC3339),
		SigningKeyID:                       signingKeyID, SignatureAlgorithm: "Ed25519"}
	if err := validateDatabaseAttestation(attestation,
		DatabaseAttestationVerifyOptions{}); err != nil {
		return nil, err
	}
	payload, err := databaseAttestationSignaturePayload(attestation)
	if err != nil {
		return nil, err
	}
	attestation.SignatureB64URL, err = signDomainPayload(
		databaseAttestationSignatureDomain, payload, privateKeyPath)
	if err != nil {
		return nil, err
	}
	return canonicalDatabaseAttestation(attestation)
}

func VerifyDatabaseAttestationFile(path string,
	options DatabaseAttestationVerifyOptions) (DatabaseAttestation, []byte, error) {
	payload, err := readRegular(path, maximumDocumentBytes, false)
	if err != nil {
		return DatabaseAttestation{}, nil, fmt.Errorf("managed database attestation rejected")
	}
	attestation, err := VerifyDatabaseAttestation(payload, options)
	if err != nil {
		return DatabaseAttestation{}, nil, err
	}
	return attestation, payload, nil
}

func VerifyDatabaseAttestation(payload []byte,
	options DatabaseAttestationVerifyOptions) (DatabaseAttestation, error) {
	if err := strictjson.RejectDuplicateFields(payload); err != nil {
		return DatabaseAttestation{}, fmt.Errorf("managed database attestation is ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var attestation DatabaseAttestation
	if err := decoder.Decode(&attestation); err != nil {
		return DatabaseAttestation{}, fmt.Errorf("managed database attestation JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return DatabaseAttestation{}, fmt.Errorf("managed database attestation has trailing JSON")
	}
	canonical, err := canonicalDatabaseAttestation(attestation)
	if err != nil || !bytes.Equal(canonical, payload) {
		return DatabaseAttestation{}, fmt.Errorf("managed database attestation is not canonical JSON")
	}
	if err := validateDatabaseAttestation(attestation, options); err != nil {
		return DatabaseAttestation{}, err
	}
	signingPayload, err := databaseAttestationSignaturePayload(attestation)
	if err != nil || verifyDomainPayload(databaseAttestationSignatureDomain,
		signingPayload, attestation.SignatureB64URL, options.TrustedPublicKey) != nil {
		return DatabaseAttestation{}, fmt.Errorf("managed database attestation signature is invalid")
	}
	return attestation, nil
}

func validateDatabaseAttestation(attestation DatabaseAttestation,
	options DatabaseAttestationVerifyOptions) error {
	audit := AuditDocument{Schema: 1, QualificationID: attestation.QualificationID,
		Environment: attestation.Environment, DevelopmentOnly: attestation.DevelopmentOnly,
		Provider: attestation.AttestationProvider, WORMRecordID: attestation.WORMRecordID,
		FailoverStartedAt:   attestation.FailoverStartedAt,
		FailoverCompletedAt: attestation.FailoverCompletedAt,
		RestoreCompletedAt:  attestation.RestoreCompletedAt,
		RPOTargetSeconds:    attestation.RPOTargetSeconds, RTOTargetSeconds: attestation.RTOTargetSeconds,
		Databases:                          attestation.Databases,
		ManagedServiceControlPlaneVerified: attestation.ManagedServiceControlPlaneVerified,
		FailoverOperatorEventVerified:      attestation.FailoverOperatorEventVerified,
		AutomatedBackupsVerified:           attestation.AutomatedBackupsVerified,
		PointInTimeRestoreVerified:         attestation.PointInTimeRestoreVerified,
		EncryptionAtRestVerified:           attestation.EncryptionAtRestVerified,
		RestoreIsolationVerified:           attestation.RestoreIsolationVerified,
		WORMRetentionVerified:              attestation.WORMRetentionVerified}
	if attestation.Schema != DatabaseAttestationSchema ||
		!validSHA256(attestation.RunBindingSHA256) ||
		!validSHA256(attestation.FailoverObservationSHA256) ||
		!validSHA256(attestation.RestoreObservationSHA256) ||
		!validSHA256(attestation.ProviderAuditEvidenceSHA256) ||
		!auth.ValidIdentifier(attestation.SigningKeyID, 64) ||
		attestation.SignatureAlgorithm != "Ed25519" ||
		validateAuditDocument(audit) != nil {
		return fmt.Errorf("managed database attestation fields are invalid")
	}
	expectedResult := LiveDatabaseAttestationResult
	if attestation.DevelopmentOnly {
		expectedResult = FixtureDatabaseAttestationResult
	}
	if attestation.Result != expectedResult ||
		(options.RequireLive && attestation.DevelopmentOnly) {
		return fmt.Errorf("managed database attestation result is invalid")
	}
	verified, verifiedErr := parseCanonicalTime(attestation.VerifiedAt)
	expires, expiresErr := parseCanonicalTime(attestation.ExpiresAt)
	restoreCompleted, restoreErr := parseCanonicalTime(attestation.RestoreCompletedAt)
	if verifiedErr != nil || expiresErr != nil || restoreErr != nil ||
		verified.Before(restoreCompleted) ||
		verified.After(restoreCompleted.Add(maximumDatabaseEvidenceDelay)) ||
		!expires.After(verified) ||
		expires.Sub(verified) > maximumDatabaseAttestationLife {
		return fmt.Errorf("managed database attestation validity window is invalid")
	}
	if !options.EvaluationTime.IsZero() &&
		(options.EvaluationTime.Before(verified) || !options.EvaluationTime.Before(expires)) {
		return fmt.Errorf("managed database attestation is outside its validity window")
	}
	checks := []struct{ actual, expected string }{
		{attestation.SigningKeyID, options.ExpectedSigningKeyID},
		{attestation.AttestationProvider, options.ExpectedProvider},
		{attestation.ProviderAuditEvidenceSHA256, options.ExpectedProviderAuditSHA256},
	}
	for _, check := range checks {
		if check.expected != "" && check.actual != check.expected {
			return fmt.Errorf("managed database attestation identity does not match")
		}
	}
	return nil
}

func databaseAuditMatchesObservations(audit AuditDocument,
	failover FailoverObservation, restore RestoreObservation) bool {
	if validateAuditDocument(audit) != nil ||
		audit.QualificationID != failover.QualificationID ||
		audit.QualificationID != restore.QualificationID ||
		audit.Environment != failover.Environment || audit.Environment != restore.Environment ||
		audit.DevelopmentOnly != failover.DevelopmentOnly ||
		audit.DevelopmentOnly != restore.DevelopmentOnly ||
		failover.RunBindingSHA256 != restore.RunBindingSHA256 {
		return false
	}
	failoverStarted, _ := parseCanonicalTime(audit.FailoverStartedAt)
	failoverCompleted, _ := parseCanonicalTime(audit.FailoverCompletedAt)
	restoreCompleted, _ := parseCanonicalTime(audit.RestoreCompletedAt)
	ready, readyErr := parseCanonicalTime(failover.ReadyAt)
	failoverFinished, failoverErr := parseCanonicalTime(failover.FinishedAt)
	restoreStarted, restoreStartErr := parseCanonicalTime(restore.StartedAt)
	restoreFinished, restoreErr := parseCanonicalTime(restore.FinishedAt)
	if readyErr != nil || failoverErr != nil || restoreStartErr != nil || restoreErr != nil ||
		failoverStarted.Before(ready.Add(-databaseClockSkew)) ||
		failoverStarted.After(failoverFinished) ||
		failoverCompleted.Before(failoverFinished.Add(-databaseClockSkew)) ||
		failoverCompleted.After(failoverFinished.Add(maximumDatabaseEvidenceDelay)) ||
		restoreStarted.Before(failoverFinished) ||
		restoreCompleted.Before(restoreFinished.Add(-databaseClockSkew)) ||
		restoreCompleted.After(restoreFinished.Add(maximumDatabaseEvidenceDelay)) {
		return false
	}
	for index, binding := range audit.Databases {
		if binding.Role != failover.Databases[index].Role ||
			binding.Role != restore.Databases[index].Role ||
			binding.ManagedClusterID != failover.Databases[index].ManagedClusterID ||
			binding.ManagedClusterID != restore.Databases[index].ManagedClusterID ||
			binding.RestoreOperationID != restore.Databases[index].RestoreOperationID ||
			binding.RequestedRecoveryTarget != restore.Databases[index].RequestedRecoveryTarget {
			return false
		}
	}
	return true
}

func databaseAttestationMatchesObservations(attestation DatabaseAttestation,
	failover FailoverObservation, restore RestoreObservation) bool {
	audit := AuditDocument{Schema: 1, QualificationID: attestation.QualificationID,
		Environment: attestation.Environment, DevelopmentOnly: attestation.DevelopmentOnly,
		Provider: attestation.AttestationProvider, WORMRecordID: attestation.WORMRecordID,
		FailoverStartedAt:   attestation.FailoverStartedAt,
		FailoverCompletedAt: attestation.FailoverCompletedAt,
		RestoreCompletedAt:  attestation.RestoreCompletedAt,
		RPOTargetSeconds:    attestation.RPOTargetSeconds, RTOTargetSeconds: attestation.RTOTargetSeconds,
		Databases:                          attestation.Databases,
		ManagedServiceControlPlaneVerified: attestation.ManagedServiceControlPlaneVerified,
		FailoverOperatorEventVerified:      attestation.FailoverOperatorEventVerified,
		AutomatedBackupsVerified:           attestation.AutomatedBackupsVerified,
		PointInTimeRestoreVerified:         attestation.PointInTimeRestoreVerified,
		EncryptionAtRestVerified:           attestation.EncryptionAtRestVerified,
		RestoreIsolationVerified:           attestation.RestoreIsolationVerified,
		WORMRetentionVerified:              attestation.WORMRetentionVerified}
	return attestation.RunBindingSHA256 == failover.RunBindingSHA256 &&
		databaseAuditMatchesObservations(audit, failover, restore)
}

func databaseAttestationSignaturePayload(attestation DatabaseAttestation) ([]byte, error) {
	attestation.SignatureB64URL = ""
	return json.Marshal(attestation)
}

func canonicalDatabaseAttestation(attestation DatabaseAttestation) ([]byte, error) {
	payload, err := json.MarshalIndent(attestation, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}

func databaseAttestationsEqual(left, right DatabaseAttestation) bool {
	return reflect.DeepEqual(left, right)
}
