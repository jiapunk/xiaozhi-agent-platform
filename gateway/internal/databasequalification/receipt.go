package databasequalification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/providerrevocationqualification"
	"xiaozhi-agent-platform/gateway/internal/strictjson"
)

const (
	DatabaseReceiptSchema = 1
	LiveDatabaseResult    = "LIVE_MANAGED_DATABASE_FAILOVER_RESTORE_PASS"
	FixtureDatabaseResult = "FIXTURE_MANAGED_DATABASE_FAILOVER_RESTORE_PASS"
)

var (
	databaseReceiptSignatureDomain = []byte(
		"XIAOZHI-MANAGED-DATABASE-QUALIFICATION-V1\x00")
	liveDatabaseUnresolvedProductionGates    = []string{}
	fixtureDatabaseUnresolvedProductionGates = []string{
		"end_to_end_mtls_dispatch",
		"managed_database_failover",
		"provider_credential_revocation",
		"signed_app_delivery_receipt",
	}
)

type DatabaseReceipt struct {
	Schema                             uint32                 `json:"schema"`
	QualificationID                    string                 `json:"qualification_id"`
	Result                             string                 `json:"result"`
	Environment                        string                 `json:"environment"`
	DevelopmentOnly                    bool                   `json:"development_only"`
	DeploymentID                       string                 `json:"deployment_id"`
	OCIReleaseID                       string                 `json:"oci_release_id"`
	Roles                              []Role                 `json:"roles"`
	RunBindingSHA256                   string                 `json:"run_binding_sha256"`
	FailoverConfigSHA256               string                 `json:"failover_config_sha256"`
	RestoreConfigSHA256                string                 `json:"restore_config_sha256"`
	FailoverQualificationToolSHA256    string                 `json:"failover_qualification_tool_sha256"`
	RestoreQualificationToolSHA256     string                 `json:"restore_qualification_tool_sha256"`
	ReadySignalSHA256                  string                 `json:"ready_signal_sha256"`
	FailoverObservationSHA256          string                 `json:"failover_observation_sha256"`
	RestoreObservationSHA256           string                 `json:"restore_observation_sha256"`
	FailoverDatabases                  []RoleFailoverEvidence `json:"failover_databases"`
	RestoreDatabases                   []RoleRestoreEvidence  `json:"restore_databases"`
	FailoverStartedAt                  string                 `json:"failover_started_at"`
	FailoverReadyAt                    string                 `json:"failover_ready_at"`
	FailoverFinishedAt                 string                 `json:"failover_finished_at"`
	RestoreStartedAt                   string                 `json:"restore_started_at"`
	RestoreFinishedAt                  string                 `json:"restore_finished_at"`
	ProviderRevocationResult           string                 `json:"provider_revocation_result"`
	ProviderRevocationReceiptSHA256    string                 `json:"provider_revocation_receipt_sha256"`
	DatabaseAttestationResult          string                 `json:"database_attestation_result"`
	DatabaseAttestationReceiptSHA256   string                 `json:"database_attestation_receipt_sha256"`
	AttestationProvider                string                 `json:"attestation_provider"`
	ProviderAuditEvidenceSHA256        string                 `json:"provider_audit_evidence_sha256"`
	WORMRecordID                       string                 `json:"worm_record_id"`
	RPOTargetSeconds                   int64                  `json:"rpo_target_seconds"`
	RTOTargetSeconds                   int64                  `json:"rto_target_seconds"`
	DatabaseAuditBindings              []DatabaseAuditBinding `json:"database_audit_bindings"`
	ManagedServiceControlPlaneVerified bool                   `json:"managed_service_control_plane_verified"`
	FailoverOperatorEventVerified      bool                   `json:"failover_operator_event_verified"`
	AutomatedBackupsVerified           bool                   `json:"automated_backups_verified"`
	PointInTimeRestoreVerified         bool                   `json:"point_in_time_restore_verified"`
	EncryptionAtRestVerified           bool                   `json:"encryption_at_rest_verified"`
	RestoreIsolationVerified           bool                   `json:"restore_isolation_verified"`
	WORMRetentionVerified              bool                   `json:"worm_retention_verified"`
	EvaluatedAt                        string                 `json:"evaluated_at"`
	SecretFree                         bool                   `json:"secret_free"`
	ProductionReady                    bool                   `json:"production_ready"`
	UnresolvedProductionGates          []string               `json:"unresolved_production_gates"`
	SigningKeyID                       string                 `json:"signing_key_id"`
	SignatureAlgorithm                 string                 `json:"signature_algorithm"`
	SignatureB64URL                    string                 `json:"signature_b64url"`
}

type DatabaseEvidenceOptions struct {
	FailoverObservationPath           string
	ReadySignalPath                   string
	RestoreObservationPath            string
	DatabaseAttestationPath           string
	DatabaseAttestationVerifyOptions  DatabaseAttestationVerifyOptions
	ProviderRevocationReceiptPath     string
	ProviderRevocationVerifyOptions   providerrevocationqualification.ReceiptVerifyOptions
	ProviderRevocationEvidenceOptions providerrevocationqualification.EvidenceOptions
	EvaluationTime                    time.Time
	RequireLive                       bool
}

type DatabaseReceiptVerifyOptions struct {
	TrustedPublicKey                  string
	ExpectedSigningKeyID              string
	ExpectedQualificationID           string
	ExpectedEnvironment               string
	ExpectedDeploymentID              string
	ExpectedOCIReleaseID              string
	ExpectedRunBindingSHA256          string
	ExpectedFailoverObservationSHA256 string
	ExpectedRestoreObservationSHA256  string
	ExpectedProviderRevocationSHA256  string
	ExpectedDatabaseAttestationSHA256 string
	ExpectedEvaluationTime            string
	RequireLive                       bool
}

func BuildDatabaseReceipt(options DatabaseEvidenceOptions) (DatabaseReceipt, error) {
	if options.EvaluationTime.IsZero() || options.EvaluationTime.Nanosecond() != 0 {
		return DatabaseReceipt{}, fmt.Errorf("managed database evaluation time is invalid")
	}
	failover, failoverPayload, err := LoadFailoverObservation(
		options.FailoverObservationPath)
	if err != nil {
		return DatabaseReceipt{}, err
	}
	ready, readyPayload, err := LoadReadySignal(options.ReadySignalPath)
	if err != nil {
		return DatabaseReceipt{}, err
	}
	restore, restorePayload, err := LoadRestoreObservation(
		options.RestoreObservationPath)
	if err != nil {
		return DatabaseReceipt{}, err
	}
	providerPayload, err := readRegular(options.ProviderRevocationReceiptPath,
		maximumDocumentBytes, false)
	if err != nil {
		return DatabaseReceipt{}, fmt.Errorf("provider revocation receipt rejected")
	}
	providerVerify := options.ProviderRevocationVerifyOptions
	providerVerify.RequireLive = options.RequireLive
	providerReceipt, err := providerrevocationqualification.VerifyReceiptFile(
		options.ProviderRevocationReceiptPath, providerVerify)
	if err != nil {
		return DatabaseReceipt{}, fmt.Errorf("provider revocation receipt rejected")
	}
	providerEvidence := options.ProviderRevocationEvidenceOptions
	providerEvidence.RequireLive = options.RequireLive
	expectedProvider, err := providerrevocationqualification.BuildReceipt(providerEvidence)
	if err != nil || !providerrevocationqualification.ReceiptMatchesEvidence(
		providerReceipt, expectedProvider) {
		return DatabaseReceipt{}, fmt.Errorf("provider revocation evidence bundle rejected")
	}
	attestationVerify := options.DatabaseAttestationVerifyOptions
	attestationVerify.RequireLive = options.RequireLive
	attestationVerify.EvaluationTime = options.EvaluationTime.UTC()
	attestation, attestationPayload, err := VerifyDatabaseAttestationFile(
		options.DatabaseAttestationPath, attestationVerify)
	if err != nil {
		return DatabaseReceipt{}, err
	}
	failoverSHA := digestBytes(failoverPayload)
	restoreSHA := digestBytes(restorePayload)
	readySHA := digestBytes(readyPayload)
	providerEvaluated, providerTimeErr := parseCanonicalTime(providerReceipt.EvaluatedAt)
	failoverStarted, failoverTimeErr := parseCanonicalTime(failover.StartedAt)
	attestationVerified, attestationTimeErr := parseCanonicalTime(attestation.VerifiedAt)
	if failover.QualificationID != restore.QualificationID ||
		failover.QualificationID != providerReceipt.QualificationID ||
		failover.QualificationID != attestation.QualificationID ||
		failover.Environment != restore.Environment ||
		failover.Environment != providerReceipt.Environment ||
		failover.Environment != attestation.Environment ||
		failover.DevelopmentOnly != restore.DevelopmentOnly ||
		failover.DevelopmentOnly != providerReceipt.DevelopmentOnly ||
		failover.DevelopmentOnly != attestation.DevelopmentOnly ||
		failover.RunBindingSHA256 != restore.RunBindingSHA256 ||
		failoverSHA != restore.FailoverObservationSHA256 ||
		failoverSHA != attestation.FailoverObservationSHA256 ||
		restoreSHA != attestation.RestoreObservationSHA256 ||
		readySHA != failover.ReadySignalSHA256 ||
		ready.QualificationID != failover.QualificationID ||
		ready.RunBindingSHA256 != failover.RunBindingSHA256 ||
		ready.ConfigSHA256 != failover.ConfigSHA256 ||
		ready.ReadyAt != failover.ReadyAt || !equalRoles(ready.Roles) ||
		!databaseAttestationMatchesObservations(attestation, failover, restore) ||
		providerTimeErr != nil || failoverTimeErr != nil || attestationTimeErr != nil ||
		failoverStarted.Before(providerEvaluated.Add(-databaseClockSkew)) ||
		options.EvaluationTime.Before(attestationVerified) ||
		options.EvaluationTime.After(attestationVerified.Add(maximumDatabaseEvidenceDelay)) {
		return DatabaseReceipt{}, fmt.Errorf("managed database evidence subjects do not match")
	}
	if options.RequireLive && (failover.DevelopmentOnly || restore.DevelopmentOnly ||
		providerReceipt.DevelopmentOnly || attestation.DevelopmentOnly) {
		return DatabaseReceipt{}, fmt.Errorf("live managed database evidence is required")
	}
	result := LiveDatabaseResult
	unresolved := liveDatabaseUnresolvedProductionGates
	if failover.DevelopmentOnly {
		result = FixtureDatabaseResult
		unresolved = fixtureDatabaseUnresolvedProductionGates
	}
	receipt := DatabaseReceipt{Schema: DatabaseReceiptSchema,
		QualificationID: failover.QualificationID, Result: result,
		Environment: failover.Environment, DevelopmentOnly: failover.DevelopmentOnly,
		DeploymentID: providerReceipt.DeploymentID, OCIReleaseID: providerReceipt.OCIReleaseID,
		Roles: append([]Role(nil), ExactRoles...), RunBindingSHA256: failover.RunBindingSHA256,
		FailoverConfigSHA256:            failover.ConfigSHA256,
		RestoreConfigSHA256:             restore.ConfigSHA256,
		FailoverQualificationToolSHA256: failover.QualificationToolSHA256,
		RestoreQualificationToolSHA256:  restore.QualificationToolSHA256,
		ReadySignalSHA256:               readySHA, FailoverObservationSHA256: failoverSHA,
		RestoreObservationSHA256: restoreSHA,
		FailoverDatabases:        append([]RoleFailoverEvidence(nil), failover.Databases...),
		RestoreDatabases:         append([]RoleRestoreEvidence(nil), restore.Databases...),
		FailoverStartedAt:        failover.StartedAt, FailoverReadyAt: failover.ReadyAt,
		FailoverFinishedAt: failover.FinishedAt, RestoreStartedAt: restore.StartedAt,
		RestoreFinishedAt:                  restore.FinishedAt,
		ProviderRevocationResult:           providerReceipt.Result,
		ProviderRevocationReceiptSHA256:    digestBytes(providerPayload),
		DatabaseAttestationResult:          attestation.Result,
		DatabaseAttestationReceiptSHA256:   digestBytes(attestationPayload),
		AttestationProvider:                attestation.AttestationProvider,
		ProviderAuditEvidenceSHA256:        attestation.ProviderAuditEvidenceSHA256,
		WORMRecordID:                       attestation.WORMRecordID,
		RPOTargetSeconds:                   attestation.RPOTargetSeconds,
		RTOTargetSeconds:                   attestation.RTOTargetSeconds,
		DatabaseAuditBindings:              append([]DatabaseAuditBinding(nil), attestation.Databases...),
		ManagedServiceControlPlaneVerified: attestation.ManagedServiceControlPlaneVerified,
		FailoverOperatorEventVerified:      attestation.FailoverOperatorEventVerified,
		AutomatedBackupsVerified:           attestation.AutomatedBackupsVerified,
		PointInTimeRestoreVerified:         attestation.PointInTimeRestoreVerified,
		EncryptionAtRestVerified:           attestation.EncryptionAtRestVerified,
		RestoreIsolationVerified:           attestation.RestoreIsolationVerified,
		WORMRetentionVerified:              attestation.WORMRetentionVerified,
		EvaluatedAt:                        options.EvaluationTime.UTC().Format(time.RFC3339), SecretFree: true,
		ProductionReady: false, UnresolvedProductionGates: append([]string(nil), unresolved...)}
	if err := validateDatabaseReceipt(receipt, DatabaseReceiptVerifyOptions{}); err != nil {
		return DatabaseReceipt{}, err
	}
	return receipt, nil
}

func SignDatabaseReceipt(receipt DatabaseReceipt, privateKeyPath,
	signingKeyID string) ([]byte, error) {
	receipt.SigningKeyID = signingKeyID
	receipt.SignatureAlgorithm = "Ed25519"
	receipt.SignatureB64URL = ""
	if err := validateDatabaseReceipt(receipt, DatabaseReceiptVerifyOptions{
		ExpectedSigningKeyID: signingKeyID}); err != nil {
		return nil, err
	}
	payload, err := databaseReceiptSignaturePayload(receipt)
	if err != nil {
		return nil, err
	}
	receipt.SignatureB64URL, err = signDomainPayload(databaseReceiptSignatureDomain,
		payload, privateKeyPath)
	if err != nil {
		return nil, err
	}
	return canonicalDatabaseReceipt(receipt)
}

func VerifyDatabaseReceiptFile(path string,
	options DatabaseReceiptVerifyOptions) (DatabaseReceipt, error) {
	payload, err := readRegular(path, maximumDocumentBytes, false)
	if err != nil {
		return DatabaseReceipt{}, fmt.Errorf("managed database qualification receipt rejected")
	}
	return VerifyDatabaseReceipt(payload, options)
}

func VerifyDatabaseReceipt(payload []byte,
	options DatabaseReceiptVerifyOptions) (DatabaseReceipt, error) {
	if err := strictjson.RejectDuplicateFields(payload); err != nil {
		return DatabaseReceipt{}, fmt.Errorf("managed database qualification receipt is ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var receipt DatabaseReceipt
	if err := decoder.Decode(&receipt); err != nil {
		return DatabaseReceipt{}, fmt.Errorf("managed database qualification receipt JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return DatabaseReceipt{}, fmt.Errorf("managed database qualification receipt has trailing JSON")
	}
	canonical, err := canonicalDatabaseReceipt(receipt)
	if err != nil || !bytes.Equal(canonical, payload) {
		return DatabaseReceipt{}, fmt.Errorf("managed database qualification receipt is not canonical JSON")
	}
	if err := validateDatabaseReceipt(receipt, options); err != nil {
		return DatabaseReceipt{}, err
	}
	payloadToVerify, err := databaseReceiptSignaturePayload(receipt)
	if err != nil || verifyDomainPayload(databaseReceiptSignatureDomain,
		payloadToVerify, receipt.SignatureB64URL, options.TrustedPublicKey) != nil {
		return DatabaseReceipt{}, fmt.Errorf("managed database qualification receipt signature is invalid")
	}
	return receipt, nil
}

func validateDatabaseReceipt(receipt DatabaseReceipt,
	options DatabaseReceiptVerifyOptions) error {
	unsigned := receipt.SigningKeyID == "" && receipt.SignatureAlgorithm == "" &&
		receipt.SignatureB64URL == ""
	expectedUnresolved := liveDatabaseUnresolvedProductionGates
	if receipt.DevelopmentOnly {
		expectedUnresolved = fixtureDatabaseUnresolvedProductionGates
	}
	failover := FailoverObservation{Schema: FailoverObservationSchema,
		QualificationID: receipt.QualificationID, Environment: receipt.Environment,
		DevelopmentOnly: receipt.DevelopmentOnly, RunBindingSHA256: receipt.RunBindingSHA256,
		ConfigSHA256:            receipt.FailoverConfigSHA256,
		QualificationToolSHA256: receipt.FailoverQualificationToolSHA256,
		ReadySignalSHA256:       receipt.ReadySignalSHA256, Roles: receipt.Roles,
		Databases: receipt.FailoverDatabases, ReadyAt: receipt.FailoverReadyAt,
		StartedAt: receipt.FailoverStartedAt, FinishedAt: receipt.FailoverFinishedAt,
		SecretFree: receipt.SecretFree}
	restore := RestoreObservation{Schema: RestoreObservationSchema,
		QualificationID: receipt.QualificationID, Environment: receipt.Environment,
		DevelopmentOnly: receipt.DevelopmentOnly, RunBindingSHA256: receipt.RunBindingSHA256,
		FailoverObservationSHA256: receipt.FailoverObservationSHA256,
		ConfigSHA256:              receipt.RestoreConfigSHA256,
		QualificationToolSHA256:   receipt.RestoreQualificationToolSHA256,
		Roles:                     receipt.Roles, Databases: receipt.RestoreDatabases,
		StartedAt: receipt.RestoreStartedAt, FinishedAt: receipt.RestoreFinishedAt,
		SecretFree: receipt.SecretFree}
	if validateFailoverObservation(failover) != nil ||
		validateRestoreObservation(restore) != nil ||
		!auth.ValidIdentifier(receipt.DeploymentID, 64) ||
		!auth.ValidIdentifier(receipt.OCIReleaseID, 64) ||
		!validSHA256(receipt.FailoverObservationSHA256) ||
		!validSHA256(receipt.RestoreObservationSHA256) ||
		!validSHA256(receipt.ProviderRevocationReceiptSHA256) ||
		!validSHA256(receipt.DatabaseAttestationReceiptSHA256) ||
		!validSHA256(receipt.ProviderAuditEvidenceSHA256) ||
		!auth.ValidIdentifier(receipt.WORMRecordID, 128) ||
		receipt.RPOTargetSeconds < 1 || receipt.RPOTargetSeconds > maximumRecoverySLO ||
		receipt.RTOTargetSeconds < 1 || receipt.RTOTargetSeconds > maximumRecoverySLO ||
		len(receipt.DatabaseAuditBindings) != len(ExactRoles) ||
		!receipt.SecretFree || receipt.ProductionReady ||
		!reflect.DeepEqual(receipt.UnresolvedProductionGates, expectedUnresolved) ||
		(!unsigned && (!auth.ValidIdentifier(receipt.SigningKeyID, 64) ||
			receipt.SignatureAlgorithm != "Ed25519")) {
		return fmt.Errorf("managed database qualification receipt fields are invalid")
	}
	for index, binding := range receipt.DatabaseAuditBindings {
		if binding.Role != ExactRoles[index] ||
			binding.Role != receipt.FailoverDatabases[index].Role ||
			binding.Role != receipt.RestoreDatabases[index].Role ||
			binding.ManagedClusterID != receipt.FailoverDatabases[index].ManagedClusterID ||
			binding.ManagedClusterID != receipt.RestoreDatabases[index].ManagedClusterID ||
			binding.RestoreOperationID != receipt.RestoreDatabases[index].RestoreOperationID ||
			binding.RequestedRecoveryTarget != receipt.RestoreDatabases[index].RequestedRecoveryTarget ||
			!auth.ValidIdentifier(binding.FailoverOperationID, 128) ||
			!auth.ValidIdentifier(binding.AutomatedBackupID, 128) ||
			binding.ObservedRPOSeconds < 0 ||
			binding.ObservedRPOSeconds > receipt.RPOTargetSeconds ||
			binding.FailoverRTOSeconds < 0 ||
			binding.FailoverRTOSeconds > receipt.RTOTargetSeconds ||
			binding.RestoreRTOSeconds < 0 ||
			binding.RestoreRTOSeconds > receipt.RTOTargetSeconds {
			return fmt.Errorf("managed database qualification audit binding is invalid")
		}
	}
	verified := receipt.ManagedServiceControlPlaneVerified &&
		receipt.FailoverOperatorEventVerified && receipt.AutomatedBackupsVerified &&
		receipt.PointInTimeRestoreVerified && receipt.EncryptionAtRestVerified &&
		receipt.RestoreIsolationVerified && receipt.WORMRetentionVerified
	if receipt.DevelopmentOnly {
		if receipt.Result != FixtureDatabaseResult ||
			receipt.ProviderRevocationResult != providerrevocationqualification.FixtureResult ||
			receipt.DatabaseAttestationResult != FixtureDatabaseAttestationResult ||
			receipt.AttestationProvider != FixtureAuditProvider ||
			receipt.ManagedServiceControlPlaneVerified ||
			receipt.FailoverOperatorEventVerified ||
			receipt.AutomatedBackupsVerified ||
			receipt.PointInTimeRestoreVerified ||
			receipt.EncryptionAtRestVerified ||
			receipt.RestoreIsolationVerified ||
			receipt.WORMRetentionVerified || verified {
			return fmt.Errorf("fixture managed database receipt overstates live evidence")
		}
	} else if receipt.Result != LiveDatabaseResult ||
		receipt.ProviderRevocationResult != providerrevocationqualification.LiveResult ||
		receipt.DatabaseAttestationResult != LiveDatabaseAttestationResult ||
		receipt.AttestationProvider != LiveAuditProvider || !verified ||
		len(receipt.UnresolvedProductionGates) != 0 {
		return fmt.Errorf("live managed database receipt fields are invalid")
	}
	if options.RequireLive && receipt.DevelopmentOnly {
		return fmt.Errorf("live managed database qualification receipt is required")
	}
	evaluated, err := parseCanonicalTime(receipt.EvaluatedAt)
	if err != nil {
		return fmt.Errorf("managed database receipt evaluation time is invalid")
	}
	restoreFinished, _ := parseCanonicalTime(receipt.RestoreFinishedAt)
	if evaluated.Before(restoreFinished) {
		return fmt.Errorf("managed database receipt precedes restore evidence")
	}
	checks := []struct{ actual, expected string }{
		{receipt.SigningKeyID, options.ExpectedSigningKeyID},
		{receipt.QualificationID, options.ExpectedQualificationID},
		{receipt.Environment, options.ExpectedEnvironment},
		{receipt.DeploymentID, options.ExpectedDeploymentID},
		{receipt.OCIReleaseID, options.ExpectedOCIReleaseID},
		{receipt.RunBindingSHA256, options.ExpectedRunBindingSHA256},
		{receipt.FailoverObservationSHA256, options.ExpectedFailoverObservationSHA256},
		{receipt.RestoreObservationSHA256, options.ExpectedRestoreObservationSHA256},
		{receipt.ProviderRevocationReceiptSHA256, options.ExpectedProviderRevocationSHA256},
		{receipt.DatabaseAttestationReceiptSHA256, options.ExpectedDatabaseAttestationSHA256},
		{receipt.EvaluatedAt, options.ExpectedEvaluationTime},
	}
	for _, check := range checks {
		if check.expected != "" && check.actual != check.expected {
			return fmt.Errorf("managed database qualification identity does not match")
		}
	}
	return nil
}

func DatabaseReceiptMatchesEvidence(receipt, expected DatabaseReceipt) bool {
	receipt.SigningKeyID, receipt.SignatureAlgorithm, receipt.SignatureB64URL = "", "", ""
	expected.SigningKeyID, expected.SignatureAlgorithm, expected.SignatureB64URL = "", "", ""
	return reflect.DeepEqual(receipt, expected)
}

func databaseReceiptSignaturePayload(receipt DatabaseReceipt) ([]byte, error) {
	receipt.SignatureB64URL = ""
	return json.Marshal(receipt)
}

func canonicalDatabaseReceipt(receipt DatabaseReceipt) ([]byte, error) {
	payload, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}
