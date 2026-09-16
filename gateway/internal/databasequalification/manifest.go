package databasequalification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"xiaozhi-agent-platform/gateway/internal/providerrevocationqualification"
	"xiaozhi-agent-platform/gateway/internal/strictjson"
)

type databaseEvidenceManifest struct {
	Schema                                 uint32 `json:"schema"`
	QualificationID                        string `json:"qualification_id"`
	Environment                            string `json:"environment"`
	DeploymentID                           string `json:"deployment_id"`
	OCIReleaseID                           string `json:"oci_release_id"`
	EvaluationTime                         string `json:"evaluation_time"`
	ExpectedRunBindingSHA256               string `json:"expected_run_binding_sha256"`
	ExpectedFailoverConfigSHA256           string `json:"expected_failover_config_sha256"`
	ExpectedFailoverToolSHA256             string `json:"expected_failover_tool_sha256"`
	ExpectedRestoreConfigSHA256            string `json:"expected_restore_config_sha256"`
	ExpectedRestoreToolSHA256              string `json:"expected_restore_tool_sha256"`
	FailoverObservationPath                string `json:"failover_observation_path"`
	ReadySignalPath                        string `json:"ready_signal_path"`
	RestoreObservationPath                 string `json:"restore_observation_path"`
	DatabaseAttestationPath                string `json:"database_attestation_path"`
	DatabaseAttestationPublicKeyPath       string `json:"database_attestation_public_key_path"`
	ExpectedDatabaseAttestationKeyID       string `json:"expected_database_attestation_key_id"`
	ExpectedDatabaseAttestationProvider    string `json:"expected_database_attestation_provider"`
	ExpectedProviderAuditEvidenceSHA256    string `json:"expected_provider_audit_evidence_sha256"`
	ProviderRevocationReceiptPath          string `json:"provider_revocation_receipt_path"`
	ProviderRevocationPublicKeyPath        string `json:"provider_revocation_public_key_path"`
	ExpectedProviderRevocationKeyID        string `json:"expected_provider_revocation_key_id"`
	ProviderRevocationEvidenceManifestPath string `json:"provider_revocation_evidence_manifest_path"`
}

func LoadDatabaseEvidenceManifest(path string, requireLive bool) (
	DatabaseEvidenceOptions, DatabaseReceiptVerifyOptions, error) {
	payload, err := readRegular(path, maximumDocumentBytes, false)
	if err != nil {
		return DatabaseEvidenceOptions{}, DatabaseReceiptVerifyOptions{},
			fmt.Errorf("managed database evidence manifest rejected")
	}
	if err := strictjson.RejectDuplicateFields(payload); err != nil {
		return DatabaseEvidenceOptions{}, DatabaseReceiptVerifyOptions{},
			fmt.Errorf("managed database evidence manifest is ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var manifest databaseEvidenceManifest
	if err := decoder.Decode(&manifest); err != nil {
		return DatabaseEvidenceOptions{}, DatabaseReceiptVerifyOptions{},
			fmt.Errorf("managed database evidence manifest JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF || manifest.Schema != 1 {
		return DatabaseEvidenceOptions{}, DatabaseReceiptVerifyOptions{},
			fmt.Errorf("managed database evidence manifest fields are invalid")
	}
	paths := []string{manifest.FailoverObservationPath, manifest.ReadySignalPath,
		manifest.RestoreObservationPath, manifest.DatabaseAttestationPath,
		manifest.DatabaseAttestationPublicKeyPath,
		manifest.ProviderRevocationReceiptPath,
		manifest.ProviderRevocationPublicKeyPath,
		manifest.ProviderRevocationEvidenceManifestPath}
	for _, candidate := range paths {
		if !filepath.IsAbs(candidate) {
			return DatabaseEvidenceOptions{}, DatabaseReceiptVerifyOptions{},
				fmt.Errorf("managed database evidence paths must be absolute")
		}
	}
	evaluationTime, err := databaseManifestTime(manifest.EvaluationTime)
	if err != nil {
		return DatabaseEvidenceOptions{}, DatabaseReceiptVerifyOptions{}, err
	}
	failover, failoverPayload, err := LoadFailoverObservation(
		manifest.FailoverObservationPath)
	if err != nil {
		return DatabaseEvidenceOptions{}, DatabaseReceiptVerifyOptions{}, err
	}
	_, readyPayload, err := LoadReadySignal(manifest.ReadySignalPath)
	if err != nil {
		return DatabaseEvidenceOptions{}, DatabaseReceiptVerifyOptions{}, err
	}
	restore, restorePayload, err := LoadRestoreObservation(
		manifest.RestoreObservationPath)
	if err != nil {
		return DatabaseEvidenceOptions{}, DatabaseReceiptVerifyOptions{}, err
	}
	attestationSHA, err := DigestRegularFile(manifest.DatabaseAttestationPath,
		maximumDocumentBytes)
	if err != nil {
		return DatabaseEvidenceOptions{}, DatabaseReceiptVerifyOptions{},
			fmt.Errorf("managed database attestation evidence rejected")
	}
	providerSHA, err := DigestRegularFile(manifest.ProviderRevocationReceiptPath,
		maximumDocumentBytes)
	if err != nil {
		return DatabaseEvidenceOptions{}, DatabaseReceiptVerifyOptions{},
			fmt.Errorf("provider revocation receipt evidence rejected")
	}
	if manifest.QualificationID != failover.QualificationID ||
		manifest.QualificationID != restore.QualificationID ||
		manifest.Environment != failover.Environment ||
		manifest.Environment != restore.Environment ||
		manifest.ExpectedRunBindingSHA256 != failover.RunBindingSHA256 ||
		manifest.ExpectedRunBindingSHA256 != restore.RunBindingSHA256 ||
		manifest.ExpectedFailoverConfigSHA256 != failover.ConfigSHA256 ||
		manifest.ExpectedFailoverToolSHA256 != failover.QualificationToolSHA256 ||
		manifest.ExpectedRestoreConfigSHA256 != restore.ConfigSHA256 ||
		manifest.ExpectedRestoreToolSHA256 != restore.QualificationToolSHA256 ||
		digestBytes(readyPayload) != failover.ReadySignalSHA256 ||
		digestBytes(failoverPayload) != restore.FailoverObservationSHA256 {
		return DatabaseEvidenceOptions{}, DatabaseReceiptVerifyOptions{},
			fmt.Errorf("managed database evidence manifest identity does not match")
	}
	providerEvidence, providerVerify, err :=
		providerrevocationqualification.LoadEvidenceManifest(
			manifest.ProviderRevocationEvidenceManifestPath, requireLive)
	if err != nil {
		return DatabaseEvidenceOptions{}, DatabaseReceiptVerifyOptions{},
			fmt.Errorf("provider revocation evidence manifest rejected")
	}
	providerVerify.TrustedPublicKey = manifest.ProviderRevocationPublicKeyPath
	providerVerify.ExpectedSigningKeyID = manifest.ExpectedProviderRevocationKeyID
	providerVerify.ExpectedQualificationID = manifest.QualificationID
	providerVerify.ExpectedEnvironment = manifest.Environment
	providerVerify.ExpectedDeploymentID = manifest.DeploymentID
	providerVerify.ExpectedOCIReleaseID = manifest.OCIReleaseID
	providerVerify.RequireLive = requireLive
	evidence := DatabaseEvidenceOptions{
		FailoverObservationPath: manifest.FailoverObservationPath,
		ReadySignalPath:         manifest.ReadySignalPath,
		RestoreObservationPath:  manifest.RestoreObservationPath,
		DatabaseAttestationPath: manifest.DatabaseAttestationPath,
		DatabaseAttestationVerifyOptions: DatabaseAttestationVerifyOptions{
			TrustedPublicKey:            manifest.DatabaseAttestationPublicKeyPath,
			ExpectedSigningKeyID:        manifest.ExpectedDatabaseAttestationKeyID,
			ExpectedProvider:            manifest.ExpectedDatabaseAttestationProvider,
			ExpectedProviderAuditSHA256: manifest.ExpectedProviderAuditEvidenceSHA256,
			EvaluationTime:              evaluationTime, RequireLive: requireLive},
		ProviderRevocationReceiptPath:     manifest.ProviderRevocationReceiptPath,
		ProviderRevocationVerifyOptions:   providerVerify,
		ProviderRevocationEvidenceOptions: providerEvidence,
		EvaluationTime:                    evaluationTime, RequireLive: requireLive}
	verify := DatabaseReceiptVerifyOptions{
		ExpectedQualificationID:           manifest.QualificationID,
		ExpectedEnvironment:               manifest.Environment,
		ExpectedDeploymentID:              manifest.DeploymentID,
		ExpectedOCIReleaseID:              manifest.OCIReleaseID,
		ExpectedRunBindingSHA256:          manifest.ExpectedRunBindingSHA256,
		ExpectedFailoverObservationSHA256: digestBytes(failoverPayload),
		ExpectedRestoreObservationSHA256:  digestBytes(restorePayload),
		ExpectedProviderRevocationSHA256:  providerSHA,
		ExpectedDatabaseAttestationSHA256: attestationSHA,
		ExpectedEvaluationTime:            manifest.EvaluationTime, RequireLive: requireLive}
	return evidence, verify, nil
}

func databaseManifestTime(value string) (time.Time, error) {
	parsed, err := parseCanonicalTime(value)
	if err != nil || parsed.Nanosecond() != 0 {
		return time.Time{}, fmt.Errorf("managed database manifest time is invalid")
	}
	return parsed, nil
}
