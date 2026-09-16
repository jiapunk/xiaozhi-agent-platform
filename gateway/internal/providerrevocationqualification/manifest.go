package providerrevocationqualification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"xiaozhi-agent-platform/gateway/internal/appdeliveryqualification"
	"xiaozhi-agent-platform/gateway/internal/mtlsdispatchqualification"
	"xiaozhi-agent-platform/gateway/internal/pushqualification"
	"xiaozhi-agent-platform/gateway/internal/strictjson"
)

type evidenceManifest struct {
	Schema                                    uint32 `json:"schema"`
	QualificationID                           string `json:"qualification_id"`
	Environment                               string `json:"environment"`
	DeploymentID                              string `json:"deployment_id"`
	OCIReleaseID                              string `json:"oci_release_id"`
	EvaluationTime                            string `json:"evaluation_time"`
	MTLSDispatchEvaluationTime                string `json:"mtls_dispatch_evaluation_time"`
	AppDeliveryEvaluationTime                 string `json:"app_delivery_evaluation_time"`
	ObservationPath                           string `json:"observation_path"`
	RevocationAttestationPath                 string `json:"revocation_attestation_path"`
	RevocationAttestationPublicKeyPath        string `json:"revocation_attestation_public_key_path"`
	ExpectedRevocationAttestationKeyID        string `json:"expected_revocation_attestation_key_id"`
	ExpectedRevocationAttestationProvider     string `json:"expected_revocation_attestation_provider"`
	ExpectedProviderAuditEvidenceSHA256       string `json:"expected_provider_audit_evidence_sha256"`
	MTLSDispatchReceiptPath                   string `json:"mtls_dispatch_receipt_path"`
	MTLSDispatchPublicKeyPath                 string `json:"mtls_dispatch_public_key_path"`
	ExpectedMTLSDispatchKeyID                 string `json:"expected_mtls_dispatch_key_id"`
	MTLSDispatchObservationPath               string `json:"mtls_dispatch_observation_path"`
	AppDeliveryReceiptPath                    string `json:"app_delivery_receipt_path"`
	AppDeliveryPublicKeyPath                  string `json:"app_delivery_public_key_path"`
	ExpectedAppDeliveryKeyID                  string `json:"expected_app_delivery_key_id"`
	AppObservationPath                        string `json:"app_observation_path"`
	ProviderQualificationReceiptPath          string `json:"provider_qualification_receipt_path"`
	ProviderQualificationPublicKeyPath        string `json:"provider_qualification_public_key_path"`
	ExpectedProviderQualificationKeyID        string `json:"expected_provider_qualification_key_id"`
	ExpectedProviderQualificationConfigSHA256 string `json:"expected_provider_qualification_config_sha256"`
	ExpectedProviderQualificationToolSHA256   string `json:"expected_provider_qualification_tool_sha256"`
	AppAttestationReceiptPath                 string `json:"app_attestation_receipt_path"`
	AppAttestationPublicKeyPath               string `json:"app_attestation_public_key_path"`
	ExpectedAppAttestationKeyID               string `json:"expected_app_attestation_key_id"`
	ExpectedAppAttestationProvider            string `json:"expected_app_attestation_provider"`
	ExpectedVendorEvidenceSHA256              string `json:"expected_vendor_evidence_sha256"`
	ExpectedAppBinarySHA256                   string `json:"expected_app_binary_sha256"`
	DeploymentAttestationReceiptPath          string `json:"deployment_attestation_receipt_path"`
	DeploymentAttestationPublicKeyPath        string `json:"deployment_attestation_public_key_path"`
	ExpectedDeploymentAttestationKeyID        string `json:"expected_deployment_attestation_key_id"`
	ExpectedDeploymentAttestationProvider     string `json:"expected_deployment_attestation_provider"`
	ExpectedWorkloadEvidenceSHA256            string `json:"expected_workload_evidence_sha256"`
}

func LoadEvidenceManifest(path string, requireLive bool) (
	EvidenceOptions, ReceiptVerifyOptions, error) {
	payload, err := readRegular(path, maximumDocumentBytes, false)
	if err != nil {
		return EvidenceOptions{}, ReceiptVerifyOptions{},
			fmt.Errorf("provider revocation evidence manifest: %w", err)
	}
	if err := strictjson.RejectDuplicateFields(payload); err != nil {
		return EvidenceOptions{}, ReceiptVerifyOptions{},
			fmt.Errorf("provider revocation evidence manifest is ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var manifest evidenceManifest
	if err := decoder.Decode(&manifest); err != nil {
		return EvidenceOptions{}, ReceiptVerifyOptions{},
			fmt.Errorf("provider revocation evidence manifest JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF || manifest.Schema != 1 {
		return EvidenceOptions{}, ReceiptVerifyOptions{},
			fmt.Errorf("provider revocation evidence manifest fields are invalid")
	}
	paths := []string{manifest.ObservationPath,
		manifest.RevocationAttestationPath,
		manifest.RevocationAttestationPublicKeyPath,
		manifest.MTLSDispatchReceiptPath, manifest.MTLSDispatchPublicKeyPath,
		manifest.MTLSDispatchObservationPath, manifest.AppDeliveryReceiptPath,
		manifest.AppDeliveryPublicKeyPath, manifest.AppObservationPath,
		manifest.ProviderQualificationReceiptPath,
		manifest.ProviderQualificationPublicKeyPath,
		manifest.AppAttestationReceiptPath,
		manifest.AppAttestationPublicKeyPath,
		manifest.DeploymentAttestationReceiptPath,
		manifest.DeploymentAttestationPublicKeyPath}
	for _, candidate := range paths {
		if !filepath.IsAbs(candidate) {
			return EvidenceOptions{}, ReceiptVerifyOptions{},
				fmt.Errorf("provider revocation evidence paths must be absolute")
		}
	}
	evaluationTime, err := manifestTime(manifest.EvaluationTime)
	if err != nil {
		return EvidenceOptions{}, ReceiptVerifyOptions{}, err
	}
	mtlsEvaluationTime, err := manifestTime(manifest.MTLSDispatchEvaluationTime)
	if err != nil {
		return EvidenceOptions{}, ReceiptVerifyOptions{}, err
	}
	appEvaluationTime, err := manifestTime(manifest.AppDeliveryEvaluationTime)
	if err != nil {
		return EvidenceOptions{}, ReceiptVerifyOptions{}, err
	}
	digests := make(map[string]string, 7)
	for label, filePath := range map[string]string{
		"observation":            manifest.ObservationPath,
		"revocation-attestation": manifest.RevocationAttestationPath,
		"mtls-receipt":           manifest.MTLSDispatchReceiptPath,
		"mtls-observation":       manifest.MTLSDispatchObservationPath,
		"app-receipt":            manifest.AppDeliveryReceiptPath,
		"app-observation":        manifest.AppObservationPath,
		"provider-receipt":       manifest.ProviderQualificationReceiptPath,
		"app-attestation":        manifest.AppAttestationReceiptPath,
		"deployment-attestation": manifest.DeploymentAttestationReceiptPath,
	} {
		digests[label], err = DigestRegularFile(filePath, maximumDocumentBytes)
		if err != nil {
			return EvidenceOptions{}, ReceiptVerifyOptions{},
				fmt.Errorf("provider revocation evidence file rejected")
		}
	}
	providerVerify := pushqualification.VerifyOptions{
		TrustedPublicKey:        manifest.ProviderQualificationPublicKeyPath,
		ExpectedSigningKeyID:    manifest.ExpectedProviderQualificationKeyID,
		ExpectedQualificationID: manifest.QualificationID,
		ExpectedEnvironment:     manifest.Environment,
		ExpectedConfigSHA256:    manifest.ExpectedProviderQualificationConfigSHA256,
		ExpectedToolSHA256:      manifest.ExpectedProviderQualificationToolSHA256,
		RequireLive:             requireLive}
	appEvidence := appdeliveryqualification.EvidenceOptions{
		ObservationPath:        manifest.AppObservationPath,
		ProviderReceiptPath:    manifest.ProviderQualificationReceiptPath,
		ProviderVerifyOptions:  providerVerify,
		AttestationReceiptPath: manifest.AppAttestationReceiptPath,
		AttestationVerifyOptions: appdeliveryqualification.AttestationVerifyOptions{
			TrustedPublicKey:     manifest.AppAttestationPublicKeyPath,
			ExpectedSigningKeyID: manifest.ExpectedAppAttestationKeyID,
			ExpectedProvider:     manifest.ExpectedAppAttestationProvider,
			ExpectedVendorSHA256: manifest.ExpectedVendorEvidenceSHA256,
			EvaluationTime:       appEvaluationTime, RequireLive: requireLive},
		EvaluationTime: appEvaluationTime, RequireLive: requireLive}
	appVerify := appdeliveryqualification.ReceiptVerifyOptions{
		TrustedPublicKey:                 manifest.AppDeliveryPublicKeyPath,
		ExpectedSigningKeyID:             manifest.ExpectedAppDeliveryKeyID,
		ExpectedQualificationID:          manifest.QualificationID,
		ExpectedEnvironment:              manifest.Environment,
		ExpectedAppBinarySHA256:          manifest.ExpectedAppBinarySHA256,
		ExpectedProviderReceiptSHA256:    digests["provider-receipt"],
		ExpectedObservationSHA256:        digests["app-observation"],
		ExpectedAttestationReceiptSHA256: digests["app-attestation"],
		ExpectedEvaluationTime:           manifest.AppDeliveryEvaluationTime,
		RequireLive:                      requireLive}
	mtlsEvidence := mtlsdispatchqualification.EvidenceOptions{
		ObservationPath:                  manifest.MTLSDispatchObservationPath,
		AppDeliveryReceiptPath:           manifest.AppDeliveryReceiptPath,
		AppDeliveryVerifyOptions:         appVerify,
		AppDeliveryEvidenceOptions:       appEvidence,
		DeploymentAttestationReceiptPath: manifest.DeploymentAttestationReceiptPath,
		DeploymentAttestationVerifyOptions: mtlsdispatchqualification.AttestationVerifyOptions{
			TrustedPublicKey:               manifest.DeploymentAttestationPublicKeyPath,
			ExpectedSigningKeyID:           manifest.ExpectedDeploymentAttestationKeyID,
			ExpectedProvider:               manifest.ExpectedDeploymentAttestationProvider,
			ExpectedWorkloadEvidenceSHA256: manifest.ExpectedWorkloadEvidenceSHA256,
			EvaluationTime:                 mtlsEvaluationTime, RequireLive: requireLive},
		EvaluationTime: mtlsEvaluationTime, RequireLive: requireLive}
	mtlsVerify := mtlsdispatchqualification.ReceiptVerifyOptions{
		TrustedPublicKey:                    manifest.MTLSDispatchPublicKeyPath,
		ExpectedSigningKeyID:                manifest.ExpectedMTLSDispatchKeyID,
		ExpectedQualificationID:             manifest.QualificationID,
		ExpectedEnvironment:                 manifest.Environment,
		ExpectedDeploymentID:                manifest.DeploymentID,
		ExpectedOCIReleaseID:                manifest.OCIReleaseID,
		ExpectedObservationSHA256:           digests["mtls-observation"],
		ExpectedAppDeliveryReceiptSHA256:    digests["app-receipt"],
		ExpectedDeploymentAttestationSHA256: digests["deployment-attestation"],
		ExpectedEvaluationTime:              manifest.MTLSDispatchEvaluationTime,
		RequireLive:                         requireLive}
	evidence := EvidenceOptions{ObservationPath: manifest.ObservationPath,
		MTLSDispatchReceiptPath:          manifest.MTLSDispatchReceiptPath,
		MTLSDispatchVerifyOptions:        mtlsVerify,
		MTLSDispatchEvidenceOptions:      mtlsEvidence,
		RevocationAttestationReceiptPath: manifest.RevocationAttestationPath,
		RevocationAttestationVerifyOptions: AttestationVerifyOptions{
			TrustedPublicKey:            manifest.RevocationAttestationPublicKeyPath,
			ExpectedSigningKeyID:        manifest.ExpectedRevocationAttestationKeyID,
			ExpectedProvider:            manifest.ExpectedRevocationAttestationProvider,
			ExpectedProviderAuditSHA256: manifest.ExpectedProviderAuditEvidenceSHA256,
			EvaluationTime:              evaluationTime, RequireLive: requireLive},
		EvaluationTime: evaluationTime, RequireLive: requireLive}
	verify := ReceiptVerifyOptions{ExpectedQualificationID: manifest.QualificationID,
		ExpectedEnvironment:                 manifest.Environment,
		ExpectedDeploymentID:                manifest.DeploymentID,
		ExpectedOCIReleaseID:                manifest.OCIReleaseID,
		ExpectedObservationSHA256:           digests["observation"],
		ExpectedMTLSDispatchSHA256:          digests["mtls-receipt"],
		ExpectedRevocationAttestationSHA256: digests["revocation-attestation"],
		ExpectedEvaluationTime:              manifest.EvaluationTime, RequireLive: requireLive}
	return evidence, verify, nil
}

func manifestTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Format(time.RFC3339) != value || parsed.Nanosecond() != 0 {
		return time.Time{}, fmt.Errorf("provider revocation manifest time is invalid")
	}
	return parsed, nil
}
