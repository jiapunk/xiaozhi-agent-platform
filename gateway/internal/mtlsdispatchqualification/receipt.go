package mtlsdispatchqualification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"time"

	"xiaozhi-agent-platform/gateway/internal/appdeliveryqualification"
	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/strictjson"
)

const (
	ReceiptSchema = 1
	LiveResult    = "LIVE_MTLS_DISPATCH_PASS"
	FixtureResult = "FIXTURE_MTLS_DISPATCH_PASS"
)

var (
	receiptSignatureDomain = []byte(
		"XIAOZHI-MTLS-DISPATCH-QUALIFICATION-V1\x00")
	liveUnresolvedProductionGates = []string{
		"managed_database_failover",
		"provider_credential_revocation",
	}
	fixtureUnresolvedProductionGates = []string{
		"end_to_end_mtls_dispatch",
		"managed_database_failover",
		"provider_credential_revocation",
		"signed_app_delivery_receipt",
	}
)

type Receipt struct {
	Schema                              uint32   `json:"schema"`
	QualificationID                     string   `json:"qualification_id"`
	Result                              string   `json:"result"`
	Environment                         string   `json:"environment"`
	DevelopmentOnly                     bool     `json:"development_only"`
	DeploymentID                        string   `json:"deployment_id"`
	OCIReleaseID                        string   `json:"oci_release_id"`
	Services                            []string `json:"services"`
	EndpointAuthoritySHA256             string   `json:"endpoint_authority_sha256"`
	ConfigSHA256                        string   `json:"config_sha256"`
	QualificationToolSHA256             string   `json:"qualification_tool_sha256"`
	KubernetesDeploymentReceiptSHA256   string   `json:"kubernetes_deployment_receipt_sha256"`
	KubernetesAdmissionReceiptSHA256    string   `json:"kubernetes_admission_receipt_sha256"`
	WorkloadEvidenceSHA256              string   `json:"workload_evidence_sha256"`
	ControlplanePodBindingSHA256        string   `json:"controlplane_pod_binding_sha256"`
	CurrentClientCertificateSHA256      string   `json:"current_client_certificate_sha256"`
	NextClientCertificateSHA256         string   `json:"next_client_certificate_sha256"`
	RevokedClientCertificateSHA256      string   `json:"revoked_client_certificate_sha256"`
	ServerLeafCertificateSHA256         string   `json:"server_leaf_certificate_sha256"`
	TLSVersion                          string   `json:"tls_version"`
	NegotiatedProtocol                  string   `json:"negotiated_protocol"`
	WakeContract                        string   `json:"wake_contract"`
	CurrentCredentialAccepted           bool     `json:"current_credential_accepted"`
	NextCredentialAccepted              bool     `json:"next_credential_accepted"`
	AnonymousClientRejected             bool     `json:"anonymous_client_rejected"`
	RevokedClientRejected               bool     `json:"revoked_client_rejected"`
	WrongServerNameRejected             bool     `json:"wrong_server_name_rejected"`
	CurrentLatencyMS                    int64    `json:"current_latency_ms"`
	NextLatencyMS                       int64    `json:"next_latency_ms"`
	StartedAt                           string   `json:"started_at"`
	FinishedAt                          string   `json:"finished_at"`
	ObservationSHA256                   string   `json:"observation_sha256"`
	AppDeliveryResult                   string   `json:"app_delivery_result"`
	AppDeliveryReceiptSHA256            string   `json:"app_delivery_receipt_sha256"`
	DeploymentAttestationResult         string   `json:"deployment_attestation_result"`
	DeploymentAttestationReceiptSHA256  string   `json:"deployment_attestation_receipt_sha256"`
	AttestationProvider                 string   `json:"attestation_provider"`
	ExactSevenServiceDeploymentVerified bool     `json:"exact_seven_service_deployment_verified"`
	LiveAPIServerAdmissionVerified      bool     `json:"live_api_server_admission_verified"`
	MountedWorkloadIdentityVerified     bool     `json:"mounted_workload_identity_verified"`
	NetworkPolicyPathVerified           bool     `json:"network_policy_path_verified"`
	EvaluatedAt                         string   `json:"evaluated_at"`
	SecretFree                          bool     `json:"secret_free"`
	ProductionReady                     bool     `json:"production_ready"`
	UnresolvedProductionGates           []string `json:"unresolved_production_gates"`
	SigningKeyID                        string   `json:"signing_key_id"`
	SignatureAlgorithm                  string   `json:"signature_algorithm"`
	SignatureB64URL                     string   `json:"signature_b64url"`
}

type EvidenceOptions struct {
	ObservationPath                    string
	AppDeliveryReceiptPath             string
	AppDeliveryVerifyOptions           appdeliveryqualification.ReceiptVerifyOptions
	AppDeliveryEvidenceOptions         appdeliveryqualification.EvidenceOptions
	DeploymentAttestationReceiptPath   string
	DeploymentAttestationVerifyOptions AttestationVerifyOptions
	EvaluationTime                     time.Time
	RequireLive                        bool
}

type ReceiptVerifyOptions struct {
	TrustedPublicKey                    string
	ExpectedSigningKeyID                string
	ExpectedQualificationID             string
	ExpectedEnvironment                 string
	ExpectedDeploymentID                string
	ExpectedOCIReleaseID                string
	ExpectedObservationSHA256           string
	ExpectedAppDeliveryReceiptSHA256    string
	ExpectedDeploymentAttestationSHA256 string
	ExpectedEvaluationTime              string
	RequireLive                         bool
}

func BuildReceipt(options EvidenceOptions) (Receipt, error) {
	if options.EvaluationTime.IsZero() || options.EvaluationTime.Nanosecond() != 0 {
		return Receipt{}, fmt.Errorf("mTLS dispatch evaluation time is invalid")
	}
	observation, observationPayload, err := LoadObservation(options.ObservationPath)
	if err != nil {
		return Receipt{}, err
	}
	appPayload, err := readRegular(options.AppDeliveryReceiptPath,
		maximumDocumentBytes, false)
	if err != nil {
		return Receipt{}, fmt.Errorf("App delivery qualification receipt rejected")
	}
	appVerify := options.AppDeliveryVerifyOptions
	appVerify.RequireLive = options.RequireLive
	appReceipt, err := appdeliveryqualification.VerifyReceiptFile(
		options.AppDeliveryReceiptPath, appVerify)
	if err != nil {
		return Receipt{}, fmt.Errorf("App delivery qualification receipt rejected")
	}
	appEvidence := options.AppDeliveryEvidenceOptions
	appEvidence.RequireLive = options.RequireLive
	expectedAppReceipt, err := appdeliveryqualification.BuildReceipt(appEvidence)
	if err != nil || !appdeliveryqualification.ReceiptMatchesEvidence(
		appReceipt, expectedAppReceipt) {
		return Receipt{}, fmt.Errorf("App delivery qualification evidence bundle rejected")
	}
	attestationOptions := options.DeploymentAttestationVerifyOptions
	attestationOptions.EvaluationTime = options.EvaluationTime.UTC()
	attestationOptions.RequireLive = options.RequireLive
	attestation, attestationPayload, err := VerifyAttestationFile(
		options.DeploymentAttestationReceiptPath, attestationOptions)
	if err != nil {
		return Receipt{}, err
	}
	observationSHA := digest(observationPayload)
	started, startErr := time.Parse(time.RFC3339, observation.StartedAt)
	finished, finishErr := time.Parse(time.RFC3339, observation.FinishedAt)
	appEvaluated, appTimeErr := time.Parse(time.RFC3339, appReceipt.EvaluatedAt)
	appWake := time.UnixMilli(int64(appReceipt.WakeReceivedAtUnixMS)).UTC()
	if observation.QualificationID != appReceipt.QualificationID ||
		observation.QualificationID != attestation.QualificationID ||
		observation.Environment != appReceipt.Environment ||
		observation.Environment != attestation.Environment ||
		observation.DevelopmentOnly != appReceipt.DevelopmentOnly ||
		observation.DevelopmentOnly != attestation.DevelopmentOnly ||
		observation.DeploymentID != attestation.DeploymentID ||
		observation.OCIReleaseID != attestation.OCIReleaseID ||
		!reflect.DeepEqual(observation.Services, attestation.Services) ||
		observationSHA != attestation.ObservationSHA256 ||
		observation.KubernetesDeploymentReceiptSHA256 !=
			attestation.KubernetesDeploymentReceiptSHA256 ||
		observation.KubernetesAdmissionReceiptSHA256 !=
			attestation.KubernetesAdmissionReceiptSHA256 ||
		observation.ControlplanePodBindingSHA256 !=
			attestation.ControlplanePodBindingSHA256 ||
		observation.CurrentClientCertificateSHA256 !=
			attestation.CurrentClientCertificateSHA256 ||
		observation.NextClientCertificateSHA256 !=
			attestation.NextClientCertificateSHA256 ||
		observation.RevokedClientCertificateSHA256 !=
			attestation.RevokedClientCertificateSHA256 ||
		observation.ServerLeafCertificateSHA256 !=
			attestation.ServerLeafCertificateSHA256 ||
		startErr != nil || finishErr != nil || appTimeErr != nil ||
		appWake.Before(started.Add(-maximumClockSkew)) ||
		appWake.After(finished.Add(maximumEvidenceDelay)) ||
		options.EvaluationTime.Before(appEvaluated) ||
		options.EvaluationTime.After(appEvaluated.Add(maximumEvidenceDelay)) {
		return Receipt{}, fmt.Errorf("mTLS dispatch evidence subjects do not match")
	}
	if options.RequireLive && (observation.DevelopmentOnly ||
		appReceipt.DevelopmentOnly || attestation.DevelopmentOnly) {
		return Receipt{}, fmt.Errorf("live mTLS dispatch evidence is required")
	}
	result := LiveResult
	unresolved := liveUnresolvedProductionGates
	if observation.DevelopmentOnly {
		result = FixtureResult
		unresolved = fixtureUnresolvedProductionGates
	}
	receipt := Receipt{Schema: ReceiptSchema,
		QualificationID: observation.QualificationID, Result: result,
		Environment:                       observation.Environment,
		DevelopmentOnly:                   observation.DevelopmentOnly,
		DeploymentID:                      observation.DeploymentID,
		OCIReleaseID:                      observation.OCIReleaseID,
		Services:                          append([]string(nil), observation.Services...),
		EndpointAuthoritySHA256:           observation.EndpointAuthoritySHA256,
		ConfigSHA256:                      observation.ConfigSHA256,
		QualificationToolSHA256:           observation.QualificationToolSHA256,
		KubernetesDeploymentReceiptSHA256: observation.KubernetesDeploymentReceiptSHA256,
		KubernetesAdmissionReceiptSHA256:  observation.KubernetesAdmissionReceiptSHA256,
		WorkloadEvidenceSHA256:            attestation.WorkloadEvidenceSHA256,
		ControlplanePodBindingSHA256:      observation.ControlplanePodBindingSHA256,
		CurrentClientCertificateSHA256:    observation.CurrentClientCertificateSHA256,
		NextClientCertificateSHA256:       observation.NextClientCertificateSHA256,
		RevokedClientCertificateSHA256:    observation.RevokedClientCertificateSHA256,
		ServerLeafCertificateSHA256:       observation.ServerLeafCertificateSHA256,
		TLSVersion:                        observation.TLSVersion,
		NegotiatedProtocol:                observation.NegotiatedProtocol,
		WakeContract:                      observation.WakeContract,
		CurrentCredentialAccepted:         observation.CurrentCredentialAccepted,
		NextCredentialAccepted:            observation.NextCredentialAccepted,
		AnonymousClientRejected:           observation.AnonymousClientRejected,
		RevokedClientRejected:             observation.RevokedClientRejected,
		WrongServerNameRejected:           observation.WrongServerNameRejected,
		CurrentLatencyMS:                  observation.CurrentLatencyMS,
		NextLatencyMS:                     observation.NextLatencyMS,
		StartedAt:                         observation.StartedAt, FinishedAt: observation.FinishedAt,
		ObservationSHA256:                   observationSHA,
		AppDeliveryResult:                   appReceipt.Result,
		AppDeliveryReceiptSHA256:            digest(appPayload),
		DeploymentAttestationResult:         attestation.Result,
		DeploymentAttestationReceiptSHA256:  digest(attestationPayload),
		AttestationProvider:                 attestation.AttestationProvider,
		ExactSevenServiceDeploymentVerified: attestation.ExactSevenServiceDeploymentVerified,
		LiveAPIServerAdmissionVerified:      attestation.LiveAPIServerAdmissionVerified,
		MountedWorkloadIdentityVerified:     attestation.MountedWorkloadIdentityVerified,
		NetworkPolicyPathVerified:           attestation.NetworkPolicyPathVerified,
		EvaluatedAt:                         options.EvaluationTime.UTC().Format(time.RFC3339),
		SecretFree:                          true, ProductionReady: false,
		UnresolvedProductionGates: append([]string(nil), unresolved...)}
	if err := validateReceipt(receipt, ReceiptVerifyOptions{}); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func SignReceipt(receipt Receipt, privateKeyPath,
	signingKeyID string) ([]byte, error) {
	receipt.SigningKeyID = signingKeyID
	receipt.SignatureAlgorithm = "Ed25519"
	receipt.SignatureB64URL = ""
	if err := validateReceipt(receipt, ReceiptVerifyOptions{
		ExpectedSigningKeyID: signingKeyID}); err != nil {
		return nil, err
	}
	payload, err := receiptSignaturePayload(receipt)
	if err != nil {
		return nil, err
	}
	receipt.SignatureB64URL, err = signDomainPayload(
		receiptSignatureDomain, payload, privateKeyPath)
	if err != nil {
		return nil, err
	}
	return canonicalReceipt(receipt)
}

func VerifyReceiptFile(path string, options ReceiptVerifyOptions) (
	Receipt, error) {
	payload, err := readRegular(path, maximumDocumentBytes, false)
	if err != nil {
		return Receipt{}, fmt.Errorf("mTLS dispatch qualification receipt: %w", err)
	}
	return VerifyReceipt(payload, options)
}

func VerifyReceipt(payload []byte, options ReceiptVerifyOptions) (
	Receipt, error) {
	if err := strictjson.RejectDuplicateFields(payload); err != nil {
		return Receipt{}, fmt.Errorf("mTLS dispatch qualification receipt is ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var receipt Receipt
	if err := decoder.Decode(&receipt); err != nil {
		return Receipt{}, fmt.Errorf("mTLS dispatch qualification receipt JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Receipt{}, fmt.Errorf("mTLS dispatch qualification receipt has trailing JSON")
	}
	canonical, err := canonicalReceipt(receipt)
	if err != nil || !bytes.Equal(canonical, payload) {
		return Receipt{}, fmt.Errorf("mTLS dispatch qualification receipt is not canonical JSON")
	}
	if err := validateReceipt(receipt, options); err != nil {
		return Receipt{}, err
	}
	signaturePayload, err := receiptSignaturePayload(receipt)
	if err != nil || verifyDomainPayload(receiptSignatureDomain,
		signaturePayload, receipt.SignatureB64URL,
		options.TrustedPublicKey) != nil {
		return Receipt{}, fmt.Errorf("mTLS dispatch qualification receipt signature is invalid")
	}
	return receipt, nil
}

func validateReceipt(receipt Receipt, options ReceiptVerifyOptions) error {
	unsigned := receipt.SigningKeyID == "" && receipt.SignatureAlgorithm == "" &&
		receipt.SignatureB64URL == ""
	expectedUnresolved := liveUnresolvedProductionGates
	if receipt.DevelopmentOnly {
		expectedUnresolved = fixtureUnresolvedProductionGates
	}
	observation := Observation{Schema: ObservationSchema,
		QualificationID: receipt.QualificationID,
		Environment:     receipt.Environment, DevelopmentOnly: receipt.DevelopmentOnly,
		DeploymentID: receipt.DeploymentID, OCIReleaseID: receipt.OCIReleaseID,
		Services:                          receipt.Services,
		EndpointAuthoritySHA256:           receipt.EndpointAuthoritySHA256,
		ConfigSHA256:                      receipt.ConfigSHA256,
		QualificationToolSHA256:           receipt.QualificationToolSHA256,
		KubernetesDeploymentReceiptSHA256: receipt.KubernetesDeploymentReceiptSHA256,
		KubernetesAdmissionReceiptSHA256:  receipt.KubernetesAdmissionReceiptSHA256,
		ControlplanePodBindingSHA256:      receipt.ControlplanePodBindingSHA256,
		CurrentClientCertificateSHA256:    receipt.CurrentClientCertificateSHA256,
		NextClientCertificateSHA256:       receipt.NextClientCertificateSHA256,
		RevokedClientCertificateSHA256:    receipt.RevokedClientCertificateSHA256,
		ServerLeafCertificateSHA256:       receipt.ServerLeafCertificateSHA256,
		TLSVersion:                        receipt.TLSVersion, NegotiatedProtocol: receipt.NegotiatedProtocol,
		WakeContract:              receipt.WakeContract,
		CurrentCredentialAccepted: receipt.CurrentCredentialAccepted,
		NextCredentialAccepted:    receipt.NextCredentialAccepted,
		AnonymousClientRejected:   receipt.AnonymousClientRejected,
		RevokedClientRejected:     receipt.RevokedClientRejected,
		WrongServerNameRejected:   receipt.WrongServerNameRejected,
		CurrentLatencyMS:          receipt.CurrentLatencyMS,
		NextLatencyMS:             receipt.NextLatencyMS,
		StartedAt:                 receipt.StartedAt, FinishedAt: receipt.FinishedAt,
		SecretFree: receipt.SecretFree}
	if receipt.Schema != ReceiptSchema || validateObservation(observation) != nil ||
		!validSHA256(receipt.WorkloadEvidenceSHA256) ||
		!validSHA256(receipt.ObservationSHA256) ||
		!validSHA256(receipt.AppDeliveryReceiptSHA256) ||
		!validSHA256(receipt.DeploymentAttestationReceiptSHA256) ||
		!receipt.SecretFree || receipt.ProductionReady ||
		!reflect.DeepEqual(receipt.UnresolvedProductionGates, expectedUnresolved) ||
		(!unsigned && (!auth.ValidIdentifier(receipt.SigningKeyID, 64) ||
			receipt.SignatureAlgorithm != "Ed25519")) {
		return fmt.Errorf("mTLS dispatch qualification receipt fields are invalid")
	}
	if receipt.DevelopmentOnly {
		if receipt.Environment != "staging" || receipt.Result != FixtureResult ||
			receipt.AppDeliveryResult != appdeliveryqualification.FixtureResult ||
			receipt.DeploymentAttestationResult != FixtureAttestationResult ||
			receipt.AttestationProvider != FixtureAttestationProvider ||
			receipt.ExactSevenServiceDeploymentVerified ||
			receipt.LiveAPIServerAdmissionVerified ||
			receipt.MountedWorkloadIdentityVerified ||
			receipt.NetworkPolicyPathVerified {
			return fmt.Errorf("fixture mTLS dispatch receipt overstates live evidence")
		}
	} else if receipt.Result != LiveResult ||
		receipt.AppDeliveryResult != appdeliveryqualification.LiveResult ||
		receipt.DeploymentAttestationResult != LiveAttestationResult ||
		receipt.AttestationProvider != LiveAttestationProvider ||
		!receipt.ExactSevenServiceDeploymentVerified ||
		!receipt.LiveAPIServerAdmissionVerified ||
		!receipt.MountedWorkloadIdentityVerified ||
		!receipt.NetworkPolicyPathVerified {
		return fmt.Errorf("live mTLS dispatch receipt fields are invalid")
	}
	if options.RequireLive && receipt.DevelopmentOnly {
		return fmt.Errorf("live mTLS dispatch qualification receipt is required")
	}
	evaluated, err := time.Parse(time.RFC3339, receipt.EvaluatedAt)
	if err != nil || evaluated.Format(time.RFC3339) != receipt.EvaluatedAt {
		return fmt.Errorf("mTLS dispatch qualification evaluation time is invalid")
	}
	checks := []struct{ actual, expected string }{
		{receipt.SigningKeyID, options.ExpectedSigningKeyID},
		{receipt.QualificationID, options.ExpectedQualificationID},
		{receipt.Environment, options.ExpectedEnvironment},
		{receipt.DeploymentID, options.ExpectedDeploymentID},
		{receipt.OCIReleaseID, options.ExpectedOCIReleaseID},
		{receipt.ObservationSHA256, options.ExpectedObservationSHA256},
		{receipt.AppDeliveryReceiptSHA256,
			options.ExpectedAppDeliveryReceiptSHA256},
		{receipt.DeploymentAttestationReceiptSHA256,
			options.ExpectedDeploymentAttestationSHA256},
		{receipt.EvaluatedAt, options.ExpectedEvaluationTime},
	}
	for _, check := range checks {
		if check.expected != "" && check.actual != check.expected {
			return fmt.Errorf("mTLS dispatch qualification identity does not match")
		}
	}
	return nil
}

func ReceiptMatchesEvidence(receipt, expected Receipt) bool {
	receipt.SigningKeyID = ""
	receipt.SignatureAlgorithm = ""
	receipt.SignatureB64URL = ""
	expected.SigningKeyID = ""
	expected.SignatureAlgorithm = ""
	expected.SignatureB64URL = ""
	return reflect.DeepEqual(receipt, expected)
}

func receiptSignaturePayload(receipt Receipt) ([]byte, error) {
	receipt.SignatureB64URL = ""
	return json.Marshal(receipt)
}

func canonicalReceipt(receipt Receipt) ([]byte, error) {
	payload, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}
