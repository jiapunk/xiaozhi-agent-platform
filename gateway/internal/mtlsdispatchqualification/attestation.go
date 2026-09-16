package mtlsdispatchqualification

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
	AttestationSchema          = 1
	LiveAttestationResult      = "LIVE_SEVEN_SERVICE_DEPLOYMENT_PASS"
	FixtureAttestationResult   = "FIXTURE_DEPLOYMENT_ATTESTATION_PASS"
	LiveAttestationProvider    = "kubernetes-cluster-authority"
	FixtureAttestationProvider = "fixture"
	maximumAttestationLifetime = 24 * time.Hour
	maximumEvidenceDelay       = 10 * time.Minute
	maximumClockSkew           = 30 * time.Second
)

var attestationSignatureDomain = []byte(
	"XIAOZHI-MTLS-DISPATCH-DEPLOYMENT-ATTESTATION-V1\x00")

type Attestation struct {
	Schema                              uint32   `json:"schema"`
	QualificationID                     string   `json:"qualification_id"`
	Result                              string   `json:"result"`
	Environment                         string   `json:"environment"`
	DevelopmentOnly                     bool     `json:"development_only"`
	AttestationProvider                 string   `json:"attestation_provider"`
	DeploymentID                        string   `json:"deployment_id"`
	OCIReleaseID                        string   `json:"oci_release_id"`
	Services                            []string `json:"services"`
	ObservationSHA256                   string   `json:"observation_sha256"`
	KubernetesDeploymentReceiptSHA256   string   `json:"kubernetes_deployment_receipt_sha256"`
	KubernetesAdmissionReceiptSHA256    string   `json:"kubernetes_admission_receipt_sha256"`
	WorkloadEvidenceSHA256              string   `json:"workload_evidence_sha256"`
	ControlplanePodBindingSHA256        string   `json:"controlplane_pod_binding_sha256"`
	CurrentClientCertificateSHA256      string   `json:"current_client_certificate_sha256"`
	NextClientCertificateSHA256         string   `json:"next_client_certificate_sha256"`
	RevokedClientCertificateSHA256      string   `json:"revoked_client_certificate_sha256"`
	ServerLeafCertificateSHA256         string   `json:"server_leaf_certificate_sha256"`
	ExactSevenServiceDeploymentVerified bool     `json:"exact_seven_service_deployment_verified"`
	LiveAPIServerAdmissionVerified      bool     `json:"live_api_server_admission_verified"`
	MountedWorkloadIdentityVerified     bool     `json:"mounted_workload_identity_verified"`
	NetworkPolicyPathVerified           bool     `json:"network_policy_path_verified"`
	VerifiedAt                          string   `json:"verified_at"`
	ExpiresAt                           string   `json:"expires_at"`
	SigningKeyID                        string   `json:"signing_key_id"`
	SignatureAlgorithm                  string   `json:"signature_algorithm"`
	SignatureB64URL                     string   `json:"signature_b64url"`
}

type AttestationInput struct {
	Observation            Observation
	ObservationSHA256      string
	WorkloadEvidenceSHA256 string
	Provider               string
	VerifiedAt             time.Time
	ExpiresAt              time.Time
	DevelopmentOnly        bool
}

type AttestationVerifyOptions struct {
	TrustedPublicKey               string
	ExpectedSigningKeyID           string
	ExpectedProvider               string
	ExpectedWorkloadEvidenceSHA256 string
	EvaluationTime                 time.Time
	RequireLive                    bool
}

func SignAttestation(input AttestationInput, privateKeyPath,
	signingKeyID string) ([]byte, error) {
	if input.DevelopmentOnly != input.Observation.DevelopmentOnly ||
		!validSHA256(input.ObservationSHA256) ||
		!validSHA256(input.WorkloadEvidenceSHA256) ||
		!observationNearTime(input.Observation, input.VerifiedAt) {
		return nil, fmt.Errorf("mTLS dispatch deployment attestation input is invalid")
	}
	result := LiveAttestationResult
	if input.DevelopmentOnly {
		result = FixtureAttestationResult
	}
	attestation := Attestation{Schema: AttestationSchema,
		QualificationID: input.Observation.QualificationID, Result: result,
		Environment:                         input.Observation.Environment,
		DevelopmentOnly:                     input.DevelopmentOnly,
		AttestationProvider:                 input.Provider,
		DeploymentID:                        input.Observation.DeploymentID,
		OCIReleaseID:                        input.Observation.OCIReleaseID,
		Services:                            append([]string(nil), input.Observation.Services...),
		ObservationSHA256:                   input.ObservationSHA256,
		KubernetesDeploymentReceiptSHA256:   input.Observation.KubernetesDeploymentReceiptSHA256,
		KubernetesAdmissionReceiptSHA256:    input.Observation.KubernetesAdmissionReceiptSHA256,
		WorkloadEvidenceSHA256:              input.WorkloadEvidenceSHA256,
		ControlplanePodBindingSHA256:        input.Observation.ControlplanePodBindingSHA256,
		CurrentClientCertificateSHA256:      input.Observation.CurrentClientCertificateSHA256,
		NextClientCertificateSHA256:         input.Observation.NextClientCertificateSHA256,
		RevokedClientCertificateSHA256:      input.Observation.RevokedClientCertificateSHA256,
		ServerLeafCertificateSHA256:         input.Observation.ServerLeafCertificateSHA256,
		ExactSevenServiceDeploymentVerified: !input.DevelopmentOnly,
		LiveAPIServerAdmissionVerified:      !input.DevelopmentOnly,
		MountedWorkloadIdentityVerified:     !input.DevelopmentOnly,
		NetworkPolicyPathVerified:           !input.DevelopmentOnly,
		VerifiedAt:                          input.VerifiedAt.UTC().Format(time.RFC3339),
		ExpiresAt:                           input.ExpiresAt.UTC().Format(time.RFC3339),
		SigningKeyID:                        signingKeyID, SignatureAlgorithm: "Ed25519"}
	if err := validateAttestation(attestation, AttestationVerifyOptions{}); err != nil {
		return nil, err
	}
	payload, err := attestationSignaturePayload(attestation)
	if err != nil {
		return nil, err
	}
	attestation.SignatureB64URL, err = signDomainPayload(
		attestationSignatureDomain, payload, privateKeyPath)
	if err != nil {
		return nil, err
	}
	return canonicalAttestation(attestation)
}

func VerifyAttestationFile(path string, options AttestationVerifyOptions) (
	Attestation, []byte, error) {
	payload, err := readRegular(path, maximumDocumentBytes, false)
	if err != nil {
		return Attestation{}, nil, fmt.Errorf("mTLS dispatch deployment attestation: %w", err)
	}
	attestation, err := VerifyAttestation(payload, options)
	if err != nil {
		return Attestation{}, nil, err
	}
	return attestation, payload, nil
}

func VerifyAttestation(payload []byte, options AttestationVerifyOptions) (
	Attestation, error) {
	if err := strictjson.RejectDuplicateFields(payload); err != nil {
		return Attestation{}, fmt.Errorf("mTLS dispatch deployment attestation is ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var attestation Attestation
	if err := decoder.Decode(&attestation); err != nil {
		return Attestation{}, fmt.Errorf("mTLS dispatch deployment attestation JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Attestation{}, fmt.Errorf("mTLS dispatch deployment attestation has trailing JSON")
	}
	canonical, err := canonicalAttestation(attestation)
	if err != nil || !bytes.Equal(canonical, payload) {
		return Attestation{}, fmt.Errorf("mTLS dispatch deployment attestation is not canonical JSON")
	}
	if err := validateAttestation(attestation, options); err != nil {
		return Attestation{}, err
	}
	signaturePayload, err := attestationSignaturePayload(attestation)
	if err != nil || verifyDomainPayload(attestationSignatureDomain,
		signaturePayload, attestation.SignatureB64URL,
		options.TrustedPublicKey) != nil {
		return Attestation{}, fmt.Errorf("mTLS dispatch deployment attestation signature is invalid")
	}
	return attestation, nil
}

func validateAttestation(attestation Attestation,
	options AttestationVerifyOptions) error {
	if attestation.Schema != AttestationSchema ||
		!auth.ValidIdentifier(attestation.QualificationID, 64) ||
		(attestation.Environment != "staging" && attestation.Environment != "production") ||
		!auth.ValidIdentifier(attestation.DeploymentID, 64) ||
		!auth.ValidIdentifier(attestation.OCIReleaseID, 64) ||
		!equalServices(attestation.Services) ||
		!validSHA256(attestation.ObservationSHA256) ||
		!validSHA256(attestation.KubernetesDeploymentReceiptSHA256) ||
		!validSHA256(attestation.KubernetesAdmissionReceiptSHA256) ||
		!validSHA256(attestation.WorkloadEvidenceSHA256) ||
		!validSHA256(attestation.ControlplanePodBindingSHA256) ||
		!validSHA256(attestation.CurrentClientCertificateSHA256) ||
		!validSHA256(attestation.NextClientCertificateSHA256) ||
		!validSHA256(attestation.RevokedClientCertificateSHA256) ||
		!validSHA256(attestation.ServerLeafCertificateSHA256) ||
		!auth.ValidIdentifier(attestation.SigningKeyID, 64) ||
		attestation.SignatureAlgorithm != "Ed25519" {
		return fmt.Errorf("mTLS dispatch deployment attestation fields are invalid")
	}
	if attestation.DevelopmentOnly {
		if attestation.Environment != "staging" ||
			attestation.Result != FixtureAttestationResult ||
			attestation.AttestationProvider != FixtureAttestationProvider ||
			attestation.ExactSevenServiceDeploymentVerified ||
			attestation.LiveAPIServerAdmissionVerified ||
			attestation.MountedWorkloadIdentityVerified ||
			attestation.NetworkPolicyPathVerified {
			return fmt.Errorf("fixture deployment attestation overstates live evidence")
		}
	} else if attestation.Result != LiveAttestationResult ||
		attestation.AttestationProvider != LiveAttestationProvider ||
		!attestation.ExactSevenServiceDeploymentVerified ||
		!attestation.LiveAPIServerAdmissionVerified ||
		!attestation.MountedWorkloadIdentityVerified ||
		!attestation.NetworkPolicyPathVerified {
		return fmt.Errorf("live deployment attestation fields are invalid")
	}
	if options.RequireLive && attestation.DevelopmentOnly {
		return fmt.Errorf("live mTLS deployment attestation is required")
	}
	verified, err := time.Parse(time.RFC3339, attestation.VerifiedAt)
	if err != nil || verified.Format(time.RFC3339) != attestation.VerifiedAt {
		return fmt.Errorf("mTLS deployment attestation verification time is invalid")
	}
	expires, err := time.Parse(time.RFC3339, attestation.ExpiresAt)
	if err != nil || expires.Format(time.RFC3339) != attestation.ExpiresAt ||
		!expires.After(verified) || expires.Sub(verified) > maximumAttestationLifetime {
		return fmt.Errorf("mTLS deployment attestation expiry is invalid")
	}
	if !options.EvaluationTime.IsZero() &&
		(options.EvaluationTime.Before(verified) ||
			!options.EvaluationTime.Before(expires)) {
		return fmt.Errorf("mTLS deployment attestation is outside its validity window")
	}
	checks := []struct{ actual, expected string }{
		{attestation.SigningKeyID, options.ExpectedSigningKeyID},
		{attestation.AttestationProvider, options.ExpectedProvider},
		{attestation.WorkloadEvidenceSHA256,
			options.ExpectedWorkloadEvidenceSHA256},
	}
	for _, check := range checks {
		if check.expected != "" && check.actual != check.expected {
			return fmt.Errorf("mTLS deployment attestation identity does not match")
		}
	}
	return nil
}

func observationNearTime(observation Observation, verifiedAt time.Time) bool {
	finished, err := time.Parse(time.RFC3339, observation.FinishedAt)
	if err != nil {
		return false
	}
	verifiedAt = verifiedAt.UTC()
	return !verifiedAt.Before(finished.Add(-maximumClockSkew)) &&
		!verifiedAt.After(finished.Add(maximumEvidenceDelay))
}

func attestationSignaturePayload(attestation Attestation) ([]byte, error) {
	attestation.SignatureB64URL = ""
	return json.Marshal(attestation)
}

func canonicalAttestation(attestation Attestation) ([]byte, error) {
	payload, err := json.MarshalIndent(attestation, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}
