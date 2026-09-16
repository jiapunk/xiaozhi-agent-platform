package appdeliveryqualification

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
	LiveAttestationResult      = "LIVE_APP_ATTESTATION_PASS"
	FixtureAttestationResult   = "FIXTURE_APP_ATTESTATION_PASS"
	FixtureAttestationProvider = "fixture"
	AppleAttestationProvider   = "apple-app-attest"
	maximumAttestationLifetime = 24 * time.Hour
)

var attestationSignatureDomain = []byte(
	"XIAOZHI-APP-DELIVERY-ATTESTATION-V1\x00")

type Attestation struct {
	Schema                             uint32 `json:"schema"`
	QualificationID                    string `json:"qualification_id"`
	Result                             string `json:"result"`
	Environment                        string `json:"environment"`
	DevelopmentOnly                    bool   `json:"development_only"`
	Platform                           string `json:"platform"`
	AttestationProvider                string `json:"attestation_provider"`
	ApplicationID                      string `json:"application_id"`
	AppBuildID                         string `json:"app_build_id"`
	AppBinarySHA256                    string `json:"app_binary_sha256"`
	ObservationSHA256                  string `json:"observation_sha256"`
	ProviderQualificationReceiptSHA256 string `json:"provider_qualification_receipt_sha256"`
	VendorEvidenceSHA256               string `json:"vendor_evidence_sha256"`
	AttestedKeySHA256                  string `json:"attested_key_sha256"`
	SignedArtifactVerified             bool   `json:"signed_artifact_verified"`
	VendorAttestationVerified          bool   `json:"vendor_attestation_verified"`
	VerifiedAt                         string `json:"verified_at"`
	ExpiresAt                          string `json:"expires_at"`
	SigningKeyID                       string `json:"signing_key_id"`
	SignatureAlgorithm                 string `json:"signature_algorithm"`
	SignatureB64URL                    string `json:"signature_b64url"`
}

type AttestationInput struct {
	Observation                        Observation
	ObservationSHA256                  string
	ProviderQualificationReceiptSHA256 string
	VendorEvidenceSHA256               string
	AttestedKeySHA256                  string
	Provider                           string
	VerifiedAt                         time.Time
	ExpiresAt                          time.Time
	DevelopmentOnly                    bool
}

type AttestationVerifyOptions struct {
	TrustedPublicKey     string
	ExpectedSigningKeyID string
	ExpectedProvider     string
	ExpectedVendorSHA256 string
	EvaluationTime       time.Time
	RequireLive          bool
}

func SignAttestation(input AttestationInput, privateKeyPath,
	signingKeyID string) ([]byte, error) {
	if input.DevelopmentOnly != input.Observation.DevelopmentOnly ||
		!validSHA256(input.ObservationSHA256) ||
		!validSHA256(input.ProviderQualificationReceiptSHA256) ||
		!observationNearAttestation(input.Observation, input.VerifiedAt) {
		return nil, fmt.Errorf("App attestation input is invalid")
	}
	result := LiveAttestationResult
	if input.DevelopmentOnly {
		result = FixtureAttestationResult
	}
	attestation := Attestation{Schema: AttestationSchema,
		QualificationID: input.Observation.QualificationID,
		Result:          result, Environment: input.Observation.Environment,
		DevelopmentOnly:                    input.DevelopmentOnly,
		Platform:                           input.Observation.Platform,
		AttestationProvider:                input.Provider,
		ApplicationID:                      input.Observation.ApplicationID,
		AppBuildID:                         input.Observation.AppBuildID,
		AppBinarySHA256:                    input.Observation.AppBinarySHA256,
		ObservationSHA256:                  input.ObservationSHA256,
		ProviderQualificationReceiptSHA256: input.ProviderQualificationReceiptSHA256,
		VendorEvidenceSHA256:               input.VendorEvidenceSHA256,
		AttestedKeySHA256:                  input.AttestedKeySHA256,
		SignedArtifactVerified:             !input.DevelopmentOnly,
		VendorAttestationVerified:          !input.DevelopmentOnly,
		VerifiedAt:                         input.VerifiedAt.UTC().Format(time.RFC3339),
		ExpiresAt:                          input.ExpiresAt.UTC().Format(time.RFC3339),
		SigningKeyID:                       signingKeyID, SignatureAlgorithm: "Ed25519"}
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

func VerifyAttestationFile(path string,
	options AttestationVerifyOptions) (Attestation, []byte, error) {
	payload, err := readRegular(path, maximumQualificationDoc, false)
	if err != nil {
		return Attestation{}, nil, fmt.Errorf("App attestation receipt: %w", err)
	}
	attestation, err := VerifyAttestation(payload, options)
	if err != nil {
		return Attestation{}, nil, err
	}
	return attestation, payload, nil
}

func VerifyAttestation(payload []byte,
	options AttestationVerifyOptions) (Attestation, error) {
	if err := strictjson.RejectDuplicateFields(payload); err != nil {
		return Attestation{}, fmt.Errorf("App attestation receipt JSON is ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var attestation Attestation
	if err := decoder.Decode(&attestation); err != nil {
		return Attestation{}, fmt.Errorf("App attestation receipt JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Attestation{}, fmt.Errorf("App attestation receipt has trailing JSON")
	}
	canonical, err := canonicalAttestation(attestation)
	if err != nil || !bytes.Equal(canonical, payload) {
		return Attestation{}, fmt.Errorf("App attestation receipt is not canonical JSON")
	}
	if err := validateAttestation(attestation, options); err != nil {
		return Attestation{}, err
	}
	signaturePayload, err := attestationSignaturePayload(attestation)
	if err != nil || verifyDomainPayload(attestationSignatureDomain,
		signaturePayload, attestation.SignatureB64URL,
		options.TrustedPublicKey) != nil {
		return Attestation{}, fmt.Errorf("App attestation receipt signature is invalid")
	}
	return attestation, nil
}

func validateAttestation(attestation Attestation,
	options AttestationVerifyOptions) error {
	if attestation.Schema != AttestationSchema ||
		!auth.ValidIdentifier(attestation.QualificationID, 64) ||
		(attestation.Environment != "staging" &&
			attestation.Environment != "production") ||
		attestation.Platform != "ios" ||
		!auth.ValidIdentifier(attestation.ApplicationID, 128) ||
		!auth.ValidIdentifier(attestation.AppBuildID, 64) ||
		!validSHA256(attestation.AppBinarySHA256) ||
		!validSHA256(attestation.ObservationSHA256) ||
		!validSHA256(attestation.ProviderQualificationReceiptSHA256) ||
		!validSHA256(attestation.VendorEvidenceSHA256) ||
		!validSHA256(attestation.AttestedKeySHA256) ||
		!auth.ValidIdentifier(attestation.SigningKeyID, 64) ||
		attestation.SignatureAlgorithm != "Ed25519" {
		return fmt.Errorf("App attestation receipt fields are invalid")
	}
	if attestation.DevelopmentOnly {
		if attestation.Environment != "staging" ||
			attestation.Result != FixtureAttestationResult ||
			attestation.AttestationProvider != FixtureAttestationProvider ||
			attestation.SignedArtifactVerified ||
			attestation.VendorAttestationVerified {
			return fmt.Errorf("fixture App attestation overstates live evidence")
		}
	} else if attestation.Result != LiveAttestationResult ||
		attestation.AttestationProvider != AppleAttestationProvider ||
		!attestation.SignedArtifactVerified ||
		!attestation.VendorAttestationVerified {
		return fmt.Errorf("live App attestation fields are invalid")
	}
	if options.RequireLive && attestation.DevelopmentOnly {
		return fmt.Errorf("live App attestation evidence is required")
	}
	verified, err := time.Parse(time.RFC3339, attestation.VerifiedAt)
	if err != nil || verified.Format(time.RFC3339) != attestation.VerifiedAt {
		return fmt.Errorf("App attestation verification time is invalid")
	}
	expires, err := time.Parse(time.RFC3339, attestation.ExpiresAt)
	if err != nil || expires.Format(time.RFC3339) != attestation.ExpiresAt ||
		!expires.After(verified) || expires.Sub(verified) > maximumAttestationLifetime {
		return fmt.Errorf("App attestation expiry is invalid")
	}
	if !options.EvaluationTime.IsZero() &&
		(options.EvaluationTime.Before(verified) ||
			!options.EvaluationTime.Before(expires)) {
		return fmt.Errorf("App attestation is outside its validity window")
	}
	checks := []struct{ actual, expected string }{
		{attestation.SigningKeyID, options.ExpectedSigningKeyID},
		{attestation.AttestationProvider, options.ExpectedProvider},
		{attestation.VendorEvidenceSHA256, options.ExpectedVendorSHA256},
	}
	for _, check := range checks {
		if check.expected != "" && check.actual != check.expected {
			return fmt.Errorf("App attestation identity does not match")
		}
	}
	return nil
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
