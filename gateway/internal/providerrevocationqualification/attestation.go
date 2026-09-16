package providerrevocationqualification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"time"

	"xiaozhi-agent-platform/gateway/internal/accountauth"
	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/strictjson"
)

const (
	AttestationSchema          = 1
	LiveAttestationResult      = "LIVE_PROVIDER_CONSOLE_REVOCATION_PASS"
	FixtureAttestationResult   = "FIXTURE_PROVIDER_REVOCATION_ATTESTATION_PASS"
	LiveAttestationProvider    = "provider-credential-audit-authority"
	FixtureAttestationProvider = "fixture"
	maximumAttestationLifetime = 24 * time.Hour
	maximumEvidenceDelay       = 10 * time.Minute
	maximumClockSkew           = 30 * time.Second
)

var attestationSignatureDomain = []byte(
	"XIAOZHI-PROVIDER-CREDENTIAL-REVOCATION-ATTESTATION-V1\x00")

type CredentialBinding struct {
	Platform               accountauth.PushPlatform `json:"platform"`
	ApplicationID          string                   `json:"application_id"`
	RevokedCredentialID    string                   `json:"revoked_credential_id"`
	ActiveCredentialID     string                   `json:"active_credential_id"`
	RevokedPublicKeySHA256 string                   `json:"revoked_public_key_sha256"`
	ActivePublicKeySHA256  string                   `json:"active_public_key_sha256"`
}

type Attestation struct {
	Schema                            uint32              `json:"schema"`
	QualificationID                   string              `json:"qualification_id"`
	Result                            string              `json:"result"`
	Environment                       string              `json:"environment"`
	DevelopmentOnly                   bool                `json:"development_only"`
	AttestationProvider               string              `json:"attestation_provider"`
	ObservationSHA256                 string              `json:"observation_sha256"`
	ProviderAuditEvidenceSHA256       string              `json:"provider_audit_evidence_sha256"`
	Providers                         []CredentialBinding `json:"providers"`
	RevocationChangeStartedAt         string              `json:"revocation_change_started_at"`
	RevocationChangeCompletedAt       string              `json:"revocation_change_completed_at"`
	ProviderConsoleRevocationVerified bool                `json:"provider_console_revocation_verified"`
	RevokedCredentialDisabledVerified bool                `json:"revoked_credential_disabled_verified"`
	ActiveCredentialEnabledVerified   bool                `json:"active_credential_enabled_verified"`
	WORMRetentionVerified             bool                `json:"worm_retention_verified"`
	VerifiedAt                        string              `json:"verified_at"`
	ExpiresAt                         string              `json:"expires_at"`
	SigningKeyID                      string              `json:"signing_key_id"`
	SignatureAlgorithm                string              `json:"signature_algorithm"`
	SignatureB64URL                   string              `json:"signature_b64url"`
}

type AttestationInput struct {
	Observation                 Observation
	ObservationSHA256           string
	ProviderAuditEvidenceSHA256 string
	Provider                    string
	RevocationChangeStartedAt   time.Time
	RevocationChangeCompletedAt time.Time
	VerifiedAt                  time.Time
	ExpiresAt                   time.Time
	DevelopmentOnly             bool
}

type AttestationVerifyOptions struct {
	TrustedPublicKey            string
	ExpectedSigningKeyID        string
	ExpectedProvider            string
	ExpectedProviderAuditSHA256 string
	EvaluationTime              time.Time
	RequireLive                 bool
}

func SignAttestation(input AttestationInput, privateKeyPath,
	signingKeyID string) ([]byte, error) {
	if input.DevelopmentOnly != input.Observation.DevelopmentOnly ||
		!validSHA256(input.ObservationSHA256) ||
		!validSHA256(input.ProviderAuditEvidenceSHA256) ||
		!validChangeWindow(input.Observation,
			input.RevocationChangeStartedAt,
			input.RevocationChangeCompletedAt) ||
		!observationNearTime(input.Observation, input.VerifiedAt) {
		return nil, fmt.Errorf("provider revocation attestation input is invalid")
	}
	result := LiveAttestationResult
	if input.DevelopmentOnly {
		result = FixtureAttestationResult
	}
	attestation := Attestation{Schema: AttestationSchema,
		QualificationID: input.Observation.QualificationID, Result: result,
		Environment:     input.Observation.Environment,
		DevelopmentOnly: input.DevelopmentOnly, AttestationProvider: input.Provider,
		ObservationSHA256:                 input.ObservationSHA256,
		ProviderAuditEvidenceSHA256:       input.ProviderAuditEvidenceSHA256,
		Providers:                         bindingsFromObservation(input.Observation.Providers),
		RevocationChangeStartedAt:         input.RevocationChangeStartedAt.UTC().Format(time.RFC3339),
		RevocationChangeCompletedAt:       input.RevocationChangeCompletedAt.UTC().Format(time.RFC3339),
		ProviderConsoleRevocationVerified: !input.DevelopmentOnly,
		RevokedCredentialDisabledVerified: !input.DevelopmentOnly,
		ActiveCredentialEnabledVerified:   !input.DevelopmentOnly,
		WORMRetentionVerified:             !input.DevelopmentOnly,
		VerifiedAt:                        input.VerifiedAt.UTC().Format(time.RFC3339),
		ExpiresAt:                         input.ExpiresAt.UTC().Format(time.RFC3339),
		SigningKeyID:                      signingKeyID, SignatureAlgorithm: "Ed25519"}
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
		return Attestation{}, nil, fmt.Errorf("provider revocation attestation: %w", err)
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
		return Attestation{}, fmt.Errorf("provider revocation attestation is ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var attestation Attestation
	if err := decoder.Decode(&attestation); err != nil {
		return Attestation{}, fmt.Errorf("provider revocation attestation JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Attestation{}, fmt.Errorf("provider revocation attestation has trailing JSON")
	}
	canonical, err := canonicalAttestation(attestation)
	if err != nil || !bytes.Equal(canonical, payload) {
		return Attestation{}, fmt.Errorf("provider revocation attestation is not canonical JSON")
	}
	if err := validateAttestation(attestation, options); err != nil {
		return Attestation{}, err
	}
	signaturePayload, err := attestationSignaturePayload(attestation)
	if err != nil || verifyDomainPayload(attestationSignatureDomain,
		signaturePayload, attestation.SignatureB64URL,
		options.TrustedPublicKey) != nil {
		return Attestation{}, fmt.Errorf("provider revocation attestation signature is invalid")
	}
	return attestation, nil
}

func validateAttestation(attestation Attestation,
	options AttestationVerifyOptions) error {
	if attestation.Schema != AttestationSchema ||
		!auth.ValidIdentifier(attestation.QualificationID, 64) ||
		(attestation.Environment != "staging" && attestation.Environment != "production") ||
		!validSHA256(attestation.ObservationSHA256) ||
		!validSHA256(attestation.ProviderAuditEvidenceSHA256) ||
		!validBindings(attestation.Providers) ||
		!auth.ValidIdentifier(attestation.SigningKeyID, 64) ||
		attestation.SignatureAlgorithm != "Ed25519" {
		return fmt.Errorf("provider revocation attestation fields are invalid")
	}
	if attestation.DevelopmentOnly {
		if attestation.Environment != "staging" ||
			attestation.Result != FixtureAttestationResult ||
			attestation.AttestationProvider != FixtureAttestationProvider ||
			attestation.ProviderConsoleRevocationVerified ||
			attestation.RevokedCredentialDisabledVerified ||
			attestation.ActiveCredentialEnabledVerified ||
			attestation.WORMRetentionVerified {
			return fmt.Errorf("fixture provider revocation attestation overstates live evidence")
		}
	} else if attestation.Result != LiveAttestationResult ||
		attestation.AttestationProvider != LiveAttestationProvider ||
		!attestation.ProviderConsoleRevocationVerified ||
		!attestation.RevokedCredentialDisabledVerified ||
		!attestation.ActiveCredentialEnabledVerified ||
		!attestation.WORMRetentionVerified {
		return fmt.Errorf("live provider revocation attestation fields are invalid")
	}
	if options.RequireLive && attestation.DevelopmentOnly {
		return fmt.Errorf("live provider revocation attestation is required")
	}
	changeStarted, err := parseCanonicalTime(attestation.RevocationChangeStartedAt)
	if err != nil {
		return fmt.Errorf("provider revocation change start time is invalid")
	}
	changeCompleted, err := parseCanonicalTime(attestation.RevocationChangeCompletedAt)
	if err != nil || changeCompleted.Before(changeStarted) ||
		changeCompleted.Sub(changeStarted) > maximumAttestationLifetime {
		return fmt.Errorf("provider revocation change completion time is invalid")
	}
	verified, err := parseCanonicalTime(attestation.VerifiedAt)
	if err != nil || verified.Before(changeCompleted) {
		return fmt.Errorf("provider revocation verification time is invalid")
	}
	expires, err := parseCanonicalTime(attestation.ExpiresAt)
	if err != nil || !expires.After(verified) ||
		expires.Sub(verified) > maximumAttestationLifetime {
		return fmt.Errorf("provider revocation attestation expiry is invalid")
	}
	if !options.EvaluationTime.IsZero() &&
		(options.EvaluationTime.Before(verified) ||
			!options.EvaluationTime.Before(expires)) {
		return fmt.Errorf("provider revocation attestation is outside its validity window")
	}
	checks := []struct{ actual, expected string }{
		{attestation.SigningKeyID, options.ExpectedSigningKeyID},
		{attestation.AttestationProvider, options.ExpectedProvider},
		{attestation.ProviderAuditEvidenceSHA256,
			options.ExpectedProviderAuditSHA256},
	}
	for _, check := range checks {
		if check.expected != "" && check.actual != check.expected {
			return fmt.Errorf("provider revocation attestation identity does not match")
		}
	}
	return nil
}

func bindingsFromObservation(providers []ProviderObservation) []CredentialBinding {
	bindings := make([]CredentialBinding, len(providers))
	for index, provider := range providers {
		bindings[index] = CredentialBinding{Platform: provider.Platform,
			ApplicationID:          provider.ApplicationID,
			RevokedCredentialID:    provider.RevokedCredentialID,
			ActiveCredentialID:     provider.ActiveCredentialID,
			RevokedPublicKeySHA256: provider.RevokedPublicKeySHA256,
			ActivePublicKeySHA256:  provider.ActivePublicKeySHA256}
	}
	return bindings
}

func validBindings(bindings []CredentialBinding) bool {
	if len(bindings) < 1 || len(bindings) > 3 {
		return false
	}
	seen := make(map[accountauth.PushPlatform]bool, len(bindings))
	for index, binding := range bindings {
		if seen[binding.Platform] || !accountauth.ValidPushPlatform(binding.Platform) ||
			!auth.ValidIdentifier(binding.ApplicationID, 128) ||
			!validCredentialID(binding.RevokedCredentialID) ||
			!validCredentialID(binding.ActiveCredentialID) ||
			binding.RevokedCredentialID == binding.ActiveCredentialID ||
			!validSHA256(binding.RevokedPublicKeySHA256) ||
			!validSHA256(binding.ActivePublicKeySHA256) ||
			binding.RevokedPublicKeySHA256 == binding.ActivePublicKeySHA256 ||
			(index > 0 && bindings[index-1].Platform >= binding.Platform) {
			return false
		}
		seen[binding.Platform] = true
	}
	return true
}

func validChangeWindow(observation Observation, started, completed time.Time) bool {
	observationStarted, err := time.Parse(time.RFC3339, observation.StartedAt)
	if err != nil || started.IsZero() || completed.IsZero() ||
		started.Nanosecond() != 0 || completed.Nanosecond() != 0 {
		return false
	}
	started, completed = started.UTC(), completed.UTC()
	return !completed.Before(started) &&
		completed.Sub(started) <= maximumAttestationLifetime &&
		!completed.After(observationStarted.Add(maximumClockSkew))
}

func observationNearTime(observation Observation, verifiedAt time.Time) bool {
	finished, err := time.Parse(time.RFC3339, observation.FinishedAt)
	if err != nil || verifiedAt.IsZero() || verifiedAt.Nanosecond() != 0 {
		return false
	}
	verifiedAt = verifiedAt.UTC()
	return !verifiedAt.Before(finished.Add(-maximumClockSkew)) &&
		!verifiedAt.After(finished.Add(maximumEvidenceDelay))
}

func parseCanonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Format(time.RFC3339) != value {
		return time.Time{}, fmt.Errorf("invalid canonical time")
	}
	return parsed, nil
}

func attestationMatchesObservation(attestation Attestation,
	observation Observation) bool {
	return attestation.QualificationID == observation.QualificationID &&
		attestation.Environment == observation.Environment &&
		attestation.DevelopmentOnly == observation.DevelopmentOnly &&
		reflect.DeepEqual(attestation.Providers,
			bindingsFromObservation(observation.Providers))
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
