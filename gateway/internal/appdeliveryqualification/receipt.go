package appdeliveryqualification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"time"

	"xiaozhi-agent-platform/gateway/internal/accountauth"
	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/pushqualification"
	"xiaozhi-agent-platform/gateway/internal/strictjson"
)

const (
	ReceiptSchema = 1
	LiveResult    = "LIVE_SIGNED_APP_FLOW_PASS"
	FixtureResult = "FIXTURE_APP_FLOW_PASS"
)

var (
	receiptSignatureDomain = []byte(
		"XIAOZHI-APP-DELIVERY-QUALIFICATION-V1\x00")
	liveUnresolvedProductionGates = []string{
		"end_to_end_mtls_dispatch",
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
	Schema                             uint32   `json:"schema"`
	QualificationID                    string   `json:"qualification_id"`
	Result                             string   `json:"result"`
	Environment                        string   `json:"environment"`
	DevelopmentOnly                    bool     `json:"development_only"`
	Platform                           string   `json:"platform"`
	ApplicationID                      string   `json:"application_id"`
	AppBuildID                         string   `json:"app_build_id"`
	AppBinarySHA256                    string   `json:"app_binary_sha256"`
	ProviderQualificationResult        string   `json:"provider_qualification_result"`
	ProviderQualificationReceiptSHA256 string   `json:"provider_qualification_receipt_sha256"`
	AppObservationSHA256               string   `json:"app_observation_sha256"`
	AppAttestationResult               string   `json:"app_attestation_result"`
	AppAttestationReceiptSHA256        string   `json:"app_attestation_receipt_sha256"`
	AttestationProvider                string   `json:"attestation_provider"`
	VendorEvidenceSHA256               string   `json:"vendor_evidence_sha256"`
	AttestedKeySHA256                  string   `json:"attested_key_sha256"`
	ContentFreeWake                    bool     `json:"content_free_wake"`
	BackgroundNetworkRequest           bool     `json:"background_network_request"`
	BackgroundWakeCount                uint32   `json:"background_wake_count"`
	WakeReceivedAtUnixMS               uint64   `json:"wake_received_at_unix_ms"`
	ForegroundEnteredAtUnixMS          uint64   `json:"foreground_entered_at_unix_ms"`
	AuthenticatedFetchAtUnixMS         uint64   `json:"authenticated_fetch_presented_at_unix_ms"`
	WakeToFetchMS                      uint64   `json:"wake_to_fetch_ms"`
	ChallengeBindingSHA256             string   `json:"challenge_binding_sha256"`
	DeviceBindingSHA256                string   `json:"device_binding_sha256"`
	DecisionIssued                     bool     `json:"decision_issued"`
	SignedArtifactVerified             bool     `json:"signed_artifact_verified"`
	VendorAttestationVerified          bool     `json:"vendor_attestation_verified"`
	EvaluatedAt                        string   `json:"evaluated_at"`
	SecretFree                         bool     `json:"secret_free"`
	ProductionReady                    bool     `json:"production_ready"`
	UnresolvedProductionGates          []string `json:"unresolved_production_gates"`
	SigningKeyID                       string   `json:"signing_key_id"`
	SignatureAlgorithm                 string   `json:"signature_algorithm"`
	SignatureB64URL                    string   `json:"signature_b64url"`
}

type EvidenceOptions struct {
	ObservationPath          string
	ProviderReceiptPath      string
	ProviderVerifyOptions    pushqualification.VerifyOptions
	AttestationReceiptPath   string
	AttestationVerifyOptions AttestationVerifyOptions
	EvaluationTime           time.Time
	RequireLive              bool
}

type ReceiptVerifyOptions struct {
	TrustedPublicKey                 string
	ExpectedSigningKeyID             string
	ExpectedQualificationID          string
	ExpectedEnvironment              string
	ExpectedAppBinarySHA256          string
	ExpectedProviderReceiptSHA256    string
	ExpectedObservationSHA256        string
	ExpectedAttestationReceiptSHA256 string
	ExpectedEvaluationTime           string
	RequireLive                      bool
}

func BuildReceipt(options EvidenceOptions) (Receipt, error) {
	if options.EvaluationTime.IsZero() || options.EvaluationTime.Nanosecond() != 0 {
		return Receipt{}, fmt.Errorf("App delivery evaluation time is invalid")
	}
	observation, observationPayload, err := LoadObservation(options.ObservationPath)
	if err != nil {
		return Receipt{}, err
	}
	providerPayload, err := readRegular(options.ProviderReceiptPath,
		maximumQualificationDoc, false)
	if err != nil {
		return Receipt{}, fmt.Errorf("provider qualification receipt rejected")
	}
	providerDigest := digest(providerPayload)
	providerOptions := options.ProviderVerifyOptions
	providerOptions.RequireLive = options.RequireLive
	providerReceipt, err := pushqualification.VerifyReceiptFile(
		options.ProviderReceiptPath, providerOptions)
	if err != nil {
		return Receipt{}, fmt.Errorf("provider qualification receipt rejected")
	}
	attestationOptions := options.AttestationVerifyOptions
	attestationOptions.EvaluationTime = options.EvaluationTime.UTC()
	attestationOptions.RequireLive = options.RequireLive
	attestation, attestationPayload, err := VerifyAttestationFile(
		options.AttestationReceiptPath, attestationOptions)
	if err != nil {
		return Receipt{}, err
	}
	observationSHA := digest(observationPayload)
	providerStarted, startErr := time.Parse(time.RFC3339,
		providerReceipt.StartedAt)
	providerFinished, finishErr := time.Parse(time.RFC3339,
		providerReceipt.FinishedAt)
	attestationVerified, attestationTimeErr := time.Parse(time.RFC3339,
		attestation.VerifiedAt)
	wakeAt, _ := observationTimes(observation)
	if observation.QualificationID != providerReceipt.QualificationID ||
		observation.QualificationID != attestation.QualificationID ||
		observation.Environment != providerReceipt.Environment ||
		observation.Environment != attestation.Environment ||
		observation.DevelopmentOnly != providerReceipt.DevelopmentOnly ||
		observation.DevelopmentOnly != attestation.DevelopmentOnly ||
		observation.Platform != attestation.Platform ||
		observation.ApplicationID != attestation.ApplicationID ||
		observation.AppBuildID != attestation.AppBuildID ||
		observation.AppBinarySHA256 != attestation.AppBinarySHA256 ||
		observationSHA != attestation.ObservationSHA256 ||
		providerDigest != attestation.ProviderQualificationReceiptSHA256 ||
		startErr != nil || finishErr != nil || attestationTimeErr != nil ||
		wakeAt.Before(providerStarted.Add(-maximumClockSkew)) ||
		wakeAt.After(providerFinished.Add(maximumEvidenceDelay)) ||
		!observationNearAttestation(observation, attestationVerified) ||
		!providerSupportsObservation(providerReceipt, observation) {
		return Receipt{}, fmt.Errorf("App delivery evidence subjects do not match")
	}
	if options.RequireLive && (observation.DevelopmentOnly ||
		providerReceipt.DevelopmentOnly || attestation.DevelopmentOnly) {
		return Receipt{}, fmt.Errorf("live signed-App delivery evidence is required")
	}
	result := LiveResult
	unresolved := liveUnresolvedProductionGates
	if observation.DevelopmentOnly {
		result = FixtureResult
		unresolved = fixtureUnresolvedProductionGates
	}
	receipt := Receipt{Schema: ReceiptSchema,
		QualificationID: observation.QualificationID, Result: result,
		Environment:     observation.Environment,
		DevelopmentOnly: observation.DevelopmentOnly,
		Platform:        observation.Platform, ApplicationID: observation.ApplicationID,
		AppBuildID:                         observation.AppBuildID,
		AppBinarySHA256:                    observation.AppBinarySHA256,
		ProviderQualificationResult:        providerReceipt.Result,
		ProviderQualificationReceiptSHA256: providerDigest,
		AppObservationSHA256:               observationSHA,
		AppAttestationResult:               attestation.Result,
		AppAttestationReceiptSHA256:        digest(attestationPayload),
		AttestationProvider:                attestation.AttestationProvider,
		VendorEvidenceSHA256:               attestation.VendorEvidenceSHA256,
		AttestedKeySHA256:                  attestation.AttestedKeySHA256,
		ContentFreeWake:                    observation.ContentFreeWake,
		BackgroundNetworkRequest:           observation.BackgroundNetworkRequest,
		BackgroundWakeCount:                observation.BackgroundWakeCount,
		WakeReceivedAtUnixMS:               observation.WakeReceivedAtUnixMS,
		ForegroundEnteredAtUnixMS:          observation.ForegroundEnteredAtUnixMS,
		AuthenticatedFetchAtUnixMS:         observation.AuthenticatedFetchPresentedAtUnixMS,
		WakeToFetchMS:                      observation.WakeToFetchMS,
		ChallengeBindingSHA256:             observation.ChallengeBindingSHA256,
		DeviceBindingSHA256:                observation.DeviceBindingSHA256,
		DecisionIssued:                     observation.DecisionIssued,
		SignedArtifactVerified:             attestation.SignedArtifactVerified,
		VendorAttestationVerified:          attestation.VendorAttestationVerified,
		EvaluatedAt:                        options.EvaluationTime.UTC().Format(time.RFC3339),
		SecretFree:                         true, ProductionReady: false,
		UnresolvedProductionGates: append([]string(nil), unresolved...)}
	if err := validateReceipt(receipt, ReceiptVerifyOptions{}); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func providerSupportsObservation(provider pushqualification.Receipt,
	observation Observation) bool {
	for _, evidence := range provider.Providers {
		if evidence.ApplicationID != observation.ApplicationID {
			continue
		}
		if observation.Environment == "production" {
			if evidence.Platform == accountauth.PushPlatformAPNSProduction {
				return true
			}
			continue
		}
		if evidence.Platform == accountauth.PushPlatformAPNSDevelopment ||
			evidence.Platform == accountauth.PushPlatformAPNSProduction {
			return true
		}
	}
	return false
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

func VerifyReceiptFile(path string,
	options ReceiptVerifyOptions) (Receipt, error) {
	payload, err := readRegular(path, maximumQualificationDoc, false)
	if err != nil {
		return Receipt{}, fmt.Errorf("App delivery qualification receipt: %w", err)
	}
	return VerifyReceipt(payload, options)
}

func VerifyReceipt(payload []byte,
	options ReceiptVerifyOptions) (Receipt, error) {
	if err := strictjson.RejectDuplicateFields(payload); err != nil {
		return Receipt{}, fmt.Errorf("App delivery qualification receipt JSON is ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var receipt Receipt
	if err := decoder.Decode(&receipt); err != nil {
		return Receipt{}, fmt.Errorf("App delivery qualification receipt JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Receipt{}, fmt.Errorf("App delivery qualification receipt has trailing JSON")
	}
	canonical, err := canonicalReceipt(receipt)
	if err != nil || !bytes.Equal(canonical, payload) {
		return Receipt{}, fmt.Errorf("App delivery qualification receipt is not canonical JSON")
	}
	if err := validateReceipt(receipt, options); err != nil {
		return Receipt{}, err
	}
	signaturePayload, err := receiptSignaturePayload(receipt)
	if err != nil || verifyDomainPayload(receiptSignatureDomain,
		signaturePayload, receipt.SignatureB64URL,
		options.TrustedPublicKey) != nil {
		return Receipt{}, fmt.Errorf("App delivery qualification receipt signature is invalid")
	}
	return receipt, nil
}

func validateReceipt(receipt Receipt, options ReceiptVerifyOptions) error {
	unsigned := receipt.SigningKeyID == "" &&
		receipt.SignatureAlgorithm == "" && receipt.SignatureB64URL == ""
	expectedUnresolved := liveUnresolvedProductionGates
	if receipt.DevelopmentOnly {
		expectedUnresolved = fixtureUnresolvedProductionGates
	}
	if receipt.Schema != ReceiptSchema ||
		!auth.ValidIdentifier(receipt.QualificationID, 64) ||
		(receipt.Environment != "staging" && receipt.Environment != "production") ||
		receipt.Platform != "ios" ||
		!auth.ValidIdentifier(receipt.ApplicationID, 128) ||
		!auth.ValidIdentifier(receipt.AppBuildID, 64) ||
		!validSHA256(receipt.AppBinarySHA256) ||
		!validSHA256(receipt.ProviderQualificationReceiptSHA256) ||
		!validSHA256(receipt.AppObservationSHA256) ||
		!validSHA256(receipt.AppAttestationReceiptSHA256) ||
		!validSHA256(receipt.VendorEvidenceSHA256) ||
		!validSHA256(receipt.AttestedKeySHA256) ||
		!receipt.ContentFreeWake || receipt.BackgroundNetworkRequest ||
		receipt.BackgroundWakeCount < 1 || receipt.BackgroundWakeCount > 8 ||
		receipt.WakeReceivedAtUnixMS == 0 ||
		receipt.WakeReceivedAtUnixMS > maximumUnixMS ||
		receipt.ForegroundEnteredAtUnixMS > maximumUnixMS ||
		receipt.AuthenticatedFetchAtUnixMS > maximumUnixMS ||
		receipt.ForegroundEnteredAtUnixMS < receipt.WakeReceivedAtUnixMS ||
		receipt.AuthenticatedFetchAtUnixMS < receipt.ForegroundEnteredAtUnixMS ||
		receipt.AuthenticatedFetchAtUnixMS-receipt.WakeReceivedAtUnixMS !=
			receipt.WakeToFetchMS || receipt.WakeToFetchMS > maximumWakeToFetchMS ||
		!validSHA256(receipt.ChallengeBindingSHA256) ||
		!validSHA256(receipt.DeviceBindingSHA256) || receipt.DecisionIssued ||
		!receipt.SecretFree || receipt.ProductionReady ||
		!reflect.DeepEqual(receipt.UnresolvedProductionGates,
			expectedUnresolved) || (!unsigned &&
		(!auth.ValidIdentifier(receipt.SigningKeyID, 64) ||
			receipt.SignatureAlgorithm != "Ed25519")) {
		return fmt.Errorf("App delivery qualification receipt fields are invalid")
	}
	if receipt.DevelopmentOnly {
		if receipt.Environment != "staging" || receipt.Result != FixtureResult ||
			receipt.ProviderQualificationResult != pushqualification.FixtureResult ||
			receipt.AppAttestationResult != FixtureAttestationResult ||
			receipt.AttestationProvider != FixtureAttestationProvider ||
			receipt.SignedArtifactVerified ||
			receipt.VendorAttestationVerified {
			return fmt.Errorf("fixture App delivery receipt overstates live evidence")
		}
	} else if receipt.Result != LiveResult ||
		receipt.ProviderQualificationResult != pushqualification.LiveResult ||
		receipt.AppAttestationResult != LiveAttestationResult ||
		receipt.AttestationProvider != AppleAttestationProvider ||
		!receipt.SignedArtifactVerified || !receipt.VendorAttestationVerified {
		return fmt.Errorf("live App delivery receipt fields are invalid")
	}
	if options.RequireLive && receipt.DevelopmentOnly {
		return fmt.Errorf("live signed-App delivery receipt is required")
	}
	evaluated, err := time.Parse(time.RFC3339, receipt.EvaluatedAt)
	if err != nil || evaluated.Format(time.RFC3339) != receipt.EvaluatedAt {
		return fmt.Errorf("App delivery evaluation time is invalid")
	}
	checks := []struct{ actual, expected string }{
		{receipt.SigningKeyID, options.ExpectedSigningKeyID},
		{receipt.QualificationID, options.ExpectedQualificationID},
		{receipt.Environment, options.ExpectedEnvironment},
		{receipt.AppBinarySHA256, options.ExpectedAppBinarySHA256},
		{receipt.ProviderQualificationReceiptSHA256,
			options.ExpectedProviderReceiptSHA256},
		{receipt.AppObservationSHA256, options.ExpectedObservationSHA256},
		{receipt.AppAttestationReceiptSHA256,
			options.ExpectedAttestationReceiptSHA256},
		{receipt.EvaluatedAt, options.ExpectedEvaluationTime},
	}
	for _, check := range checks {
		if check.expected != "" && check.actual != check.expected {
			return fmt.Errorf("App delivery qualification identity does not match")
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
