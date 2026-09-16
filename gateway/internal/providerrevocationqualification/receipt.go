package providerrevocationqualification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/mtlsdispatchqualification"
	"xiaozhi-agent-platform/gateway/internal/pushqualification"
	"xiaozhi-agent-platform/gateway/internal/strictjson"
)

const (
	ReceiptSchema = 1
	LiveResult    = "LIVE_PROVIDER_CREDENTIAL_REVOCATION_PASS"
	FixtureResult = "FIXTURE_PROVIDER_CREDENTIAL_REVOCATION_PASS"
)

var (
	receiptSignatureDomain = []byte(
		"XIAOZHI-PROVIDER-CREDENTIAL-REVOCATION-QUALIFICATION-V1\x00")
	liveUnresolvedProductionGates = []string{
		"managed_database_failover",
	}
	fixtureUnresolvedProductionGates = []string{
		"end_to_end_mtls_dispatch",
		"managed_database_failover",
		"provider_credential_revocation",
		"signed_app_delivery_receipt",
	}
)

type Receipt struct {
	Schema                             uint32                `json:"schema"`
	QualificationID                    string                `json:"qualification_id"`
	Result                             string                `json:"result"`
	Environment                        string                `json:"environment"`
	DevelopmentOnly                    bool                  `json:"development_only"`
	DeploymentID                       string                `json:"deployment_id"`
	OCIReleaseID                       string                `json:"oci_release_id"`
	ConfigSHA256                       string                `json:"config_sha256"`
	QualificationToolSHA256            string                `json:"qualification_tool_sha256"`
	Providers                          []ProviderObservation `json:"providers"`
	StartedAt                          string                `json:"started_at"`
	FinishedAt                         string                `json:"finished_at"`
	ObservationSHA256                  string                `json:"observation_sha256"`
	ProviderQualificationResult        string                `json:"provider_qualification_result"`
	ProviderQualificationReceiptSHA256 string                `json:"provider_qualification_receipt_sha256"`
	MTLSDispatchResult                 string                `json:"mtls_dispatch_result"`
	MTLSDispatchReceiptSHA256          string                `json:"mtls_dispatch_receipt_sha256"`
	RevocationAttestationResult        string                `json:"revocation_attestation_result"`
	RevocationAttestationReceiptSHA256 string                `json:"revocation_attestation_receipt_sha256"`
	AttestationProvider                string                `json:"attestation_provider"`
	ProviderAuditEvidenceSHA256        string                `json:"provider_audit_evidence_sha256"`
	RevocationChangeStartedAt          string                `json:"revocation_change_started_at"`
	RevocationChangeCompletedAt        string                `json:"revocation_change_completed_at"`
	ProviderConsoleRevocationVerified  bool                  `json:"provider_console_revocation_verified"`
	RevokedCredentialDisabledVerified  bool                  `json:"revoked_credential_disabled_verified"`
	ActiveCredentialEnabledVerified    bool                  `json:"active_credential_enabled_verified"`
	WORMRetentionVerified              bool                  `json:"worm_retention_verified"`
	EvaluatedAt                        string                `json:"evaluated_at"`
	SecretFree                         bool                  `json:"secret_free"`
	ProductionReady                    bool                  `json:"production_ready"`
	UnresolvedProductionGates          []string              `json:"unresolved_production_gates"`
	SigningKeyID                       string                `json:"signing_key_id"`
	SignatureAlgorithm                 string                `json:"signature_algorithm"`
	SignatureB64URL                    string                `json:"signature_b64url"`
}

type EvidenceOptions struct {
	ObservationPath                    string
	MTLSDispatchReceiptPath            string
	MTLSDispatchVerifyOptions          mtlsdispatchqualification.ReceiptVerifyOptions
	MTLSDispatchEvidenceOptions        mtlsdispatchqualification.EvidenceOptions
	RevocationAttestationReceiptPath   string
	RevocationAttestationVerifyOptions AttestationVerifyOptions
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
	ExpectedMTLSDispatchSHA256          string
	ExpectedRevocationAttestationSHA256 string
	ExpectedEvaluationTime              string
	RequireLive                         bool
}

func BuildReceipt(options EvidenceOptions) (Receipt, error) {
	if options.EvaluationTime.IsZero() || options.EvaluationTime.Nanosecond() != 0 {
		return Receipt{}, fmt.Errorf("provider revocation evaluation time is invalid")
	}
	observation, observationPayload, err := LoadObservation(options.ObservationPath)
	if err != nil {
		return Receipt{}, err
	}
	mtlsPayload, err := readRegular(options.MTLSDispatchReceiptPath,
		maximumDocumentBytes, false)
	if err != nil {
		return Receipt{}, fmt.Errorf("mTLS dispatch qualification receipt rejected")
	}
	mtlsVerify := options.MTLSDispatchVerifyOptions
	mtlsVerify.RequireLive = options.RequireLive
	mtlsReceipt, err := mtlsdispatchqualification.VerifyReceiptFile(
		options.MTLSDispatchReceiptPath, mtlsVerify)
	if err != nil {
		return Receipt{}, fmt.Errorf("mTLS dispatch qualification receipt rejected")
	}
	mtlsEvidence := options.MTLSDispatchEvidenceOptions
	mtlsEvidence.RequireLive = options.RequireLive
	expectedMTLS, err := mtlsdispatchqualification.BuildReceipt(mtlsEvidence)
	if err != nil || !mtlsdispatchqualification.ReceiptMatchesEvidence(
		mtlsReceipt, expectedMTLS) {
		return Receipt{}, fmt.Errorf("mTLS dispatch qualification evidence bundle rejected")
	}
	providerPath := mtlsEvidence.AppDeliveryEvidenceOptions.ProviderReceiptPath
	providerPayload, err := readRegular(providerPath, maximumDocumentBytes, false)
	if err != nil {
		return Receipt{}, fmt.Errorf("provider qualification receipt rejected")
	}
	providerVerify := mtlsEvidence.AppDeliveryEvidenceOptions.ProviderVerifyOptions
	providerVerify.RequireLive = options.RequireLive
	providerReceipt, err := pushqualification.VerifyReceiptFile(
		providerPath, providerVerify)
	if err != nil {
		return Receipt{}, fmt.Errorf("provider qualification receipt rejected")
	}
	attestationVerify := options.RevocationAttestationVerifyOptions
	attestationVerify.EvaluationTime = options.EvaluationTime.UTC()
	attestationVerify.RequireLive = options.RequireLive
	attestation, attestationPayload, err := VerifyAttestationFile(
		options.RevocationAttestationReceiptPath, attestationVerify)
	if err != nil {
		return Receipt{}, err
	}
	observationSHA := digest(observationPayload)
	providerFinished, providerTimeErr := time.Parse(time.RFC3339,
		providerReceipt.FinishedAt)
	mtlsEvaluated, mtlsTimeErr := time.Parse(time.RFC3339,
		mtlsReceipt.EvaluatedAt)
	changeStarted, changeStartErr := time.Parse(time.RFC3339,
		attestation.RevocationChangeStartedAt)
	changeCompleted, changeCompleteErr := time.Parse(time.RFC3339,
		attestation.RevocationChangeCompletedAt)
	observationStarted, observationStartErr := time.Parse(time.RFC3339,
		observation.StartedAt)
	attestationVerified, attestationTimeErr := time.Parse(time.RFC3339,
		attestation.VerifiedAt)
	if observation.QualificationID != mtlsReceipt.QualificationID ||
		observation.QualificationID != providerReceipt.QualificationID ||
		observation.QualificationID != attestation.QualificationID ||
		observation.Environment != mtlsReceipt.Environment ||
		observation.Environment != providerReceipt.Environment ||
		observation.Environment != attestation.Environment ||
		observation.DevelopmentOnly != mtlsReceipt.DevelopmentOnly ||
		observation.DevelopmentOnly != providerReceipt.DevelopmentOnly ||
		observation.DevelopmentOnly != attestation.DevelopmentOnly ||
		observationSHA != attestation.ObservationSHA256 ||
		!attestationMatchesObservation(attestation, observation) ||
		!observationMatchesProviderReceipt(observation, providerReceipt) ||
		providerTimeErr != nil || mtlsTimeErr != nil || changeStartErr != nil ||
		changeCompleteErr != nil || observationStartErr != nil ||
		attestationTimeErr != nil || changeStarted.Before(providerFinished) ||
		changeStarted.Before(mtlsEvaluated) || changeCompleted.Before(changeStarted) ||
		observationStarted.Before(changeCompleted.Add(-maximumClockSkew)) ||
		options.EvaluationTime.Before(attestationVerified) ||
		options.EvaluationTime.After(attestationVerified.Add(maximumEvidenceDelay)) {
		return Receipt{}, fmt.Errorf("provider revocation evidence subjects do not match")
	}
	if options.RequireLive && (observation.DevelopmentOnly ||
		mtlsReceipt.DevelopmentOnly || providerReceipt.DevelopmentOnly ||
		attestation.DevelopmentOnly) {
		return Receipt{}, fmt.Errorf("live provider credential revocation evidence is required")
	}
	result := LiveResult
	unresolved := liveUnresolvedProductionGates
	if observation.DevelopmentOnly {
		result = FixtureResult
		unresolved = fixtureUnresolvedProductionGates
	}
	receipt := Receipt{Schema: ReceiptSchema,
		QualificationID: observation.QualificationID, Result: result,
		Environment: observation.Environment, DevelopmentOnly: observation.DevelopmentOnly,
		DeploymentID: mtlsReceipt.DeploymentID, OCIReleaseID: mtlsReceipt.OCIReleaseID,
		ConfigSHA256:            observation.ConfigSHA256,
		QualificationToolSHA256: observation.QualificationToolSHA256,
		Providers:               append([]ProviderObservation(nil), observation.Providers...),
		StartedAt:               observation.StartedAt, FinishedAt: observation.FinishedAt,
		ObservationSHA256:                  observationSHA,
		ProviderQualificationResult:        providerReceipt.Result,
		ProviderQualificationReceiptSHA256: digest(providerPayload),
		MTLSDispatchResult:                 mtlsReceipt.Result,
		MTLSDispatchReceiptSHA256:          digest(mtlsPayload),
		RevocationAttestationResult:        attestation.Result,
		RevocationAttestationReceiptSHA256: digest(attestationPayload),
		AttestationProvider:                attestation.AttestationProvider,
		ProviderAuditEvidenceSHA256:        attestation.ProviderAuditEvidenceSHA256,
		RevocationChangeStartedAt:          attestation.RevocationChangeStartedAt,
		RevocationChangeCompletedAt:        attestation.RevocationChangeCompletedAt,
		ProviderConsoleRevocationVerified:  attestation.ProviderConsoleRevocationVerified,
		RevokedCredentialDisabledVerified:  attestation.RevokedCredentialDisabledVerified,
		ActiveCredentialEnabledVerified:    attestation.ActiveCredentialEnabledVerified,
		WORMRetentionVerified:              attestation.WORMRetentionVerified,
		EvaluatedAt:                        options.EvaluationTime.UTC().Format(time.RFC3339),
		SecretFree:                         true, ProductionReady: false,
		UnresolvedProductionGates: append([]string(nil), unresolved...)}
	if err := validateReceipt(receipt, ReceiptVerifyOptions{}); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func observationMatchesProviderReceipt(observation Observation,
	receipt pushqualification.Receipt) bool {
	if len(observation.Providers) != len(receipt.Providers) {
		return false
	}
	for index, provider := range observation.Providers {
		qualified := receipt.Providers[index]
		if provider.Platform != qualified.Platform ||
			provider.ApplicationID != qualified.ApplicationID ||
			provider.RevokedCredentialID != qualified.CurrentCredentialID ||
			provider.ActiveCredentialID != qualified.NextCredentialID {
			return false
		}
	}
	return true
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
		return Receipt{}, fmt.Errorf("provider revocation qualification receipt: %w", err)
	}
	return VerifyReceipt(payload, options)
}

func VerifyReceipt(payload []byte, options ReceiptVerifyOptions) (
	Receipt, error) {
	if err := strictjson.RejectDuplicateFields(payload); err != nil {
		return Receipt{}, fmt.Errorf("provider revocation qualification receipt is ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var receipt Receipt
	if err := decoder.Decode(&receipt); err != nil {
		return Receipt{}, fmt.Errorf("provider revocation qualification receipt JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Receipt{}, fmt.Errorf("provider revocation qualification receipt has trailing JSON")
	}
	canonical, err := canonicalReceipt(receipt)
	if err != nil || !bytes.Equal(canonical, payload) {
		return Receipt{}, fmt.Errorf("provider revocation qualification receipt is not canonical JSON")
	}
	if err := validateReceipt(receipt, options); err != nil {
		return Receipt{}, err
	}
	signaturePayload, err := receiptSignaturePayload(receipt)
	if err != nil || verifyDomainPayload(receiptSignatureDomain,
		signaturePayload, receipt.SignatureB64URL,
		options.TrustedPublicKey) != nil {
		return Receipt{}, fmt.Errorf("provider revocation qualification receipt signature is invalid")
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
		QualificationID: receipt.QualificationID, Environment: receipt.Environment,
		DevelopmentOnly: receipt.DevelopmentOnly, ConfigSHA256: receipt.ConfigSHA256,
		QualificationToolSHA256: receipt.QualificationToolSHA256,
		Providers:               receipt.Providers, StartedAt: receipt.StartedAt,
		FinishedAt: receipt.FinishedAt, SecretFree: receipt.SecretFree}
	if err := validateObservation(observation); err != nil ||
		!auth.ValidIdentifier(receipt.DeploymentID, 64) ||
		!auth.ValidIdentifier(receipt.OCIReleaseID, 64) ||
		!validSHA256(receipt.ObservationSHA256) ||
		!validSHA256(receipt.ProviderQualificationReceiptSHA256) ||
		!validSHA256(receipt.MTLSDispatchReceiptSHA256) ||
		!validSHA256(receipt.RevocationAttestationReceiptSHA256) ||
		!validSHA256(receipt.ProviderAuditEvidenceSHA256) ||
		!receipt.SecretFree || receipt.ProductionReady ||
		!reflect.DeepEqual(receipt.UnresolvedProductionGates, expectedUnresolved) ||
		(!unsigned && (!auth.ValidIdentifier(receipt.SigningKeyID, 64) ||
			receipt.SignatureAlgorithm != "Ed25519")) {
		return fmt.Errorf("provider revocation qualification receipt fields are invalid")
	}
	if receipt.DevelopmentOnly {
		if receipt.Environment != "staging" || receipt.Result != FixtureResult ||
			receipt.ProviderQualificationResult != pushqualification.FixtureResult ||
			receipt.MTLSDispatchResult != mtlsdispatchqualification.FixtureResult ||
			receipt.RevocationAttestationResult != FixtureAttestationResult ||
			receipt.AttestationProvider != FixtureAttestationProvider ||
			receipt.ProviderConsoleRevocationVerified ||
			receipt.RevokedCredentialDisabledVerified ||
			receipt.ActiveCredentialEnabledVerified ||
			receipt.WORMRetentionVerified {
			return fmt.Errorf("fixture provider revocation receipt overstates live evidence")
		}
	} else if receipt.Result != LiveResult ||
		receipt.ProviderQualificationResult != pushqualification.LiveResult ||
		receipt.MTLSDispatchResult != mtlsdispatchqualification.LiveResult ||
		receipt.RevocationAttestationResult != LiveAttestationResult ||
		receipt.AttestationProvider != LiveAttestationProvider ||
		!receipt.ProviderConsoleRevocationVerified ||
		!receipt.RevokedCredentialDisabledVerified ||
		!receipt.ActiveCredentialEnabledVerified ||
		!receipt.WORMRetentionVerified {
		return fmt.Errorf("live provider revocation receipt fields are invalid")
	}
	if options.RequireLive && receipt.DevelopmentOnly {
		return fmt.Errorf("live provider credential revocation receipt is required")
	}
	changeStarted, err := parseCanonicalTime(receipt.RevocationChangeStartedAt)
	if err != nil {
		return fmt.Errorf("provider revocation receipt change start time is invalid")
	}
	changeCompleted, err := parseCanonicalTime(receipt.RevocationChangeCompletedAt)
	if err != nil || changeCompleted.Before(changeStarted) ||
		changeCompleted.Sub(changeStarted) > maximumAttestationLifetime {
		return fmt.Errorf("provider revocation receipt change completion time is invalid")
	}
	evaluated, err := parseCanonicalTime(receipt.EvaluatedAt)
	if err != nil || evaluated.Before(changeCompleted) {
		return fmt.Errorf("provider revocation receipt evaluation time is invalid")
	}
	checks := []struct{ actual, expected string }{
		{receipt.SigningKeyID, options.ExpectedSigningKeyID},
		{receipt.QualificationID, options.ExpectedQualificationID},
		{receipt.Environment, options.ExpectedEnvironment},
		{receipt.DeploymentID, options.ExpectedDeploymentID},
		{receipt.OCIReleaseID, options.ExpectedOCIReleaseID},
		{receipt.ObservationSHA256, options.ExpectedObservationSHA256},
		{receipt.MTLSDispatchReceiptSHA256, options.ExpectedMTLSDispatchSHA256},
		{receipt.RevocationAttestationReceiptSHA256,
			options.ExpectedRevocationAttestationSHA256},
		{receipt.EvaluatedAt, options.ExpectedEvaluationTime},
	}
	for _, check := range checks {
		if check.expected != "" && check.actual != check.expected {
			return fmt.Errorf("provider revocation qualification identity does not match")
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
