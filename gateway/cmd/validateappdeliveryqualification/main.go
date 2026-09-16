package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"xiaozhi-agent-platform/gateway/internal/appdeliveryqualification"
	"xiaozhi-agent-platform/gateway/internal/pushqualification"
)

func main() {
	receiptPath := flag.String("receipt", "", "signed M70 qualification receipt")
	receiptPublicKey := flag.String("trusted-public-key", "", "trusted M70 public key")
	receiptKeyID := flag.String("expected-signing-key-id", "", "expected M70 signing key ID")
	observationPath := flag.String("observation", "", "canonical App flow observation")
	providerReceiptPath := flag.String("provider-receipt", "", "signed M69 receipt")
	providerPublicKey := flag.String("provider-trusted-public-key", "", "trusted M69 public key")
	providerKeyID := flag.String("expected-provider-signing-key-id", "", "expected M69 signing key ID")
	providerConfigSHA := flag.String("expected-provider-config-sha256", "", "expected M69 config digest")
	providerToolSHA := flag.String("expected-provider-tool-sha256", "", "expected M69 tool digest")
	attestationPath := flag.String("app-attestation-receipt", "", "signed App attestation receipt")
	attestationPublicKey := flag.String("app-attestation-trusted-public-key", "", "trusted App attestation authority key")
	attestationKeyID := flag.String("expected-app-attestation-signing-key-id", "", "expected App attestation key ID")
	attestationProvider := flag.String("expected-app-attestation-provider", "", "expected attestation provider")
	vendorEvidenceSHA := flag.String("expected-vendor-evidence-sha256", "", "expected vendor evidence digest")
	qualificationID := flag.String("expected-qualification-id", "", "expected shared qualification ID")
	environment := flag.String("expected-environment", "", "expected environment")
	appBinarySHA := flag.String("expected-app-binary-sha256", "", "expected signed App binary digest")
	evaluationTimeText := flag.String("evaluation-time", "", "trusted RFC3339 evaluation time")
	requireLive := flag.Bool("require-live", false, "reject all fixture evidence")
	flag.Parse()
	if flag.NArg() != 0 || *receiptPath == "" || *receiptPublicKey == "" ||
		*receiptKeyID == "" || *observationPath == "" ||
		*providerReceiptPath == "" || *providerPublicKey == "" ||
		*providerKeyID == "" || *providerConfigSHA == "" ||
		*providerToolSHA == "" || *attestationPath == "" ||
		*attestationPublicKey == "" || *attestationKeyID == "" ||
		*attestationProvider == "" || *vendorEvidenceSHA == "" ||
		*qualificationID == "" || *environment == "" || *appBinarySHA == "" ||
		*evaluationTimeText == "" {
		fail("all App delivery qualification trust inputs are required")
	}
	evaluationTime, err := time.Parse(time.RFC3339, *evaluationTimeText)
	if err != nil || evaluationTime.Format(time.RFC3339) != *evaluationTimeText {
		fail("trusted App delivery evaluation time rejected")
	}
	providerDigest, err := appdeliveryqualification.DigestRegularFile(
		*providerReceiptPath, 1<<20)
	if err != nil {
		fail("provider receipt digest unavailable")
	}
	observationDigest, err := appdeliveryqualification.DigestRegularFile(
		*observationPath, 1<<20)
	if err != nil {
		fail("App observation digest unavailable")
	}
	attestationDigest, err := appdeliveryqualification.DigestRegularFile(
		*attestationPath, 1<<20)
	if err != nil {
		fail("App attestation receipt digest unavailable")
	}
	receipt, err := appdeliveryqualification.VerifyReceiptFile(
		*receiptPath, appdeliveryqualification.ReceiptVerifyOptions{
			TrustedPublicKey:                 *receiptPublicKey,
			ExpectedSigningKeyID:             *receiptKeyID,
			ExpectedQualificationID:          *qualificationID,
			ExpectedEnvironment:              *environment,
			ExpectedAppBinarySHA256:          *appBinarySHA,
			ExpectedProviderReceiptSHA256:    providerDigest,
			ExpectedObservationSHA256:        observationDigest,
			ExpectedAttestationReceiptSHA256: attestationDigest,
			ExpectedEvaluationTime:           *evaluationTimeText,
			RequireLive:                      *requireLive})
	if err != nil {
		fail("App delivery qualification receipt rejected")
	}
	expected, err := appdeliveryqualification.BuildReceipt(
		appdeliveryqualification.EvidenceOptions{
			ObservationPath:     *observationPath,
			ProviderReceiptPath: *providerReceiptPath,
			ProviderVerifyOptions: pushqualification.VerifyOptions{
				TrustedPublicKey:        *providerPublicKey,
				ExpectedSigningKeyID:    *providerKeyID,
				ExpectedQualificationID: *qualificationID,
				ExpectedEnvironment:     *environment,
				ExpectedConfigSHA256:    *providerConfigSHA,
				ExpectedToolSHA256:      *providerToolSHA,
				RequireLive:             *requireLive},
			AttestationReceiptPath: *attestationPath,
			AttestationVerifyOptions: appdeliveryqualification.AttestationVerifyOptions{
				TrustedPublicKey:     *attestationPublicKey,
				ExpectedSigningKeyID: *attestationKeyID,
				ExpectedProvider:     *attestationProvider,
				ExpectedVendorSHA256: *vendorEvidenceSHA},
			EvaluationTime: evaluationTime, RequireLive: *requireLive})
	if err != nil || !appdeliveryqualification.ReceiptMatchesEvidence(
		receipt, expected) {
		fail("App delivery qualification evidence bundle rejected")
	}
	fmt.Printf("%s: %s\n", receipt.Result, *receiptPath)
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
