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
	environment := flag.String("expected-environment", "", "expected staging or production environment")
	evaluationTimeText := flag.String("evaluation-time", "", "trusted RFC3339 evaluation time")
	privateKeyPath := flag.String("signing-private-key", "", "M70 authority Ed25519 private key")
	signingKeyID := flag.String("signing-key-id", "", "M70 signing key ID")
	outputPath := flag.String("output", "", "new signed M70 receipt")
	acknowledge := flag.Bool("acknowledge-live-signed-app-delivery", false,
		"acknowledge live provider, signed artifact and vendor-attested App evidence")
	flag.Parse()
	if flag.NArg() != 0 || *observationPath == "" || *providerReceiptPath == "" ||
		*providerPublicKey == "" || *providerKeyID == "" ||
		*providerConfigSHA == "" || *providerToolSHA == "" ||
		*attestationPath == "" || *attestationPublicKey == "" ||
		*attestationKeyID == "" || *attestationProvider == "" ||
		*vendorEvidenceSHA == "" || *qualificationID == "" ||
		*environment == "" || *evaluationTimeText == "" ||
		*privateKeyPath == "" || *signingKeyID == "" || *outputPath == "" {
		fail("complete App delivery qualification arguments are required")
	}
	evaluationTime, err := time.Parse(time.RFC3339, *evaluationTimeText)
	if err != nil || evaluationTime.Format(time.RFC3339) != *evaluationTimeText {
		fail("trusted App delivery evaluation time rejected")
	}
	observation, _, err := appdeliveryqualification.LoadObservation(*observationPath)
	if err != nil || observation.QualificationID != *qualificationID ||
		observation.Environment != *environment {
		fail("App delivery observation rejected")
	}
	requireLive := !observation.DevelopmentOnly
	if requireLive && !*acknowledge {
		fail("live signed-App delivery acknowledgement is required")
	}
	receipt, err := appdeliveryqualification.BuildReceipt(
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
				RequireLive:             requireLive},
			AttestationReceiptPath: *attestationPath,
			AttestationVerifyOptions: appdeliveryqualification.AttestationVerifyOptions{
				TrustedPublicKey:     *attestationPublicKey,
				ExpectedSigningKeyID: *attestationKeyID,
				ExpectedProvider:     *attestationProvider,
				ExpectedVendorSHA256: *vendorEvidenceSHA},
			EvaluationTime: evaluationTime, RequireLive: requireLive})
	if err != nil {
		fail("App delivery qualification evidence rejected")
	}
	payload, err := appdeliveryqualification.SignReceipt(
		receipt, *privateKeyPath, *signingKeyID)
	if err != nil {
		fail("App delivery qualification receipt signing failed")
	}
	if err := appdeliveryqualification.WriteNew(*outputPath, payload); err != nil {
		fail("App delivery qualification receipt publication failed")
	}
	fmt.Printf("%s: %s\n", receipt.Result, *outputPath)
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
