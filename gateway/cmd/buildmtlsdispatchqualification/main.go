package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"xiaozhi-agent-platform/gateway/internal/appdeliveryqualification"
	"xiaozhi-agent-platform/gateway/internal/mtlsdispatchqualification"
	"xiaozhi-agent-platform/gateway/internal/pushqualification"
)

func main() {
	observationPath := flag.String("observation", "", "canonical M71 transport observation")
	appReceiptPath := flag.String("app-delivery-receipt", "", "signed M70 receipt")
	appReceiptPublicKey := flag.String("app-delivery-trusted-public-key", "", "trusted M70 public key")
	appReceiptKeyID := flag.String("expected-app-delivery-signing-key-id", "", "expected M70 signing key ID")
	appObservationPath := flag.String("app-observation", "", "canonical M70 App observation")
	providerReceiptPath := flag.String("provider-receipt", "", "signed M69 receipt")
	providerPublicKey := flag.String("provider-trusted-public-key", "", "trusted M69 public key")
	providerKeyID := flag.String("expected-provider-signing-key-id", "", "expected M69 signing key ID")
	providerConfigSHA := flag.String("expected-provider-config-sha256", "", "expected M69 config digest")
	providerToolSHA := flag.String("expected-provider-tool-sha256", "", "expected M69 tool digest")
	appAttestationPath := flag.String("app-attestation-receipt", "", "signed App attestation receipt")
	appAttestationPublicKey := flag.String("app-attestation-trusted-public-key", "", "trusted App attestation key")
	appAttestationKeyID := flag.String("expected-app-attestation-signing-key-id", "", "expected App attestation key ID")
	appAttestationProvider := flag.String("expected-app-attestation-provider", "", "expected App attestation provider")
	vendorEvidenceSHA := flag.String("expected-vendor-evidence-sha256", "", "expected App vendor evidence digest")
	appBinarySHA := flag.String("expected-app-binary-sha256", "", "expected signed App digest")
	appEvaluationTimeText := flag.String("app-evaluation-time", "", "trusted M70 RFC3339 evaluation time")
	deploymentAttestationPath := flag.String("deployment-attestation-receipt", "", "signed M71 deployment attestation")
	deploymentAttestationPublicKey := flag.String("deployment-attestation-trusted-public-key", "", "trusted deployment authority key")
	deploymentAttestationKeyID := flag.String("expected-deployment-attestation-signing-key-id", "", "expected deployment authority key ID")
	deploymentAttestationProvider := flag.String("expected-deployment-attestation-provider", "", "expected deployment attestation provider")
	workloadEvidenceSHA := flag.String("expected-workload-evidence-sha256", "", "expected seven-service evidence digest")
	qualificationID := flag.String("expected-qualification-id", "", "expected shared qualification ID")
	environment := flag.String("expected-environment", "", "expected staging or production environment")
	deploymentID := flag.String("expected-deployment-id", "", "expected Kubernetes deployment ID")
	ociReleaseID := flag.String("expected-oci-release-id", "", "expected seven-service OCI release ID")
	evaluationTimeText := flag.String("evaluation-time", "", "trusted M71 RFC3339 evaluation time")
	privateKeyPath := flag.String("signing-private-key", "", "M71 authority Ed25519 private key")
	signingKeyID := flag.String("signing-key-id", "", "M71 signing key ID")
	outputPath := flag.String("output", "", "new signed M71 receipt")
	acknowledge := flag.Bool("acknowledge-live-mtls-dispatch", false,
		"acknowledge live App, cluster and mTLS dispatch evidence")
	flag.Parse()
	if flag.NArg() != 0 || *observationPath == "" || *appReceiptPath == "" ||
		*appReceiptPublicKey == "" || *appReceiptKeyID == "" ||
		*appObservationPath == "" || *providerReceiptPath == "" ||
		*providerPublicKey == "" || *providerKeyID == "" ||
		*providerConfigSHA == "" || *providerToolSHA == "" ||
		*appAttestationPath == "" || *appAttestationPublicKey == "" ||
		*appAttestationKeyID == "" || *appAttestationProvider == "" ||
		*vendorEvidenceSHA == "" || *appBinarySHA == "" ||
		*appEvaluationTimeText == "" || *deploymentAttestationPath == "" ||
		*deploymentAttestationPublicKey == "" ||
		*deploymentAttestationKeyID == "" ||
		*deploymentAttestationProvider == "" || *workloadEvidenceSHA == "" ||
		*qualificationID == "" || *environment == "" || *deploymentID == "" ||
		*ociReleaseID == "" || *evaluationTimeText == "" ||
		*privateKeyPath == "" || *signingKeyID == "" || *outputPath == "" {
		fail("complete mTLS dispatch qualification arguments are required")
	}
	appEvaluationTime := parseTime(*appEvaluationTimeText,
		"trusted App delivery evaluation time rejected")
	evaluationTime := parseTime(*evaluationTimeText,
		"trusted mTLS dispatch evaluation time rejected")
	observation, _, err := mtlsdispatchqualification.LoadObservation(*observationPath)
	if err != nil || observation.QualificationID != *qualificationID ||
		observation.Environment != *environment ||
		observation.DeploymentID != *deploymentID ||
		observation.OCIReleaseID != *ociReleaseID {
		fail("mTLS dispatch observation rejected")
	}
	requireLive := !observation.DevelopmentOnly
	if requireLive && !*acknowledge {
		fail("live mTLS dispatch acknowledgement is required")
	}
	providerDigest := mustDigest(*providerReceiptPath, "provider receipt digest unavailable")
	appObservationDigest := mustDigest(*appObservationPath, "App observation digest unavailable")
	appAttestationDigest := mustDigest(*appAttestationPath, "App attestation digest unavailable")
	receipt, err := mtlsdispatchqualification.BuildReceipt(
		mtlsdispatchqualification.EvidenceOptions{
			ObservationPath:        *observationPath,
			AppDeliveryReceiptPath: *appReceiptPath,
			AppDeliveryVerifyOptions: appdeliveryqualification.ReceiptVerifyOptions{
				TrustedPublicKey:                 *appReceiptPublicKey,
				ExpectedSigningKeyID:             *appReceiptKeyID,
				ExpectedQualificationID:          *qualificationID,
				ExpectedEnvironment:              *environment,
				ExpectedAppBinarySHA256:          *appBinarySHA,
				ExpectedProviderReceiptSHA256:    providerDigest,
				ExpectedObservationSHA256:        appObservationDigest,
				ExpectedAttestationReceiptSHA256: appAttestationDigest,
				ExpectedEvaluationTime:           *appEvaluationTimeText,
				RequireLive:                      requireLive},
			AppDeliveryEvidenceOptions: appdeliveryqualification.EvidenceOptions{
				ObservationPath:     *appObservationPath,
				ProviderReceiptPath: *providerReceiptPath,
				ProviderVerifyOptions: pushqualification.VerifyOptions{
					TrustedPublicKey:        *providerPublicKey,
					ExpectedSigningKeyID:    *providerKeyID,
					ExpectedQualificationID: *qualificationID,
					ExpectedEnvironment:     *environment,
					ExpectedConfigSHA256:    *providerConfigSHA,
					ExpectedToolSHA256:      *providerToolSHA},
				AttestationReceiptPath: *appAttestationPath,
				AttestationVerifyOptions: appdeliveryqualification.AttestationVerifyOptions{
					TrustedPublicKey:     *appAttestationPublicKey,
					ExpectedSigningKeyID: *appAttestationKeyID,
					ExpectedProvider:     *appAttestationProvider,
					ExpectedVendorSHA256: *vendorEvidenceSHA},
				EvaluationTime: appEvaluationTime},
			DeploymentAttestationReceiptPath: *deploymentAttestationPath,
			DeploymentAttestationVerifyOptions: mtlsdispatchqualification.AttestationVerifyOptions{
				TrustedPublicKey:               *deploymentAttestationPublicKey,
				ExpectedSigningKeyID:           *deploymentAttestationKeyID,
				ExpectedProvider:               *deploymentAttestationProvider,
				ExpectedWorkloadEvidenceSHA256: *workloadEvidenceSHA},
			EvaluationTime: evaluationTime, RequireLive: requireLive})
	if err != nil {
		fail("mTLS dispatch qualification evidence rejected")
	}
	payload, err := mtlsdispatchqualification.SignReceipt(
		receipt, *privateKeyPath, *signingKeyID)
	if err != nil {
		fail("mTLS dispatch qualification receipt signing failed")
	}
	if err := mtlsdispatchqualification.WriteNew(*outputPath, payload); err != nil {
		fail("mTLS dispatch qualification receipt publication failed")
	}
	fmt.Printf("%s: %s\n", receipt.Result, *outputPath)
}

func parseTime(value, message string) time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Format(time.RFC3339) != value {
		fail(message)
	}
	return parsed
}

func mustDigest(path, message string) string {
	value, err := mtlsdispatchqualification.DigestRegularFile(path, 1<<20)
	if err != nil {
		fail(message)
	}
	return value
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
