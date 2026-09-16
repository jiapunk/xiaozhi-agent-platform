package appdeliveryqualification

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xiaozhi-agent-platform/gateway/internal/accountauth"
	"xiaozhi-agent-platform/gateway/internal/pushqualification"
)

func TestFixtureChainCannotSatisfyLiveSignedAppVerifier(t *testing.T) {
	directory := t.TempDir()
	providerPrivate, providerPublic := writeKeyPair(t, directory, "provider")
	attestationPrivate, attestationPublic := writeKeyPair(t, directory, "attestation")
	finalPrivate, finalPublic := writeKeyPair(t, directory, "final")

	provider := pushqualification.Receipt{Schema: 1,
		QualificationID: "m70-fixture-1",
		Result:          pushqualification.FixtureResult, Environment: "staging",
		ConfigSHA256:            strings.Repeat("0", 64),
		QualificationToolSHA256: strings.Repeat("1", 64),
		StartedAt:               "2026-08-10T12:00:00Z", FinishedAt: "2026-08-10T12:00:01Z",
		DevelopmentOnly: true, SecretFree: true,
		Providers: []pushqualification.ProviderEvidence{{
			Platform:            accountauth.PushPlatformAPNSDevelopment,
			ApplicationID:       "com.example.product",
			CurrentCredentialID: "fixture-current-1",
			NextCredentialID:    "fixture-next-2",
			CurrentAccepted:     true, NextAccepted: true,
			InvalidTargetClassified: true, CanceledRequestRetried: true,
			CurrentLatencyMS: 10, NextLatencyMS: 11,
			InvalidClassificationMS: 12}},
		ProductionReady: false,
		UnresolvedProductionGates: []string{"end_to_end_mtls_dispatch",
			"managed_database_failover", "provider_credential_revocation",
			"signed_app_delivery_receipt"}}
	providerPayload, err := pushqualification.SignReceipt(
		provider, providerPrivate, "provider-fixture-key")
	if err != nil {
		t.Fatal(err)
	}
	providerPath := filepath.Join(directory, "provider.json")
	writeFile(t, providerPath, providerPayload, 0o444)

	observation := fixtureObservation(digest(providerPayload))
	observationPayload, err := canonicalObservation(observation)
	if err != nil {
		t.Fatal(err)
	}
	observationPath := filepath.Join(directory, "observation.json")
	writeFile(t, observationPath, observationPayload, 0o444)
	for _, forbidden := range []string{
		"AAECAwQFBgcICQoLDA0ODw", "xz-device-1", "indicator", "token",
	} {
		if bytes.Contains(observationPayload, []byte(forbidden)) {
			t.Fatalf("observation contains %q", forbidden)
		}
	}

	verifiedAt := time.Date(2026, 8, 10, 12, 1, 0, 0, time.UTC)
	attestationPayload, err := SignAttestation(AttestationInput{
		Observation: observation, ObservationSHA256: digest(observationPayload),
		ProviderQualificationReceiptSHA256: digest(providerPayload),
		VendorEvidenceSHA256:               strings.Repeat("2", 64),
		AttestedKeySHA256:                  strings.Repeat("3", 64),
		Provider:                           FixtureAttestationProvider, VerifiedAt: verifiedAt,
		ExpiresAt: verifiedAt.Add(time.Hour), DevelopmentOnly: true,
	}, attestationPrivate, "app-attestation-fixture-key")
	if err != nil {
		t.Fatal(err)
	}
	attestationPath := filepath.Join(directory, "attestation.json")
	writeFile(t, attestationPath, attestationPayload, 0o444)

	evidence := fixtureEvidenceOptions(observationPath, providerPath,
		providerPublic, attestationPath, attestationPublic, verifiedAt)
	receipt, err := BuildReceipt(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Result != FixtureResult || !receipt.DevelopmentOnly ||
		receipt.SignedArtifactVerified || receipt.VendorAttestationVerified ||
		receipt.ProductionReady || len(receipt.UnresolvedProductionGates) != 4 ||
		receipt.UnresolvedProductionGates[3] != "signed_app_delivery_receipt" {
		t.Fatalf("receipt=%+v", receipt)
	}
	receiptPayload, err := SignReceipt(receipt, finalPrivate, "m70-fixture-key")
	if err != nil {
		t.Fatal(err)
	}
	verifiedReceipt, err := VerifyReceipt(receiptPayload, ReceiptVerifyOptions{
		TrustedPublicKey:                 finalPublic,
		ExpectedSigningKeyID:             "m70-fixture-key",
		ExpectedQualificationID:          "m70-fixture-1",
		ExpectedEnvironment:              "staging",
		ExpectedAppBinarySHA256:          strings.Repeat("a", 64),
		ExpectedProviderReceiptSHA256:    digest(providerPayload),
		ExpectedObservationSHA256:        digest(observationPayload),
		ExpectedAttestationReceiptSHA256: digest(attestationPayload),
		ExpectedEvaluationTime:           verifiedAt.Format(time.RFC3339)})
	if err != nil || !ReceiptMatchesEvidence(verifiedReceipt, receipt) {
		t.Fatalf("verified=%+v err=%v", verifiedReceipt, err)
	}
	if _, err := VerifyReceipt(receiptPayload, ReceiptVerifyOptions{
		TrustedPublicKey: finalPublic, RequireLive: true}); err == nil {
		t.Fatal("fixture satisfied live signed-App verifier")
	}
	evidence.RequireLive = true
	if _, err := BuildReceipt(evidence); err == nil {
		t.Fatal("fixture evidence built a live receipt")
	}

	lateObservation := observation
	lateObservation.WakeReceivedAtUnixMS += uint64(time.Hour / time.Millisecond)
	lateObservation.ForegroundEnteredAtUnixMS += uint64(time.Hour / time.Millisecond)
	lateObservation.AuthenticatedFetchPresentedAtUnixMS +=
		uint64(time.Hour / time.Millisecond)
	lateObservationPayload, _ := canonicalObservation(lateObservation)
	lateObservationPath := filepath.Join(directory, "late-observation.json")
	writeFile(t, lateObservationPath, lateObservationPayload, 0o444)
	lateVerifiedAt := verifiedAt.Add(time.Hour)
	lateAttestationPayload, err := SignAttestation(AttestationInput{
		Observation:                        lateObservation,
		ObservationSHA256:                  digest(lateObservationPayload),
		ProviderQualificationReceiptSHA256: digest(providerPayload),
		VendorEvidenceSHA256:               strings.Repeat("2", 64),
		AttestedKeySHA256:                  strings.Repeat("3", 64),
		Provider:                           FixtureAttestationProvider, VerifiedAt: lateVerifiedAt,
		ExpiresAt: lateVerifiedAt.Add(time.Hour), DevelopmentOnly: true,
	}, attestationPrivate, "app-attestation-fixture-key")
	if err != nil {
		t.Fatal(err)
	}
	lateAttestationPath := filepath.Join(directory, "late-attestation.json")
	writeFile(t, lateAttestationPath, lateAttestationPayload, 0o444)
	lateEvidence := fixtureEvidenceOptions(lateObservationPath, providerPath,
		providerPublic, lateAttestationPath, attestationPublic, lateVerifiedAt)
	if _, err := BuildReceipt(lateEvidence); err == nil {
		t.Fatal("evidence outside the M69 delivery window was accepted")
	}
}

func TestObservationRejectsAmbiguityAndInvalidSequence(t *testing.T) {
	observation := fixtureObservation(strings.Repeat("4", 64))
	payload, _ := canonicalObservation(observation)
	if _, err := ParseObservation(payload); err != nil {
		t.Fatal(err)
	}
	duplicate := bytes.Replace(payload, []byte(`"schema":1`),
		[]byte(`"schema":1,"schema":1`), 1)
	if _, err := ParseObservation(duplicate); err == nil {
		t.Fatal("duplicate observation field accepted")
	}
	observation.ForegroundEnteredAtUnixMS = observation.WakeReceivedAtUnixMS - 1
	payload, _ = canonicalObservation(observation)
	if _, err := ParseObservation(payload); err == nil {
		t.Fatal("out-of-order observation accepted")
	}
	observation = fixtureObservation(strings.Repeat("4", 64))
	if _, err := SignAttestation(AttestationInput{Observation: observation,
		ObservationSHA256:                  strings.Repeat("5", 64),
		ProviderQualificationReceiptSHA256: strings.Repeat("6", 64),
		VendorEvidenceSHA256:               strings.Repeat("7", 64),
		AttestedKeySHA256:                  strings.Repeat("8", 64),
		Provider:                           FixtureAttestationProvider,
		VerifiedAt: time.UnixMilli(int64(
			observation.AuthenticatedFetchPresentedAtUnixMS)).Add(11 * time.Minute),
		ExpiresAt: time.UnixMilli(int64(
			observation.AuthenticatedFetchPresentedAtUnixMS)).Add(12 * time.Minute),
		DevelopmentOnly: true}, "unused", "fixture-key"); err == nil {
		t.Fatal("stale App observation was accepted for attestation")
	}
}

func fixtureObservation(_ string) Observation {
	return Observation{Schema: 1, QualificationID: "m70-fixture-1",
		QualificationNonce: "AAAAAAAAAAAAAAAAAAAAAA",
		Environment:        "staging", DevelopmentOnly: true, Platform: "ios",
		ApplicationID: "com.example.product", AppBuildID: "ios-fixture-1",
		AppBinarySHA256: strings.Repeat("a", 64),
		WakeContract:    WakeContract, ContentFreeWake: true,
		BackgroundNetworkRequest: false, BackgroundWakeCount: 1,
		WakeReceivedAtUnixMS:                1786363200000,
		ForegroundEnteredAtUnixMS:           1786363201000,
		AuthenticatedFetchPresentedAtUnixMS: 1786363201200,
		WakeToFetchMS:                       1200, ChallengeBindingSHA256: strings.Repeat("b", 64),
		DeviceBindingSHA256: strings.Repeat("c", 64), DecisionIssued: false}
}

func fixtureEvidenceOptions(observationPath, providerPath, providerPublic,
	attestationPath, attestationPublic string,
	evaluationTime time.Time) EvidenceOptions {
	return EvidenceOptions{ObservationPath: observationPath,
		ProviderReceiptPath: providerPath,
		ProviderVerifyOptions: pushqualification.VerifyOptions{
			TrustedPublicKey:        providerPublic,
			ExpectedSigningKeyID:    "provider-fixture-key",
			ExpectedQualificationID: "m70-fixture-1",
			ExpectedEnvironment:     "staging",
			ExpectedConfigSHA256:    strings.Repeat("0", 64),
			ExpectedToolSHA256:      strings.Repeat("1", 64)},
		AttestationReceiptPath: attestationPath,
		AttestationVerifyOptions: AttestationVerifyOptions{
			TrustedPublicKey:     attestationPublic,
			ExpectedSigningKeyID: "app-attestation-fixture-key",
			ExpectedProvider:     FixtureAttestationProvider,
			ExpectedVendorSHA256: strings.Repeat("2", 64)},
		EvaluationTime: evaluationTime}
}

func writeKeyPair(t *testing.T, directory, name string) (string, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, _ := x509.MarshalPKCS8PrivateKey(private)
	publicDER, _ := x509.MarshalPKIXPublicKey(public)
	privatePath := filepath.Join(directory, name+"-private.pem")
	publicPath := filepath.Join(directory, name+"-public.pem")
	writeFile(t, privatePath, pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: privateDER}), 0o600)
	writeFile(t, publicPath, pem.EncodeToMemory(&pem.Block{
		Type: "PUBLIC KEY", Bytes: publicDER}), 0o644)
	return privatePath, publicPath
}

func writeFile(t *testing.T, path string, payload []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, payload, mode); err != nil {
		t.Fatal(err)
	}
}
