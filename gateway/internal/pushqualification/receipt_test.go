package pushqualification

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignedFixtureReceiptCannotSatisfyLiveVerifier(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "approval-private.pem")
	publicPath := filepath.Join(directory, "approval-public.pem")
	privateDER, _ := x509.MarshalPKCS8PrivateKey(private)
	publicDER, _ := x509.MarshalPKIXPublicKey(public)
	if err := os.WriteFile(privatePath, pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{
		Type: "PUBLIC KEY", Bytes: publicDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	receipt := fixtureReceipt()
	payload, err := SignReceipt(receipt, privatePath, "m69-approval-key")
	if err != nil {
		t.Fatal(err)
	}
	options := VerifyOptions{TrustedPublicKey: publicPath,
		ExpectedSigningKeyID:    "m69-approval-key",
		ExpectedQualificationID: "m69-fixture-1",
		ExpectedEnvironment:     "staging",
		ExpectedConfigSHA256:    stringsOfZeroSHA256,
		ExpectedToolSHA256:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	verified, err := VerifyReceipt(payload, options)
	if err != nil || verified.Result != FixtureResult {
		t.Fatalf("verified=%+v err=%v", verified, err)
	}
	options.RequireLive = true
	if _, err := VerifyReceipt(payload, options); err == nil {
		t.Fatal("fixture receipt satisfied live verifier")
	}
	tampered := []byte(strings.Replace(string(payload),
		"m69-fixture-1", "m69-fixture-9", 1))
	options.RequireLive = false
	options.ExpectedQualificationID = "m69-fixture-9"
	if _, err := VerifyReceipt(tampered, options); err == nil {
		t.Fatal("tampered receipt retained authority")
	}
}

func fixtureReceipt() Receipt {
	return Receipt{Schema: 1, QualificationID: "m69-fixture-1",
		Result: FixtureResult, Environment: "staging",
		ConfigSHA256:            stringsOfZeroSHA256,
		QualificationToolSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		StartedAt:               "2026-08-10T12:00:00Z", FinishedAt: "2026-08-10T12:00:01Z",
		DevelopmentOnly: true, SecretFree: true,
		Providers: []ProviderEvidence{{Platform: "fcm",
			ApplicationID: "product-123", CurrentCredentialID: "current-key-123",
			NextCredentialID: "next-key-456", CurrentAccepted: true,
			NextAccepted: true, InvalidTargetClassified: true,
			CanceledRequestRetried: true, CurrentLatencyMS: 10,
			NextLatencyMS: 10, InvalidClassificationMS: 10}},
		ProductionReady: false,
		UnresolvedProductionGates: append([]string(nil),
			unresolvedProductionGates...)}
}
