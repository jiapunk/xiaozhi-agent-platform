package providerrevocationqualification

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xiaozhi-agent-platform/gateway/internal/accountauth"
	"xiaozhi-agent-platform/gateway/internal/pushdelivery"
)

type providerFixture struct {
	result pushdelivery.DeliveryResult
	err    error
	calls  int
}

func (provider *providerFixture) Send(context.Context, string) (
	pushdelivery.DeliveryResult, error) {
	provider.calls++
	return provider.result, provider.err
}

func fixtureCandidate() Candidate {
	return Candidate{Platform: accountauth.PushPlatformFCM,
		ApplicationID: "product-123", RevokedCredentialID: "current-key-123",
		ActiveCredentialID:     "next-key-456",
		RevokedPublicKeySHA256: strings.Repeat("a", 64),
		ActivePublicKeySHA256:  strings.Repeat("b", 64),
		ActiveBefore:           &providerFixture{result: pushdelivery.DeliveryAccepted},
		Revoked: &providerFixture{result: pushdelivery.DeliveryRetry,
			err: fmt.Errorf("%w: %w", pushdelivery.ErrUnavailable,
				pushdelivery.ErrCredentialRejected)},
		ActiveAfter: &providerFixture{result: pushdelivery.DeliveryAccepted},
		ValidTarget: "fcm-staging-token:abcdefghijklmnopqrstuvwxyz0123456789"}
}

func fixtureRunConfig() RunConfig {
	return RunConfig{QualificationID: "m72-fixture-1", Environment: "staging",
		DevelopmentOnly: true, ConfigSHA256: zeroSHA256,
		ToolSHA256: strings.Repeat("c", 64),
		Candidates: []Candidate{fixtureCandidate()}}
}

func TestRunnerRequiresActiveRevokedActiveSandwichWithoutSecrets(t *testing.T) {
	now := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	runner := &Runner{now: func() time.Time {
		value := now
		now = now.Add(10 * time.Millisecond)
		return value
	}}
	config := fixtureRunConfig()
	observation, err := runner.Run(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	provider := observation.Providers[0]
	if !provider.ActiveBeforeAccepted || !provider.RevokedCredentialRejected ||
		!provider.ActiveAfterAccepted ||
		provider.RejectionClass != "google-oauth-invalid-grant" ||
		!observation.SecretFree || !observation.DevelopmentOnly {
		t.Fatalf("observation=%+v", observation)
	}
	payload, _ := CanonicalObservation(observation)
	if strings.Contains(string(payload), config.Candidates[0].ValidTarget) ||
		strings.Contains(string(payload), "access_token") ||
		strings.Contains(string(payload), "PRIVATE KEY") {
		t.Fatal("provider target or credential escaped observation")
	}
}

func TestRunnerRejectsNetworkFailureAsRevocationEvidence(t *testing.T) {
	config := fixtureRunConfig()
	config.Candidates[0].Revoked = &providerFixture{
		result: pushdelivery.DeliveryRetry, err: pushdelivery.ErrUnavailable}
	if _, err := NewRunner().Run(context.Background(), config); err == nil {
		t.Fatal("network failure was accepted as credential revocation")
	}
}

func TestLoadLiveConfigBuildsFreshAPNsProvidersAndRejectsRelativePaths(t *testing.T) {
	directory := t.TempDir()
	writeKey := func(name string) string {
		t.Helper()
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalPKCS8PrivateKey(key)
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, pemBlock("PRIVATE KEY", der), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	revoked := writeKey("revoked.p8")
	active := writeKey("active.p8")
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte(strings.Repeat("ab", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	document := map[string]any{"schema": 1,
		"qualification_id": "m72-live-1", "environment": "staging",
		"acknowledge_live_credential_revocation": true,
		"providers": []map[string]any{{
			"platform": "apns-development", "application_id": "com.example.product",
			"team_id": "TEAM12ABCD", "revoked_credential_id": "ABC123DEFG",
			"revoked_credential_file": revoked, "active_credential_id": "XYZ987WQRS",
			"active_credential_file": active, "valid_target_file": target,
		}},
	}
	payload, _ := json.Marshal(document)
	configPath := filepath.Join(directory, "config.json")
	if err := os.WriteFile(configPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadLiveConfig(configPath, 2*time.Second)
	if err != nil || len(config.Candidates) != 1 ||
		config.Candidates[0].ActiveBefore == nil ||
		config.Candidates[0].Revoked == nil ||
		config.Candidates[0].ActiveAfter == nil {
		t.Fatalf("config=%+v err=%v", config, err)
	}
	providers := document["providers"].([]map[string]any)
	providers[0]["valid_target_file"] = "relative-target"
	payload, _ = json.Marshal(document)
	if err := os.WriteFile(configPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadLiveConfig(configPath, 2*time.Second); err == nil {
		t.Fatal("relative secret path was accepted")
	}
}

func TestSignedFixtureAttestationCannotSatisfyLiveVerifier(t *testing.T) {
	directory := t.TempDir()
	privatePath, publicPath := testEd25519Pair(t, directory)
	now := time.Date(2026, time.August, 10, 12, 0, 0, 0, time.UTC)
	runner := &Runner{now: func() time.Time { return now }}
	observation, err := runner.Run(context.Background(), fixtureRunConfig())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := SignAttestation(AttestationInput{
		Observation: observation, ObservationSHA256: strings.Repeat("d", 64),
		ProviderAuditEvidenceSHA256: strings.Repeat("e", 64), Provider: "fixture",
		RevocationChangeStartedAt:   now.Add(-2 * time.Minute),
		RevocationChangeCompletedAt: now.Add(-time.Minute),
		VerifiedAt:                  now, ExpiresAt: now.Add(time.Hour), DevelopmentOnly: true,
	}, privatePath, "m72-audit-fixture-key")
	if err != nil {
		t.Fatal(err)
	}
	options := AttestationVerifyOptions{TrustedPublicKey: publicPath,
		ExpectedSigningKeyID: "m72-audit-fixture-key",
		ExpectedProvider:     "fixture", ExpectedProviderAuditSHA256: strings.Repeat("e", 64),
		EvaluationTime: now}
	if _, err := VerifyAttestation(payload, options); err != nil {
		t.Fatal(err)
	}
	options.RequireLive = true
	if _, err := VerifyAttestation(payload, options); err == nil {
		t.Fatal("fixture attestation satisfied live verifier")
	}
	tampered := bytesReplace(payload,
		[]byte(FixtureAttestationResult), []byte(LiveAttestationResult))
	options.RequireLive = false
	if _, err := VerifyAttestation(tampered, options); err == nil {
		t.Fatal("tampered attestation retained authority")
	}
}

func pemBlock(kind string, der []byte) []byte {
	return []byte(fmt.Sprintf("-----BEGIN %s-----\n%s-----END %s-----\n",
		kind, chunkBase64(der), kind))
}

func chunkBase64(value []byte) string {
	encoded := base64.StdEncoding.EncodeToString(value)
	var builder strings.Builder
	for len(encoded) > 64 {
		builder.WriteString(encoded[:64])
		builder.WriteByte('\n')
		encoded = encoded[64:]
	}
	builder.WriteString(encoded)
	builder.WriteByte('\n')
	return builder.String()
}

func testEd25519Pair(t *testing.T, directory string) (string, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, _ := x509.MarshalPKCS8PrivateKey(private)
	publicDER, _ := x509.MarshalPKIXPublicKey(public)
	privatePath := filepath.Join(directory, "private.pem")
	publicPath := filepath.Join(directory, "public.pem")
	if err := os.WriteFile(privatePath, pemBlock("PRIVATE KEY", privateDER), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, pemBlock("PUBLIC KEY", publicDER), 0o644); err != nil {
		t.Fatal(err)
	}
	return privatePath, publicPath
}

func bytesReplace(payload, old, replacement []byte) []byte {
	return []byte(strings.Replace(string(payload), string(old), string(replacement), 1))
}
