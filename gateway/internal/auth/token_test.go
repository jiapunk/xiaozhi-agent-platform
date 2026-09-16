package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func signTestTokenVersion(t *testing.T, secret []byte, version string,
	claims Claims) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	input := version + "." + encoded
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func signTestToken(t *testing.T, secret []byte, claims Claims) string {
	t.Helper()
	version := "v1"
	if claims.Audience == VoiceAudience || claims.Audience == AgentAudience {
		version = "v3"
	}
	return signTestTokenVersion(t, secret, version, claims)
}

func testVerifier(t *testing.T) (*Verifier, []byte, time.Time) {
	t.Helper()
	secret := []byte("0123456789abcdef0123456789abcdef")
	now := time.Unix(1_800_000_000, 0)
	verifier, err := NewVerifier(secret, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	verifier.now = func() time.Time { return now }
	return verifier, secret, now
}

func TestVerifyAuthorization(t *testing.T) {
	verifier, secret, now := testVerifier(t)
	token := signTestToken(t, secret, Claims{
		DeviceID: "device:01",
		OwnerID:  "owner-1", TenantID: "tenant-1",
		BindingID: "MDEyMzQ1Njc4OWFiY2RlZg", BindingRevision: 1,
		Audience: VoiceAudience,
		IssuedAt: now.Add(-time.Minute).Unix(),
		Expires:  now.Add(5 * time.Minute).Unix(),
		TokenID:  "token-1",
	})
	claims, err := verifier.VerifyAuthorization("Bearer " + token)
	if err != nil {
		t.Fatal(err)
	}
	if claims.DeviceID != "device:01" {
		t.Fatalf("unexpected device: %q", claims.DeviceID)
	}
}

func TestRejectsInvalidTokens(t *testing.T) {
	verifier, secret, now := testVerifier(t)
	valid := Claims{
		DeviceID: "device-1",
		OwnerID:  "owner-1", TenantID: "tenant-1",
		BindingID: "MDEyMzQ1Njc4OWFiY2RlZg", BindingRevision: 1,
		Audience: VoiceAudience,
		IssuedAt: now.Add(-time.Minute).Unix(),
		Expires:  now.Add(5 * time.Minute).Unix(),
		TokenID:  "token-1",
	}
	cases := []struct {
		name   string
		token  string
		target error
	}{
		{"malformed", "not-a-token", ErrMalformed},
		{"signature", signTestToken(t, []byte("abcdef0123456789abcdef0123456789"), valid), ErrSignature},
		{"expired", signTestToken(t, secret, Claims{DeviceID: "device-1", Audience: VoiceAudience, IssuedAt: now.Add(-10 * time.Minute).Unix(), Expires: now.Add(-time.Minute).Unix()}), ErrExpired},
		{"wrong audience", signTestToken(t, secret, Claims{DeviceID: "device-1", Audience: "other", IssuedAt: now.Unix(), Expires: now.Add(time.Minute).Unix()}), ErrClaims},
		{"long ttl", signTestToken(t, secret, Claims{DeviceID: "device-1", Audience: VoiceAudience, IssuedAt: now.Unix(), Expires: now.Add(time.Hour).Unix()}), ErrClaims},
		{"unsafe device id", signTestToken(t, secret, Claims{DeviceID: "device/../1", Audience: VoiceAudience, IssuedAt: now.Unix(), Expires: now.Add(time.Minute).Unix()}), ErrClaims},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := verifier.Verify(test.token)
			if !errors.Is(err, test.target) {
				t.Fatalf("got %v, want %v", err, test.target)
			}
		})
	}
}

func TestRequiresStrongSecret(t *testing.T) {
	if _, err := NewVerifier([]byte("short"), time.Minute); err == nil {
		t.Fatal("expected a short secret to fail")
	}
}

func TestKeyringAcceptsCurrentAndPreviousKeys(t *testing.T) {
	current := []byte("current-key-0123456789abcdef012345")
	previous := []byte("previous-key-0123456789abcdef0123")
	now := time.Now()
	verifier, err := NewKeyringVerifier([][]byte{current, previous}, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	claims := Claims{
		DeviceID: "device-1", Audience: VoiceAudience,
		OwnerID: "owner-1", TenantID: "tenant-1",
		BindingID: "MDEyMzQ1Njc4OWFiY2RlZg", BindingRevision: 1,
		IssuedAt: now.Add(-time.Minute).Unix(), Expires: now.Add(time.Minute).Unix(),
		TokenID: "token-1",
	}
	for _, key := range [][]byte{current, previous} {
		if _, err := verifier.Verify(signTestToken(t, key, claims)); err != nil {
			t.Fatalf("keyring rejected a rotation key: %v", err)
		}
	}
}

func TestAudienceIsolation(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	now := time.Unix(1_800_000_000, 0)
	issuer, err := NewIssuerForAudience(secret, 5*time.Minute, AgentAudience)
	if err != nil {
		t.Fatal(err)
	}
	issuer.now = func() time.Time { return now }
	agentVerifier, err := NewVerifierForAudience(secret, 5*time.Minute, AgentAudience)
	if err != nil {
		t.Fatal(err)
	}
	voiceVerifier, err := NewVerifier(secret, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	agentVerifier.now = func() time.Time { return now }
	voiceVerifier.now = func() time.Time { return now }
	token, claims, err := issuer.IssueOwned(
		"device-1", "owner-1", "tenant-1",
		"MDEyMzQ1Njc4OWFiY2RlZg", 7)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Audience != AgentAudience {
		t.Fatalf("unexpected audience: %q", claims.Audience)
	}
	if _, err := agentVerifier.Verify(token); err != nil {
		t.Fatal(err)
	}
	if _, err := voiceVerifier.Verify(token); !errors.Is(err, ErrClaims) {
		t.Fatalf("voice verifier accepted Agent token: %v", err)
	}
}

func TestOwnedServiceTokenRejectsOldVersionsAndMissingAuthorizationScope(t *testing.T) {
	verifier, secret, now := testVerifier(t)
	owned := Claims{
		DeviceID: "device-1", OwnerID: "owner-1", TenantID: "tenant-1",
		BindingID: "MDEyMzQ1Njc4OWFiY2RlZg", BindingRevision: 7,
		Audience: VoiceAudience, IssuedAt: now.Unix(),
		Expires: now.Add(5 * time.Minute).Unix(), TokenID: "token-1",
	}
	if _, err := verifier.Verify(signTestTokenVersion(
		t, secret, "v1", owned)); !errors.Is(err, ErrClaims) {
		t.Fatalf("v1 ownership downgrade accepted: %v", err)
	}
	if _, err := verifier.Verify(signTestTokenVersion(
		t, secret, "v2", owned)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("v2 ownership downgrade accepted: %v", err)
	}
	owned.TenantID = ""
	if _, err := verifier.Verify(signTestToken(
		t, secret, owned)); !errors.Is(err, ErrClaims) {
		t.Fatalf("missing tenant accepted: %v", err)
	}
	owned.TenantID = "tenant-1"
	owned.TokenID = ""
	if _, err := verifier.Verify(signTestToken(
		t, secret, owned)); !errors.Is(err, ErrClaims) {
		t.Fatalf("missing token id accepted: %v", err)
	}
	owned.TokenID = "token-1"
	owned.BindingRevision = MaximumBindingRevision + 1
	if _, err := verifier.Verify(signTestToken(
		t, secret, owned)); !errors.Is(err, ErrClaims) {
		t.Fatalf("oversized binding revision accepted: %v", err)
	}
	owned.BindingRevision = 7
	scope, ok := OwnedDeviceScope(owned)
	if !ok || scope != "MDEyMzQ1Njc4OWFiY2RlZg\x007\x00device-1" {
		t.Fatalf("unexpected ownership scope: %q %v", scope, ok)
	}
}

func TestOTAReleaseTokenIsAudienceAndObjectBound(t *testing.T) {
	secret := []byte("ota-token-key-0123456789abcdef0123456")
	now := time.Unix(1_800_000_000, 0)
	issuer, err := NewIssuerForAudience(secret, 3*time.Minute, OTAAudience)
	if err != nil {
		t.Fatal(err)
	}
	issuer.now = func() time.Time { return now }
	issuer.random = strings.NewReader("0123456789abcdef")
	digest := strings.Repeat("a", 64)
	token, issued, err := issuer.IssueForRelease(
		"device-1", "box3-development-0015", digest)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifierForAudience(secret, 5*time.Minute, OTAAudience)
	if err != nil {
		t.Fatal(err)
	}
	verifier.now = func() time.Time { return now }
	claims, err := verifier.VerifyAuthorizationForRelease(
		"Bearer "+token, issued.ReleaseID, issued.ImageSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if claims.DeviceID != "device-1" || claims.Audience != OTAAudience ||
		claims.TokenID == "" || claims.Expires-claims.IssuedAt != 180 {
		t.Fatalf("unexpected OTA claims: %#v", claims)
	}
	if _, err := verifier.VerifyAuthorizationForRelease(
		"Bearer "+token, "box3-development-0016", digest); !errors.Is(err, ErrClaims) {
		t.Fatalf("cross-release token: %v", err)
	}
	if _, err := verifier.VerifyAuthorizationForRelease(
		"Bearer "+token, issued.ReleaseID, strings.Repeat("b", 64)); !errors.Is(err, ErrClaims) {
		t.Fatalf("cross-image token: %v", err)
	}
	voiceVerifier, err := NewVerifierForAudience(secret, 5*time.Minute,
		VoiceAudience)
	if err != nil {
		t.Fatal(err)
	}
	voiceVerifier.now = func() time.Time { return now }
	if _, err := voiceVerifier.Verify(token); !errors.Is(err, ErrClaims) {
		t.Fatalf("voice verifier accepted OTA token: %v", err)
	}
	if _, _, err := issuer.Issue("device-1"); !errors.Is(err, ErrClaims) {
		t.Fatalf("generic issuance accepted OTA audience: %v", err)
	}
}
