package auth

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func companionJWTFixture(t *testing.T) (*CompanionJWTIssuer,
	*CompanionJWTVerifier, time.Time) {
	t.Helper()
	seed := sha256.Sum256([]byte("companion-account-signing-key-1"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	issuer, err := NewCompanionJWTIssuer(privateKey, "account-key-1",
		"https://accounts.example/product", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewCompanionJWTVerifier(map[string]ed25519.PublicKey{
		"account-key-1": privateKey.Public().(ed25519.PublicKey),
	}, "https://accounts.example/product", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	issuer.now = func() time.Time { return now }
	issuer.random = strings.NewReader("0123456789abcdef")
	verifier.now = func() time.Time { return now }
	return issuer, verifier, now
}

func TestCompanionJWTRoundTripAndPublicKeyIsolation(t *testing.T) {
	issuer, verifier, now := companionJWTFixture(t)
	token, issued, err := issuer.Issue("user-1", "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := verifier.VerifyAuthorization("Bearer " + token)
	if err != nil {
		t.Fatal(err)
	}
	if claims != issued || claims.Issuer !=
		"https://accounts.example/product" ||
		claims.Expires != now.Add(5*time.Minute).Unix() ||
		claims.TokenID == "" || claims.Action != CompanionClaimAction {
		t.Fatalf("unexpected Companion JWT claims: %#v", claims)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("JWT compact serialization is malformed")
	}
	parts[1] = base64.RawURLEncoding.EncodeToString(
		[]byte(`{"sub":"attacker"}`))
	if _, err := verifier.Verify(strings.Join(parts, ".")); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered Companion JWT: %v", err)
	}
}

func TestCompanionJWTReleaseIsDeviceAndActionBound(t *testing.T) {
	issuer, verifier, _ := companionJWTFixture(t)
	token, issued, err := issuer.IssueRelease(
		"user-1", "tenant-1", "device-1")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := verifier.Verify(token)
	if err != nil || claims != issued ||
		claims.Action != CompanionReleaseAction ||
		claims.DeviceID != "device-1" {
		t.Fatalf("release claims: %#v %v", claims, err)
	}
	if _, _, err := issuer.IssueRelease(
		"user-1", "tenant-1", "device/unsafe"); !errors.Is(err, ErrClaims) {
		t.Fatalf("unsafe release device: %v", err)
	}
}

func TestCompanionJWTActionConsentIsDeviceAndActionBound(t *testing.T) {
	issuer, verifier, _ := companionJWTFixture(t)
	token, issued, err := issuer.IssueActionConsent(
		"user-1", "tenant-1", "device-1")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := verifier.Verify(token)
	if err != nil || claims != issued ||
		claims.Action != CompanionConsentAction ||
		claims.DeviceID != "device-1" {
		t.Fatalf("action consent claims: %#v %v", claims, err)
	}
	if _, _, err := issuer.IssueActionConsent(
		"user-1", "tenant-1", "device/unsafe"); !errors.Is(err, ErrClaims) {
		t.Fatalf("unsafe action consent device: %v", err)
	}
}

func TestCompanionJWTRejectsWrongIssuerKeyAndClaims(t *testing.T) {
	issuer, verifier, _ := companionJWTFixture(t)
	token, _, err := issuer.Issue("user-1", "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("wrong-companion-account-key"))
	wrongVerifier, err := NewCompanionJWTVerifier(map[string]ed25519.PublicKey{
		"account-key-1": ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey),
	}, "https://accounts.example/product", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongVerifier.Verify(token); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong account key: %v", err)
	}
	otherIssuer, err := NewCompanionJWTVerifier(verifier.keys,
		"https://other.example/product", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	otherIssuer.now = verifier.now
	if _, err := otherIssuer.Verify(token); !errors.Is(err, ErrClaims) {
		t.Fatalf("wrong account issuer: %v", err)
	}
	if _, _, err := issuer.Issue("user-1", ""); !errors.Is(err, ErrClaims) {
		t.Fatalf("missing tenant: %v", err)
	}
}

func TestCompanionJWTRejectsUnsafeConfigurationAndDuplicateFields(t *testing.T) {
	seed := sha256.Sum256([]byte("companion-account-signing-key-1"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	if _, err := NewCompanionJWTIssuer(privateKey, "account-key-1",
		"http://accounts.example", 5*time.Minute); err == nil {
		t.Fatal("insecure account issuer accepted")
	}
	if _, err := NewCompanionJWTVerifier(map[string]ed25519.PublicKey{
		"unsafe/key": privateKey.Public().(ed25519.PublicKey),
	}, "https://accounts.example", 5*time.Minute); err == nil {
		t.Fatal("unsafe account key id accepted")
	}
	var claims Claims
	if err := decodeStrictJSON([]byte(
		`{"sub":"user-1","sub":"user-2"}`), &claims); err == nil {
		t.Fatal("duplicate JWT claim accepted")
	}
}
