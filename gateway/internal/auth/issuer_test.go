package auth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestIssuerRoundTripAndUniqueJTI(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	now := time.Unix(1_800_000_000, 0)
	issuer, err := NewIssuer(secret, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	issuer.now = func() time.Time { return now }
	verifier, err := NewVerifier(secret, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	verifier.now = func() time.Time { return now }

	first, firstClaims, err := issuer.IssueOwned(
		"device-1", "owner-1", "tenant-1", "MDEyMzQ1Njc4OWFiY2RlZg", 7)
	if err != nil {
		t.Fatal(err)
	}
	second, secondClaims, err := issuer.IssueOwned(
		"device-1", "owner-1", "tenant-1", "MDEyMzQ1Njc4OWFiY2RlZg", 7)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || firstClaims.TokenID == secondClaims.TokenID {
		t.Fatal("issued tokens must have unique token ids")
	}
	verified, err := verifier.Verify(first)
	if err != nil {
		t.Fatal(err)
	}
	if verified.DeviceID != "device-1" || verified.IssuedAt != now.Unix() ||
		verified.OwnerID != "owner-1" || verified.TenantID != "tenant-1" ||
		verified.BindingID != "MDEyMzQ1Njc4OWFiY2RlZg" ||
		verified.BindingRevision != 7 ||
		verified.Expires != now.Add(15*time.Minute).Unix() || verified.TokenID == "" {
		t.Fatalf("unexpected claims: %#v", verified)
	}
	verifier.now = func() time.Time { return now.Add(16 * time.Minute) }
	if _, err := verifier.Verify(first); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired token: %v", err)
	}
}

func TestOwnedIssuerNeverOutlivesEntitlement(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	now := time.Unix(1_800_000_000, 0).UTC()
	issuer, err := NewIssuer(secret, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	issuer.now = func() time.Time { return now }
	_, claims, err := issuer.IssueOwnedUntil(
		"device-1", "owner-1", "tenant-1",
		"MDEyMzQ1Njc4OWFiY2RlZg", 7, now.Add(5*time.Minute))
	if err != nil || claims.Expires != now.Add(5*time.Minute).Unix() {
		t.Fatalf("claims=%#v err=%v", claims, err)
	}
	if _, _, err := issuer.IssueOwnedUntil(
		"device-1", "owner-1", "tenant-1",
		"MDEyMzQ1Njc4OWFiY2RlZg", 7,
		now.Add(59*time.Second)); !errors.Is(err, ErrClaims) {
		t.Fatalf("short entitlement window=%v", err)
	}
	if _, _, err := issuer.IssueOwnedUntil(
		"device-1", "owner-1", "tenant-1",
		"MDEyMzQ1Njc4OWFiY2RlZg", 7,
		now.Add(5*time.Minute).In(time.FixedZone("other", 0))); !errors.Is(err, ErrClaims) {
		t.Fatalf("non-UTC entitlement time=%v", err)
	}
}

func TestIssuerRejectsWeakKeyTTLAndDevice(t *testing.T) {
	if _, err := NewIssuer([]byte("weak"), time.Minute); err == nil {
		t.Fatal("expected weak key rejection")
	}
	secret := []byte("0123456789abcdef0123456789abcdef")
	for _, ttl := range []time.Duration{time.Second, 2 * time.Hour} {
		if _, err := NewIssuer(secret, ttl); err == nil {
			t.Fatalf("expected TTL %s rejection", ttl)
		}
	}
	issuer, err := NewIssuer(secret, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := issuer.IssueOwned(
		"device/unsafe", "owner-1", "tenant-1",
		"MDEyMzQ1Njc4OWFiY2RlZg", 1); !errors.Is(err, ErrClaims) {
		t.Fatalf("got %v", err)
	}
	if _, _, err := issuer.IssueOwned(
		"device-1", "owner-1", "tenant-1",
		"MDEyMzQ1Njc4OWFiY2RlZg",
		MaximumBindingRevision+1); !errors.Is(err, ErrClaims) {
		t.Fatalf("oversized binding revision: %v", err)
	}
}

func TestIssuerPropagatesRandomFailure(t *testing.T) {
	issuer, err := NewIssuer(
		[]byte("0123456789abcdef0123456789abcdef"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	issuer.random = strings.NewReader("")
	if _, _, err := issuer.IssueOwned(
		"device-1", "owner-1", "tenant-1",
		"MDEyMzQ1Njc4OWFiY2RlZg", 1); err == nil {
		t.Fatal("expected random source failure")
	}
}

func TestIssuerRejectsUnsafeAudience(t *testing.T) {
	if _, err := NewIssuerForAudience(
		[]byte("0123456789abcdef0123456789abcdef"), time.Minute,
		"agent/proxy"); err == nil {
		t.Fatal("expected unsafe audience rejection")
	}
}

func TestCompanionSubjectRoundTripAndIsolation(t *testing.T) {
	secret := []byte("companion-token-key-0123456789abcdef")
	now := time.Unix(1_800_000_000, 0)
	issuer, err := NewIssuerForAudience(secret, 5*time.Minute,
		CompanionAudience)
	if err != nil {
		t.Fatal(err)
	}
	issuer.now = func() time.Time { return now }
	issuer.random = strings.NewReader("0123456789abcdef")
	token, issued, err := issuer.IssueCompanion("user-123", "tenant-9")
	if err != nil {
		t.Fatal(err)
	}
	if issued.Subject != "user-123" || issued.TenantID != "tenant-9" ||
		issued.DeviceID != "" ||
		issued.TokenID == "" || issued.Action != CompanionClaimAction {
		t.Fatalf("unexpected companion claims: %#v", issued)
	}
	verifier, err := NewVerifierForAudience(secret, 5*time.Minute,
		CompanionAudience)
	if err != nil {
		t.Fatal(err)
	}
	verifier.now = func() time.Time { return now }
	verified, err := verifier.Verify(token)
	if err != nil || verified.Subject != "user-123" ||
		verified.TenantID != "tenant-9" {
		t.Fatalf("companion token: %#v %v", verified, err)
	}
	if _, _, err := issuer.Issue("user-123"); !errors.Is(err, ErrClaims) {
		t.Fatalf("companion issuer accepted device issuance: %v", err)
	}
	if _, _, err := issuer.IssueCompanion(
		"user-123", ""); !errors.Is(err, ErrClaims) {
		t.Fatalf("companion issuer inferred a missing tenant: %v", err)
	}
	issuer.random = strings.NewReader("fedcba9876543210")
	releaseToken, releaseClaims, err := issuer.IssueCompanionRelease(
		"user-123", "tenant-9", "device-1")
	if err != nil || releaseToken == "" ||
		releaseClaims.Action != CompanionReleaseAction ||
		releaseClaims.DeviceID != "device-1" {
		t.Fatalf("release token: %#v %v", releaseClaims, err)
	}
	issuer.random = strings.NewReader("0011223344556677")
	consentToken, consentClaims, err := issuer.IssueCompanionActionConsent(
		"user-123", "tenant-9", "device-1")
	if err != nil || consentToken == "" ||
		consentClaims.Action != CompanionConsentAction ||
		consentClaims.DeviceID != "device-1" {
		t.Fatalf("action consent token: %#v %v", consentClaims, err)
	}
	deviceVerifier, err := NewVerifier(secret, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	deviceVerifier.now = func() time.Time { return now }
	if _, err := deviceVerifier.Verify(token); !errors.Is(err, ErrClaims) {
		t.Fatalf("device verifier accepted companion token: %v", err)
	}
}
