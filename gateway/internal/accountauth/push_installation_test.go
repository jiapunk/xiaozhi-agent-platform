package accountauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"
)

func pushInstallationFixture(t *testing.T) (*Store, Principal, Session, *time.Time) {
	t.Helper()
	store, err := NewStore(1024)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	principal := Principal{TenantID: "tenant-1", Subject: "user-1"}
	session, err := store.BeginAuthenticatedSession(context.Background(), principal)
	if err != nil {
		t.Fatal(err)
	}
	return store, principal, session, &now
}

func pushInstallationID(value byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, 16))
}

func protectedPushToken(value string) ProtectedPushToken {
	digest := sha256.Sum256([]byte("digest:" + value))
	return ProtectedPushToken{
		Ciphertext: bytes.Repeat([]byte(value), 48),
		KeyID:      "push-kek-1",
		Digest:     digest,
	}
}

func TestPushInstallationRotationUsesAccountFenceAndDigestCAS(t *testing.T) {
	store, principal, session, now := pushInstallationFixture(t)
	registration := PushInstallationRegistration{
		InstallationID: pushInstallationID(1),
		Platform:       PushPlatformAPNSProduction,
		Token:          protectedPushToken("a"),
	}
	first, err := store.UpsertPushInstallation(context.Background(), session,
		registration)
	if err != nil || first.AccountRevision != 1 ||
		first.ValidUntil.Sub(first.RefreshedAt) != MaximumPushInstallationLifetime {
		t.Fatalf("first registration: %#v %v", first, err)
	}
	registration.Token.Ciphertext[0] ^= 0xff
	active, err := store.ActivePushInstallations(context.Background(), principal)
	if err != nil || len(active) != 1 ||
		active[0].Token.Ciphertext[0] == registration.Token.Ciphertext[0] {
		t.Fatalf("stored token was aliased: %#v %v", active, err)
	}

	oldDigest := first.Token.Digest
	*now = now.Add(time.Hour)
	rotatedRegistration := PushInstallationRegistration{
		InstallationID: first.InstallationID,
		Platform:       PushPlatformAPNSProduction,
		Token:          protectedPushToken("b"),
	}
	rotated, err := store.UpsertPushInstallation(context.Background(), session,
		rotatedRegistration)
	if err != nil || !rotated.RegisteredAt.Equal(first.RegisteredAt) ||
		!rotated.RefreshedAt.Equal(*now) {
		t.Fatalf("rotated registration: %#v %v", rotated, err)
	}
	if err := store.InvalidatePushInstallation(context.Background(), principal,
		rotated.InstallationID, oldDigest); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old provider response invalidated new token: %v", err)
	}
	active, _ = store.ActivePushInstallations(context.Background(), principal)
	if len(active) != 1 || active[0].Token.Digest != rotated.Token.Digest {
		t.Fatalf("rotated token disappeared: %#v", active)
	}
	if err := store.InvalidatePushInstallation(context.Background(), principal,
		rotated.InstallationID, rotated.Token.Digest); err != nil {
		t.Fatal(err)
	}
	active, _ = store.ActivePushInstallations(context.Background(), principal)
	if len(active) != 0 {
		t.Fatalf("invalid token remained active: %#v", active)
	}
}

func TestPushInstallationsAreRemovedByLogoutAndExpire(t *testing.T) {
	store, principal, session, now := pushInstallationFixture(t)
	registration := PushInstallationRegistration{
		InstallationID: pushInstallationID(2), Platform: PushPlatformFCM,
		Token: protectedPushToken("c"),
	}
	if _, err := store.UpsertPushInstallation(context.Background(), session,
		registration); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Logout(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	active, err := store.ActivePushInstallations(context.Background(), principal)
	if err != nil || len(active) != 0 {
		t.Fatalf("logged-out installation active: %#v %v", active, err)
	}
	if _, err := store.UpsertPushInstallation(context.Background(), session,
		registration); !errors.Is(err, ErrStaleSession) {
		t.Fatalf("stale session registered installation: %v", err)
	}

	newSession, err := store.BeginAuthenticatedSession(context.Background(), principal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.UpsertPushInstallation(context.Background(), newSession,
		registration); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(MaximumPushInstallationLifetime + time.Second)
	active, err = store.ActivePushInstallations(context.Background(), principal)
	if err != nil || len(active) != 0 {
		t.Fatalf("expired installation active: %#v %v", active, err)
	}
}

func TestPushInstallationCapacityAndCrossAccountTokenConflict(t *testing.T) {
	store, _, session, _ := pushInstallationFixture(t)
	for index := 0; index < MaximumPushInstallationsPerAccount; index++ {
		registration := PushInstallationRegistration{
			InstallationID: pushInstallationID(byte(index + 1)),
			Platform:       PushPlatformFCM,
			Token:          protectedPushToken(fmt.Sprintf("token-%d", index)),
		}
		if _, err := store.UpsertPushInstallation(context.Background(), session,
			registration); err != nil {
			t.Fatalf("registration %d: %v", index, err)
		}
	}
	overflow := PushInstallationRegistration{
		InstallationID: pushInstallationID(99), Platform: PushPlatformFCM,
		Token: protectedPushToken("overflow"),
	}
	if _, err := store.UpsertPushInstallation(context.Background(), session,
		overflow); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity not enforced: %v", err)
	}

	other := Principal{TenantID: "tenant-1", Subject: "user-2"}
	otherSession, err := store.BeginAuthenticatedSession(context.Background(), other)
	if err != nil {
		t.Fatal(err)
	}
	conflict := PushInstallationRegistration{
		InstallationID: pushInstallationID(100), Platform: PushPlatformFCM,
		Token: protectedPushToken("token-0"),
	}
	if _, err := store.UpsertPushInstallation(context.Background(), otherSession,
		conflict); !errors.Is(err, ErrConflict) {
		t.Fatalf("cross-account provider token accepted: %v", err)
	}
}

func TestPushInstallationValidationRejectsNoncanonicalAndUnprotectedData(t *testing.T) {
	store, _, session, _ := pushInstallationFixture(t)
	tests := []PushInstallationRegistration{
		{InstallationID: "not-an-installation", Platform: PushPlatformFCM,
			Token: protectedPushToken("a")},
		{InstallationID: pushInstallationID(1), Platform: "webpush",
			Token: protectedPushToken("a")},
		{InstallationID: pushInstallationID(1), Platform: PushPlatformFCM,
			Token: ProtectedPushToken{Ciphertext: []byte("raw"), KeyID: "push-kek-1"}},
	}
	for _, registration := range tests {
		if _, err := store.UpsertPushInstallation(context.Background(), session,
			registration); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid registration accepted: %#v %v", registration, err)
		}
	}
}
