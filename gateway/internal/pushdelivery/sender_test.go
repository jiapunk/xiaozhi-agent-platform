package pushdelivery

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"

	"xiaozhi-agent-platform/gateway/internal/accountauth"
	"xiaozhi-agent-platform/gateway/internal/actionconsent"
)

type providerStub struct {
	results map[string]DeliveryResult
	mu      sync.Mutex
	tokens  []string
}

func (stub *providerStub) Send(_ context.Context, token string) (
	DeliveryResult, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.tokens = append(stub.tokens, token)
	result := stub.results[token]
	if result == DeliveryRetry {
		return result, ErrUnavailable
	}
	return result, nil
}

func (stub *providerStub) tokenCount() int {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return len(stub.tokens)
}

func deliveryInstallationID(value byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, 16))
}

func deliveryFixture(t *testing.T) (*accountauth.Store,
	*accountauth.AESGCMPushTokenProtector, accountauth.Session,
	actionconsent.Actor) {
	t.Helper()
	store, err := accountauth.NewStore(1024)
	if err != nil {
		t.Fatal(err)
	}
	principal := accountauth.Principal{TenantID: "tenant-1", Subject: "user-1"}
	session, err := store.BeginAuthenticatedSession(context.Background(), principal)
	if err != nil {
		t.Fatal(err)
	}
	protector, err := accountauth.NewAESGCMPushTokenProtector("push-kek-1",
		map[string]accountauth.PushTokenKeyMaterial{
			"push-kek-1": {EncryptionKey: bytes.Repeat([]byte{1}, 32),
				LookupKey: bytes.Repeat([]byte{2}, 32)},
		})
	if err != nil {
		t.Fatal(err)
	}
	return store, protector, session, actionconsent.Actor{
		OwnerID: principal.Subject, TenantID: principal.TenantID,
		DeviceID: "device-1", OwnerRevision: 1,
	}
}

func registerDeliveryToken(t *testing.T, store accountauth.PushInstallationStore,
	protector accountauth.PushTokenProtector, session accountauth.Session,
	id byte, raw string) accountauth.PushInstallation {
	t.Helper()
	binding := accountauth.PushTokenBinding{Principal: session.Principal,
		InstallationID: deliveryInstallationID(id), Platform: accountauth.PushPlatformFCM}
	protected, err := protector.Seal(context.Background(), binding, raw)
	if err != nil {
		t.Fatal(err)
	}
	installation, err := store.UpsertPushInstallation(context.Background(), session,
		accountauth.PushInstallationRegistration{InstallationID: binding.InstallationID,
			Platform: binding.Platform, Token: protected})
	if err != nil {
		t.Fatal(err)
	}
	return installation
}

func TestWakeSenderFansOutAndCASRemovesInvalidToken(t *testing.T) {
	store, protector, session, actor := deliveryFixture(t)
	acceptedToken := "fcm-token:accepted-abcdefghijklmnopqrstuvwxyz"
	invalidToken := "fcm-token:invalid-abcdefghijklmnopqrstuvwxyz"
	registerDeliveryToken(t, store, protector, session, 1, acceptedToken)
	invalid := registerDeliveryToken(t, store, protector, session, 2, invalidToken)
	provider := &providerStub{results: map[string]DeliveryResult{
		acceptedToken: DeliveryAccepted,
		invalidToken:  DeliveryInvalidInstallation,
	}}
	sender, err := NewWakeSender(store, protector,
		map[accountauth.PushPlatform]Provider{accountauth.PushPlatformFCM: provider})
	if err != nil {
		t.Fatal(err)
	}
	disposition, err := sender.SendWake(context.Background(), actor,
		actionconsent.WakeContract, actionconsent.CanonicalWakePayload())
	if err != nil || disposition != actionconsent.WakeSendAccepted ||
		provider.tokenCount() != 2 {
		t.Fatalf("disposition=%d tokens=%#v err=%v", disposition,
			provider.tokens, err)
	}
	active, err := store.ActivePushInstallations(context.Background(), session.Principal)
	if err != nil || len(active) != 1 ||
		active[0].InstallationID == invalid.InstallationID {
		t.Fatalf("invalid token not removed: %#v %v", active, err)
	}
}

func TestWakeSenderRetriesWithoutDeletingTemporaryFailure(t *testing.T) {
	store, protector, session, actor := deliveryFixture(t)
	raw := "fcm-token:retry-abcdefghijklmnopqrstuvwxyz"
	installation := registerDeliveryToken(t, store, protector, session, 1, raw)
	provider := &providerStub{results: map[string]DeliveryResult{raw: DeliveryRetry}}
	sender, _ := NewWakeSender(store, protector,
		map[accountauth.PushPlatform]Provider{accountauth.PushPlatformFCM: provider})
	disposition, err := sender.SendWake(context.Background(), actor,
		actionconsent.WakeContract, actionconsent.CanonicalWakePayload())
	if disposition != actionconsent.WakeSendRetry || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("disposition=%d err=%v", disposition, err)
	}
	active, _ := store.ActivePushInstallations(context.Background(), session.Principal)
	if len(active) != 1 || active[0].InstallationID != installation.InstallationID {
		t.Fatalf("temporary failure deleted installation: %#v", active)
	}
}

func TestWakeSenderHasNoAuthorityFromMutatedPayload(t *testing.T) {
	store, protector, _, actor := deliveryFixture(t)
	provider := &providerStub{results: map[string]DeliveryResult{}}
	sender, _ := NewWakeSender(store, protector,
		map[accountauth.PushPlatform]Provider{accountauth.PushPlatformFCM: provider})
	mutated := append(actionconsent.CanonicalWakePayload(), '\n')
	disposition, err := sender.SendWake(context.Background(), actor,
		actionconsent.WakeContract, mutated)
	if disposition != actionconsent.WakeSendRetry || !errors.Is(err, ErrInvalid) ||
		provider.tokenCount() != 0 {
		t.Fatalf("mutated payload disposition=%d tokens=%#v err=%v",
			disposition, provider.tokens, err)
	}
}
