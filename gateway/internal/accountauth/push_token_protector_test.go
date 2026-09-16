package accountauth

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func pushProtectorFixture(t *testing.T) (*AESGCMPushTokenProtector, PushTokenBinding) {
	t.Helper()
	protector, err := NewAESGCMPushTokenProtector("push-kek-2",
		map[string]PushTokenKeyMaterial{
			"push-kek-1": {EncryptionKey: bytes.Repeat([]byte{1}, 32),
				LookupKey: bytes.Repeat([]byte{2}, 32)},
			"push-kek-2": {EncryptionKey: bytes.Repeat([]byte{3}, 32),
				LookupKey: bytes.Repeat([]byte{4}, 32)},
		})
	if err != nil {
		t.Fatal(err)
	}
	protector.random = bytes.NewReader(bytes.Repeat([]byte{9}, 256))
	return protector, PushTokenBinding{
		Principal:      Principal{TenantID: "tenant-1", Subject: "user-1"},
		InstallationID: pushInstallationID(1), Platform: PushPlatformFCM,
	}
}

func TestPushTokenProtectorRoundTripAndBinding(t *testing.T) {
	protector, binding := pushProtectorFixture(t)
	raw := "fcm-token:abcdefghijklmnopqrstuvwxyz_0123456789"
	protected, err := protector.Seal(context.Background(), binding, raw)
	if err != nil || protected.KeyID != "push-kek-2" ||
		bytes.Contains(protected.Ciphertext, []byte(raw)) {
		t.Fatalf("seal: %#v %v", protected, err)
	}
	opened, err := protector.Open(context.Background(), binding, protected)
	if err != nil || opened != raw {
		t.Fatalf("open=%q err=%v", opened, err)
	}

	changed := binding
	changed.InstallationID = pushInstallationID(2)
	if _, err := protector.Open(context.Background(), changed,
		protected); !errors.Is(err, ErrPushTokenAuthentication) {
		t.Fatalf("ciphertext moved across installation: %v", err)
	}
	tampered := cloneProtectedPushToken(protected)
	tampered.Digest[0] ^= 1
	if _, err := protector.Open(context.Background(), binding,
		tampered); !errors.Is(err, ErrPushTokenAuthentication) {
		t.Fatalf("digest mutation accepted: %v", err)
	}
}

func TestPushTokenProtectorReadsOldKeyDuringRotation(t *testing.T) {
	old, err := NewAESGCMPushTokenProtector("push-kek-1",
		map[string]PushTokenKeyMaterial{
			"push-kek-1": {EncryptionKey: bytes.Repeat([]byte{1}, 32),
				LookupKey: bytes.Repeat([]byte{2}, 32)},
		})
	if err != nil {
		t.Fatal(err)
	}
	old.random = bytes.NewReader(bytes.Repeat([]byte{7}, 64))
	_, binding := pushProtectorFixture(t)
	raw := "fcm-token:abcdefghijklmnopqrstuvwxyz_0123456789"
	protected, err := old.Seal(context.Background(), binding, raw)
	if err != nil {
		t.Fatal(err)
	}
	rotated, _ := pushProtectorFixture(t)
	opened, err := rotated.Open(context.Background(), binding, protected)
	if err != nil || opened != raw {
		t.Fatalf("old key unavailable during rotation: %q %v", opened, err)
	}
}

func TestRawProviderTokenValidationIsBoundedAndCanonical(t *testing.T) {
	apns := strings.Repeat("ab", 32)
	if !ValidRawPushToken(PushPlatformAPNSProduction, apns) ||
		ValidRawPushToken(PushPlatformAPNSProduction, strings.ToUpper(apns)) ||
		ValidRawPushToken(PushPlatformAPNSProduction, "raw-token") {
		t.Fatal("APNs canonical token validation failed")
	}
	if !ValidRawPushToken(PushPlatformFCM,
		"fcm-token:abcdefghijklmnopqrstuvwxyz_0123456789") ||
		ValidRawPushToken(PushPlatformFCM, "token with spaces") ||
		ValidRawPushToken(PushPlatformFCM, strings.Repeat("x", 4097)) {
		t.Fatal("FCM bounded token validation failed")
	}
}

func TestPushTokenProtectorRejectsSharedOrMissingKeys(t *testing.T) {
	shared := bytes.Repeat([]byte{1}, 32)
	for _, testCase := range []struct {
		current string
		keys    map[string]PushTokenKeyMaterial
	}{
		{"missing", map[string]PushTokenKeyMaterial{"present": {
			EncryptionKey: bytes.Repeat([]byte{1}, 32), LookupKey: bytes.Repeat([]byte{2}, 32)}}},
		{"shared", map[string]PushTokenKeyMaterial{"shared": {
			EncryptionKey: shared, LookupKey: shared}}},
	} {
		if _, err := NewAESGCMPushTokenProtector(testCase.current,
			testCase.keys); !errors.Is(err, ErrInvalid) {
			t.Fatalf("unsafe keyring accepted: %v", err)
		}
	}
}
