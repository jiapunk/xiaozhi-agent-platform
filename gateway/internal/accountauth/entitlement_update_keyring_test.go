package accountauth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func entitlementUpdateKeyringFixture(t *testing.T, now time.Time) (
	*EntitlementUpdateKeyring, ed25519.PrivateKey) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	document := entitlementUpdateKeyringDocument{
		Schema: ServiceEntitlementUpdateKeyringSchema, Revision: 7,
		Keys: []entitlementUpdateKeyringDocumentKey{{
			KeyID: "billing-adapter-1",
			PublicKeyBase64URL: base64.RawURLEncoding.EncodeToString(
				privateKey.Public().(ed25519.PublicKey)),
			State: "active", VerifyUntilUnix: now.Add(24 * time.Hour).Unix(),
		}},
	}
	keyring, err := buildEntitlementUpdateKeyring(document, 7, now)
	if err != nil {
		t.Fatal(err)
	}
	return keyring, privateKey
}

func writeEntitlementUpdateKeyringDocument(t *testing.T,
	document entitlementUpdateKeyringDocument) string {
	t.Helper()
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "entitlement-update-keyring.json")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadEntitlementUpdateKeyringSupportsBoundedRotation(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	privateA := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	seedB := make([]byte, ed25519.SeedSize)
	seedB[0] = 1
	privateB := ed25519.NewKeyFromSeed(seedB)
	document := entitlementUpdateKeyringDocument{
		Schema: ServiceEntitlementUpdateKeyringSchema, Revision: 9,
		Keys: []entitlementUpdateKeyringDocumentKey{
			{KeyID: "billing-adapter-1",
				PublicKeyBase64URL: base64.RawURLEncoding.EncodeToString(
					privateA.Public().(ed25519.PublicKey)),
				State: "retiring", VerifyUntilUnix: now.Add(time.Hour).Unix()},
			{KeyID: "billing-adapter-2",
				PublicKeyBase64URL: base64.RawURLEncoding.EncodeToString(
					privateB.Public().(ed25519.PublicKey)),
				State: "active", VerifyUntilUnix: now.Add(24 * time.Hour).Unix()},
		},
	}
	path := writeEntitlementUpdateKeyringDocument(t, document)
	keyring, err := LoadEntitlementUpdateKeyring(path, 9, now)
	if err != nil || keyring.Revision() != 9 || len(keyring.keys) != 2 {
		t.Fatalf("keyring=%#v err=%v", keyring, err)
	}
	message := []byte("normalized-entitlement-event")
	for keyID, privateKey := range map[string]ed25519.PrivateKey{
		"billing-adapter-1": privateA,
		"billing-adapter-2": privateB,
	} {
		signature := ed25519.Sign(privateKey, message)
		if !keyring.verify(keyID, message, signature,
			now.Add(5*time.Minute), now) {
			t.Fatalf("rotation key %s did not verify", keyID)
		}
	}
	if _, err := LoadEntitlementUpdateKeyring(path, 10, now); err == nil {
		t.Fatal("rollback below the approved revision floor was accepted")
	}
}

func TestLoadEntitlementUpdateKeyringRejectsUnsafeTrustFiles(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	document := entitlementUpdateKeyringDocument{
		Schema: ServiceEntitlementUpdateKeyringSchema, Revision: 1,
		Keys: []entitlementUpdateKeyringDocumentKey{{
			KeyID: "billing-adapter-1",
			PublicKeyBase64URL: base64.RawURLEncoding.EncodeToString(
				privateKey.Public().(ed25519.PublicKey)),
			State: "active", VerifyUntilUnix: now.Add(time.Hour).Unix(),
		}},
	}
	path := writeEntitlementUpdateKeyringDocument(t, document)
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEntitlementUpdateKeyring(path, 1, now); err == nil {
		t.Fatal("group/world-readable trust file was accepted")
	}

	path = writeEntitlementUpdateKeyringDocument(t, document)
	symlink := filepath.Join(t.TempDir(), "entitlement-update-keyring.json")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEntitlementUpdateKeyring(symlink, 1, now); err == nil {
		t.Fatal("symlink trust file was accepted")
	}

	document.Keys[0].State = "retiring"
	if _, err := LoadEntitlementUpdateKeyring(
		writeEntitlementUpdateKeyringDocument(t, document), 1, now); err == nil {
		t.Fatal("keyring without exactly one active key was accepted")
	}
}
