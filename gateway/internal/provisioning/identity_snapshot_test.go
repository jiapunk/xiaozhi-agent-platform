package provisioning

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func identityTestKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := []byte("identity-snapshot-test-seed-0001")
	privateKey := ed25519.NewKeyFromSeed(seed)
	return privateKey.Public().(ed25519.PublicKey), privateKey
}

func unsignedIdentityJSON(revision uint64, disabled bool,
	issuedAt, validUntil time.Time) string {
	return `{"version":2,"revision":` + formatUint(revision) +
		`,"purpose":"proof"` +
		`,"issued_at":"` + issuedAt.UTC().Format(time.RFC3339) +
		`","valid_until":"` + validUntil.UTC().Format(time.RFC3339) +
		`","devices":[{"device_id":"device-1","secret_b64":"` +
		base64.RawURLEncoding.EncodeToString(testDeviceSecret) +
		`","board":"esp32s3-box3","ota_channel":"development","disabled":` +
		map[bool]string{true: "true", false: "false"}[disabled] + `}]}`
}

func formatUint(value uint64) string {
	if value == 0 {
		return "0"
	}
	var result [20]byte
	index := len(result)
	for value > 0 {
		index--
		result[index] = byte('0' + value%10)
		value /= 10
	}
	return string(result[index:])
}

func signedIdentity(t *testing.T, revision uint64, disabled bool,
	issuedAt, validUntil, now time.Time) ([]byte, *Snapshot) {
	t.Helper()
	publicKey, privateKey := identityTestKey()
	payload, err := SignRegistrySnapshot(strings.NewReader(unsignedIdentityJSON(
		revision, disabled, issuedAt, validUntil)), "identity-test-1",
		privateKey, now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := ParseSignedRegistrySnapshot(bytesReader(payload), publicKey,
		"identity-test-1", now)
	if err != nil {
		t.Fatal(err)
	}
	return payload, snapshot
}

func bytesReader(payload []byte) *strings.Reader {
	return strings.NewReader(string(payload))
}

func TestSignedIdentitySnapshotApplyRollbackEquivocationAndExpiry(t *testing.T) {
	clock := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	_, initial := signedIdentity(t, 41, false, clock.Add(-time.Minute),
		clock.Add(10*time.Minute), clock)
	registry, err := NewRegistryFromSnapshot(initial, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	if !registry.Ready() || !registry.DeviceAllowed("device-1") {
		t.Fatal("initial signed identity did not authorize device")
	}
	_, revoked := signedIdentity(t, 42, true, clock,
		clock.Add(10*time.Minute), clock)
	changed, err := registry.ApplySnapshot(revoked)
	if err != nil || !changed || registry.DeviceAllowed("device-1") {
		t.Fatalf("revoke update: changed=%v allowed=%v err=%v",
			changed, registry.DeviceAllowed("device-1"), err)
	}
	if changed, err := registry.ApplySnapshot(initial); changed ||
		!errors.Is(err, ErrSnapshotRollback) {
		t.Fatalf("rollback result: changed=%v err=%v", changed, err)
	}
	_, equivocation := signedIdentity(t, 42, false, clock,
		clock.Add(10*time.Minute), clock)
	if changed, err := registry.ApplySnapshot(equivocation); changed ||
		!errors.Is(err, ErrSnapshotEquivocation) {
		t.Fatalf("equivocation result: changed=%v err=%v", changed, err)
	}
	clock = clock.Add(11 * time.Minute)
	if registry.Ready() || registry.DeviceAllowed("device-1") {
		t.Fatal("expired identity snapshot did not fail closed")
	}
}

func TestSignedIdentityRejectsTamperWrongKeyAndNonCanonicalInput(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey := identityTestKey()
	signed, _ := signedIdentity(t, 1, false, now,
		now.Add(10*time.Minute), now)
	tampered := strings.Replace(string(signed), `"revision": 1`,
		`"revision": 2`, 1)
	if _, err := ParseSignedRegistrySnapshot(strings.NewReader(tampered),
		publicKey, "identity-test-1", now); err == nil {
		t.Fatal("tampered signed snapshot was accepted")
	}
	otherPrivate := ed25519.NewKeyFromSeed([]byte("identity-snapshot-test-seed-0002"))
	otherPublic := otherPrivate.Public().(ed25519.PublicKey)
	if _, err := ParseSignedRegistrySnapshot(bytesReader(signed), otherPublic,
		"identity-test-1", now); err == nil {
		t.Fatal("wrong verification key was accepted")
	}
	unsorted := strings.Replace(unsignedIdentityJSON(2, false, now,
		now.Add(10*time.Minute)), `"devices":[`, `"devices":[{"device_id":"z-device","secret_b64":"`+
		base64.RawURLEncoding.EncodeToString(testDeviceSecret)+`"},`, 1)
	if _, err := SignRegistrySnapshot(strings.NewReader(unsorted),
		"identity-test-1", privateKey, now); err == nil {
		t.Fatal("unsorted identity devices were accepted")
	}
}

func TestIdentityReloaderIsAtomicAndConcurrentReadersAreSafe(t *testing.T) {
	clock := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	publicKey, _ := identityTestKey()
	firstBytes, first := signedIdentity(t, 5, false, clock,
		clock.Add(10*time.Minute), clock)
	registry, err := NewRegistryFromSnapshot(first, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "identity.json")
	if err := os.WriteFile(path, firstBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	reloader, err := NewRegistryReloader(path, publicKey,
		"identity-test-1", ProofSnapshotPurpose, registry,
		func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, _ := signedIdentity(t, 6, true, clock,
		clock.Add(10*time.Minute), clock)
	if err := os.WriteFile(path, secondBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	var readers sync.WaitGroup
	for range 32 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for range 1000 {
				_ = registry.DeviceAllowed("device-1")
				_ = registry.Ready()
			}
		}()
	}
	changed, status, err := reloader.Reload()
	readers.Wait()
	if err != nil || !changed || status.Revision != 6 ||
		status.SigningKeyID != "identity-test-1" ||
		registry.DeviceAllowed("device-1") {
		t.Fatalf("reload: changed=%v status=%#v err=%v", changed, status, err)
	}
	if err := os.WriteFile(path, firstBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, _, err := reloader.Reload(); changed ||
		!errors.Is(err, ErrSnapshotRollback) {
		t.Fatalf("reloader rollback: changed=%v err=%v", changed, err)
	}
	_, privateKey := identityTestKey()
	accessUnsigned := `{"version":2,"revision":7,"purpose":"access",` +
		`"issued_at":"` + clock.Format(time.RFC3339) + `",` +
		`"valid_until":"` + clock.Add(10*time.Minute).Format(time.RFC3339) +
		`","devices":[{"device_id":"device-1"}]}`
	accessBytes, err := SignRegistrySnapshot(strings.NewReader(accessUnsigned),
		"identity-test-1", privateKey, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, accessBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, status, err := reloader.Reload(); changed || err == nil ||
		status.Revision != 6 {
		t.Fatalf("purpose swap: changed=%v status=%#v err=%v",
			changed, status, err)
	}
}

func TestConfidentialIdentitySnapshotRejectsBroadFileMode(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	publicKey, _ := identityTestKey()
	payload, _ := signedIdentity(t, 1, false, now,
		now.Add(10*time.Minute), now)
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSignedRegistrySnapshot(path, publicKey,
		"identity-test-1", now); err == nil {
		t.Fatal("broad identity snapshot file permissions were accepted")
	}
}

func TestSecretFreeAccessSnapshotCannotBecomeProofAuthority(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey := identityTestKey()
	unsigned := `{"version":2,"revision":1,"purpose":"access","issued_at":"` +
		now.Format(time.RFC3339) + `","valid_until":"` +
		now.Add(10*time.Minute).Format(time.RFC3339) +
		`","devices":[{"device_id":"device-1"}]}`
	signed, err := SignRegistrySnapshot(strings.NewReader(unsigned),
		"identity-test-1", privateKey, now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := ParseSignedRegistrySnapshot(bytesReader(signed), publicKey,
		"identity-test-1", now)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistryFromSnapshot(snapshot, func() time.Time { return now })
	if err != nil || !registry.Ready() || !registry.DeviceAllowed("device-1") {
		t.Fatalf("access registry: ready=%v allowed=%v err=%v",
			registry.Ready(), registry.DeviceAllowed("device-1"), err)
	}
	if _, err := NewProofVerifier(registry, time.Minute, 0); err == nil {
		t.Fatal("secret-free access snapshot became a device proof authority")
	}
}

func TestIdentityUpdateWaitsForLinearizedTokenIssuance(t *testing.T) {
	clock := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	_, initial := signedIdentity(t, 90, false, clock,
		clock.Add(10*time.Minute), clock)
	registry, err := NewRegistryFromSnapshot(initial, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	_, revoked := signedIdentity(t, 91, true, clock,
		clock.Add(10*time.Minute), clock)
	actionStarted := make(chan struct{})
	releaseAction := make(chan struct{})
	actionDone := make(chan error, 1)
	go func() {
		actionDone <- registry.withDeviceAllowed("device-1", func() error {
			close(actionStarted)
			<-releaseAction
			return nil
		})
	}()
	<-actionStarted
	applyDone := make(chan error, 1)
	go func() {
		_, applyErr := registry.ApplySnapshot(revoked)
		applyDone <- applyErr
	}()
	select {
	case err := <-applyDone:
		t.Fatalf("identity update crossed issuance boundary: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(releaseAction)
	if err := <-actionDone; err != nil {
		t.Fatal(err)
	}
	if err := <-applyDone; err != nil {
		t.Fatal(err)
	}
	if registry.DeviceAllowed("device-1") {
		t.Fatal("device remained allowed after serialized revoke")
	}
}

func TestReloadableIdentityEnforcesExternalRestartRevisionFloor(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	publicKey, _ := identityTestKey()
	payload, _ := signedIdentity(t, 50, false, now,
		now.Add(10*time.Minute), now)
	directory := t.TempDir()
	snapshotPath := filepath.Join(directory, "identity.json")
	publicKeyPath := filepath.Join(directory, "identity.pub")
	if err := os.WriteFile(snapshotPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicKeyPath, []byte(
		base64.RawURLEncoding.EncodeToString(publicKey)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadReloadableRegistry(snapshotPath, publicKeyPath,
		"identity-test-1", ProofSnapshotPurpose, 51,
		func() time.Time { return now }); err == nil {
		t.Fatal("restart accepted a snapshot below the external revision floor")
	}
	registry, reloader, err := LoadReloadableRegistry(snapshotPath,
		publicKeyPath, "identity-test-1", ProofSnapshotPurpose, 50,
		func() time.Time { return now })
	if err != nil || registry == nil || reloader == nil {
		t.Fatalf("revision floor load: registry=%v reloader=%v err=%v",
			registry, reloader, err)
	}
	if registry.Status().Revision != 50 {
		t.Fatalf("revision floor status: %#v", registry.Status())
	}
}
