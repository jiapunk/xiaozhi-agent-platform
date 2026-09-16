package identityruntime

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xiaozhi-agent-platform/gateway/internal/identityconfig"
	"xiaozhi-agent-platform/gateway/internal/provisioning"
)

func runtimeSignedAccess(t *testing.T, privateKey ed25519.PrivateKey,
	revision uint64, disabled bool, now time.Time) []byte {
	t.Helper()
	disabledText := "false"
	if disabled {
		disabledText = "true"
	}
	unsigned := `{"version":2,"revision":` + formatRuntimeUint(revision) +
		`,"purpose":"access","issued_at":"` +
		now.Add(-time.Minute).Format(time.RFC3339) +
		`","valid_until":"` + now.Add(10*time.Minute).Format(time.RFC3339) +
		`","devices":[{"device_id":"device-1","disabled":` +
		disabledText + `}]}`
	payload, err := provisioning.SignRegistrySnapshot(strings.NewReader(unsigned),
		"identity-runtime-test", privateKey, now)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func formatRuntimeUint(value uint64) string {
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[index:])
}

func TestLoadSelectsSignedFileAndReturnsCommonUpdater(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	privateKey := ed25519.NewKeyFromSeed(
		[]byte("identity-runtime-test-seed-00001"))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	directory := t.TempDir()
	snapshotPath := filepath.Join(directory, "access.json")
	publicKeyPath := filepath.Join(directory, "identity.pub")
	if err := os.WriteFile(snapshotPath,
		runtimeSignedAccess(t, privateKey, 10, false, now), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicKeyPath, []byte(
		base64.RawURLEncoding.EncodeToString(publicKey)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	settings := identityconfig.Settings{
		File: snapshotPath, SigningPublicKeyFile: publicKeyPath,
		SigningKeyID: "identity-runtime-test", MinimumRevision: 10,
		ReloadInterval: time.Second,
	}
	registry, updater, err := Load(context.Background(), settings,
		provisioning.AccessSnapshotPurpose, func() time.Time { return now })
	if err != nil || registry == nil || updater == nil ||
		!registry.DeviceAllowed("device-1") {
		t.Fatalf("signed runtime load: registry=%v updater=%v err=%v",
			registry, updater, err)
	}
	if err := os.WriteFile(snapshotPath,
		runtimeSignedAccess(t, privateKey, 11, true, now), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, status, err := updater.Reload()
	if err != nil || !changed || status.Revision != 11 ||
		registry.DeviceAllowed("device-1") {
		t.Fatalf("common updater: changed=%v status=%#v err=%v",
			changed, status, err)
	}
}

func TestLoadKeepsLegacyFileDevelopmentOnlyPathExplicit(t *testing.T) {
	secret := base64.RawURLEncoding.EncodeToString(
		[]byte("identity-runtime-device-secret-0001"))
	path := filepath.Join(t.TempDir(), "legacy.json")
	payload := `{"version":1,"devices":[{"device_id":"device-1",` +
		`"secret_b64":"` + secret + `"}]}`
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	registry, updater, err := Load(context.Background(),
		identityconfig.Settings{File: path}, provisioning.ProofSnapshotPurpose,
		time.Now)
	if err != nil || registry == nil || updater != nil || !registry.ProofReady() {
		t.Fatalf("legacy runtime load: registry=%v updater=%v err=%v",
			registry, updater, err)
	}
}

func TestLoadRejectsInvalidPurposeAndAllowsUnconfiguredOptionalMode(t *testing.T) {
	registry, updater, err := Load(context.Background(),
		identityconfig.Settings{}, provisioning.AccessSnapshotPurpose, time.Now)
	if err != nil || registry != nil || updater != nil {
		t.Fatalf("optional identity: registry=%v updater=%v err=%v",
			registry, updater, err)
	}
	if _, _, err := Load(context.Background(),
		identityconfig.Settings{File: "/not-used"}, "wrong", time.Now); err == nil {
		t.Fatal("invalid identity purpose was accepted")
	}
}
