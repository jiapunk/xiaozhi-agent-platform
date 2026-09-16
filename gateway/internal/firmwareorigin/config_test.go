package firmwareorigin

import (
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xiaozhi-agent-platform/gateway/internal/testkeyring"
)

func setOriginEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("ALLOW_INSECURE_DEVELOPMENT", "true")
	t.Setenv("FIRMWARE_ORIGIN_TLS_CERT_FILE", "")
	t.Setenv("FIRMWARE_ORIGIN_TLS_KEY_FILE", "")
	t.Setenv("FIRMWARE_ORIGIN_CATALOG_FILE", "/run/config/firmware.json")
	t.Setenv("FIRMWARE_ORIGIN_PUBLIC_AUTHORITY", "updates.example")
	t.Setenv("OTA_TOKEN_HMAC_KEYS_B64", base64.RawURLEncoding.EncodeToString(
		[]byte("ota-token-current-0123456789abcdef0123")))
	t.Setenv("OTA_TOKEN_MAX_TTL_SECONDS", "")
	t.Setenv("FIRMWARE_ORIGIN_MAX_CONCURRENT", "")
	t.Setenv("FIRMWARE_ORIGIN_WRITE_TIMEOUT_SECONDS", "")
	t.Setenv("GENERATION_COORDINATOR_URL", "http://generation.local:8447")
	t.Setenv("GENERATION_REPLICA_ID", "firmwareorigin-a")
	t.Setenv("GENERATION_REPLICA_HMAC_KEY_B64", base64.RawURLEncoding.EncodeToString(
		[]byte("generation-origin-a-0123456789abcdef012")))
	t.Setenv("OTA_DEPLOYMENT_BUNDLE_ROOT", "/run/ota-bundle")
}

func TestLoadOriginDevelopmentSettingsAndRotationKeys(t *testing.T) {
	setOriginEnvironment(t)
	previous := base64.RawURLEncoding.EncodeToString(
		[]byte("ota-token-previous-0123456789abcdef01"))
	t.Setenv("OTA_TOKEN_HMAC_KEYS_B64",
		base64.RawURLEncoding.EncodeToString(
			[]byte("ota-token-current-0123456789abcdef0123"))+","+previous)
	t.Setenv("OTA_TOKEN_MAX_TTL_SECONDS", "300")
	t.Setenv("FIRMWARE_ORIGIN_MAX_CONCURRENT", "32")
	t.Setenv("FIRMWARE_ORIGIN_WRITE_TIMEOUT_SECONDS", "600")
	settings, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if settings.Address != ":8446" || !settings.AllowInsecure ||
		settings.CatalogFile == "" ||
		settings.PublicAuthority != "updates.example" ||
		len(settings.OTATokenKeys) != 2 ||
		settings.OTATokenMaxTTL != 5*time.Minute ||
		settings.MaxConcurrent != 32 || settings.WriteTimeout != 10*time.Minute {
		t.Fatalf("unexpected settings: %#v", settings)
	}
}

func TestOriginSettingsRejectMissingTLSWeakAndDuplicateKeys(t *testing.T) {
	setOriginEnvironment(t)
	t.Setenv("ALLOW_INSECURE_DEVELOPMENT", "false")
	if _, err := LoadSettings(); err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("missing TLS: %v", err)
	}

	setOriginEnvironment(t)
	t.Setenv("OTA_TOKEN_HMAC_KEYS_B64", "d2Vhaw")
	if _, err := LoadSettings(); err == nil {
		t.Fatal("weak OTA token key was accepted")
	}

	setOriginEnvironment(t)
	key := base64.RawURLEncoding.EncodeToString(
		[]byte("ota-token-current-0123456789abcdef0123"))
	t.Setenv("OTA_TOKEN_HMAC_KEYS_B64", key+","+key)
	if _, err := LoadSettings(); err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("duplicate OTA keys: %v", err)
	}
}

func TestOriginSettingsRejectPartialTLSAndUnsafeBounds(t *testing.T) {
	setOriginEnvironment(t)
	t.Setenv("FIRMWARE_ORIGIN_TLS_CERT_FILE", "/run/tls/cert.pem")
	if _, err := LoadSettings(); err == nil || !strings.Contains(err.Error(), "together") {
		t.Fatalf("partial TLS: %v", err)
	}

	setOriginEnvironment(t)
	t.Setenv("OTA_TOKEN_MAX_TTL_SECONDS", "901")
	if _, err := LoadSettings(); err == nil {
		t.Fatal("oversized token TTL was accepted")
	}

	setOriginEnvironment(t)
	t.Setenv("FIRMWARE_ORIGIN_MAX_CONCURRENT", "0")
	if _, err := LoadSettings(); err == nil {
		t.Fatal("zero concurrency was accepted")
	}

	setOriginEnvironment(t)
	t.Setenv("FIRMWARE_ORIGIN_PUBLIC_AUTHORITY", "Updates.Example")
	if _, err := LoadSettings(); err == nil {
		t.Fatal("non-canonical public authority was accepted")
	}
}

func TestOriginLoadsSignedIdentityAccessSettings(t *testing.T) {
	setOriginEnvironment(t)
	t.Setenv("DEVICE_REGISTRY_FILE", "/run/identity/access.json")
	t.Setenv("DEVICE_REGISTRY_SIGNING_PUBLIC_KEY_FILE", "/run/trust/identity.pub")
	t.Setenv("DEVICE_REGISTRY_SIGNING_KEY_ID", "identity-prod-1")
	t.Setenv("DEVICE_REGISTRY_RELOAD_INTERVAL_SECONDS", "2")
	settings, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if settings.Identity.MinimumRevision != 1 ||
		settings.Identity.ReloadInterval != 2*time.Second ||
		settings.Identity.SigningKeyID != "identity-prod-1" {
		t.Fatalf("unexpected identity settings: %#v", settings)
	}
}

func TestProductionOriginRequiresIdentityAndRevisionFloor(t *testing.T) {
	setOriginEnvironment(t)
	t.Setenv("ALLOW_INSECURE_DEVELOPMENT", "false")
	t.Setenv("FIRMWARE_ORIGIN_TLS_CERT_FILE", "/run/tls/cert.pem")
	t.Setenv("FIRMWARE_ORIGIN_TLS_KEY_FILE", "/run/tls/key.pem")
	t.Setenv("GENERATION_COORDINATOR_URL", "https://generation.example:8447")
	if _, err := LoadSettings(); err == nil || !strings.Contains(err.Error(), "snapshot") {
		t.Fatalf("missing identity snapshot: %v", err)
	}
	t.Setenv("DEVICE_REGISTRY_FILE", "/run/identity/access.json")
	t.Setenv("DEVICE_REGISTRY_SIGNING_PUBLIC_KEY_FILE", "/run/trust/identity.pub")
	t.Setenv("DEVICE_REGISTRY_SIGNING_KEY_ID", "identity-prod-1")
	if _, err := LoadSettings(); err == nil || !strings.Contains(err.Error(), "MIN_REVISION") {
		t.Fatalf("missing identity revision floor: %v", err)
	}
	t.Setenv("DEVICE_REGISTRY_MIN_REVISION", "55")
	if _, err := LoadSettings(); err == nil || !strings.Contains(err.Error(), "managed") {
		t.Fatalf("production legacy OTA keyring: %v", err)
	}
	keyring := filepath.Join(t.TempDir(), "ota-token-keyring.json")
	if err := testkeyring.Write(keyring, "ota", 55, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OTA_TOKEN_HMAC_KEYS_B64", "")
	t.Setenv("OTA_TOKEN_HMAC_KEYRING_FILE", keyring)
	t.Setenv("OTA_TOKEN_HMAC_KEYRING_MIN_REVISION", "55")
	settings, err := LoadSettings()
	if err != nil || settings.Identity.MinimumRevision != 55 ||
		settings.OTATokenKeyring == nil {
		t.Fatalf("production identity settings: %#v err=%v", settings, err)
	}
}
