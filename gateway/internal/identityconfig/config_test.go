package identityconfig

import (
	"strings"
	"testing"
	"time"
)

func TestIdentitySourceLoadsSignedFileAndRemoteMTLSModes(t *testing.T) {
	t.Setenv("DEVICE_REGISTRY_FILE", "/run/identity/access.json")
	t.Setenv("DEVICE_REGISTRY_SIGNING_PUBLIC_KEY_FILE", "/run/trust/identity.pub")
	t.Setenv("DEVICE_REGISTRY_SIGNING_KEY_ID", "identity-prod-1")
	file, err := Load(true, true)
	if err != nil || !file.Configured() || file.Remote() || !file.Signed() ||
		file.MinimumRevision != 1 || file.ReloadInterval != 5*time.Second {
		t.Fatalf("signed file: %#v err=%v", file, err)
	}

	t.Setenv("DEVICE_REGISTRY_FILE", "")
	t.Setenv("DEVICE_REGISTRY_URL",
		"https://identity.example/v1/device-identity/access")
	t.Setenv("DEVICE_REGISTRY_TLS_CA_FILE", "/run/trust/identity-ca.pem")
	t.Setenv("DEVICE_REGISTRY_TLS_CERT_FILE", "/run/workload/client.pem")
	t.Setenv("DEVICE_REGISTRY_TLS_KEY_FILE", "/run/workload/client-key.pem")
	t.Setenv("DEVICE_REGISTRY_REQUEST_TIMEOUT_SECONDS", "7")
	t.Setenv("DEVICE_REGISTRY_RELOAD_INTERVAL_SECONDS", "2")
	remote, err := Load(true, true)
	if err != nil || !remote.Remote() || !remote.Signed() ||
		remote.RequestTimeout != 7*time.Second ||
		remote.ReloadInterval != 2*time.Second {
		t.Fatalf("remote mTLS: %#v err=%v", remote, err)
	}
}

func TestIdentitySourceProductionRequiresExplicitFloor(t *testing.T) {
	t.Setenv("DEVICE_REGISTRY_FILE", "/run/identity/access.json")
	t.Setenv("DEVICE_REGISTRY_SIGNING_PUBLIC_KEY_FILE", "/run/trust/identity.pub")
	t.Setenv("DEVICE_REGISTRY_SIGNING_KEY_ID", "identity-prod-1")
	if _, err := Load(false, true); err == nil ||
		!strings.Contains(err.Error(), "MIN_REVISION") {
		t.Fatalf("missing revision floor: %v", err)
	}
	t.Setenv("DEVICE_REGISTRY_MIN_REVISION", "55")
	settings, err := Load(false, true)
	if err != nil || settings.MinimumRevision != 55 {
		t.Fatalf("explicit revision floor: %#v err=%v", settings, err)
	}
}

func TestRemoteIdentityNeverAllowsPlaintextPartialTLSOrDualSources(t *testing.T) {
	t.Setenv("DEVICE_REGISTRY_URL", "http://identity.example/v1/device-identity/access")
	t.Setenv("DEVICE_REGISTRY_SIGNING_PUBLIC_KEY_FILE", "/identity.pub")
	t.Setenv("DEVICE_REGISTRY_SIGNING_KEY_ID", "identity-prod-1")
	if _, err := Load(true, true); err == nil {
		t.Fatal("plaintext remote identity URL was accepted")
	}

	t.Setenv("DEVICE_REGISTRY_URL", "https://identity.example/v1/device-identity/access")
	t.Setenv("DEVICE_REGISTRY_TLS_CA_FILE", "/ca.pem")
	if _, err := Load(true, true); err == nil ||
		!strings.Contains(err.Error(), "configured together") {
		t.Fatalf("partial mTLS: %v", err)
	}

	t.Setenv("DEVICE_REGISTRY_TLS_CERT_FILE", "/client.pem")
	t.Setenv("DEVICE_REGISTRY_TLS_KEY_FILE", "/client-key.pem")
	t.Setenv("DEVICE_REGISTRY_FILE", "/identity.json")
	if _, err := Load(true, true); err == nil ||
		!strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("dual sources: %v", err)
	}
}

func TestIdentitySourceOptionalDevelopmentAndLegacyFile(t *testing.T) {
	settings, err := Load(true, false)
	if err != nil || settings.Configured() {
		t.Fatalf("optional identity: %#v err=%v", settings, err)
	}
	t.Setenv("DEVICE_REGISTRY_FILE", "/devices-v1.json")
	settings, err = Load(true, true)
	if err != nil || settings.Signed() || settings.Remote() {
		t.Fatalf("legacy development file: %#v err=%v", settings, err)
	}
	if _, err := Load(false, true); err == nil ||
		!strings.Contains(err.Error(), "signed") {
		t.Fatalf("production legacy file: %v", err)
	}
}
