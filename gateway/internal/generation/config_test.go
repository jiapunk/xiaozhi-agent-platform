package generation

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func setCoordinatorEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("ALLOW_INSECURE_DEVELOPMENT", "true")
	t.Setenv("GENERATION_STATE_DIRECTORY", "/run/generation-state")
	t.Setenv("GENERATION_STATE_HMAC_KEY_B64",
		base64.RawURLEncoding.EncodeToString(testStateKey))
	t.Setenv("GENERATION_PUBLISHER_ID", "release-publisher")
	t.Setenv("GENERATION_PUBLISHER_HMAC_KEY_B64",
		base64.RawURLEncoding.EncodeToString(testPublisherKey))
	t.Setenv("GENERATION_REPLICA_REGISTRY_FILE", "/run/secrets/replicas.json")
}

func TestLoadCoordinatorSettingsAndKeyIsolation(t *testing.T) {
	setCoordinatorEnvironment(t)
	t.Setenv("GENERATION_PREPARE_TIMEOUT_SECONDS", "300")
	t.Setenv("GENERATION_COMMIT_TIMEOUT_SECONDS", "600")
	settings, err := LoadCoordinatorSettings()
	if err != nil {
		t.Fatal(err)
	}
	if !settings.AllowInsecure || settings.Address != ":8447" ||
		settings.PrepareTimeout != 5*time.Minute ||
		settings.CommitTimeout != 10*time.Minute ||
		settings.Publisher.Role != "publisher" {
		t.Fatalf("unexpected coordinator settings: %#v", settings)
	}
	setCoordinatorEnvironment(t)
	t.Setenv("GENERATION_PUBLISHER_HMAC_KEY_B64",
		base64.RawURLEncoding.EncodeToString(testStateKey))
	if _, err := LoadCoordinatorSettings(); err == nil ||
		!strings.Contains(err.Error(), "distinct") {
		t.Fatalf("shared coordinator keys: %v", err)
	}
}

func TestCoordinatorSettingsRequireProductionTLSAndCanonicalKeys(t *testing.T) {
	setCoordinatorEnvironment(t)
	t.Setenv("ALLOW_INSECURE_DEVELOPMENT", "false")
	if _, err := LoadCoordinatorSettings(); err == nil ||
		!strings.Contains(err.Error(), "TLS") {
		t.Fatalf("missing TLS: %v", err)
	}
	setCoordinatorEnvironment(t)
	t.Setenv("GENERATION_STATE_HMAC_KEY_B64", "d2Vhaw")
	if _, err := LoadCoordinatorSettings(); err == nil {
		t.Fatal("weak state key was accepted")
	}
}

func TestReplicaSettingsRequireHTTPSOutsideDevelopment(t *testing.T) {
	t.Setenv("GENERATION_COORDINATOR_URL", "http://generation.example:8447")
	t.Setenv("GENERATION_REPLICA_ID", "controlplane-a")
	t.Setenv("GENERATION_REPLICA_HMAC_KEY_B64",
		base64.RawURLEncoding.EncodeToString(testControlKey))
	t.Setenv("OTA_DEPLOYMENT_BUNDLE_ROOT", "/run/ota-bundle")
	if _, err := LoadReplicaSettings("controlplane", false); err == nil {
		t.Fatal("production replica accepted HTTP coordinator")
	}
	settings, err := LoadReplicaSettings("controlplane", true)
	if err != nil || settings.Replica.Role != "controlplane" {
		t.Fatalf("development replica settings: %#v %v", settings, err)
	}
}
