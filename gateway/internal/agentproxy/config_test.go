package agentproxy

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xiaozhi-agent-platform/gateway/internal/testkeyring"
)

func setAgentProxyEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("ALLOW_INSECURE_DEVELOPMENT", "true")
	t.Setenv("AGENT_PROVIDER_URL", "http://localhost:9010/v1/chat/completions")
	t.Setenv("AGENT_PROVIDER_API_KEY", "provider-secret")
	t.Setenv("AGENT_PROVIDER_MODEL", "gpt-product")
	t.Setenv("AGENT_TOKEN_HMAC_KEYS_B64",
		base64.RawURLEncoding.EncodeToString(testAgentTokenKey))
}

func setAgentUsageBudgetEnvironment(t *testing.T) {
	t.Helper()
	keyPath := filepath.Join(t.TempDir(), "usage-digest.key")
	encoded := base64.RawURLEncoding.EncodeToString(
		[]byte("0123456789abcdef0123456789abcdef"))
	if err := os.WriteFile(keyPath, []byte(encoded+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENT_PRICING_PROFILE_ID", "provider-contract-2026-08")
	t.Setenv("AGENT_INPUT_MICROUSD_PER_MILLION_TOKENS", "250000")
	t.Setenv("AGENT_OUTPUT_MICROUSD_PER_MILLION_TOKENS", "1000000")
	t.Setenv("AGENT_DAILY_BUDGET_MICROUSD", "50000")
	t.Setenv("AGENT_INPUT_TOKEN_OVERHEAD", "8192")
	t.Setenv("AGENT_USAGE_RESERVATION_TTL_SECONDS", "120")
	t.Setenv("AGENT_USAGE_DIGEST_KEY_FILE", keyPath)
}

func TestLoadAgentProxyDevelopmentSettings(t *testing.T) {
	setAgentProxyEnvironment(t)
	t.Setenv("AGENT_TOKEN_MAX_TTL_SECONDS", "300")
	t.Setenv("AGENT_MAX_OUTPUT_TOKENS", "2048")
	settings, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if settings.Address != ":8445" || !settings.AllowInsecure ||
		settings.PublicModel != "product-agent" ||
		settings.AgentTokenMaxTTL != 5*time.Minute ||
		settings.MaxOutputTokens != 2048 ||
		len(settings.AgentTokenKeys) != 1 {
		t.Fatalf("unexpected settings: %#v", settings)
	}
}

func TestRejectsMissingProductionTLSAndUnsafeProvider(t *testing.T) {
	setAgentProxyEnvironment(t)
	t.Setenv("ALLOW_INSECURE_DEVELOPMENT", "false")
	t.Setenv("AGENT_PROVIDER_URL", "https://api.openai.com/v1/chat/completions")
	if _, err := LoadSettings(); err == nil ||
		!strings.Contains(err.Error(), "TLS") {
		t.Fatalf("missing TLS: %v", err)
	}
	setAgentProxyEnvironment(t)
	t.Setenv("AGENT_PROVIDER_URL", "http://user@localhost/v1/chat/completions")
	if _, err := LoadSettings(); err == nil {
		t.Fatal("expected userinfo rejection")
	}
	setAgentProxyEnvironment(t)
	t.Setenv("AGENT_PROVIDER_URL", "http://localhost/v1/responses")
	if _, err := LoadSettings(); err == nil {
		t.Fatal("expected wrong path rejection")
	}
}

func TestRejectsWeakTokenKeyAndUnsafeAPIKey(t *testing.T) {
	setAgentProxyEnvironment(t)
	t.Setenv("AGENT_TOKEN_HMAC_KEYS_B64", "d2Vhaw")
	if _, err := LoadSettings(); err == nil {
		t.Fatal("expected weak token key rejection")
	}
	setAgentProxyEnvironment(t)
	t.Setenv("AGENT_PROVIDER_API_KEY", "bad\nkey")
	if _, err := LoadSettings(); err == nil {
		t.Fatal("expected unsafe provider key rejection")
	}
}

func TestRejectsUnsafeOptionalProviderHeaders(t *testing.T) {
	setAgentProxyEnvironment(t)
	t.Setenv("OPENAI_ORGANIZATION", "org-safe")
	t.Setenv("OPENAI_PROJECT", "project_safe.1")
	if _, err := LoadSettings(); err != nil {
		t.Fatalf("safe identifiers rejected: %v", err)
	}

	setAgentProxyEnvironment(t)
	t.Setenv("OPENAI_ORGANIZATION", "org-safe\r\nX-Injected: true")
	if _, err := LoadSettings(); err == nil {
		t.Fatal("expected organization header injection rejection")
	}

	setAgentProxyEnvironment(t)
	t.Setenv("OPENAI_PROJECT", "project with spaces")
	if _, err := LoadSettings(); err == nil {
		t.Fatal("expected unsafe project identifier rejection")
	}
}

func TestAgentProxyLoadsSignedIdentityAccessSettings(t *testing.T) {
	setAgentProxyEnvironment(t)
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

func TestProductionAgentProxyRequiresIdentityAndRevisionFloor(t *testing.T) {
	setAgentProxyEnvironment(t)
	t.Setenv("ALLOW_INSECURE_DEVELOPMENT", "false")
	t.Setenv("AGENT_PROXY_TLS_CERT_FILE", "/run/tls/cert.pem")
	t.Setenv("AGENT_PROXY_TLS_KEY_FILE", "/run/tls/key.pem")
	t.Setenv("AGENT_PROVIDER_URL", "https://provider.example/v1/chat/completions")
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
		t.Fatalf("production legacy Agent keyring: %v", err)
	}
	keyring := filepath.Join(t.TempDir(), "agent-token-keyring.json")
	if err := testkeyring.Write(keyring, "agent", 55, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENT_TOKEN_HMAC_KEYS_B64", "")
	t.Setenv("AGENT_TOKEN_HMAC_KEYRING_FILE", keyring)
	t.Setenv("AGENT_TOKEN_HMAC_KEYRING_MIN_REVISION", "55")
	setAgentUsageBudgetEnvironment(t)
	settings, err := LoadSettings()
	if err != nil || settings.Identity.MinimumRevision != 55 ||
		settings.AgentTokenKeyring == nil || !settings.UsageBudgetEnabled ||
		len(settings.UsageDigestKey) != 32 {
		t.Fatalf("production identity settings: %#v err=%v", settings, err)
	}
}

func TestAgentUsageBudgetSettingsAreAllOrNothingAndPrivate(t *testing.T) {
	setAgentProxyEnvironment(t)
	t.Setenv("AGENT_PRICING_PROFILE_ID", "partial")
	if _, err := LoadSettings(); err == nil || !strings.Contains(err.Error(),
		"configured together") {
		t.Fatalf("partial usage budget settings: %v", err)
	}

	setAgentProxyEnvironment(t)
	setAgentUsageBudgetEnvironment(t)
	t.Setenv("AGENT_USAGE_RESERVATION_TTL_SECONDS", "49")
	if _, err := LoadSettings(); err == nil || !strings.Contains(err.Error(),
		"pricing or reservation") {
		t.Fatalf("short reservation TTL: %v", err)
	}
}
