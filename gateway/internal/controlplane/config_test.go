package controlplane

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xiaozhi-agent-platform/gateway/internal/testkeyring"
)

func setControlEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("APP_TOKEN_HMAC_KEYS_B64", "")
	t.Setenv("APP_TOKEN_ED25519_KEYRING", "")
	t.Setenv("APP_TOKEN_ISSUER", "")
	t.Setenv("APP_TOKEN_MAX_TTL_SECONDS", "")
	t.Setenv("APP_TOKEN_INTROSPECTION_URL", "")
	t.Setenv("APP_TOKEN_INTROSPECTION_CA_FILE", "")
	t.Setenv("APP_TOKEN_INTROSPECTION_CLIENT_CERT_FILE", "")
	t.Setenv("APP_TOKEN_INTROSPECTION_CLIENT_KEY_FILE", "")
	t.Setenv("APP_TOKEN_INTROSPECTION_TIMEOUT_MS", "")
	t.Setenv("SERVICE_ENTITLEMENT_AUTHORIZATION_URL", "")
	t.Setenv("DEVICE_CLAIM_TTL_SECONDS", "")
	t.Setenv("DEVICE_CLAIM_MAX_PENDING", "")
	t.Setenv("OWNERSHIP_DATABASE_URL", "")
	t.Setenv("OWNERSHIP_DATABASE_MAX_CONNECTIONS", "")
	t.Setenv("OWNERSHIP_DATABASE_IDLE_CONNECTIONS", "")
	t.Setenv("OWNERSHIP_DATABASE_CONNECTION_TTL_SECONDS", "")
	t.Setenv("OWNERSHIP_DATABASE_OPERATION_TIMEOUT_MS", "")
	t.Setenv("ACTION_CONSENT_REFERENCE_ENABLED", "")
	t.Setenv("ACTION_CONSENT_ENABLED", "")
	t.Setenv("ACTION_CONSENT_MAX_PENDING", "")
	t.Setenv("ACTION_CONSENT_PUSH_ENABLED", "")
	t.Setenv("ACTION_CONSENT_PUSH_WORKER_ID", "")
	t.Setenv("ACTION_CONSENT_PUSH_POLL_MS", "")
	t.Setenv("ACTION_CONSENT_PUSH_LEASE_MS", "")
	t.Setenv("ACTION_CONSENT_PUSH_RETRY_MS", "")
	t.Setenv("ACTION_CONSENT_PUSH_REQUEST_TIMEOUT_MS", "")
	t.Setenv("ALLOW_INSECURE_DEVELOPMENT", "true")
	t.Setenv("DEVICE_REGISTRY_FILE", "/run/secrets/devices.json")
	t.Setenv("PUBLIC_DEVICE_WSS_URL", "ws://localhost:8443/v1/device")
	t.Setenv("VOICE_TOKEN_HMAC_KEY_B64", base64.RawURLEncoding.EncodeToString(
		[]byte("voice-token-key-0123456789abcdef01234")))
	t.Setenv("AGENT_TOKEN_HMAC_KEY_B64", base64.RawURLEncoding.EncodeToString(
		[]byte("agent-token-key-0123456789abcdef01234")))
}

func setManagedControlTokenKeyrings(t *testing.T) {
	t.Helper()
	directory := t.TempDir()
	voice := filepath.Join(directory, "voice-token-keyring.json")
	agent := filepath.Join(directory, "agent-token-keyring.json")
	now := time.Now().UTC()
	if err := testkeyring.Write(voice, "voice", 1, now); err != nil {
		t.Fatal(err)
	}
	if err := testkeyring.Write(agent, "agent", 1, now); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VOICE_TOKEN_HMAC_KEY_B64", "")
	t.Setenv("AGENT_TOKEN_HMAC_KEY_B64", "")
	t.Setenv("VOICE_TOKEN_HMAC_KEYRING_FILE", voice)
	t.Setenv("VOICE_TOKEN_HMAC_KEYRING_MIN_REVISION", "1")
	t.Setenv("AGENT_TOKEN_HMAC_KEYRING_FILE", agent)
	t.Setenv("AGENT_TOKEN_HMAC_KEYRING_MIN_REVISION", "1")
}

func TestActionConsentPushRequiresDurableStoreAndExistingMTLSBoundary(t *testing.T) {
	setControlEnvironment(t)
	t.Setenv("APP_TOKEN_HMAC_KEYS_B64", base64.RawURLEncoding.EncodeToString(
		[]byte("companion-token-key-0123456789abcdef")))
	setCompanionIntrospectionEnvironment(t)
	t.Setenv("OWNERSHIP_DATABASE_URL",
		"postgresql://ownership@db.example/product?sslmode=verify-full")
	t.Setenv("ACTION_CONSENT_ENABLED", "true")
	t.Setenv("ACTION_CONSENT_PUSH_ENABLED", "true")
	t.Setenv("ACTION_CONSENT_PUSH_WORKER_ID", "controlplane-pod-1")
	settings, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if !settings.ActionConsentPushEnabled ||
		settings.ActionConsentPushWorkerID != "controlplane-pod-1" ||
		settings.ActionConsentPushPoll != 500*time.Millisecond ||
		settings.ActionConsentPushLease != 9*time.Second ||
		settings.ActionConsentPushRetry != time.Second ||
		settings.ActionConsentPushTimeout != 7*time.Second {
		t.Fatalf("unexpected push worker settings: %#v", settings)
	}
	t.Setenv("ACTION_CONSENT_PUSH_LEASE_MS", "7000")
	t.Setenv("ACTION_CONSENT_PUSH_REQUEST_TIMEOUT_MS", "7000")
	if _, err := LoadSettings(); err == nil ||
		!strings.Contains(err.Error(), "lease") {
		t.Fatalf("nonexclusive wake timeout budget: %v", err)
	}

	setControlEnvironment(t)
	t.Setenv("ACTION_CONSENT_PUSH_ENABLED", "true")
	t.Setenv("ACTION_CONSENT_PUSH_WORKER_ID", "controlplane-pod-1")
	if _, err := LoadSettings(); err == nil {
		t.Fatal("wake worker accepted without durable consent configuration")
	}
	setControlEnvironment(t)
	t.Setenv("ACTION_CONSENT_PUSH_WORKER_ID", "controlplane-pod-1")
	if _, err := LoadSettings(); err == nil {
		t.Fatal("wake worker settings accepted without explicit opt-in")
	}
}

func setCompanionIntrospectionEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("APP_TOKEN_INTROSPECTION_URL",
		"https://accounts.example/v1/companion-tokens/introspect")
	t.Setenv("APP_TOKEN_INTROSPECTION_CA_FILE", "/run/secrets/account-ca.pem")
	t.Setenv("APP_TOKEN_INTROSPECTION_CLIENT_CERT_FILE",
		"/run/secrets/control-account-cert.pem")
	t.Setenv("APP_TOKEN_INTROSPECTION_CLIENT_KEY_FILE",
		"/run/secrets/control-account-key.pem")
	t.Setenv("APP_TOKEN_INTROSPECTION_TIMEOUT_MS", "750")
	t.Setenv("SERVICE_ENTITLEMENT_AUTHORIZATION_URL",
		"https://accounts.example/v1/service-entitlements/authorize")
}

func setControlGenerationEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("GENERATION_COORDINATOR_URL", "http://generation.local:8447")
	t.Setenv("GENERATION_REPLICA_ID", "controlplane-a")
	t.Setenv("GENERATION_REPLICA_HMAC_KEY_B64", base64.RawURLEncoding.EncodeToString(
		[]byte("generation-control-a-0123456789abcdef01")))
	t.Setenv("OTA_DEPLOYMENT_BUNDLE_ROOT", "/run/ota-bundle")
}

func TestLoadControlPlaneDevelopmentSettings(t *testing.T) {
	setControlEnvironment(t)
	t.Setenv("VOICE_TOKEN_TTL_SECONDS", "300")
	t.Setenv("AGENT_TOKEN_TTL_SECONDS", "240")
	settings, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if settings.Address != ":8444" || !settings.AllowInsecure ||
		settings.VoiceTokenTTL != 5*time.Minute ||
		settings.AgentTokenTTL != 4*time.Minute ||
		settings.ProofMaxSkew != time.Minute ||
		settings.ProofMinInterval != 5*time.Second {
		t.Fatalf("unexpected settings: %#v", settings)
	}
}

func TestRejectsSharedKeysAndMissingProductionTLS(t *testing.T) {
	setControlEnvironment(t)
	t.Setenv("AGENT_TOKEN_HMAC_KEY_B64",
		base64.RawURLEncoding.EncodeToString(
			[]byte("voice-token-key-0123456789abcdef01234")))
	if _, err := LoadSettings(); err == nil ||
		!strings.Contains(err.Error(), "distinct") {
		t.Fatalf("shared keys: %v", err)
	}

	setControlEnvironment(t)
	t.Setenv("ALLOW_INSECURE_DEVELOPMENT", "false")
	t.Setenv("PUBLIC_DEVICE_WSS_URL", "wss://voice.example/v1/device")
	if _, err := LoadSettings(); err == nil ||
		!strings.Contains(err.Error(), "TLS") {
		t.Fatalf("missing TLS: %v", err)
	}
}

func TestRejectsWeakKeysAndUnsafePublicURL(t *testing.T) {
	setControlEnvironment(t)
	t.Setenv("VOICE_TOKEN_HMAC_KEY_B64", "d2Vhaw")
	if _, err := LoadSettings(); err == nil {
		t.Fatal("expected weak key rejection")
	}
	setControlEnvironment(t)
	t.Setenv("PUBLIC_DEVICE_WSS_URL", "ws://user@localhost/v1/device")
	if _, err := LoadSettings(); err == nil {
		t.Fatal("expected userinfo rejection")
	}
}

func TestOTASettingsAreAllOrNothingAndKeyIsolated(t *testing.T) {
	setControlEnvironment(t)
	setControlGenerationEnvironment(t)
	t.Setenv("OTA_RELEASE_REGISTRY_FILE", "/run/config/ota-releases.json")
	if _, err := LoadSettings(); err == nil ||
		!strings.Contains(err.Error(), "configured together") {
		t.Fatalf("partial OTA settings: %v", err)
	}

	setControlEnvironment(t)
	setControlGenerationEnvironment(t)
	t.Setenv("OTA_RELEASE_REGISTRY_FILE", "/run/config/ota-releases.json")
	t.Setenv("OTA_TOKEN_HMAC_KEY_B64", base64.RawURLEncoding.EncodeToString(
		[]byte("ota-token-key-0123456789abcdef0123456")))
	t.Setenv("OTA_ROLLOUT_HMAC_KEY_B64", base64.RawURLEncoding.EncodeToString(
		[]byte("ota-rollout-key-0123456789abcdef0123")))
	t.Setenv("OTA_TOKEN_TTL_SECONDS", "180")
	settings, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if settings.OTAReleaseRegistryFile == "" ||
		settings.OTATokenTTL != 3*time.Minute ||
		len(settings.OTATokenKey) < 32 || len(settings.OTARolloutKey) < 32 {
		t.Fatalf("unexpected OTA settings: %#v", settings)
	}

	t.Setenv("OTA_ROLLOUT_HMAC_KEY_B64",
		base64.RawURLEncoding.EncodeToString(settings.OTATokenKey))
	if _, err := LoadSettings(); err == nil || !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("shared OTA keys: %v", err)
	}
}

func TestControlPlaneLoadsSignedIdentityReloadConfiguration(t *testing.T) {
	setControlEnvironment(t)
	t.Setenv("DEVICE_REGISTRY_SIGNING_PUBLIC_KEY_FILE", "/run/config/identity.pub")
	t.Setenv("DEVICE_REGISTRY_SIGNING_KEY_ID", "identity-prod-1")
	t.Setenv("DEVICE_REGISTRY_RELOAD_INTERVAL_SECONDS", "3")
	settings, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if settings.Identity.SigningKeyID != "identity-prod-1" ||
		settings.Identity.ReloadInterval != 3*time.Second ||
		settings.Identity.MinimumRevision != 1 {
		t.Fatalf("unexpected identity settings: %#v", settings)
	}
}

func TestProductionControlPlaneRequiresSignedIdentityRegistry(t *testing.T) {
	setControlEnvironment(t)
	t.Setenv("ALLOW_INSECURE_DEVELOPMENT", "false")
	t.Setenv("PUBLIC_DEVICE_WSS_URL", "wss://voice.example/v1/device")
	t.Setenv("CONTROL_TLS_CERT_FILE", "/tls/cert.pem")
	t.Setenv("CONTROL_TLS_KEY_FILE", "/tls/key.pem")
	if _, err := LoadSettings(); err == nil || !strings.Contains(err.Error(), "signed") {
		t.Fatalf("missing production identity snapshot: %v", err)
	}
}

func TestProductionControlPlaneRequiresExplicitIdentityRevisionFloor(t *testing.T) {
	setControlEnvironment(t)
	t.Setenv("ALLOW_INSECURE_DEVELOPMENT", "false")
	t.Setenv("PUBLIC_DEVICE_WSS_URL", "wss://voice.example/v1/device")
	t.Setenv("CONTROL_TLS_CERT_FILE", "/tls/cert.pem")
	t.Setenv("CONTROL_TLS_KEY_FILE", "/tls/key.pem")
	t.Setenv("DEVICE_REGISTRY_SIGNING_PUBLIC_KEY_FILE", "/run/config/identity.pub")
	t.Setenv("DEVICE_REGISTRY_SIGNING_KEY_ID", "identity-prod-1")
	if _, err := LoadSettings(); err == nil ||
		!strings.Contains(err.Error(), "MIN_REVISION") {
		t.Fatalf("missing production revision floor: %v", err)
	}
}

func TestDevelopmentDeviceClaimSettingsAndKeyIsolation(t *testing.T) {
	setControlEnvironment(t)
	t.Setenv("APP_TOKEN_HMAC_KEYS_B64", base64.RawURLEncoding.EncodeToString(
		[]byte("companion-token-key-0123456789abcdef")))
	t.Setenv("APP_TOKEN_MAX_TTL_SECONDS", "600")
	t.Setenv("DEVICE_CLAIM_TTL_SECONDS", "240")
	t.Setenv("DEVICE_CLAIM_MAX_PENDING", "128")
	settings, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if !settings.DeviceClaimEnabled || len(settings.AppTokenKeys) != 1 ||
		settings.AppTokenMaxTTL != 10*time.Minute ||
		settings.DeviceClaimTTL != 4*time.Minute ||
		settings.DeviceClaimMaxPending != 128 {
		t.Fatalf("unexpected claim settings: %#v", settings)
	}

	setControlEnvironment(t)
	t.Setenv("APP_TOKEN_HMAC_KEYS_B64", base64.RawURLEncoding.EncodeToString(
		[]byte("voice-token-key-0123456789abcdef01234")))
	if _, err := LoadSettings(); err == nil ||
		!strings.Contains(err.Error(), "distinct") {
		t.Fatalf("shared App key: %v", err)
	}

	setControlEnvironment(t)
	t.Setenv("DEVICE_CLAIM_TTL_SECONDS", "300")
	if _, err := LoadSettings(); err == nil ||
		!strings.Contains(err.Error(), "keyring") {
		t.Fatalf("partial claim settings: %v", err)
	}
}

func TestCompanionIntrospectionSettingsAreStrictAndAllOrNothing(t *testing.T) {
	setControlEnvironment(t)
	t.Setenv("APP_TOKEN_HMAC_KEYS_B64", base64.RawURLEncoding.EncodeToString(
		[]byte("companion-token-key-0123456789abcdef")))
	setCompanionIntrospectionEnvironment(t)
	settings, err := LoadSettings()
	if err != nil || settings.AppTokenIntrospectionURL == "" ||
		settings.ServiceEntitlementAuthorizationURL == "" ||
		settings.AppTokenIntrospectionTimeout != 750*time.Millisecond {
		t.Fatalf("introspection settings=%#v err=%v", settings, err)
	}

	setControlEnvironment(t)
	t.Setenv("APP_TOKEN_HMAC_KEYS_B64", base64.RawURLEncoding.EncodeToString(
		[]byte("companion-token-key-0123456789abcdef")))
	t.Setenv("APP_TOKEN_INTROSPECTION_URL",
		"https://accounts.example/v1/companion-tokens/introspect")
	if _, err := LoadSettings(); err == nil ||
		!strings.Contains(err.Error(), "configured together") {
		t.Fatalf("partial introspection: %v", err)
	}

	setControlEnvironment(t)
	t.Setenv("APP_TOKEN_HMAC_KEYS_B64", base64.RawURLEncoding.EncodeToString(
		[]byte("companion-token-key-0123456789abcdef")))
	setCompanionIntrospectionEnvironment(t)
	t.Setenv("SERVICE_ENTITLEMENT_AUTHORIZATION_URL",
		"https://other.example/v1/service-entitlements/authorize")
	if _, err := LoadSettings(); err == nil ||
		!strings.Contains(err.Error(), "mTLS authority") {
		t.Fatalf("cross-authority entitlement: %v", err)
	}

	setControlEnvironment(t)
	t.Setenv("APP_TOKEN_HMAC_KEYS_B64", base64.RawURLEncoding.EncodeToString(
		[]byte("companion-token-key-0123456789abcdef")))
	setCompanionIntrospectionEnvironment(t)
	t.Setenv("APP_TOKEN_INTROSPECTION_URL",
		"http://accounts.example/v1/companion-tokens/introspect")
	if _, err := LoadSettings(); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("plaintext introspection: %v", err)
	}
}

func TestProductionRejectsReferenceInMemoryClaimStore(t *testing.T) {
	setControlEnvironment(t)
	setManagedControlTokenKeyrings(t)
	t.Setenv("ALLOW_INSECURE_DEVELOPMENT", "false")
	t.Setenv("PUBLIC_DEVICE_WSS_URL", "wss://voice.example/v1/device")
	t.Setenv("CONTROL_TLS_CERT_FILE", "/tls/cert.pem")
	t.Setenv("CONTROL_TLS_KEY_FILE", "/tls/key.pem")
	t.Setenv("DEVICE_REGISTRY_SIGNING_PUBLIC_KEY_FILE", "/run/config/identity.pub")
	t.Setenv("DEVICE_REGISTRY_SIGNING_KEY_ID", "identity-prod-1")
	t.Setenv("DEVICE_REGISTRY_MIN_REVISION", "1")
	t.Setenv("APP_TOKEN_HMAC_KEYS_B64", base64.RawURLEncoding.EncodeToString(
		[]byte("companion-token-key-0123456789abcdef")))
	if _, err := LoadSettings(); err == nil ||
		!strings.Contains(err.Error(), "durable transactional") {
		t.Fatalf("production memory claim store: %v", err)
	}
}

func TestDevelopmentActionConsentReferenceRequiresExplicitSafeConfiguration(t *testing.T) {
	setControlEnvironment(t)
	t.Setenv("APP_TOKEN_HMAC_KEYS_B64", base64.RawURLEncoding.EncodeToString(
		[]byte("companion-token-key-0123456789abcdef")))
	t.Setenv("ACTION_CONSENT_REFERENCE_ENABLED", "true")
	t.Setenv("ACTION_CONSENT_MAX_PENDING", "128")
	settings, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if !settings.ActionConsentEnabled || !settings.ActionConsentReference ||
		settings.ActionConsentMaxPending != 128 {
		t.Fatalf("unexpected action consent settings: %#v", settings)
	}

	setControlEnvironment(t)
	t.Setenv("APP_TOKEN_HMAC_KEYS_B64", base64.RawURLEncoding.EncodeToString(
		[]byte("companion-token-key-0123456789abcdef")))
	t.Setenv("ACTION_CONSENT_MAX_PENDING", "128")
	if _, err := LoadSettings(); err == nil ||
		!strings.Contains(err.Error(), "requires") {
		t.Fatalf("orphan action consent capacity: %v", err)
	}

	setControlEnvironment(t)
	t.Setenv("APP_TOKEN_HMAC_KEYS_B64", base64.RawURLEncoding.EncodeToString(
		[]byte("companion-token-key-0123456789abcdef")))
	t.Setenv("ACTION_CONSENT_ENABLED", "true")
	if _, err := LoadSettings(); err == nil ||
		!strings.Contains(err.Error(), "OWNERSHIP_DATABASE_URL") {
		t.Fatalf("durable action consent without database: %v", err)
	}

	setControlEnvironment(t)
	t.Setenv("APP_TOKEN_HMAC_KEYS_B64", base64.RawURLEncoding.EncodeToString(
		[]byte("companion-token-key-0123456789abcdef")))
	t.Setenv("OWNERSHIP_DATABASE_URL",
		"postgresql://ownership@localhost/product?sslmode=disable")
	t.Setenv("ACTION_CONSENT_REFERENCE_ENABLED", "true")
	if _, err := LoadSettings(); err == nil ||
		!strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("ambiguous action consent adapters: %v", err)
	}
}

func TestProductionRejectsReferenceActionConsentStore(t *testing.T) {
	setControlEnvironment(t)
	setManagedControlTokenKeyrings(t)
	t.Setenv("ALLOW_INSECURE_DEVELOPMENT", "false")
	t.Setenv("PUBLIC_DEVICE_WSS_URL", "wss://voice.example/v1/device")
	t.Setenv("CONTROL_TLS_CERT_FILE", "/tls/cert.pem")
	t.Setenv("CONTROL_TLS_KEY_FILE", "/tls/key.pem")
	t.Setenv("DEVICE_REGISTRY_SIGNING_PUBLIC_KEY_FILE", "/run/config/identity.pub")
	t.Setenv("DEVICE_REGISTRY_SIGNING_KEY_ID", "identity-prod-1")
	t.Setenv("DEVICE_REGISTRY_MIN_REVISION", "1")
	seed := sha256.Sum256([]byte("production-action-consent-account-key"))
	publicKey := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	t.Setenv("APP_TOKEN_ED25519_KEYRING", "account-key-1="+
		base64.RawURLEncoding.EncodeToString(publicKey))
	t.Setenv("APP_TOKEN_ISSUER", "https://accounts.example/product")
	t.Setenv("OWNERSHIP_DATABASE_URL",
		"postgresql://ownership@db.example/product?sslmode=verify-full")
	t.Setenv("ACTION_CONSENT_REFERENCE_ENABLED", "true")
	if _, err := LoadSettings(); err == nil ||
		!strings.Contains(err.Error(), "durable multi-replica") {
		t.Fatalf("production action consent reference store: %v", err)
	}
}

func TestProductionAcceptsTLSVerifiedPostgresOwnershipStore(t *testing.T) {
	setControlEnvironment(t)
	setManagedControlTokenKeyrings(t)
	t.Setenv("ALLOW_INSECURE_DEVELOPMENT", "false")
	t.Setenv("PUBLIC_DEVICE_WSS_URL", "wss://voice.example/v1/device")
	t.Setenv("CONTROL_TLS_CERT_FILE", "/tls/cert.pem")
	t.Setenv("CONTROL_TLS_KEY_FILE", "/tls/key.pem")
	t.Setenv("DEVICE_REGISTRY_SIGNING_PUBLIC_KEY_FILE", "/run/config/identity.pub")
	t.Setenv("DEVICE_REGISTRY_SIGNING_KEY_ID", "identity-prod-1")
	t.Setenv("DEVICE_REGISTRY_MIN_REVISION", "1")
	seed := sha256.Sum256([]byte("production-companion-account-key"))
	publicKey := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	t.Setenv("APP_TOKEN_ED25519_KEYRING", "account-key-1="+
		base64.RawURLEncoding.EncodeToString(publicKey))
	t.Setenv("APP_TOKEN_ISSUER", "https://accounts.example/product")
	setCompanionIntrospectionEnvironment(t)
	t.Setenv("OWNERSHIP_DATABASE_URL",
		"postgresql://ownership@db.example/product?sslmode=verify-full")
	t.Setenv("OWNERSHIP_DATABASE_MAX_CONNECTIONS", "24")
	t.Setenv("OWNERSHIP_DATABASE_IDLE_CONNECTIONS", "6")
	t.Setenv("ACTION_CONSENT_ENABLED", "true")
	t.Setenv("ACTION_CONSENT_MAX_PENDING", "2048")
	settings, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if !settings.DeviceClaimEnabled || settings.OwnershipDatabaseURL == "" ||
		settings.VoiceTokenKeyring == nil || settings.AgentTokenKeyring == nil ||
		len(settings.AppTokenEd25519Keys) != 1 ||
		settings.AppTokenIssuer != "https://accounts.example/product" ||
		settings.AppTokenIntrospectionURL == "" ||
		settings.ServiceEntitlementAuthorizationURL == "" ||
		settings.AppTokenIntrospectionTimeout != 750*time.Millisecond ||
		settings.OwnershipDatabaseMax != 24 ||
		settings.OwnershipDatabaseIdle != 6 ||
		settings.OwnershipDatabaseTimeout != 2*time.Second ||
		!settings.ActionConsentEnabled || settings.ActionConsentReference ||
		settings.ActionConsentMaxPending != 2048 {
		t.Fatalf("unexpected ownership database settings: %#v", settings)
	}
}

func TestProductionControlPlaneRejectsLegacyIssuanceKeys(t *testing.T) {
	setControlEnvironment(t)
	t.Setenv("ALLOW_INSECURE_DEVELOPMENT", "false")
	t.Setenv("PUBLIC_DEVICE_WSS_URL", "wss://voice.example/v1/device")
	t.Setenv("CONTROL_TLS_CERT_FILE", "/tls/cert.pem")
	t.Setenv("CONTROL_TLS_KEY_FILE", "/tls/key.pem")
	t.Setenv("DEVICE_REGISTRY_SIGNING_PUBLIC_KEY_FILE", "/run/config/identity.pub")
	t.Setenv("DEVICE_REGISTRY_SIGNING_KEY_ID", "identity-prod-1")
	t.Setenv("DEVICE_REGISTRY_MIN_REVISION", "1")
	if _, err := LoadSettings(); err == nil || !strings.Contains(err.Error(), "managed") {
		t.Fatalf("production legacy issuance keys: %v", err)
	}
}

func TestProductionRequiresOnlineCompanionRevocation(t *testing.T) {
	setControlEnvironment(t)
	setManagedControlTokenKeyrings(t)
	t.Setenv("ALLOW_INSECURE_DEVELOPMENT", "false")
	t.Setenv("PUBLIC_DEVICE_WSS_URL", "wss://voice.example/v1/device")
	t.Setenv("CONTROL_TLS_CERT_FILE", "/tls/cert.pem")
	t.Setenv("CONTROL_TLS_KEY_FILE", "/tls/key.pem")
	t.Setenv("DEVICE_REGISTRY_SIGNING_PUBLIC_KEY_FILE", "/run/config/identity.pub")
	t.Setenv("DEVICE_REGISTRY_SIGNING_KEY_ID", "identity-prod-1")
	t.Setenv("DEVICE_REGISTRY_MIN_REVISION", "1")
	seed := sha256.Sum256([]byte("production-companion-account-key"))
	publicKey := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	t.Setenv("APP_TOKEN_ED25519_KEYRING", "account-key-1="+
		base64.RawURLEncoding.EncodeToString(publicKey))
	t.Setenv("APP_TOKEN_ISSUER", "https://accounts.example/product")
	t.Setenv("OWNERSHIP_DATABASE_URL",
		"postgresql://ownership@db.example/product?sslmode=verify-full")
	if _, err := LoadSettings(); err == nil ||
		!strings.Contains(err.Error(), "online mTLS token introspection") {
		t.Fatalf("missing production online revocation: %v", err)
	}
}

func TestProductionRejectsCompanionHMACWithDurableStore(t *testing.T) {
	setControlEnvironment(t)
	setManagedControlTokenKeyrings(t)
	t.Setenv("ALLOW_INSECURE_DEVELOPMENT", "false")
	t.Setenv("PUBLIC_DEVICE_WSS_URL", "wss://voice.example/v1/device")
	t.Setenv("CONTROL_TLS_CERT_FILE", "/tls/cert.pem")
	t.Setenv("CONTROL_TLS_KEY_FILE", "/tls/key.pem")
	t.Setenv("DEVICE_REGISTRY_SIGNING_PUBLIC_KEY_FILE", "/run/config/identity.pub")
	t.Setenv("DEVICE_REGISTRY_SIGNING_KEY_ID", "identity-prod-1")
	t.Setenv("DEVICE_REGISTRY_MIN_REVISION", "1")
	t.Setenv("APP_TOKEN_HMAC_KEYS_B64", base64.RawURLEncoding.EncodeToString(
		[]byte("companion-token-key-0123456789abcdef")))
	t.Setenv("OWNERSHIP_DATABASE_URL",
		"postgresql://ownership@db.example/product?sslmode=verify-full")
	if _, err := LoadSettings(); err == nil ||
		!strings.Contains(err.Error(), "Ed25519") {
		t.Fatalf("production Companion HMAC: %v", err)
	}
}

func TestProductionRejectsUnverifiedOwnershipDatabaseTLS(t *testing.T) {
	setControlEnvironment(t)
	setManagedControlTokenKeyrings(t)
	t.Setenv("ALLOW_INSECURE_DEVELOPMENT", "false")
	t.Setenv("PUBLIC_DEVICE_WSS_URL", "wss://voice.example/v1/device")
	t.Setenv("CONTROL_TLS_CERT_FILE", "/tls/cert.pem")
	t.Setenv("CONTROL_TLS_KEY_FILE", "/tls/key.pem")
	t.Setenv("DEVICE_REGISTRY_SIGNING_PUBLIC_KEY_FILE", "/run/config/identity.pub")
	t.Setenv("DEVICE_REGISTRY_SIGNING_KEY_ID", "identity-prod-1")
	t.Setenv("DEVICE_REGISTRY_MIN_REVISION", "1")
	t.Setenv("APP_TOKEN_HMAC_KEYS_B64", base64.RawURLEncoding.EncodeToString(
		[]byte("companion-token-key-0123456789abcdef")))
	t.Setenv("OWNERSHIP_DATABASE_URL",
		"postgresql://ownership@db.example/product?sslmode=require")
	if _, err := LoadSettings(); err == nil ||
		!strings.Contains(err.Error(), "verify-full") {
		t.Fatalf("unverified ownership database TLS: %v", err)
	}
}
