package config

import (
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xiaozhi-agent-platform/gateway/internal/testkeyring"
)

func setRequiredEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("ALLOW_INSECURE_DEVELOPMENT", "true")
	t.Setenv("DEVICE_TOKEN_HMAC_KEY_B64", base64.RawURLEncoding.EncodeToString(
		[]byte("0123456789abcdef0123456789abcdef")))
	t.Setenv("STT_UPSTREAM_URL", "ws://localhost:9001/stt")
	t.Setenv("STT_UPSTREAM_TOKEN", "stt-token")
	t.Setenv("TTS_UPSTREAM_URL", "http://localhost:9002/tts")
	t.Setenv("TTS_UPSTREAM_TOKEN", "tts-token")
}

func TestLoadsSessionIssuanceConfiguration(t *testing.T) {
	setRequiredEnvironment(t)
	t.Setenv("ENABLE_SESSION_ISSUANCE", "true")
	t.Setenv("DEVICE_REGISTRY_FILE", "/run/secrets/device-registry.json")
	t.Setenv("PUBLIC_DEVICE_WSS_URL", "ws://localhost:8443/v1/device")
	t.Setenv("SESSION_TOKEN_TTL_SECONDS", "600")
	t.Setenv("SESSION_PROOF_MAX_SKEW_SECONDS", "45")
	t.Setenv("SESSION_MIN_INTERVAL_SECONDS", "3")
	settings, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !settings.EnableSessionIssuance || settings.SessionTokenTTL != 10*time.Minute ||
		settings.SessionProofMaxSkew != 45*time.Second ||
		settings.SessionMinInterval != 3*time.Second {
		t.Fatalf("unexpected session settings: %#v", settings)
	}
}

func TestRejectsIncompleteOrInsecureSessionIssuance(t *testing.T) {
	setRequiredEnvironment(t)
	t.Setenv("ENABLE_SESSION_ISSUANCE", "true")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "identity") {
		t.Fatalf("missing registry: %v", err)
	}

	setRequiredEnvironment(t)
	t.Setenv("ENABLE_SESSION_ISSUANCE", "true")
	t.Setenv("DEVICE_REGISTRY_FILE", "/registry.json")
	t.Setenv("PUBLIC_DEVICE_WSS_URL", "https://gateway.example/v1/device")
	if _, err := Load(); err == nil {
		t.Fatal("expected non-WebSocket URL rejection")
	}

	setRequiredEnvironment(t)
	t.Setenv("ENABLE_SESSION_ISSUANCE", "true")
	t.Setenv("DEVICE_REGISTRY_FILE", "/registry.json")
	t.Setenv("PUBLIC_DEVICE_WSS_URL", "ws://gateway.example/v1/device")
	t.Setenv("ALLOW_INSECURE_DEVELOPMENT", "false")
	t.Setenv("TLS_CERT_FILE", "/tls/cert.pem")
	t.Setenv("TLS_KEY_FILE", "/tls/key.pem")
	if _, err := Load(); err == nil {
		t.Fatal("expected plaintext production URL rejection")
	}
}

func TestSessionTTLCannotExceedVerificationTTL(t *testing.T) {
	setRequiredEnvironment(t)
	t.Setenv("DEVICE_TOKEN_MAX_TTL_SECONDS", "300")
	t.Setenv("SESSION_TOKEN_TTL_SECONDS", "301")
	if _, err := Load(); err == nil {
		t.Fatal("expected session TTL rejection")
	}
}

func TestLoadDevelopmentConfiguration(t *testing.T) {
	setRequiredEnvironment(t)
	settings, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !settings.AllowInsecure || len(settings.DeviceTokenKeys) != 1 ||
		len(settings.DeviceTokenKeys[0]) != 32 ||
		settings.OutputSampleRate != 24000 || settings.MaxConnections != 1000 {
		t.Fatalf("unexpected settings: %#v", settings)
	}
}

func TestLoadsRotationKeyring(t *testing.T) {
	setRequiredEnvironment(t)
	first := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	second := base64.RawURLEncoding.EncodeToString([]byte("abcdef0123456789abcdef0123456789"))
	t.Setenv("DEVICE_TOKEN_HMAC_KEYS_B64", first+","+second)
	settings, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(settings.DeviceTokenKeys) != 2 {
		t.Fatalf("got %d keys", len(settings.DeviceTokenKeys))
	}
}

func TestProductionRequiresTLS(t *testing.T) {
	setRequiredEnvironment(t)
	t.Setenv("ALLOW_INSECURE_DEVELOPMENT", "false")
	if _, err := Load(); err == nil {
		t.Fatal("expected missing TLS configuration to fail")
	}
}

func setProductionIdentityEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("ALLOW_INSECURE_DEVELOPMENT", "false")
	t.Setenv("TLS_CERT_FILE", "/run/secrets/tls.crt")
	t.Setenv("TLS_KEY_FILE", "/run/secrets/tls.key")
	t.Setenv("DEVICE_REGISTRY_FILE", "/run/secrets/identity.json")
	t.Setenv("DEVICE_REGISTRY_SIGNING_PUBLIC_KEY_FILE", "/run/secrets/identity.pub")
	t.Setenv("DEVICE_REGISTRY_SIGNING_KEY_ID", "identity-prod-1")
	t.Setenv("DEVICE_REGISTRY_MIN_REVISION", "1")
	t.Setenv("STT_UPSTREAM_URL", "wss://stt.example/v1/stt")
	t.Setenv("STT_HEALTH_URL", "https://stt.example/readyz")
	t.Setenv("TTS_UPSTREAM_URL", "https://tts.example/v1/tts")
	t.Setenv("TTS_HEALTH_URL", "https://tts.example/readyz")
	t.Setenv("SPEECH_PRICING_PROFILE_ID", "speech-provider-contract-1")
	t.Setenv("SPEECH_STT_MICROUSD_PER_MILLION_AUDIO_MS", "1")
	t.Setenv("SPEECH_TTS_MICROUSD_PER_MILLION_CHARACTERS", "1")
	t.Setenv("SPEECH_TTS_MICROUSD_PER_MILLION_OUTPUT_AUDIO_MS", "0")
	t.Setenv("SPEECH_DAILY_BUDGET_MICROUSD", "1000000")
	t.Setenv("SPEECH_STT_RESERVATION_CHUNK_AUDIO_MS", "6000")
	t.Setenv("SPEECH_TTS_MAX_OUTPUT_AUDIO_MS", "120000")
	t.Setenv("SPEECH_USAGE_RESERVATION_TTL_SECONDS", "120")
	t.Setenv("SPEECH_USAGE_DIGEST_KEY_FILE", "/run/secrets/speech-usage-digest.key")
	path := filepath.Join(t.TempDir(), "voice-token-keyring.json")
	if err := testkeyring.Write(path, "voice", 1, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEVICE_TOKEN_HMAC_KEY_B64", "")
	t.Setenv("VOICE_TOKEN_HMAC_KEYRING_FILE", path)
	t.Setenv("VOICE_TOKEN_HMAC_KEYRING_MIN_REVISION", "1")
}

func setSpeechMTLSEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("STT_TLS_CA_FILE", "/run/secrets/stt-ca.pem")
	t.Setenv("STT_TLS_CLIENT_CERT_FILE", "/run/secrets/stt-client.crt")
	t.Setenv("STT_TLS_CLIENT_KEY_FILE", "/run/secrets/stt-client.key")
	t.Setenv("TTS_TLS_CA_FILE", "/run/secrets/tts-ca.pem")
	t.Setenv("TTS_TLS_CLIENT_CERT_FILE", "/run/secrets/tts-client.crt")
	t.Setenv("TTS_TLS_CLIENT_KEY_FILE", "/run/secrets/tts-client.key")
}

func TestProductionRequiresIsolatedSpeechMTLS(t *testing.T) {
	setRequiredEnvironment(t)
	setProductionIdentityEnvironment(t)
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "mTLS") {
		t.Fatalf("missing speech mTLS configuration: %v", err)
	}
	setSpeechMTLSEnvironment(t)
	settings, err := Load()
	if err != nil || !settings.SpeechMTLSConfigured() {
		t.Fatalf("complete speech mTLS configuration rejected: %#v err=%v", settings, err)
	}
	if settings.VoiceTokenKeyring == nil ||
		settings.VoiceTokenKeyring.ActiveKeyID() != "voice-active" {
		t.Fatalf("managed voice token keyring missing: %#v", settings)
	}
}

func TestProductionGatewayRejectsLegacyUnkeyedKeyConfiguration(t *testing.T) {
	setRequiredEnvironment(t)
	setProductionIdentityEnvironment(t)
	t.Setenv("VOICE_TOKEN_HMAC_KEYRING_FILE", "")
	t.Setenv("VOICE_TOKEN_HMAC_KEYRING_MIN_REVISION", "")
	t.Setenv("DEVICE_TOKEN_HMAC_KEY_B64", base64.RawURLEncoding.EncodeToString(
		[]byte("legacy-voice-key-0123456789abcdef012")))
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "managed") {
		t.Fatalf("production legacy voice key configuration: %v", err)
	}
}

func TestRejectsPartialSharedOrInsecureSpeechMTLS(t *testing.T) {
	setRequiredEnvironment(t)
	t.Setenv("STT_TLS_CA_FILE", "/run/secrets/stt-ca.pem")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "together") {
		t.Fatalf("partial speech mTLS configuration: %v", err)
	}

	setRequiredEnvironment(t)
	setSpeechMTLSEnvironment(t)
	t.Setenv("TTS_TLS_CA_FILE", "/run/secrets/stt-ca.pem")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "paths") {
		t.Fatalf("shared speech trust path: %v", err)
	}

	setRequiredEnvironment(t)
	setSpeechMTLSEnvironment(t)
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "must use wss") {
		t.Fatalf("plaintext endpoint with mTLS files: %v", err)
	}
}

func TestRejectsSharedSpeechBearerToken(t *testing.T) {
	setRequiredEnvironment(t)
	t.Setenv("TTS_UPSTREAM_TOKEN", "stt-token")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "tokens") {
		t.Fatalf("shared speech bearer token: %v", err)
	}
}

func TestRejectsWeakKeyAndInvalidLimits(t *testing.T) {
	setRequiredEnvironment(t)
	t.Setenv("DEVICE_TOKEN_HMAC_KEY_B64", base64.RawURLEncoding.EncodeToString([]byte("weak")))
	if _, err := Load(); err == nil {
		t.Fatal("expected weak key to fail")
	}
	setRequiredEnvironment(t)
	t.Setenv("MAX_CONNECTIONS", "0")
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid connection limit to fail")
	}
}

func TestLoadsSignedIdentityReloadConfiguration(t *testing.T) {
	setRequiredEnvironment(t)
	t.Setenv("DEVICE_REGISTRY_FILE", "/run/secrets/identity.json")
	t.Setenv("DEVICE_REGISTRY_SIGNING_PUBLIC_KEY_FILE", "/run/config/identity.pub")
	t.Setenv("DEVICE_REGISTRY_SIGNING_KEY_ID", "identity-prod-1")
	t.Setenv("DEVICE_REGISTRY_RELOAD_INTERVAL_SECONDS", "2")
	settings, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if settings.Identity.SigningKeyID != "identity-prod-1" ||
		settings.Identity.ReloadInterval != 2*time.Second ||
		settings.Identity.MinimumRevision != 1 {
		t.Fatalf("unexpected identity settings: %#v", settings)
	}
}

func TestLoadsRemoteIdentityMTLSConfiguration(t *testing.T) {
	setRequiredEnvironment(t)
	t.Setenv("DEVICE_REGISTRY_URL",
		"https://identity.example/v1/device-identity/access")
	t.Setenv("DEVICE_REGISTRY_SIGNING_PUBLIC_KEY_FILE", "/run/trust/identity.pub")
	t.Setenv("DEVICE_REGISTRY_SIGNING_KEY_ID", "identity-prod-1")
	t.Setenv("DEVICE_REGISTRY_TLS_CA_FILE", "/run/trust/identity-ca.pem")
	t.Setenv("DEVICE_REGISTRY_TLS_CERT_FILE", "/run/workload/client.pem")
	t.Setenv("DEVICE_REGISTRY_TLS_KEY_FILE", "/run/workload/client-key.pem")
	t.Setenv("DEVICE_REGISTRY_REQUEST_TIMEOUT_SECONDS", "4")
	settings, err := Load()
	if err != nil || !settings.Identity.Remote() ||
		settings.Identity.RequestTimeout != 4*time.Second {
		t.Fatalf("remote identity settings: %#v err=%v", settings.Identity, err)
	}
}

func TestProductionGatewayRequiresSignedIdentityRegistry(t *testing.T) {
	setRequiredEnvironment(t)
	t.Setenv("ALLOW_INSECURE_DEVELOPMENT", "false")
	t.Setenv("TLS_CERT_FILE", "/tls/cert.pem")
	t.Setenv("TLS_KEY_FILE", "/tls/key.pem")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "signed") {
		t.Fatalf("missing production identity snapshot: %v", err)
	}
}

func TestRejectsPartialIdentitySigningConfiguration(t *testing.T) {
	setRequiredEnvironment(t)
	t.Setenv("DEVICE_REGISTRY_FILE", "/run/secrets/identity.json")
	t.Setenv("DEVICE_REGISTRY_SIGNING_PUBLIC_KEY_FILE", "/run/config/identity.pub")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "together") {
		t.Fatalf("partial identity settings: %v", err)
	}
}

func TestProductionSignedIdentityRequiresExplicitRevisionFloor(t *testing.T) {
	setRequiredEnvironment(t)
	t.Setenv("ALLOW_INSECURE_DEVELOPMENT", "false")
	t.Setenv("TLS_CERT_FILE", "/tls/cert.pem")
	t.Setenv("TLS_KEY_FILE", "/tls/key.pem")
	t.Setenv("DEVICE_REGISTRY_FILE", "/run/secrets/identity.json")
	t.Setenv("DEVICE_REGISTRY_SIGNING_PUBLIC_KEY_FILE", "/run/config/identity.pub")
	t.Setenv("DEVICE_REGISTRY_SIGNING_KEY_ID", "identity-prod-1")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "MIN_REVISION") {
		t.Fatalf("missing production revision floor: %v", err)
	}
}
