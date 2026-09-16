package config

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/identityconfig"
	"xiaozhi-agent-platform/gateway/internal/speechbudget"
)

type Settings struct {
	Address                  string
	TLSCertFile              string
	TLSKeyFile               string
	AllowInsecure            bool
	DeviceTokenKeys          [][]byte
	VoiceTokenKeyring        *auth.ManagedTokenKeyring
	DeviceTokenMaxTTL        time.Duration
	STTURL                   string
	STTHealthURL             string
	STTToken                 string
	STTTLSCAFile             string
	STTTLSClientCertFile     string
	STTTLSClientKeyFile      string
	TTSURL                   string
	TTSHealthURL             string
	TTSToken                 string
	TTSTLSCAFile             string
	TTSTLSClientCertFile     string
	TTSTLSClientKeyFile      string
	OutputSampleRate         int
	OutputFrameMillis        int
	MaxConnections           int
	MaxMessagesPerMinute     int
	MaxAudioPacketsMinute    int
	EnableSessionIssuance    bool
	Identity                 identityconfig.Settings
	PublicDeviceWSS          string
	SessionTokenTTL          time.Duration
	SessionProofMaxSkew      time.Duration
	SessionMinInterval       time.Duration
	SpeechPricing            speechbudget.Pricing
	SpeechUsageDigestKeyFile string
}

func Load() (Settings, error) {
	settings := Settings{
		Address:                  envOr("GATEWAY_ADDRESS", ":8443"),
		TLSCertFile:              os.Getenv("TLS_CERT_FILE"),
		TLSKeyFile:               os.Getenv("TLS_KEY_FILE"),
		STTURL:                   os.Getenv("STT_UPSTREAM_URL"),
		STTHealthURL:             os.Getenv("STT_HEALTH_URL"),
		STTToken:                 os.Getenv("STT_UPSTREAM_TOKEN"),
		STTTLSCAFile:             os.Getenv("STT_TLS_CA_FILE"),
		STTTLSClientCertFile:     os.Getenv("STT_TLS_CLIENT_CERT_FILE"),
		STTTLSClientKeyFile:      os.Getenv("STT_TLS_CLIENT_KEY_FILE"),
		TTSURL:                   os.Getenv("TTS_UPSTREAM_URL"),
		TTSHealthURL:             os.Getenv("TTS_HEALTH_URL"),
		TTSToken:                 os.Getenv("TTS_UPSTREAM_TOKEN"),
		TTSTLSCAFile:             os.Getenv("TTS_TLS_CA_FILE"),
		TTSTLSClientCertFile:     os.Getenv("TTS_TLS_CLIENT_CERT_FILE"),
		TTSTLSClientKeyFile:      os.Getenv("TTS_TLS_CLIENT_KEY_FILE"),
		OutputSampleRate:         24000,
		OutputFrameMillis:        60,
		MaxConnections:           1000,
		MaxMessagesPerMinute:     120,
		MaxAudioPacketsMinute:    4000,
		DeviceTokenMaxTTL:        15 * time.Minute,
		SessionTokenTTL:          15 * time.Minute,
		SessionProofMaxSkew:      time.Minute,
		SessionMinInterval:       5 * time.Second,
		PublicDeviceWSS:          os.Getenv("PUBLIC_DEVICE_WSS_URL"),
		SpeechUsageDigestKeyFile: os.Getenv("SPEECH_USAGE_DIGEST_KEY_FILE"),
		SpeechPricing: speechbudget.Pricing{
			ProfileID:                       "development-only",
			STTMicrousdPerMillionAudioMS:    1,
			TTSMicrousdPerMillionCharacters: 1,
			DailyBudgetMicrousd:             1_000_000_000,
			STTReservationChunkAudioMS:      6_000,
			TTSMaxOutputAudioMS:             120_000,
			ReservationTTL:                  120 * time.Second,
		},
	}
	var err error
	if settings.AllowInsecure, err = parseBool("ALLOW_INSECURE_DEVELOPMENT", false); err != nil {
		return Settings{}, err
	}
	if settings.EnableSessionIssuance, err = parseBool("ENABLE_SESSION_ISSUANCE", false); err != nil {
		return Settings{}, err
	}
	if settings.OutputSampleRate, err = parseInt("OUTPUT_SAMPLE_RATE", settings.OutputSampleRate, 8000, 48000); err != nil {
		return Settings{}, err
	}
	if settings.OutputFrameMillis, err = parseInt("OUTPUT_FRAME_MILLIS", settings.OutputFrameMillis, 10, 120); err != nil {
		return Settings{}, err
	}
	if settings.MaxConnections, err = parseInt("MAX_CONNECTIONS", settings.MaxConnections, 1, 1_000_000); err != nil {
		return Settings{}, err
	}
	if settings.MaxMessagesPerMinute, err = parseInt("MAX_MESSAGES_PER_MINUTE", settings.MaxMessagesPerMinute, 10, 10_000); err != nil {
		return Settings{}, err
	}
	if settings.MaxAudioPacketsMinute, err = parseInt("MAX_AUDIO_PACKETS_PER_MINUTE", settings.MaxAudioPacketsMinute, 1000, 12_000); err != nil {
		return Settings{}, err
	}
	ttlSeconds, err := parseInt("DEVICE_TOKEN_MAX_TTL_SECONDS", int(settings.DeviceTokenMaxTTL/time.Second), 60, 3600)
	if err != nil {
		return Settings{}, err
	}
	settings.DeviceTokenMaxTTL = time.Duration(ttlSeconds) * time.Second
	defaultSessionTTL := 900
	if ttlSeconds < defaultSessionTTL {
		defaultSessionTTL = ttlSeconds
	}
	sessionTTLSeconds, err := parseInt("SESSION_TOKEN_TTL_SECONDS", defaultSessionTTL, 60, ttlSeconds)
	if err != nil {
		return Settings{}, err
	}
	settings.SessionTokenTTL = time.Duration(sessionTTLSeconds) * time.Second
	proofSkewSeconds, err := parseInt("SESSION_PROOF_MAX_SKEW_SECONDS", 60, 10, 300)
	if err != nil {
		return Settings{}, err
	}
	settings.SessionProofMaxSkew = time.Duration(proofSkewSeconds) * time.Second
	minimumIntervalSeconds, err := parseInt("SESSION_MIN_INTERVAL_SECONDS", 5, 0, 60)
	if err != nil {
		return Settings{}, err
	}
	settings.SessionMinInterval = time.Duration(minimumIntervalSeconds) * time.Second
	settings.Identity, err = identityconfig.Load(settings.AllowInsecure,
		!settings.AllowInsecure || settings.EnableSessionIssuance)
	if err != nil {
		return Settings{}, err
	}

	encodedKeys := strings.TrimSpace(os.Getenv("DEVICE_TOKEN_HMAC_KEYS_B64"))
	if encodedKeys == "" {
		encodedKeys = strings.TrimSpace(os.Getenv("DEVICE_TOKEN_HMAC_KEY_B64"))
	}
	keyringFile := strings.TrimSpace(os.Getenv("VOICE_TOKEN_HMAC_KEYRING_FILE"))
	keyringFloor := strings.TrimSpace(os.Getenv("VOICE_TOKEN_HMAC_KEYRING_MIN_REVISION"))
	if keyringFile != "" || keyringFloor != "" {
		if keyringFile == "" || keyringFloor == "" || encodedKeys != "" {
			return Settings{}, fmt.Errorf("managed voice token keyring file/revision must be configured together without legacy keys")
		}
		minimumRevision, parseErr := strconv.ParseUint(keyringFloor, 10, 64)
		if parseErr != nil || minimumRevision == 0 ||
			strconv.FormatUint(minimumRevision, 10) != keyringFloor {
			return Settings{}, fmt.Errorf("VOICE_TOKEN_HMAC_KEYRING_MIN_REVISION must be a canonical positive integer")
		}
		settings.VoiceTokenKeyring, err = auth.LoadManagedTokenKeyring(
			keyringFile, minimumRevision, time.Now().UTC())
		if err != nil {
			return Settings{}, err
		}
	} else {
		if !settings.AllowInsecure {
			return Settings{}, fmt.Errorf("production Gateway requires a managed voice token keyring")
		}
		settings.DeviceTokenKeys, err = decodeKeys(encodedKeys)
		if err != nil {
			return Settings{}, err
		}
	}
	if settings.STTURL == "" || settings.STTToken == "" ||
		settings.TTSURL == "" || settings.TTSToken == "" {
		return Settings{}, fmt.Errorf("STT and TTS upstream URLs/tokens are required")
	}
	if !validBearerToken(settings.STTToken) || !validBearerToken(settings.TTSToken) {
		return Settings{}, fmt.Errorf("STT and TTS bearer tokens have invalid format")
	}
	if settings.STTToken == settings.TTSToken {
		return Settings{}, fmt.Errorf("STT and TTS bearer tokens must be isolated")
	}
	if err := validateSpeechMTLS(settings); err != nil {
		return Settings{}, err
	}
	if !settings.AllowInsecure && (settings.TLSCertFile == "" || settings.TLSKeyFile == "") {
		return Settings{}, fmt.Errorf("TLS_CERT_FILE and TLS_KEY_FILE are required")
	}
	if (settings.TLSCertFile == "") != (settings.TLSKeyFile == "") {
		return Settings{}, fmt.Errorf("TLS certificate and key must be configured together")
	}
	if settings.EnableSessionIssuance {
		if !settings.AllowInsecure {
			return Settings{}, fmt.Errorf("embedded session issuance is development-only; use the independent control plane")
		}
		if settings.Identity.File == "" || settings.Identity.Signed() {
			return Settings{}, fmt.Errorf("embedded session issuance requires a legacy DEVICE_REGISTRY_FILE")
		}
		if err := validatePublicDeviceURL(settings.PublicDeviceWSS,
			settings.AllowInsecure); err != nil {
			return Settings{}, err
		}
	}
	if err := loadSpeechUsage(&settings); err != nil {
		return Settings{}, err
	}
	return settings, nil
}

func loadSpeechUsage(settings *Settings) error {
	if settings == nil {
		return fmt.Errorf("speech usage settings are required")
	}
	profileEnvironment := []string{
		"SPEECH_PRICING_PROFILE_ID",
		"SPEECH_STT_MICROUSD_PER_MILLION_AUDIO_MS",
		"SPEECH_TTS_MICROUSD_PER_MILLION_CHARACTERS",
		"SPEECH_TTS_MICROUSD_PER_MILLION_OUTPUT_AUDIO_MS",
		"SPEECH_DAILY_BUDGET_MICROUSD",
		"SPEECH_STT_RESERVATION_CHUNK_AUDIO_MS",
		"SPEECH_TTS_MAX_OUTPUT_AUDIO_MS",
		"SPEECH_USAGE_RESERVATION_TTL_SECONDS",
	}
	if !settings.AllowInsecure {
		for _, name := range append(profileEnvironment,
			"SPEECH_USAGE_DIGEST_KEY_FILE") {
			if os.Getenv(name) == "" {
				return fmt.Errorf("production Gateway requires %s", name)
			}
		}
	}
	pricing := settings.SpeechPricing
	if value := os.Getenv("SPEECH_PRICING_PROFILE_ID"); value != "" {
		pricing.ProfileID = value
	}
	var err error
	if pricing.STTMicrousdPerMillionAudioMS, err = parseInt64(
		"SPEECH_STT_MICROUSD_PER_MILLION_AUDIO_MS",
		pricing.STTMicrousdPerMillionAudioMS, 1, speechbudget.MaximumRate); err != nil {
		return err
	}
	if pricing.TTSMicrousdPerMillionCharacters, err = parseInt64(
		"SPEECH_TTS_MICROUSD_PER_MILLION_CHARACTERS",
		pricing.TTSMicrousdPerMillionCharacters, 0, speechbudget.MaximumRate); err != nil {
		return err
	}
	if pricing.TTSMicrousdPerMillionOutputAudioMS, err = parseInt64(
		"SPEECH_TTS_MICROUSD_PER_MILLION_OUTPUT_AUDIO_MS",
		pricing.TTSMicrousdPerMillionOutputAudioMS, 0, speechbudget.MaximumRate); err != nil {
		return err
	}
	if pricing.DailyBudgetMicrousd, err = parseInt64(
		"SPEECH_DAILY_BUDGET_MICROUSD", pricing.DailyBudgetMicrousd,
		1, speechbudget.MaximumBudget); err != nil {
		return err
	}
	if pricing.STTReservationChunkAudioMS, err = parseInt64(
		"SPEECH_STT_RESERVATION_CHUNK_AUDIO_MS",
		pricing.STTReservationChunkAudioMS, speechbudget.MinimumSTTChunkMS,
		speechbudget.MaximumSTTChunkMS); err != nil {
		return err
	}
	if pricing.TTSMaxOutputAudioMS, err = parseInt64(
		"SPEECH_TTS_MAX_OUTPUT_AUDIO_MS", pricing.TTSMaxOutputAudioMS,
		speechbudget.MinimumTTSOutputMS, speechbudget.MaximumTTSOutputMS); err != nil {
		return err
	}
	ttl, err := parseInt64("SPEECH_USAGE_RESERVATION_TTL_SECONDS",
		int64(pricing.ReservationTTL/time.Second),
		int64(speechbudget.MinimumReservationTTL/time.Second), 600)
	if err != nil {
		return err
	}
	pricing.ReservationTTL = time.Duration(ttl) * time.Second
	if err := pricing.Validate(); err != nil {
		return fmt.Errorf("speech usage pricing is invalid")
	}
	settings.SpeechPricing = pricing
	return nil
}

func validBearerToken(value string) bool {
	return len(value) <= 2048 && strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, " \t\r\n\x00")
}

func (settings Settings) SpeechMTLSConfigured() bool {
	return settings.STTTLSCAFile != "" && settings.STTTLSClientCertFile != "" &&
		settings.STTTLSClientKeyFile != "" && settings.TTSTLSCAFile != "" &&
		settings.TTSTLSClientCertFile != "" && settings.TTSTLSClientKeyFile != ""
}

func validateSpeechMTLS(settings Settings) error {
	paths := []string{
		settings.STTTLSCAFile, settings.STTTLSClientCertFile, settings.STTTLSClientKeyFile,
		settings.TTSTLSCAFile, settings.TTSTLSClientCertFile, settings.TTSTLSClientKeyFile,
	}
	configured := 0
	seen := make(map[string]bool, len(paths))
	for _, path := range paths {
		if path == "" {
			continue
		}
		configured++
		if seen[path] {
			return fmt.Errorf("STT and TTS mTLS credential paths must be isolated")
		}
		seen[path] = true
	}
	if configured != 0 && configured != len(paths) {
		return fmt.Errorf("all STT and TTS mTLS credential files must be configured together")
	}
	if !settings.AllowInsecure && configured != len(paths) {
		return fmt.Errorf("isolated STT and TTS mTLS credentials are required")
	}
	if configured == 0 {
		return nil
	}
	for _, target := range []struct {
		name   string
		value  string
		scheme string
	}{
		{"STT_UPSTREAM_URL", settings.STTURL, "wss"},
		{"STT_HEALTH_URL", settings.STTHealthURL, "https"},
		{"TTS_UPSTREAM_URL", settings.TTSURL, "https"},
		{"TTS_HEALTH_URL", settings.TTSHealthURL, "https"},
	} {
		if target.value == "" && strings.HasSuffix(target.name, "HEALTH_URL") {
			continue
		}
		parsed, err := url.Parse(target.value)
		if err != nil || parsed.IsAbs() == false || parsed.Host == "" ||
			parsed.Scheme != target.scheme {
			return fmt.Errorf("%s must use %s when speech mTLS is configured",
				target.name, target.scheme)
		}
	}
	return nil
}

func validatePublicDeviceURL(value string, allowInsecure bool) error {
	endpoint, err := url.Parse(value)
	if err != nil || endpoint.Host == "" || endpoint.Path != "/v1/device" ||
		endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return fmt.Errorf("PUBLIC_DEVICE_WSS_URL must be an absolute WebSocket /v1/device URL")
	}
	if endpoint.Scheme != "wss" && !(allowInsecure && endpoint.Scheme == "ws") {
		return fmt.Errorf("PUBLIC_DEVICE_WSS_URL must use wss outside development mode")
	}
	return nil
}

func decodeKeys(value string) ([][]byte, error) {
	parts := strings.Split(value, ",")
	if value == "" || len(parts) == 0 || len(parts) > 3 {
		return nil, fmt.Errorf("DEVICE_TOKEN_HMAC_KEYS_B64 must contain 1 through 3 keys")
	}
	keys := make([][]byte, 0, len(parts))
	for _, part := range parts {
		key, err := decodeKey(strings.TrimSpace(part))
		if err != nil || len(key) < 32 {
			return nil, fmt.Errorf("each device token HMAC key must encode at least 32 bytes")
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func decodeKey(value string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("empty key")
	}
	for _, encoding := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding,
	} {
		if decoded, err := encoding.DecodeString(value); err == nil {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("invalid base64")
}

func parseBool(name string, fallback bool) (bool, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean", name)
	}
	return parsed, nil
}

func parseInt(name string, fallback, minimum, maximum int) (int, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, fmt.Errorf("%s must be an integer from %d through %d", name, minimum, maximum)
	}
	return parsed, nil
}

func parseInt64(name string, fallback, minimum, maximum int64) (int64, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < minimum || parsed > maximum ||
		strconv.FormatInt(parsed, 10) != value {
		return 0, fmt.Errorf("%s must be a canonical integer from %d through %d",
			name, minimum, maximum)
	}
	return parsed, nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
