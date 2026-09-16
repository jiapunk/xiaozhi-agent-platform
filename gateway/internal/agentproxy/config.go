package agentproxy

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
	"xiaozhi-agent-platform/gateway/internal/usagebudget"
)

type Settings struct {
	Address              string
	TLSCertFile          string
	TLSKeyFile           string
	AllowInsecure        bool
	AgentTokenKeys       [][]byte
	AgentTokenKeyring    *auth.ManagedTokenKeyring
	AgentTokenMaxTTL     time.Duration
	ProviderURL          string
	ProviderAPIKey       string
	ProviderModel        string
	ProviderOrganization string
	ProviderProject      string
	PublicModel          string
	MaxOutputTokens      int
	MaxRequestBytes      int64
	MaxResponseBytes     int64
	RequestTimeout       time.Duration
	MaxConcurrent        int
	MaxRequestsMinute    int
	UsageBudgetEnabled   bool
	UsagePricing         usagebudget.Pricing
	UsageDigestKey       []byte
	Identity             identityconfig.Settings
}

func LoadSettings() (Settings, error) {
	settings := Settings{
		Address:              envOr("AGENT_PROXY_ADDRESS", ":8445"),
		TLSCertFile:          os.Getenv("AGENT_PROXY_TLS_CERT_FILE"),
		TLSKeyFile:           os.Getenv("AGENT_PROXY_TLS_KEY_FILE"),
		ProviderURL:          os.Getenv("AGENT_PROVIDER_URL"),
		ProviderAPIKey:       os.Getenv("AGENT_PROVIDER_API_KEY"),
		ProviderModel:        os.Getenv("AGENT_PROVIDER_MODEL"),
		PublicModel:          envOr("AGENT_PUBLIC_MODEL", "product-agent"),
		MaxOutputTokens:      1024,
		MaxRequestBytes:      256 * 1024,
		MaxResponseBytes:     1024 * 1024,
		RequestTimeout:       35 * time.Second,
		MaxConcurrent:        100,
		MaxRequestsMinute:    30,
		ProviderOrganization: os.Getenv("OPENAI_ORGANIZATION"),
		ProviderProject:      os.Getenv("OPENAI_PROJECT"),
	}
	var err error
	if settings.AllowInsecure, err = parseBool(
		"ALLOW_INSECURE_DEVELOPMENT", false); err != nil {
		return Settings{}, err
	}
	if !settings.AllowInsecure &&
		(settings.TLSCertFile == "" || settings.TLSKeyFile == "") {
		return Settings{}, fmt.Errorf("Agent proxy TLS certificate and key are required")
	}
	if (settings.TLSCertFile == "") != (settings.TLSKeyFile == "") {
		return Settings{}, fmt.Errorf("Agent proxy TLS certificate and key must be configured together")
	}
	if err := validateProviderURL(settings.ProviderURL,
		settings.AllowInsecure); err != nil {
		return Settings{}, err
	}
	if !validModel(settings.ProviderModel) || !validModel(settings.PublicModel) {
		return Settings{}, fmt.Errorf("Agent provider/public model is invalid")
	}
	if strings.TrimSpace(settings.ProviderAPIKey) == "" ||
		strings.ContainsAny(settings.ProviderAPIKey, "\r\n") {
		return Settings{}, fmt.Errorf("AGENT_PROVIDER_API_KEY is required and must be header-safe")
	}
	if !validOptionalHeaderIdentifier(settings.ProviderOrganization) ||
		!validOptionalHeaderIdentifier(settings.ProviderProject) {
		return Settings{}, fmt.Errorf("OpenAI organization/project must be header-safe identifiers")
	}
	settings.Identity, err = identityconfig.Load(settings.AllowInsecure,
		!settings.AllowInsecure)
	if err != nil {
		return Settings{}, err
	}
	ttl, err := parseInt("AGENT_TOKEN_MAX_TTL_SECONDS", 600, 60, 3600)
	if err != nil {
		return Settings{}, err
	}
	settings.AgentTokenMaxTTL = time.Duration(ttl) * time.Second
	legacyKeys := strings.TrimSpace(os.Getenv("AGENT_TOKEN_HMAC_KEYS_B64"))
	keyringFile := strings.TrimSpace(os.Getenv("AGENT_TOKEN_HMAC_KEYRING_FILE"))
	keyringFloor := strings.TrimSpace(os.Getenv("AGENT_TOKEN_HMAC_KEYRING_MIN_REVISION"))
	if keyringFile != "" || keyringFloor != "" {
		if keyringFile == "" || keyringFloor == "" || legacyKeys != "" {
			return Settings{}, fmt.Errorf("managed Agent token keyring file/revision must be configured together without legacy keys")
		}
		minimumRevision, parseErr := strconv.ParseUint(keyringFloor, 10, 64)
		if parseErr != nil || minimumRevision == 0 ||
			strconv.FormatUint(minimumRevision, 10) != keyringFloor {
			return Settings{}, fmt.Errorf("AGENT_TOKEN_HMAC_KEYRING_MIN_REVISION must be a canonical positive integer")
		}
		settings.AgentTokenKeyring, err = auth.LoadManagedTokenKeyring(
			keyringFile, minimumRevision, time.Now().UTC())
		if err != nil {
			return Settings{}, err
		}
	} else {
		if !settings.AllowInsecure {
			return Settings{}, fmt.Errorf("production Agent Proxy requires a managed token keyring")
		}
		settings.AgentTokenKeys, err = decodeKeys(legacyKeys)
		if err != nil {
			return Settings{}, err
		}
	}
	if settings.MaxOutputTokens, err = parseInt(
		"AGENT_MAX_OUTPUT_TOKENS", 1024, 1, 8192); err != nil {
		return Settings{}, err
	}
	requestKiB, err := parseInt("AGENT_MAX_REQUEST_KIB", 256, 16, 1024)
	if err != nil {
		return Settings{}, err
	}
	responseKiB, err := parseInt("AGENT_MAX_RESPONSE_KIB", 1024, 16, 4096)
	if err != nil {
		return Settings{}, err
	}
	timeoutSeconds, err := parseInt("AGENT_REQUEST_TIMEOUT_SECONDS", 35, 5, 120)
	if err != nil {
		return Settings{}, err
	}
	if settings.MaxConcurrent, err = parseInt(
		"AGENT_MAX_CONCURRENT", 100, 1, 10000); err != nil {
		return Settings{}, err
	}
	if settings.MaxRequestsMinute, err = parseInt(
		"AGENT_MAX_REQUESTS_PER_MINUTE", 30, 1, 600); err != nil {
		return Settings{}, err
	}
	settings.MaxRequestBytes = int64(requestKiB) * 1024
	settings.MaxResponseBytes = int64(responseKiB) * 1024
	settings.RequestTimeout = time.Duration(timeoutSeconds) * time.Second
	if err := loadUsageBudgetSettings(&settings); err != nil {
		return Settings{}, err
	}
	return settings, nil
}

func loadUsageBudgetSettings(settings *Settings) error {
	if settings == nil {
		return fmt.Errorf("Agent usage settings destination is required")
	}
	names := []string{
		"AGENT_PRICING_PROFILE_ID",
		"AGENT_INPUT_MICROUSD_PER_MILLION_TOKENS",
		"AGENT_OUTPUT_MICROUSD_PER_MILLION_TOKENS",
		"AGENT_DAILY_BUDGET_MICROUSD",
		"AGENT_INPUT_TOKEN_OVERHEAD",
		"AGENT_USAGE_RESERVATION_TTL_SECONDS",
		"AGENT_USAGE_DIGEST_KEY_FILE",
	}
	configured := false
	complete := true
	for _, name := range names {
		present := os.Getenv(name) != ""
		configured = configured || present
		complete = complete && present
	}
	if !configured && settings.AllowInsecure {
		return nil
	}
	if !complete {
		return fmt.Errorf("Agent usage pricing, budget, reservation, and digest key settings must be configured together")
	}
	inputRate, err := parseInt64("AGENT_INPUT_MICROUSD_PER_MILLION_TOKENS",
		1, usagebudget.MaximumRate)
	if err != nil {
		return err
	}
	outputRate, err := parseInt64("AGENT_OUTPUT_MICROUSD_PER_MILLION_TOKENS",
		1, usagebudget.MaximumRate)
	if err != nil {
		return err
	}
	dailyBudget, err := parseInt64("AGENT_DAILY_BUDGET_MICROUSD",
		1, usagebudget.MaximumBudget)
	if err != nil {
		return err
	}
	overhead, err := parseInt64("AGENT_INPUT_TOKEN_OVERHEAD", 0, 65_536)
	if err != nil {
		return err
	}
	reservationSeconds, err := parseInt64(
		"AGENT_USAGE_RESERVATION_TTL_SECONDS", 30, 600)
	if err != nil {
		return err
	}
	pricing := usagebudget.Pricing{
		ProfileID:                     os.Getenv("AGENT_PRICING_PROFILE_ID"),
		InputMicrousdPerMillionToken:  inputRate,
		OutputMicrousdPerMillionToken: outputRate,
		DailyBudgetMicrousd:           dailyBudget, InputTokenOverhead: overhead,
		ReservationTTL: time.Duration(reservationSeconds) * time.Second,
	}
	if pricing.Validate() != nil ||
		pricing.ReservationTTL < settings.RequestTimeout+15*time.Second {
		return fmt.Errorf("Agent usage pricing or reservation settings are invalid")
	}
	key, err := usagebudget.LoadDigestKey(os.Getenv("AGENT_USAGE_DIGEST_KEY_FILE"))
	if err != nil {
		return err
	}
	settings.UsageBudgetEnabled = true
	settings.UsagePricing = pricing
	settings.UsageDigestKey = key
	return nil
}

func decodeKeys(value string) ([][]byte, error) {
	parts := strings.Split(value, ",")
	if value == "" || len(parts) == 0 || len(parts) > 3 {
		return nil, fmt.Errorf("AGENT_TOKEN_HMAC_KEYS_B64 must contain 1 through 3 keys")
	}
	keys := make([][]byte, 0, len(parts))
	for _, part := range parts {
		var decoded []byte
		var err error
		for _, encoding := range []*base64.Encoding{
			base64.RawURLEncoding, base64.URLEncoding,
			base64.RawStdEncoding, base64.StdEncoding,
		} {
			if decoded, err = encoding.DecodeString(strings.TrimSpace(part)); err == nil {
				break
			}
		}
		if err != nil || len(decoded) < 32 || len(decoded) > 128 {
			return nil, fmt.Errorf("each Agent token key must encode 32 through 128 bytes")
		}
		keys = append(keys, decoded)
	}
	return keys, nil
}

func validateProviderURL(value string, allowInsecure bool) error {
	endpoint, err := url.Parse(value)
	if err != nil || endpoint.Host == "" ||
		endpoint.Path != "/v1/chat/completions" || endpoint.User != nil ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return fmt.Errorf("AGENT_PROVIDER_URL must be an absolute /v1/chat/completions URL")
	}
	if endpoint.Scheme != "https" && !(allowInsecure && endpoint.Scheme == "http") {
		return fmt.Errorf("AGENT_PROVIDER_URL must use HTTPS outside development mode")
	}
	return nil
}

func validModel(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '_' || character == '.' ||
			character == ':' {
			continue
		}
		return false
	}
	return true
}

func validOptionalHeaderIdentifier(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '-' || character == '_' || character == '.' ||
			character == ':' {
			continue
		}
		return false
	}
	return true
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
		return 0, fmt.Errorf("%s must be an integer from %d through %d",
			name, minimum, maximum)
	}
	return parsed, nil
}

func parseInt64(name string, minimum, maximum int64) (int64, error) {
	value := os.Getenv(name)
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || strconv.FormatInt(parsed, 10) != value ||
		parsed < minimum || parsed > maximum {
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
