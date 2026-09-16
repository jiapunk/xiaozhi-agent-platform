package firmwareorigin

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/generation"
	"xiaozhi-agent-platform/gateway/internal/identityconfig"
)

type Settings struct {
	Address         string
	TLSCertFile     string
	TLSKeyFile      string
	AllowInsecure   bool
	CatalogFile     string
	PublicAuthority string
	OTATokenKeys    [][]byte
	OTATokenKeyring *auth.ManagedTokenKeyring
	OTATokenMaxTTL  time.Duration
	MaxConcurrent   int
	WriteTimeout    time.Duration
	Generation      generation.ReplicaSettings
	Identity        identityconfig.Settings
}

func LoadSettings() (Settings, error) {
	settings := Settings{
		Address:         envOr("FIRMWARE_ORIGIN_ADDRESS", ":8446"),
		TLSCertFile:     os.Getenv("FIRMWARE_ORIGIN_TLS_CERT_FILE"),
		TLSKeyFile:      os.Getenv("FIRMWARE_ORIGIN_TLS_KEY_FILE"),
		CatalogFile:     os.Getenv("FIRMWARE_ORIGIN_CATALOG_FILE"),
		PublicAuthority: os.Getenv("FIRMWARE_ORIGIN_PUBLIC_AUTHORITY"),
		MaxConcurrent:   100,
		WriteTimeout:    5 * time.Minute,
	}
	var err error
	settings.AllowInsecure, err = parseBool(
		"ALLOW_INSECURE_DEVELOPMENT", false)
	if err != nil {
		return Settings{}, err
	}
	if !settings.AllowInsecure &&
		(settings.TLSCertFile == "" || settings.TLSKeyFile == "") {
		return Settings{}, fmt.Errorf("firmware origin TLS certificate and key are required")
	}
	if (settings.TLSCertFile == "") != (settings.TLSKeyFile == "") {
		return Settings{}, fmt.Errorf("firmware origin TLS certificate and key must be configured together")
	}
	if settings.CatalogFile == "" {
		return Settings{}, fmt.Errorf("FIRMWARE_ORIGIN_CATALOG_FILE is required")
	}
	if !validAuthority(settings.PublicAuthority) {
		return Settings{}, fmt.Errorf("FIRMWARE_ORIGIN_PUBLIC_AUTHORITY is invalid")
	}
	settings.Identity, err = identityconfig.Load(settings.AllowInsecure,
		!settings.AllowInsecure)
	if err != nil {
		return Settings{}, err
	}
	ttl, err := parseInt("OTA_TOKEN_MAX_TTL_SECONDS", 900, 60, 900)
	if err != nil {
		return Settings{}, err
	}
	settings.OTATokenMaxTTL = time.Duration(ttl) * time.Second
	legacyKeys := strings.TrimSpace(os.Getenv("OTA_TOKEN_HMAC_KEYS_B64"))
	keyringFile := strings.TrimSpace(os.Getenv("OTA_TOKEN_HMAC_KEYRING_FILE"))
	keyringFloor := strings.TrimSpace(os.Getenv("OTA_TOKEN_HMAC_KEYRING_MIN_REVISION"))
	if keyringFile != "" || keyringFloor != "" {
		if keyringFile == "" || keyringFloor == "" || legacyKeys != "" {
			return Settings{}, fmt.Errorf("managed OTA token keyring file/revision must be configured together without legacy keys")
		}
		minimumRevision, parseErr := strconv.ParseUint(keyringFloor, 10, 64)
		if parseErr != nil || minimumRevision == 0 ||
			strconv.FormatUint(minimumRevision, 10) != keyringFloor {
			return Settings{}, fmt.Errorf("OTA_TOKEN_HMAC_KEYRING_MIN_REVISION must be a canonical positive integer")
		}
		settings.OTATokenKeyring, err = auth.LoadManagedTokenKeyring(
			keyringFile, minimumRevision, time.Now().UTC())
		if err != nil {
			return Settings{}, err
		}
	} else {
		if !settings.AllowInsecure {
			return Settings{}, fmt.Errorf("production Firmware Origin requires a managed OTA token keyring")
		}
		settings.OTATokenKeys, err = decodeKeyring(
			"OTA_TOKEN_HMAC_KEYS_B64", legacyKeys)
		if err != nil {
			return Settings{}, err
		}
	}
	settings.MaxConcurrent, err = parseInt(
		"FIRMWARE_ORIGIN_MAX_CONCURRENT", 100, 1, 10000)
	if err != nil {
		return Settings{}, err
	}
	writeTimeout, err := parseInt(
		"FIRMWARE_ORIGIN_WRITE_TIMEOUT_SECONDS", 300, 30, 1800)
	if err != nil {
		return Settings{}, err
	}
	settings.WriteTimeout = time.Duration(writeTimeout) * time.Second
	settings.Generation, err = generation.LoadReplicaSettings(
		"firmwareorigin", settings.AllowInsecure)
	if err != nil {
		return Settings{}, err
	}
	if settings.OTATokenKeyring != nil {
		if !auth.ManagedTokenKeyringsDisjointFromSecrets(
			[]*auth.ManagedTokenKeyring{settings.OTATokenKeyring},
			[][]byte{settings.Generation.Replica.Key}) {
			return Settings{}, fmt.Errorf("generation replica key must be isolated from OTA token keyring")
		}
	} else {
		for _, key := range settings.OTATokenKeys {
			if len(key) == len(settings.Generation.Replica.Key) &&
				subtle.ConstantTimeCompare(key, settings.Generation.Replica.Key) == 1 {
				return Settings{}, fmt.Errorf("generation replica key must be isolated from OTA token keys")
			}
		}
	}
	return settings, nil
}

func validAuthority(value string) bool {
	if value == "" || len(value) > 253 || strings.ToLower(value) != value ||
		strings.ContainsAny(value, "/\\@?# \t\r\n") ||
		strings.Count(value, ":") > 1 {
		return false
	}
	host, portText, hasPort := strings.Cut(value, ":")
	if host == "" || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' ||
			label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character >= 'a' && character <= 'z') ||
				(character >= '0' && character <= '9') || character == '-' {
				continue
			}
			return false
		}
	}
	if !hasPort {
		return true
	}
	port, err := strconv.Atoi(portText)
	return err == nil && port >= 1 && port <= 65535 &&
		strconv.Itoa(port) == portText
}

// ValidAuthority reports whether value is a canonical firmware origin authority.
func ValidAuthority(value string) bool {
	return validAuthority(value)
}

func decodeKeyring(name, value string) ([][]byte, error) {
	parts := strings.Split(value, ",")
	if value == "" || len(parts) == 0 || len(parts) > 3 {
		return nil, fmt.Errorf("%s must contain 1 through 3 keys", name)
	}
	keys := make([][]byte, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		var decoded []byte
		var decodeErr error
		for _, encoding := range []*base64.Encoding{
			base64.RawURLEncoding, base64.URLEncoding,
			base64.RawStdEncoding, base64.StdEncoding,
		} {
			decoded, decodeErr = encoding.DecodeString(part)
			if decodeErr == nil {
				break
			}
		}
		if decodeErr != nil || len(decoded) < 32 || len(decoded) > 128 {
			return nil, fmt.Errorf("each %s key must encode 32 through 128 bytes", name)
		}
		for _, prior := range keys {
			if len(prior) == len(decoded) &&
				subtle.ConstantTimeCompare(prior, decoded) == 1 {
				return nil, fmt.Errorf("%s keys must be distinct", name)
			}
		}
		keys = append(keys, append([]byte(nil), decoded...))
	}
	return keys, nil
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

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
