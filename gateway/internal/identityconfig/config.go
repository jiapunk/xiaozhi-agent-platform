package identityconfig

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"
)

// Settings is the common device-identity source configuration consumed by all
// product services. File and URL are mutually exclusive.
type Settings struct {
	File                 string
	URL                  string
	SigningPublicKeyFile string
	SigningKeyID         string
	MinimumRevision      uint64
	ReloadInterval       time.Duration
	RequestTimeout       time.Duration
	TLSCAFile            string
	TLSCertificateFile   string
	TLSKeyFile           string
}

func (settings Settings) Configured() bool {
	return settings.File != "" || settings.URL != ""
}

func (settings Settings) Remote() bool { return settings.URL != "" }

func (settings Settings) Signed() bool {
	return settings.SigningPublicKeyFile != "" && settings.SigningKeyID != ""
}

// Load reads the shared DEVICE_REGISTRY_* contract. Remote delivery is always
// HTTPS/mTLS and signed, even when the rest of a process runs in development
// mode. Unsigned version-1 files remain an explicit development-only bridge.
func Load(allowInsecure, required bool) (Settings, error) {
	settings := Settings{
		File:                 os.Getenv("DEVICE_REGISTRY_FILE"),
		URL:                  os.Getenv("DEVICE_REGISTRY_URL"),
		SigningPublicKeyFile: os.Getenv("DEVICE_REGISTRY_SIGNING_PUBLIC_KEY_FILE"),
		SigningKeyID:         os.Getenv("DEVICE_REGISTRY_SIGNING_KEY_ID"),
		TLSCAFile:            os.Getenv("DEVICE_REGISTRY_TLS_CA_FILE"),
		TLSCertificateFile:   os.Getenv("DEVICE_REGISTRY_TLS_CERT_FILE"),
		TLSKeyFile:           os.Getenv("DEVICE_REGISTRY_TLS_KEY_FILE"),
		ReloadInterval:       5 * time.Second,
		RequestTimeout:       5 * time.Second,
	}
	minimumText := os.Getenv("DEVICE_REGISTRY_MIN_REVISION")
	reloadText := os.Getenv("DEVICE_REGISTRY_RELOAD_INTERVAL_SECONDS")
	timeoutText := os.Getenv("DEVICE_REGISTRY_REQUEST_TIMEOUT_SECONDS")
	requested := settings.Configured() || settings.SigningPublicKeyFile != "" ||
		settings.SigningKeyID != "" || settings.TLSCAFile != "" ||
		settings.TLSCertificateFile != "" || settings.TLSKeyFile != "" ||
		minimumText != "" || reloadText != "" || timeoutText != ""
	if !requested {
		if required {
			return Settings{}, fmt.Errorf("signed device identity snapshot source is required")
		}
		return Settings{}, nil
	}
	if (settings.File == "") == (settings.URL == "") {
		return Settings{}, fmt.Errorf("exactly one of DEVICE_REGISTRY_FILE or DEVICE_REGISTRY_URL is required")
	}

	signingParts := 0
	if settings.SigningPublicKeyFile != "" {
		signingParts++
	}
	if settings.SigningKeyID != "" {
		signingParts++
	}
	if signingParts == 1 {
		return Settings{}, fmt.Errorf("device identity signing public key and key id must be configured together")
	}
	if signingParts == 0 && (!allowInsecure || settings.Remote()) {
		return Settings{}, fmt.Errorf("signed device identity snapshot is required")
	}

	var err error
	settings.ReloadInterval, err = parseDurationSeconds(
		"DEVICE_REGISTRY_RELOAD_INTERVAL_SECONDS", reloadText, 5, 1, 300)
	if err != nil {
		return Settings{}, err
	}
	if signingParts == 2 {
		if minimumText == "" {
			if !allowInsecure {
				return Settings{}, fmt.Errorf("production identity requires DEVICE_REGISTRY_MIN_REVISION")
			}
			settings.MinimumRevision = 1
		} else {
			settings.MinimumRevision, err = canonicalPositiveUint(
				"DEVICE_REGISTRY_MIN_REVISION", minimumText)
			if err != nil {
				return Settings{}, err
			}
		}
	} else if minimumText != "" {
		return Settings{}, fmt.Errorf("DEVICE_REGISTRY_MIN_REVISION requires signed identity settings")
	}

	remoteTLSParts := 0
	for _, value := range []string{
		settings.TLSCAFile, settings.TLSCertificateFile, settings.TLSKeyFile,
	} {
		if value != "" {
			remoteTLSParts++
		}
	}
	if settings.Remote() {
		if err := validateRemoteURL(settings.URL); err != nil {
			return Settings{}, err
		}
		if remoteTLSParts != 3 {
			return Settings{}, fmt.Errorf("remote identity CA, client certificate, and client key must be configured together")
		}
		settings.RequestTimeout, err = parseDurationSeconds(
			"DEVICE_REGISTRY_REQUEST_TIMEOUT_SECONDS", timeoutText, 5, 1, 30)
		if err != nil {
			return Settings{}, err
		}
	} else if remoteTLSParts != 0 || timeoutText != "" {
		return Settings{}, fmt.Errorf("remote identity TLS/timeout settings require DEVICE_REGISTRY_URL")
	}
	return settings, nil
}

func validateRemoteURL(value string) error {
	endpoint, err := url.Parse(value)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" ||
		(endpoint.Path != "/v1/device-identity/access" &&
			endpoint.Path != "/v1/device-identity/proof") ||
		endpoint.RawPath != "" || endpoint.User != nil ||
		endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return fmt.Errorf("DEVICE_REGISTRY_URL must be an HTTPS identity access/proof endpoint")
	}
	return nil
}

func parseDurationSeconds(name, value string, fallback, minimum,
	maximum int) (time.Duration, error) {
	if value == "" {
		return time.Duration(fallback) * time.Second, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minimum || parsed > maximum ||
		strconv.Itoa(parsed) != value {
		return 0, fmt.Errorf("%s must be a canonical integer from %d through %d",
			name, minimum, maximum)
	}
	return time.Duration(parsed) * time.Second, nil
}

func canonicalPositiveUint(name, value string) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed == 0 || strconv.FormatUint(parsed, 10) != value {
		return 0, fmt.Errorf("%s must be a positive canonical integer", name)
	}
	return parsed, nil
}
