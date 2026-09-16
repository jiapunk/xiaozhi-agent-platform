package accountauth

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Settings struct {
	ListenAddress                       string
	HealthAddress                       string
	DatabaseURL                         string
	DatabaseMaxOpen                     int
	DatabaseMaxIdle                     int
	DatabaseConnTTL                     time.Duration
	OperationTimeout                    time.Duration
	ClientCAFile                        string
	ServerCertFile                      string
	ServerKeyFile                       string
	ShutdownTimeout                     time.Duration
	EntitlementUpdateKeyringFile        string
	EntitlementUpdateKeyringMinRevision uint64
	EntitlementUpdateAuthorizationTTL   time.Duration
	PushEnabled                         bool
	PushTokenKeyringFile                string
	PushAPNsTopic                       string
	PushAPNsKeyID                       string
	PushAPNsTeamID                      string
	PushAPNsPrivateKeyFile              string
	PushFCMProjectID                    string
	PushFCMCredentialMode               string
	PushFCMServiceAccountFile           string
	PushProviderTimeout                 time.Duration
}

func LoadSettings() (Settings, error) {
	settings := Settings{
		ListenAddress:   environmentDefault("ACCOUNT_AUTHORIZATION_LISTEN_ADDR", ":9444"),
		HealthAddress:   environmentDefault("ACCOUNT_AUTHORIZATION_HEALTH_LISTEN_ADDR", ":9080"),
		DatabaseURL:     os.Getenv("ACCOUNT_AUTHORIZATION_DATABASE_URL"),
		ClientCAFile:    os.Getenv("ACCOUNT_AUTHORIZATION_CLIENT_CA_FILE"),
		ServerCertFile:  os.Getenv("ACCOUNT_AUTHORIZATION_SERVER_CERT_FILE"),
		ServerKeyFile:   os.Getenv("ACCOUNT_AUTHORIZATION_SERVER_KEY_FILE"),
		ShutdownTimeout: 10 * time.Second,
	}
	if !validListenAddress(settings.ListenAddress) {
		return Settings{}, fmt.Errorf("invalid ACCOUNT_AUTHORIZATION_LISTEN_ADDR")
	}
	if !validWildcardListenAddress(settings.HealthAddress) ||
		settings.HealthAddress == settings.ListenAddress {
		return Settings{}, fmt.Errorf("invalid ACCOUNT_AUTHORIZATION_HEALTH_LISTEN_ADDR")
	}
	if !validProductionDatabaseURL(settings.DatabaseURL) {
		return Settings{}, fmt.Errorf("ACCOUNT_AUTHORIZATION_DATABASE_URL must be a PostgreSQL URL with sslmode=verify-full")
	}
	if settings.ClientCAFile == "" || settings.ServerCertFile == "" ||
		settings.ServerKeyFile == "" {
		return Settings{}, fmt.Errorf("Companion authorization client CA, server certificate, and server key are required")
	}
	settings.EntitlementUpdateKeyringFile = os.Getenv(
		"ENTITLEMENT_UPDATE_KEYRING_FILE")
	if settings.EntitlementUpdateKeyringFile == "" {
		return Settings{}, fmt.Errorf("ENTITLEMENT_UPDATE_KEYRING_FILE is required")
	}
	minimumRevision, err := accountSettingRequiredUint64(
		"ENTITLEMENT_UPDATE_KEYRING_MIN_REVISION")
	if err != nil {
		return Settings{}, err
	}
	settings.EntitlementUpdateKeyringMinRevision = minimumRevision
	entitlementTTL, err := accountSettingInt(
		"ENTITLEMENT_UPDATE_AUTHORIZATION_TTL_SECONDS", 300, 60, 300)
	if err != nil {
		return Settings{}, err
	}
	settings.EntitlementUpdateAuthorizationTTL =
		time.Duration(entitlementTTL) * time.Second
	pushEnabled, err := accountSettingBool("COMPANION_PUSH_ENABLED", false)
	if err != nil {
		return Settings{}, err
	}
	settings.PushEnabled = pushEnabled
	settings.PushTokenKeyringFile = os.Getenv("COMPANION_PUSH_TOKEN_KEYRING_FILE")
	settings.PushAPNsTopic = os.Getenv("COMPANION_PUSH_APNS_TOPIC")
	settings.PushAPNsKeyID = os.Getenv("COMPANION_PUSH_APNS_KEY_ID")
	settings.PushAPNsTeamID = os.Getenv("COMPANION_PUSH_APNS_TEAM_ID")
	settings.PushAPNsPrivateKeyFile = os.Getenv("COMPANION_PUSH_APNS_PRIVATE_KEY_FILE")
	settings.PushFCMProjectID = os.Getenv("COMPANION_PUSH_FCM_PROJECT_ID")
	settings.PushFCMCredentialMode = os.Getenv("COMPANION_PUSH_FCM_CREDENTIAL_MODE")
	settings.PushFCMServiceAccountFile = os.Getenv("COMPANION_PUSH_FCM_SERVICE_ACCOUNT_FILE")
	pushValues := []string{settings.PushTokenKeyringFile,
		settings.PushAPNsTopic, settings.PushAPNsKeyID, settings.PushAPNsTeamID,
		settings.PushAPNsPrivateKeyFile, settings.PushFCMProjectID,
		settings.PushFCMCredentialMode, settings.PushFCMServiceAccountFile,
		os.Getenv("COMPANION_PUSH_PROVIDER_TIMEOUT_MS")}
	if !settings.PushEnabled {
		for _, value := range pushValues {
			if value != "" {
				return Settings{}, fmt.Errorf("Companion push settings require COMPANION_PUSH_ENABLED=true")
			}
		}
	} else {
		if settings.PushTokenKeyringFile == "" {
			return Settings{}, fmt.Errorf("COMPANION_PUSH_TOKEN_KEYRING_FILE is required")
		}
		apnsParts := countConfigured(settings.PushAPNsTopic,
			settings.PushAPNsKeyID, settings.PushAPNsTeamID,
			settings.PushAPNsPrivateKeyFile)
		if apnsParts != 0 && apnsParts != 4 {
			return Settings{}, fmt.Errorf("APNs topic, key ID, team ID, and private key must be configured together")
		}
		fcmParts := countConfigured(settings.PushFCMProjectID,
			settings.PushFCMCredentialMode)
		if fcmParts != 0 && fcmParts != 2 {
			return Settings{}, fmt.Errorf("FCM project and credential mode must be configured together")
		}
		switch settings.PushFCMCredentialMode {
		case "":
			if settings.PushFCMServiceAccountFile != "" {
				return Settings{}, fmt.Errorf("FCM service account requires service-account credential mode")
			}
		case "metadata":
			if settings.PushFCMServiceAccountFile != "" {
				return Settings{}, fmt.Errorf("metadata credential mode forbids a service-account file")
			}
		case "service-account":
			if settings.PushFCMServiceAccountFile == "" {
				return Settings{}, fmt.Errorf("service-account credential mode requires its credential file")
			}
		default:
			return Settings{}, fmt.Errorf("invalid COMPANION_PUSH_FCM_CREDENTIAL_MODE")
		}
		if apnsParts == 0 && fcmParts == 0 {
			return Settings{}, fmt.Errorf("at least one Companion push provider is required")
		}
		pushTimeout, pushErr := accountSettingInt(
			"COMPANION_PUSH_PROVIDER_TIMEOUT_MS", 2000, 100, 3000)
		if pushErr != nil {
			return Settings{}, pushErr
		}
		settings.PushProviderTimeout = time.Duration(pushTimeout) * time.Millisecond
	}
	maximum, err := accountSettingInt("ACCOUNT_AUTHORIZATION_DATABASE_MAX_OPEN",
		16, 2, 128)
	if err != nil {
		return Settings{}, err
	}
	idle, err := accountSettingInt("ACCOUNT_AUTHORIZATION_DATABASE_MAX_IDLE",
		4, 1, maximum)
	if err != nil {
		return Settings{}, err
	}
	connectionTTL, err := accountSettingInt(
		"ACCOUNT_AUTHORIZATION_DATABASE_CONN_TTL_SECONDS", 300, 30, 3600)
	if err != nil {
		return Settings{}, err
	}
	operationTimeout, err := accountSettingInt(
		"ACCOUNT_AUTHORIZATION_DATABASE_TIMEOUT_MS", 1000, 100, 5000)
	if err != nil {
		return Settings{}, err
	}
	shutdownTimeout, err := accountSettingInt(
		"ACCOUNT_AUTHORIZATION_SHUTDOWN_TIMEOUT_SECONDS", 10, 1, 30)
	if err != nil {
		return Settings{}, err
	}
	settings.DatabaseMaxOpen = maximum
	settings.DatabaseMaxIdle = idle
	settings.DatabaseConnTTL = time.Duration(connectionTTL) * time.Second
	settings.OperationTimeout = time.Duration(operationTimeout) * time.Millisecond
	settings.ShutdownTimeout = time.Duration(shutdownTimeout) * time.Second
	return settings, nil
}

func accountSettingBool(name string, fallback bool) (bool, error) {
	text := os.Getenv(name)
	if text == "" {
		return fallback, nil
	}
	if text == "true" {
		return true, nil
	}
	if text == "false" {
		return false, nil
	}
	return false, fmt.Errorf("%s must be true or false", name)
}

func countConfigured(values ...string) int {
	count := 0
	for _, value := range values {
		if value != "" {
			count++
		}
	}
	return count
}

func environmentDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func accountSettingInt(name string, fallback, minimum, maximum int) (int, error) {
	text := os.Getenv(name)
	if text == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(text)
	if err != nil || value < minimum || value > maximum ||
		strconv.Itoa(value) != text {
		return 0, fmt.Errorf("%s must be an integer from %d through %d",
			name, minimum, maximum)
	}
	return value, nil
}

func accountSettingRequiredUint64(name string) (uint64, error) {
	text := os.Getenv(name)
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil || value == 0 || strconv.FormatUint(value, 10) != text {
		return 0, fmt.Errorf("%s must be a positive canonical integer", name)
	}
	return value, nil
}

func validListenAddress(value string) bool {
	if value == "" || len(value) > 255 || strings.ContainsAny(value, "\r\n\t /\\") {
		return false
	}
	_, portText, err := net.SplitHostPort(value)
	if err != nil {
		return false
	}
	port, err := strconv.Atoi(portText)
	return err == nil && port > 0 && port <= 65535 &&
		strconv.Itoa(port) == portText
}

func validWildcardListenAddress(value string) bool {
	if !validListenAddress(value) {
		return false
	}
	host, _, err := net.SplitHostPort(value)
	return err == nil && (host == "" || host == "0.0.0.0" || host == "::")
}

func validProductionDatabaseURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "postgres" &&
		parsed.Scheme != "postgresql") || parsed.Host == "" ||
		parsed.Fragment != "" || parsed.Opaque != "" {
		return false
	}
	sslModes := parsed.Query()["sslmode"]
	return len(sslModes) == 1 && sslModes[0] == "verify-full"
}
