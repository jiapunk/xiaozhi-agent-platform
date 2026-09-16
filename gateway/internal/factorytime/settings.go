package factorytime

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
	ListenAddress                 string
	HealthAddress                 string
	DatabaseURL                   string
	DatabaseMaxOpen               int
	DatabaseMaxIdle               int
	DatabaseConnTTL               time.Duration
	DatabaseOperationTimeout      time.Duration
	StationClientCAFile           string
	ServerCertificateFile         string
	ServerPrivateKeyFile          string
	ReceiptLifetime               time.Duration
	SignerEndpoint                string
	SignerKeyID                   string
	SignerPublicKeyFile           string
	SignerPublicKeySHA256         string
	SignerCACertificateFile       string
	SignerCACertificateSHA256     string
	SignerClientCertificateFile   string
	SignerClientCertificateSHA256 string
	SignerClientPrivateKeyFile    string
	SignerTimeout                 time.Duration
	ShutdownTimeout               time.Duration
}

func LoadSettings() (Settings, error) {
	settings := Settings{
		ListenAddress:               settingDefault("FACTORY_TIME_LISTEN_ADDR", ":9445"),
		HealthAddress:               settingDefault("FACTORY_TIME_HEALTH_LISTEN_ADDR", ":9081"),
		DatabaseURL:                 os.Getenv("FACTORY_TIME_DATABASE_URL"),
		StationClientCAFile:         os.Getenv("FACTORY_TIME_STATION_CLIENT_CA_FILE"),
		ServerCertificateFile:       os.Getenv("FACTORY_TIME_SERVER_CERT_FILE"),
		ServerPrivateKeyFile:        os.Getenv("FACTORY_TIME_SERVER_KEY_FILE"),
		SignerEndpoint:              os.Getenv("FACTORY_TIME_SIGNER_ENDPOINT"),
		SignerKeyID:                 os.Getenv("FACTORY_TIME_SIGNER_KEY_ID"),
		SignerPublicKeyFile:         os.Getenv("FACTORY_TIME_SIGNER_PUBLIC_KEY_FILE"),
		SignerPublicKeySHA256:       os.Getenv("FACTORY_TIME_SIGNER_PUBLIC_KEY_SHA256"),
		SignerCACertificateFile:     os.Getenv("FACTORY_TIME_SIGNER_CA_FILE"),
		SignerCACertificateSHA256:   os.Getenv("FACTORY_TIME_SIGNER_CA_SHA256"),
		SignerClientCertificateFile: os.Getenv("FACTORY_TIME_SIGNER_CLIENT_CERT_FILE"),
		SignerClientCertificateSHA256: os.Getenv(
			"FACTORY_TIME_SIGNER_CLIENT_CERT_SHA256"),
		SignerClientPrivateKeyFile: os.Getenv("FACTORY_TIME_SIGNER_CLIENT_KEY_FILE"),
	}
	if !validServiceListenAddress(settings.ListenAddress) ||
		!validWildcardAddress(settings.HealthAddress) ||
		settings.ListenAddress == settings.HealthAddress {
		return Settings{}, fmt.Errorf("factory-time listen addresses are invalid")
	}
	if !validDatabaseURL(settings.DatabaseURL) {
		return Settings{}, fmt.Errorf("FACTORY_TIME_DATABASE_URL must use PostgreSQL sslmode=verify-full")
	}
	for name, value := range map[string]string{
		"FACTORY_TIME_STATION_CLIENT_CA_FILE":  settings.StationClientCAFile,
		"FACTORY_TIME_SERVER_CERT_FILE":        settings.ServerCertificateFile,
		"FACTORY_TIME_SERVER_KEY_FILE":         settings.ServerPrivateKeyFile,
		"FACTORY_TIME_SIGNER_PUBLIC_KEY_FILE":  settings.SignerPublicKeyFile,
		"FACTORY_TIME_SIGNER_CA_FILE":          settings.SignerCACertificateFile,
		"FACTORY_TIME_SIGNER_CLIENT_CERT_FILE": settings.SignerClientCertificateFile,
		"FACTORY_TIME_SIGNER_CLIENT_KEY_FILE":  settings.SignerClientPrivateKeyFile,
	} {
		if value == "" {
			return Settings{}, fmt.Errorf("%s is required", name)
		}
	}
	if _, _, err := validateSignerEndpoint(settings.SignerEndpoint); err != nil ||
		!validIdentifier(settings.SignerKeyID) ||
		!validDigest(settings.SignerPublicKeySHA256) ||
		!validDigest(settings.SignerCACertificateSHA256) ||
		!validDigest(settings.SignerClientCertificateSHA256) {
		return Settings{}, fmt.Errorf("factory-time signer identity or pins are invalid")
	}
	maximum, err := settingInt("FACTORY_TIME_DATABASE_MAX_OPEN", 16, 2, 128)
	if err != nil {
		return Settings{}, err
	}
	idle, err := settingInt("FACTORY_TIME_DATABASE_MAX_IDLE", 4, 1, maximum)
	if err != nil {
		return Settings{}, err
	}
	connectionTTL, err := settingInt("FACTORY_TIME_DATABASE_CONN_TTL_SECONDS",
		300, 30, 3600)
	if err != nil {
		return Settings{}, err
	}
	databaseTimeout, err := settingInt("FACTORY_TIME_DATABASE_TIMEOUT_MS",
		1000, 100, 5000)
	if err != nil {
		return Settings{}, err
	}
	receiptLifetime, err := settingInt("FACTORY_TIME_RECEIPT_LIFETIME_SECONDS",
		5, 1, MaximumReceiptSeconds)
	if err != nil {
		return Settings{}, err
	}
	signerTimeout, err := settingInt("FACTORY_TIME_SIGNER_TIMEOUT_MS",
		1500, int(minimumSignerTimeout/time.Millisecond),
		int(maximumSignerTimeout/time.Millisecond))
	if err != nil {
		return Settings{}, err
	}
	shutdownTimeout, err := settingInt("FACTORY_TIME_SHUTDOWN_TIMEOUT_SECONDS",
		10, 1, 30)
	if err != nil {
		return Settings{}, err
	}
	settings.DatabaseMaxOpen = maximum
	settings.DatabaseMaxIdle = idle
	settings.DatabaseConnTTL = time.Duration(connectionTTL) * time.Second
	settings.DatabaseOperationTimeout = time.Duration(databaseTimeout) * time.Millisecond
	settings.ReceiptLifetime = time.Duration(receiptLifetime) * time.Second
	settings.SignerTimeout = time.Duration(signerTimeout) * time.Millisecond
	settings.ShutdownTimeout = time.Duration(shutdownTimeout) * time.Second
	return settings, nil
}

func settingDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func settingInt(name string, fallback, minimum, maximum int) (int, error) {
	text := os.Getenv(name)
	if text == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(text)
	if err != nil || value < minimum || value > maximum ||
		strconv.Itoa(value) != text {
		return 0, fmt.Errorf("%s must be a canonical integer from %d through %d",
			name, minimum, maximum)
	}
	return value, nil
}

func validServiceListenAddress(value string) bool {
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

func validWildcardAddress(value string) bool {
	if !validServiceListenAddress(value) {
		return false
	}
	host, _, err := net.SplitHostPort(value)
	return err == nil && (host == "" || host == "0.0.0.0" || host == "::")
}

func validDatabaseURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "postgres" &&
		parsed.Scheme != "postgresql") || parsed.Host == "" ||
		parsed.Path == "" || parsed.Path == "/" || parsed.Fragment != "" ||
		parsed.Opaque != "" {
		return false
	}
	sslModes := parsed.Query()["sslmode"]
	return len(sslModes) == 1 && sslModes[0] == "verify-full"
}
