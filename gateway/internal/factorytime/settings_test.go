package factorytime

import (
	"os"
	"testing"
	"time"
)

func clearFactoryTimeSettings(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"FACTORY_TIME_LISTEN_ADDR",
		"FACTORY_TIME_HEALTH_LISTEN_ADDR",
		"FACTORY_TIME_DATABASE_URL",
		"FACTORY_TIME_DATABASE_MAX_OPEN",
		"FACTORY_TIME_DATABASE_MAX_IDLE",
		"FACTORY_TIME_DATABASE_CONN_TTL_SECONDS",
		"FACTORY_TIME_DATABASE_TIMEOUT_MS",
		"FACTORY_TIME_STATION_CLIENT_CA_FILE",
		"FACTORY_TIME_SERVER_CERT_FILE",
		"FACTORY_TIME_SERVER_KEY_FILE",
		"FACTORY_TIME_RECEIPT_LIFETIME_SECONDS",
		"FACTORY_TIME_SIGNER_ENDPOINT",
		"FACTORY_TIME_SIGNER_KEY_ID",
		"FACTORY_TIME_SIGNER_PUBLIC_KEY_FILE",
		"FACTORY_TIME_SIGNER_PUBLIC_KEY_SHA256",
		"FACTORY_TIME_SIGNER_CA_FILE",
		"FACTORY_TIME_SIGNER_CA_SHA256",
		"FACTORY_TIME_SIGNER_CLIENT_CERT_FILE",
		"FACTORY_TIME_SIGNER_CLIENT_CERT_SHA256",
		"FACTORY_TIME_SIGNER_CLIENT_KEY_FILE",
		"FACTORY_TIME_SIGNER_TIMEOUT_MS",
		"FACTORY_TIME_SHUTDOWN_TIMEOUT_SECONDS",
	} {
		t.Setenv(name, "")
	}
}

func setMinimumFactoryTimeSettings(t *testing.T) {
	t.Helper()
	t.Setenv("FACTORY_TIME_DATABASE_URL",
		"postgresql://factory@db.example/product?sslmode=verify-full")
	t.Setenv("FACTORY_TIME_STATION_CLIENT_CA_FILE", "/run/secrets/station-ca.pem")
	t.Setenv("FACTORY_TIME_SERVER_CERT_FILE", "/run/secrets/server.pem")
	t.Setenv("FACTORY_TIME_SERVER_KEY_FILE", "/run/secrets/server.key")
	t.Setenv("FACTORY_TIME_SIGNER_ENDPOINT",
		"https://signer.example/v1/factory/trusted-time/sign")
	t.Setenv("FACTORY_TIME_SIGNER_KEY_ID", "factory-time-key-1")
	t.Setenv("FACTORY_TIME_SIGNER_PUBLIC_KEY_FILE", "/run/secrets/signer.pub")
	t.Setenv("FACTORY_TIME_SIGNER_PUBLIC_KEY_SHA256", strings64("1"))
	t.Setenv("FACTORY_TIME_SIGNER_CA_FILE", "/run/secrets/signer-ca.pem")
	t.Setenv("FACTORY_TIME_SIGNER_CA_SHA256", strings64("2"))
	t.Setenv("FACTORY_TIME_SIGNER_CLIENT_CERT_FILE", "/run/secrets/signer-client.pem")
	t.Setenv("FACTORY_TIME_SIGNER_CLIENT_CERT_SHA256", strings64("3"))
	t.Setenv("FACTORY_TIME_SIGNER_CLIENT_KEY_FILE", "/run/secrets/signer-client.key")
}

func TestLoadFactoryTimeSettingsRequiresAllProductionBoundaries(t *testing.T) {
	clearFactoryTimeSettings(t)
	if _, err := LoadSettings(); err == nil {
		t.Fatal("missing production settings accepted")
	}
	setMinimumFactoryTimeSettings(t)
	settings, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if settings.ListenAddress != ":9445" || settings.HealthAddress != ":9081" ||
		settings.DatabaseMaxOpen != 16 || settings.DatabaseMaxIdle != 4 ||
		settings.DatabaseConnTTL != 5*time.Minute ||
		settings.DatabaseOperationTimeout != time.Second ||
		settings.ReceiptLifetime != 5*time.Second ||
		settings.SignerTimeout != 1500*time.Millisecond ||
		settings.ShutdownTimeout != 10*time.Second {
		t.Fatalf("unexpected defaults: %#v", settings)
	}
}

func TestLoadFactoryTimeSettingsRejectsUnsafeOrPartialValues(t *testing.T) {
	clearFactoryTimeSettings(t)
	setMinimumFactoryTimeSettings(t)
	tests := []struct {
		name, key, value string
	}{
		{"plaintext database", "FACTORY_TIME_DATABASE_URL",
			"postgresql://db.example/product?sslmode=disable"},
		{"database without name", "FACTORY_TIME_DATABASE_URL",
			"postgresql://db.example/?sslmode=verify-full"},
		{"duplicate ssl mode", "FACTORY_TIME_DATABASE_URL",
			"postgresql://db.example/product?sslmode=verify-full&sslmode=require"},
		{"HTTP signer", "FACTORY_TIME_SIGNER_ENDPOINT",
			"http://signer.example/v1/factory/trusted-time/sign"},
		{"signer query", "FACTORY_TIME_SIGNER_ENDPOINT",
			"https://signer.example/v1/factory/trusted-time/sign?debug=1"},
		{"missing server key", "FACTORY_TIME_SERVER_KEY_FILE", ""},
		{"wrong public pin", "FACTORY_TIME_SIGNER_PUBLIC_KEY_SHA256", "ABCD"},
		{"unsafe listen", "FACTORY_TIME_LISTEN_ADDR", "localhost:0"},
		{"unsafe health", "FACTORY_TIME_HEALTH_LISTEN_ADDR", "localhost:9081"},
		{"same listener", "FACTORY_TIME_HEALTH_LISTEN_ADDR", ":9445"},
		{"noncanonical connections", "FACTORY_TIME_DATABASE_MAX_OPEN", "016"},
		{"signer timeout too high", "FACTORY_TIME_SIGNER_TIMEOUT_MS", "2001"},
		{"receipt too long", "FACTORY_TIME_RECEIPT_LIFETIME_SECONDS", "11"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			original := os.Getenv(testCase.key)
			t.Setenv(testCase.key, testCase.value)
			if _, err := LoadSettings(); err == nil {
				t.Fatal("unsafe setting accepted")
			}
			t.Setenv(testCase.key, original)
		})
	}
}
