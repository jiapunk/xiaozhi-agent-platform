package accountauth

import (
	"os"
	"testing"
	"time"
)

func clearAccountSettings(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"ACCOUNT_AUTHORIZATION_LISTEN_ADDR",
		"ACCOUNT_AUTHORIZATION_HEALTH_LISTEN_ADDR",
		"ACCOUNT_AUTHORIZATION_DATABASE_URL",
		"ACCOUNT_AUTHORIZATION_DATABASE_MAX_OPEN",
		"ACCOUNT_AUTHORIZATION_DATABASE_MAX_IDLE",
		"ACCOUNT_AUTHORIZATION_DATABASE_CONN_TTL_SECONDS",
		"ACCOUNT_AUTHORIZATION_DATABASE_TIMEOUT_MS",
		"ACCOUNT_AUTHORIZATION_CLIENT_CA_FILE",
		"ACCOUNT_AUTHORIZATION_SERVER_CERT_FILE",
		"ACCOUNT_AUTHORIZATION_SERVER_KEY_FILE",
		"ACCOUNT_AUTHORIZATION_SHUTDOWN_TIMEOUT_SECONDS",
		"ENTITLEMENT_UPDATE_KEYRING_FILE",
		"ENTITLEMENT_UPDATE_KEYRING_MIN_REVISION",
		"ENTITLEMENT_UPDATE_AUTHORIZATION_TTL_SECONDS",
		"COMPANION_PUSH_ENABLED",
		"COMPANION_PUSH_TOKEN_KEYRING_FILE",
		"COMPANION_PUSH_APNS_TOPIC",
		"COMPANION_PUSH_APNS_KEY_ID",
		"COMPANION_PUSH_APNS_TEAM_ID",
		"COMPANION_PUSH_APNS_PRIVATE_KEY_FILE",
		"COMPANION_PUSH_FCM_PROJECT_ID",
		"COMPANION_PUSH_FCM_CREDENTIAL_MODE",
		"COMPANION_PUSH_FCM_SERVICE_ACCOUNT_FILE",
		"COMPANION_PUSH_PROVIDER_TIMEOUT_MS",
	} {
		t.Setenv(name, "")
	}
}

func TestCompanionPushSettingsAreOptInAndAllOrNothing(t *testing.T) {
	clearAccountSettings(t)
	setMinimumAccountSettings(t)
	t.Setenv("COMPANION_PUSH_ENABLED", "true")
	t.Setenv("COMPANION_PUSH_TOKEN_KEYRING_FILE", "/run/secrets/push-keyring.json")
	t.Setenv("COMPANION_PUSH_APNS_TOPIC", "com.example.product")
	t.Setenv("COMPANION_PUSH_APNS_KEY_ID", "ABC123DEFG")
	t.Setenv("COMPANION_PUSH_APNS_TEAM_ID", "TEAM12ABCD")
	t.Setenv("COMPANION_PUSH_APNS_PRIVATE_KEY_FILE", "/run/secrets/AuthKey.p8")
	t.Setenv("COMPANION_PUSH_FCM_PROJECT_ID", "product-123")
	t.Setenv("COMPANION_PUSH_FCM_CREDENTIAL_MODE", "metadata")
	settings, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if !settings.PushEnabled || settings.PushProviderTimeout != 2*time.Second ||
		settings.PushFCMCredentialMode != "metadata" ||
		settings.PushAPNsTopic != "com.example.product" {
		t.Fatalf("unexpected push settings: %#v", settings)
	}

	t.Setenv("COMPANION_PUSH_ENABLED", "false")
	if _, err := LoadSettings(); err == nil {
		t.Fatal("disabled push accepted provider settings")
	}
	clearAccountSettings(t)
	setMinimumAccountSettings(t)
	t.Setenv("COMPANION_PUSH_ENABLED", "true")
	t.Setenv("COMPANION_PUSH_TOKEN_KEYRING_FILE", "/run/secrets/push-keyring.json")
	t.Setenv("COMPANION_PUSH_FCM_PROJECT_ID", "product-123")
	t.Setenv("COMPANION_PUSH_FCM_CREDENTIAL_MODE", "service-account")
	if _, err := LoadSettings(); err == nil {
		t.Fatal("service-account mode accepted without credential file")
	}
}

func setMinimumAccountSettings(t *testing.T) {
	t.Helper()
	t.Setenv("ACCOUNT_AUTHORIZATION_DATABASE_URL",
		"postgres://account@db.example/product?sslmode=verify-full")
	t.Setenv("ACCOUNT_AUTHORIZATION_CLIENT_CA_FILE", "/run/secrets/client-ca.pem")
	t.Setenv("ACCOUNT_AUTHORIZATION_SERVER_CERT_FILE", "/run/secrets/server.pem")
	t.Setenv("ACCOUNT_AUTHORIZATION_SERVER_KEY_FILE", "/run/secrets/server.key")
	t.Setenv("ENTITLEMENT_UPDATE_KEYRING_FILE",
		"/run/secrets/files/entitlement-update-keyring.json")
	t.Setenv("ENTITLEMENT_UPDATE_KEYRING_MIN_REVISION", "1")
}

func TestLoadSettingsRequiresProductionDatabaseAndMTLS(t *testing.T) {
	clearAccountSettings(t)
	if _, err := LoadSettings(); err == nil {
		t.Fatal("missing production settings accepted")
	}
	setMinimumAccountSettings(t)
	settings, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if settings.ListenAddress != ":9444" || settings.HealthAddress != ":9080" ||
		settings.DatabaseMaxOpen != 16 ||
		settings.DatabaseMaxIdle != 4 || settings.DatabaseConnTTL != 5*time.Minute ||
		settings.OperationTimeout != time.Second ||
		settings.ShutdownTimeout != 10*time.Second ||
		settings.EntitlementUpdateKeyringMinRevision != 1 ||
		settings.EntitlementUpdateAuthorizationTTL != 5*time.Minute {
		t.Fatalf("unexpected defaults: %#v", settings)
	}
}

func TestLoadSettingsRejectsUnsafeOrPartialValues(t *testing.T) {
	clearAccountSettings(t)
	setMinimumAccountSettings(t)
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{"plaintext database", "ACCOUNT_AUTHORIZATION_DATABASE_URL",
			"postgres://db.example/product?sslmode=disable"},
		{"duplicate sslmode", "ACCOUNT_AUTHORIZATION_DATABASE_URL",
			"postgres://db.example/product?sslmode=verify-full&sslmode=require"},
		{"missing server key", "ACCOUNT_AUTHORIZATION_SERVER_KEY_FILE", ""},
		{"unsafe listen", "ACCOUNT_AUTHORIZATION_LISTEN_ADDR", "localhost:0"},
		{"unsafe health listen", "ACCOUNT_AUTHORIZATION_HEALTH_LISTEN_ADDR", "localhost:9080"},
		{"duplicate health listen", "ACCOUNT_AUTHORIZATION_HEALTH_LISTEN_ADDR", ":9444"},
		{"noncanonical integer", "ACCOUNT_AUTHORIZATION_DATABASE_MAX_OPEN", "016"},
		{"noncanonical keyring revision", "ENTITLEMENT_UPDATE_KEYRING_MIN_REVISION", "01"},
		{"long authorization window", "ENTITLEMENT_UPDATE_AUTHORIZATION_TTL_SECONDS", "301"},
		{"idle over maximum", "ACCOUNT_AUTHORIZATION_DATABASE_MAX_IDLE", "17"},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			original := os.Getenv(testCase.key)
			t.Setenv(testCase.key, testCase.value)
			if _, err := LoadSettings(); err == nil {
				t.Fatal("unsafe settings accepted")
			}
			t.Setenv(testCase.key, original)
		})
	}
}
