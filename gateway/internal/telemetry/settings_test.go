package telemetry

import (
	"testing"
	"time"
)

var telemetryEnvironment = []string{
	"TELEMETRY_OTLP_TRACES_ENDPOINT", "TELEMETRY_DEPLOYMENT_ID",
	"TELEMETRY_OTLP_CA_FILE", "TELEMETRY_OTLP_CLIENT_CERT_FILE",
	"TELEMETRY_OTLP_CLIENT_KEY_FILE", "TELEMETRY_TRACE_SAMPLE_RATIO_PPM",
	"TELEMETRY_OTLP_TIMEOUT_MS", "OTEL_EXPORTER_OTLP_HEADERS",
	"OTEL_RESOURCE_ATTRIBUTES", "OTEL_TRACES_SAMPLER", "OTEL_PROPAGATORS",
}

func clearTelemetryEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range telemetryEnvironment {
		t.Setenv(name, "")
	}
}

func setValidTelemetryEnvironment(t *testing.T) {
	t.Helper()
	clearTelemetryEnvironment(t)
	t.Setenv("TELEMETRY_OTLP_TRACES_ENDPOINT",
		"https://otel-collector.monitoring.svc:4318/v1/traces")
	t.Setenv("TELEMETRY_DEPLOYMENT_ID", "pilot-us-west-1")
	t.Setenv("TELEMETRY_OTLP_CA_FILE", "/run/secrets/telemetry-ca.pem")
	t.Setenv("TELEMETRY_OTLP_CLIENT_CERT_FILE",
		"/run/secrets/telemetry-client.crt")
	t.Setenv("TELEMETRY_OTLP_CLIENT_KEY_FILE",
		"/run/secrets/telemetry-client.key")
}

func TestSettingsRequireProductionMTLSAndAllowDisabledDevelopment(t *testing.T) {
	clearTelemetryEnvironment(t)
	settings, err := LoadSettings("gateway", true)
	if err != nil || settings.Enabled || settings.Service != "gateway" {
		t.Fatalf("disabled development telemetry rejected: %#v err=%v", settings, err)
	}
	if _, err := LoadSettings("gateway", false); err == nil {
		t.Fatal("production telemetry was allowed without OTLP mTLS")
	}
	clearTelemetryEnvironment(t)
	t.Setenv("TELEMETRY_TRACE_SAMPLE_RATIO_PPM", "100000")
	if _, err := LoadSettings("gateway", true); err == nil {
		t.Fatal("telemetry tuning without an exporter identity was accepted")
	}
	t.Setenv("TELEMETRY_OTLP_TRACES_ENDPOINT",
		"https://otel-collector.monitoring.svc:4318/v1/traces")
	if _, err := LoadSettings("gateway", true); err == nil {
		t.Fatal("partial telemetry configuration was accepted")
	}
	if _, err := LoadSettings("unknown-service", true); err == nil {
		t.Fatal("unknown product service was accepted")
	}
}

func TestSettingsLoadBoundedProductConfiguration(t *testing.T) {
	setValidTelemetryEnvironment(t)
	t.Setenv("TELEMETRY_TRACE_SAMPLE_RATIO_PPM", "250000")
	t.Setenv("TELEMETRY_OTLP_TIMEOUT_MS", "1500")
	settings, err := LoadSettings("controlplane", false)
	if err != nil || !settings.Enabled || settings.Service != "controlplane" ||
		settings.DeploymentID != "pilot-us-west-1" ||
		settings.SampleRatioPPM != 250000 ||
		settings.ExportTimeout != 1500*time.Millisecond ||
		settings.IdentityFiles.ClientPrivateKeyFile !=
			"/run/secrets/telemetry-client.key" {
		t.Fatalf("unexpected telemetry settings: %#v err=%v", settings, err)
	}
}

func TestSettingsRejectUnsafeEndpointsOverridesAndNumbers(t *testing.T) {
	invalidEndpoints := []string{
		"http://otel.example/v1/traces",
		"https://OTEL.example/v1/traces",
		"https://user@otel.example/v1/traces",
		"https://otel.example/v1/traces?token=secret",
		"https://otel.example/v1/traces#fragment",
		"https://otel.example/other",
		"https://otel.example:04318/v1/traces",
		"https://otel_example/v1/traces",
	}
	for _, endpoint := range invalidEndpoints {
		t.Run(endpoint, func(t *testing.T) {
			setValidTelemetryEnvironment(t)
			t.Setenv("TELEMETRY_OTLP_TRACES_ENDPOINT", endpoint)
			if _, err := LoadSettings("agentproxy", false); err == nil {
				t.Fatal("unsafe telemetry endpoint was accepted")
			}
		})
	}

	setValidTelemetryEnvironment(t)
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "authorization=secret")
	if _, err := LoadSettings("agentproxy", false); err == nil {
		t.Fatal("standard OTel header override was accepted")
	}
	for name, value := range map[string]string{
		"TELEMETRY_TRACE_SAMPLE_RATIO_PPM": "01",
		"TELEMETRY_OTLP_TIMEOUT_MS":        "5001",
	} {
		t.Run(name, func(t *testing.T) {
			setValidTelemetryEnvironment(t)
			t.Setenv(name, value)
			if _, err := LoadSettings("firmwareorigin", false); err == nil {
				t.Fatal("noncanonical or out-of-range telemetry number was accepted")
			}
		})
	}
}
