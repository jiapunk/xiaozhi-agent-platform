package telemetry

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/speechidentity"
)

const (
	defaultSampleRatioPPM = 100_000
	defaultExportTimeout  = 2 * time.Second
)

var productServices = map[string]bool{
	"gateway": true, "controlplane": true, "agentproxy": true,
	"firmwareorigin": true, "generationcoordinator": true,
	"accountauthorization": true, "factorytimeauthority": true,
}

// Settings is intentionally smaller than the standard OTel environment
// surface. Arbitrary resource attributes, baggage, headers and insecure
// endpoints are not configurable in the product runtime.
type Settings struct {
	Enabled        bool
	Service        string
	DeploymentID   string
	Endpoint       string
	IdentityFiles  speechidentity.Files
	SampleRatioPPM int
	ExportTimeout  time.Duration
}

func LoadSettings(service string, allowInsecureDevelopment bool) (Settings, error) {
	if !productServices[service] {
		return Settings{}, fmt.Errorf("telemetry service identity is invalid")
	}
	if forbiddenStandardEnvironment() {
		return Settings{}, fmt.Errorf("standard OTEL environment overrides are forbidden")
	}
	settings := Settings{
		Service:      service,
		Endpoint:     strings.TrimSpace(os.Getenv("TELEMETRY_OTLP_TRACES_ENDPOINT")),
		DeploymentID: strings.TrimSpace(os.Getenv("TELEMETRY_DEPLOYMENT_ID")),
		IdentityFiles: speechidentity.Files{
			CACertificateFile: strings.TrimSpace(os.Getenv("TELEMETRY_OTLP_CA_FILE")),
			ClientCertificateFile: strings.TrimSpace(
				os.Getenv("TELEMETRY_OTLP_CLIENT_CERT_FILE")),
			ClientPrivateKeyFile: strings.TrimSpace(
				os.Getenv("TELEMETRY_OTLP_CLIENT_KEY_FILE")),
		},
		SampleRatioPPM: defaultSampleRatioPPM,
		ExportTimeout:  defaultExportTimeout,
	}
	core := []string{settings.Endpoint, settings.DeploymentID,
		settings.IdentityFiles.CACertificateFile,
		settings.IdentityFiles.ClientCertificateFile,
		settings.IdentityFiles.ClientPrivateKeyFile}
	configured := 0
	for _, value := range core {
		if value != "" {
			configured++
		}
	}
	if configured == 0 {
		if os.Getenv("TELEMETRY_TRACE_SAMPLE_RATIO_PPM") != "" ||
			os.Getenv("TELEMETRY_OTLP_TIMEOUT_MS") != "" {
			return Settings{}, fmt.Errorf("telemetry tuning requires the complete endpoint and identity configuration")
		}
		if !allowInsecureDevelopment {
			return Settings{}, fmt.Errorf("production telemetry OTLP mTLS is required")
		}
		return settings, nil
	}
	if configured != len(core) {
		return Settings{}, fmt.Errorf("telemetry endpoint, deployment, CA, certificate, and key are required together")
	}
	if !validEndpoint(settings.Endpoint) ||
		!auth.ValidIdentifier(settings.DeploymentID, 64) {
		return Settings{}, fmt.Errorf("telemetry endpoint or deployment identity is invalid")
	}
	if text := os.Getenv("TELEMETRY_TRACE_SAMPLE_RATIO_PPM"); text != "" {
		value, err := strconv.Atoi(text)
		if err != nil || value < 1 || value > 1_000_000 ||
			strconv.Itoa(value) != text {
			return Settings{}, fmt.Errorf("TELEMETRY_TRACE_SAMPLE_RATIO_PPM must be a canonical integer from 1 through 1000000")
		}
		settings.SampleRatioPPM = value
	}
	if text := os.Getenv("TELEMETRY_OTLP_TIMEOUT_MS"); text != "" {
		value, err := strconv.Atoi(text)
		if err != nil || value < 100 || value > 5_000 ||
			strconv.Itoa(value) != text {
			return Settings{}, fmt.Errorf("TELEMETRY_OTLP_TIMEOUT_MS must be a canonical integer from 100 through 5000")
		}
		settings.ExportTimeout = time.Duration(value) * time.Millisecond
	}
	settings.Enabled = true
	return settings, nil
}

func validateSettings(settings Settings) error {
	if !productServices[settings.Service] {
		return fmt.Errorf("telemetry service identity is invalid")
	}
	if forbiddenStandardEnvironment() {
		return fmt.Errorf("standard OTEL environment overrides are forbidden")
	}
	files := settings.IdentityFiles
	if !settings.Enabled {
		if settings.Endpoint != "" || settings.DeploymentID != "" ||
			files.CACertificateFile != "" ||
			files.ClientCertificateFile != "" ||
			files.ClientPrivateKeyFile != "" {
			return fmt.Errorf("disabled telemetry may not retain endpoint or identity configuration")
		}
		return nil
	}
	if !validEndpoint(settings.Endpoint) ||
		!auth.ValidIdentifier(settings.DeploymentID, 64) ||
		!canonicalNonempty(files.CACertificateFile) ||
		!canonicalNonempty(files.ClientCertificateFile) ||
		!canonicalNonempty(files.ClientPrivateKeyFile) {
		return fmt.Errorf("telemetry endpoint, deployment, or identity files are invalid")
	}
	if settings.SampleRatioPPM < 1 || settings.SampleRatioPPM > 1_000_000 {
		return fmt.Errorf("telemetry sample ratio is out of range")
	}
	if settings.ExportTimeout < 100*time.Millisecond ||
		settings.ExportTimeout > 5*time.Second {
		return fmt.Errorf("telemetry export timeout is out of range")
	}
	return nil
}

func forbiddenStandardEnvironment() bool {
	for _, item := range os.Environ() {
		name, value, found := strings.Cut(item, "=")
		if found && strings.HasPrefix(name, "OTEL_") && value != "" {
			return true
		}
	}
	return false
}

func canonicalNonempty(value string) bool {
	return value != "" && strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, "\r\n\t") && filepath.IsAbs(value) &&
		filepath.Clean(value) == value
}

func validEndpoint(raw string) bool {
	if raw == "" || len(raw) > 2048 || strings.TrimSpace(raw) != raw ||
		strings.ContainsAny(raw, "\r\n\t") {
		return false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || parsed.Path != "/v1/traces" ||
		parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || parsed.String() != raw ||
		strings.ToLower(parsed.Host) != parsed.Host {
		return false
	}
	hostname := parsed.Hostname()
	if hostname == "" || strings.HasSuffix(hostname, ".") {
		return false
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 || strconv.Itoa(value) != port {
			return false
		}
	}
	if net.ParseIP(hostname) == nil {
		for _, label := range strings.Split(hostname, ".") {
			if label == "" || len(label) > 63 ||
				label[0] == '-' || label[len(label)-1] == '-' {
				return false
			}
			for _, character := range label {
				if (character < 'a' || character > 'z') &&
					(character < '0' || character > '9') && character != '-' {
					return false
				}
			}
		}
	}
	return true
}
