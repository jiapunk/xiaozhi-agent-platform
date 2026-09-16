package generation

import (
	"crypto/subtle"
	"fmt"
	"os"
	"strconv"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

type CoordinatorSettings struct {
	Address             string
	TLSCertFile         string
	TLSKeyFile          string
	AllowInsecure       bool
	StateDirectory      string
	StateKey            []byte
	Publisher           Principal
	ReplicaRegistryFile string
	PrepareTimeout      time.Duration
	CommitTimeout       time.Duration
	MaxClockSkew        time.Duration
}

func LoadCoordinatorSettings() (CoordinatorSettings, error) {
	settings := CoordinatorSettings{
		Address:             envOr("GENERATION_COORDINATOR_ADDRESS", ":8447"),
		TLSCertFile:         os.Getenv("GENERATION_COORDINATOR_TLS_CERT_FILE"),
		TLSKeyFile:          os.Getenv("GENERATION_COORDINATOR_TLS_KEY_FILE"),
		StateDirectory:      os.Getenv("GENERATION_STATE_DIRECTORY"),
		ReplicaRegistryFile: os.Getenv("GENERATION_REPLICA_REGISTRY_FILE"),
	}
	var err error
	settings.AllowInsecure, err = parseBoolEnv("ALLOW_INSECURE_DEVELOPMENT", false)
	if err != nil {
		return CoordinatorSettings{}, err
	}
	if !settings.AllowInsecure &&
		(settings.TLSCertFile == "" || settings.TLSKeyFile == "") {
		return CoordinatorSettings{}, fmt.Errorf("generation coordinator TLS certificate and key are required")
	}
	if (settings.TLSCertFile == "") != (settings.TLSKeyFile == "") {
		return CoordinatorSettings{}, fmt.Errorf("generation coordinator TLS certificate and key must be configured together")
	}
	if settings.StateDirectory == "" || settings.ReplicaRegistryFile == "" {
		return CoordinatorSettings{}, fmt.Errorf("generation state directory and replica registry are required")
	}
	settings.StateKey, err = DecodeHMACKey("GENERATION_STATE_HMAC_KEY_B64",
		os.Getenv("GENERATION_STATE_HMAC_KEY_B64"))
	if err != nil {
		return CoordinatorSettings{}, err
	}
	publisherID := os.Getenv("GENERATION_PUBLISHER_ID")
	if !auth.ValidIdentifier(publisherID, 64) {
		return CoordinatorSettings{}, fmt.Errorf("GENERATION_PUBLISHER_ID is invalid")
	}
	publisherKey, err := DecodeHMACKey("GENERATION_PUBLISHER_HMAC_KEY_B64",
		os.Getenv("GENERATION_PUBLISHER_HMAC_KEY_B64"))
	if err != nil {
		return CoordinatorSettings{}, err
	}
	if len(settings.StateKey) == len(publisherKey) &&
		subtle.ConstantTimeCompare(settings.StateKey, publisherKey) == 1 {
		return CoordinatorSettings{}, fmt.Errorf("generation state and publisher keys must be distinct")
	}
	settings.Publisher = Principal{ID: publisherID, Role: "publisher", Key: publisherKey}
	prepare, err := parseIntEnv("GENERATION_PREPARE_TIMEOUT_SECONDS", 600, 30, 86400)
	if err != nil {
		return CoordinatorSettings{}, err
	}
	commit, err := parseIntEnv("GENERATION_COMMIT_TIMEOUT_SECONDS", 600, 30, 86400)
	if err != nil {
		return CoordinatorSettings{}, err
	}
	skew, err := parseIntEnv("GENERATION_MAX_CLOCK_SKEW_SECONDS", 60, 5, 300)
	if err != nil {
		return CoordinatorSettings{}, err
	}
	settings.PrepareTimeout = time.Duration(prepare) * time.Second
	settings.CommitTimeout = time.Duration(commit) * time.Second
	settings.MaxClockSkew = time.Duration(skew) * time.Second
	return settings, nil
}

type ReplicaSettings struct {
	CoordinatorURL string
	BundleRoot     string
	Replica        Principal
}

func LoadReplicaSettings(role string, allowInsecure bool) (ReplicaSettings, error) {
	settings := ReplicaSettings{
		CoordinatorURL: os.Getenv("GENERATION_COORDINATOR_URL"),
		BundleRoot:     os.Getenv("OTA_DEPLOYMENT_BUNDLE_ROOT"),
	}
	replicaID := os.Getenv("GENERATION_REPLICA_ID")
	key, err := DecodeHMACKey("GENERATION_REPLICA_HMAC_KEY_B64",
		os.Getenv("GENERATION_REPLICA_HMAC_KEY_B64"))
	if err != nil {
		return ReplicaSettings{}, err
	}
	if settings.CoordinatorURL == "" || settings.BundleRoot == "" ||
		!auth.ValidIdentifier(replicaID, 64) ||
		(role != "controlplane" && role != "firmwareorigin") {
		return ReplicaSettings{}, fmt.Errorf("generation replica settings are incomplete")
	}
	settings.Replica = Principal{ID: replicaID, Role: role, Key: key}
	if _, err := NewClient(settings.CoordinatorURL, settings.Replica, nil,
		allowInsecure); err != nil {
		return ReplicaSettings{}, err
	}
	return settings, nil
}

func parseBoolEnv(name string, fallback bool) (bool, error) {
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

func parseIntEnv(name string, fallback, minimum, maximum int) (int, error) {
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
