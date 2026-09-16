package providerrevocationqualification

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
	"time"

	"xiaozhi-agent-platform/gateway/internal/accountauth"
	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/strictjson"
)

const ObservationSchema = 1

type ProviderObservation struct {
	Platform                  accountauth.PushPlatform `json:"platform"`
	ApplicationID             string                   `json:"application_id"`
	RevokedCredentialID       string                   `json:"revoked_credential_id"`
	ActiveCredentialID        string                   `json:"active_credential_id"`
	RevokedPublicKeySHA256    string                   `json:"revoked_public_key_sha256"`
	ActivePublicKeySHA256     string                   `json:"active_public_key_sha256"`
	ActiveBeforeAccepted      bool                     `json:"active_before_accepted"`
	RevokedCredentialRejected bool                     `json:"revoked_credential_rejected"`
	ActiveAfterAccepted       bool                     `json:"active_after_accepted"`
	RejectionClass            string                   `json:"rejection_class"`
	ActiveBeforeLatencyMS     int64                    `json:"active_before_latency_ms"`
	RevokedRejectionLatencyMS int64                    `json:"revoked_rejection_latency_ms"`
	ActiveAfterLatencyMS      int64                    `json:"active_after_latency_ms"`
}

type Observation struct {
	Schema                  uint32                `json:"schema"`
	QualificationID         string                `json:"qualification_id"`
	Environment             string                `json:"environment"`
	DevelopmentOnly         bool                  `json:"development_only"`
	ConfigSHA256            string                `json:"config_sha256"`
	QualificationToolSHA256 string                `json:"qualification_tool_sha256"`
	Providers               []ProviderObservation `json:"providers"`
	StartedAt               string                `json:"started_at"`
	FinishedAt              string                `json:"finished_at"`
	SecretFree              bool                  `json:"secret_free"`
}

func LoadObservation(path string) (Observation, []byte, error) {
	payload, err := readRegular(path, maximumDocumentBytes, false)
	if err != nil {
		return Observation{}, nil, fmt.Errorf("provider revocation observation: %w", err)
	}
	observation, err := ParseObservation(payload)
	if err != nil {
		return Observation{}, nil, err
	}
	return observation, payload, nil
}

func ParseObservation(payload []byte) (Observation, error) {
	if err := strictjson.RejectDuplicateFields(payload); err != nil {
		return Observation{}, fmt.Errorf("provider revocation observation is ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var observation Observation
	if err := decoder.Decode(&observation); err != nil {
		return Observation{}, fmt.Errorf("provider revocation observation JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Observation{}, fmt.Errorf("provider revocation observation has trailing JSON")
	}
	canonical, err := CanonicalObservation(observation)
	if err != nil || !bytes.Equal(canonical, payload) {
		return Observation{}, fmt.Errorf("provider revocation observation is not canonical JSON")
	}
	if err := validateObservation(observation); err != nil {
		return Observation{}, err
	}
	return observation, nil
}

func CanonicalObservation(observation Observation) ([]byte, error) {
	payload, err := json.Marshal(observation)
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}

func validateObservation(observation Observation) error {
	if observation.Schema != ObservationSchema ||
		!auth.ValidIdentifier(observation.QualificationID, 64) ||
		(observation.Environment != "staging" &&
			observation.Environment != "production") ||
		(observation.DevelopmentOnly && observation.Environment != "staging") ||
		!validSHA256(observation.ConfigSHA256) ||
		!validSHA256(observation.QualificationToolSHA256) ||
		len(observation.Providers) < 1 || len(observation.Providers) > 3 ||
		!observation.SecretFree {
		return fmt.Errorf("provider revocation observation fields are invalid")
	}
	seen := make(map[accountauth.PushPlatform]bool, len(observation.Providers))
	for index, provider := range observation.Providers {
		if !validProviderObservation(provider) || seen[provider.Platform] ||
			(index > 0 && observation.Providers[index-1].Platform >= provider.Platform) {
			return fmt.Errorf("provider revocation provider evidence is invalid")
		}
		seen[provider.Platform] = true
	}
	started, err := time.Parse(time.RFC3339, observation.StartedAt)
	if err != nil || started.Format(time.RFC3339) != observation.StartedAt {
		return fmt.Errorf("provider revocation observation start time is invalid")
	}
	finished, err := time.Parse(time.RFC3339, observation.FinishedAt)
	if err != nil || finished.Format(time.RFC3339) != observation.FinishedAt ||
		finished.Before(started) || finished.Sub(started) > maximumRunTime {
		return fmt.Errorf("provider revocation observation finish time is invalid")
	}
	return nil
}

func validProviderObservation(provider ProviderObservation) bool {
	expectedClass := rejectionClass(provider.Platform)
	return accountauth.ValidPushPlatform(provider.Platform) &&
		auth.ValidIdentifier(provider.ApplicationID, 128) &&
		validCredentialID(provider.RevokedCredentialID) &&
		validCredentialID(provider.ActiveCredentialID) &&
		provider.RevokedCredentialID != provider.ActiveCredentialID &&
		validSHA256(provider.RevokedPublicKeySHA256) &&
		validSHA256(provider.ActivePublicKeySHA256) &&
		provider.RevokedPublicKeySHA256 != provider.ActivePublicKeySHA256 &&
		provider.ActiveBeforeAccepted && provider.RevokedCredentialRejected &&
		provider.ActiveAfterAccepted && provider.RejectionClass == expectedClass &&
		validLatency(provider.ActiveBeforeLatencyMS) &&
		validLatency(provider.RevokedRejectionLatencyMS) &&
		validLatency(provider.ActiveAfterLatencyMS)
}

func rejectionClass(platform accountauth.PushPlatform) string {
	switch platform {
	case accountauth.PushPlatformAPNSProduction,
		accountauth.PushPlatformAPNSDevelopment:
		return "apns-invalid-provider-token"
	case accountauth.PushPlatformFCM:
		return "google-oauth-invalid-grant"
	default:
		return ""
	}
}

func validLatency(value int64) bool {
	return value >= 0 && value <= maximumProbeTime.Milliseconds()
}

func observationsEqual(left, right []ProviderObservation) bool {
	return reflect.DeepEqual(left, right)
}

func sortObservations(values []ProviderObservation) {
	sort.Slice(values, func(left, right int) bool {
		return values[left].Platform < values[right].Platform
	})
}
