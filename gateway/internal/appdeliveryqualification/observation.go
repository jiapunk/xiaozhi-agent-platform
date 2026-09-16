package appdeliveryqualification

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/strictjson"
)

const (
	ObservationSchema       = 1
	WakeContract            = "xz-action-consent-wake-v1"
	maximumWakeToFetchMS    = uint64(120_000)
	maximumQualificationDoc = int64(1 << 20)
	maximumUnixMS           = uint64(253402300799999)
	maximumClockSkew        = 30 * time.Second
	maximumEvidenceDelay    = 10 * time.Minute
)

type Observation struct {
	Schema                              uint32 `json:"schema"`
	QualificationID                     string `json:"qualification_id"`
	QualificationNonce                  string `json:"qualification_nonce"`
	Environment                         string `json:"environment"`
	DevelopmentOnly                     bool   `json:"development_only"`
	Platform                            string `json:"platform"`
	ApplicationID                       string `json:"application_id"`
	AppBuildID                          string `json:"app_build_id"`
	AppBinarySHA256                     string `json:"app_binary_sha256"`
	WakeContract                        string `json:"wake_contract"`
	ContentFreeWake                     bool   `json:"content_free_wake"`
	BackgroundNetworkRequest            bool   `json:"background_network_request"`
	BackgroundWakeCount                 uint32 `json:"background_wake_count"`
	WakeReceivedAtUnixMS                uint64 `json:"wake_received_at_unix_ms"`
	ForegroundEnteredAtUnixMS           uint64 `json:"foreground_entered_at_unix_ms"`
	AuthenticatedFetchPresentedAtUnixMS uint64 `json:"authenticated_fetch_presented_at_unix_ms"`
	WakeToFetchMS                       uint64 `json:"wake_to_fetch_ms"`
	ChallengeBindingSHA256              string `json:"challenge_binding_sha256"`
	DeviceBindingSHA256                 string `json:"device_binding_sha256"`
	DecisionIssued                      bool   `json:"decision_issued"`
}

func LoadObservation(path string) (Observation, []byte, error) {
	payload, err := readRegular(path, maximumQualificationDoc, false)
	if err != nil {
		return Observation{}, nil, fmt.Errorf("App delivery observation: %w", err)
	}
	observation, err := ParseObservation(payload)
	if err != nil {
		return Observation{}, nil, err
	}
	return observation, payload, nil
}

func ParseObservation(payload []byte) (Observation, error) {
	if err := strictjson.RejectDuplicateFields(payload); err != nil {
		return Observation{}, fmt.Errorf("App delivery observation JSON is ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var observation Observation
	if err := decoder.Decode(&observation); err != nil {
		return Observation{}, fmt.Errorf("App delivery observation JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Observation{}, fmt.Errorf("App delivery observation has trailing JSON")
	}
	canonical, err := canonicalObservation(observation)
	if err != nil || !bytes.Equal(canonical, payload) {
		return Observation{}, fmt.Errorf("App delivery observation is not canonical JSON")
	}
	if err := validateObservation(observation); err != nil {
		return Observation{}, err
	}
	return observation, nil
}

func canonicalObservation(observation Observation) ([]byte, error) {
	payload, err := json.Marshal(observation)
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}

func validateObservation(observation Observation) error {
	if observation.Schema != ObservationSchema ||
		!auth.ValidIdentifier(observation.QualificationID, 64) ||
		!validNonce(observation.QualificationNonce) ||
		(observation.Environment != "staging" &&
			observation.Environment != "production") ||
		(observation.DevelopmentOnly && observation.Environment != "staging") ||
		observation.Platform != "ios" ||
		!auth.ValidIdentifier(observation.ApplicationID, 128) ||
		!auth.ValidIdentifier(observation.AppBuildID, 64) ||
		!validSHA256(observation.AppBinarySHA256) ||
		observation.WakeContract != WakeContract ||
		!observation.ContentFreeWake || observation.BackgroundNetworkRequest ||
		observation.BackgroundWakeCount < 1 ||
		observation.BackgroundWakeCount > 8 || observation.DecisionIssued ||
		!validSHA256(observation.ChallengeBindingSHA256) ||
		!validSHA256(observation.DeviceBindingSHA256) {
		return fmt.Errorf("App delivery observation fields are invalid")
	}
	if observation.WakeReceivedAtUnixMS == 0 ||
		observation.WakeReceivedAtUnixMS > maximumUnixMS ||
		observation.ForegroundEnteredAtUnixMS > maximumUnixMS ||
		observation.AuthenticatedFetchPresentedAtUnixMS > maximumUnixMS ||
		observation.ForegroundEnteredAtUnixMS < observation.WakeReceivedAtUnixMS ||
		observation.AuthenticatedFetchPresentedAtUnixMS <
			observation.ForegroundEnteredAtUnixMS ||
		observation.AuthenticatedFetchPresentedAtUnixMS-
			observation.WakeReceivedAtUnixMS != observation.WakeToFetchMS ||
		observation.WakeToFetchMS > maximumWakeToFetchMS {
		return fmt.Errorf("App delivery observation sequence is invalid")
	}
	return nil
}

func observationTimes(observation Observation) (time.Time, time.Time) {
	return time.UnixMilli(int64(observation.WakeReceivedAtUnixMS)).UTC(),
		time.UnixMilli(int64(
			observation.AuthenticatedFetchPresentedAtUnixMS)).UTC()
}

func observationNearAttestation(observation Observation,
	verifiedAt time.Time) bool {
	_, presented := observationTimes(observation)
	verifiedAt = verifiedAt.UTC()
	return !verifiedAt.Before(presented.Add(-maximumClockSkew)) &&
		!verifiedAt.After(presented.Add(maximumEvidenceDelay))
}

func digest(payload []byte) string {
	result := sha256.Sum256(payload)
	return hex.EncodeToString(result[:])
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func validNonce(value string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == 16 &&
		base64.RawURLEncoding.EncodeToString(decoded) == value
}
