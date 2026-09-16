package pushqualification

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"xiaozhi-agent-platform/gateway/internal/accountauth"
	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/pushdelivery"
)

const (
	ReceiptSchema     = 1
	LiveResult        = "LIVE_PROVIDER_API_PASS"
	FixtureResult     = "FIXTURE_PROTOCOL_PASS"
	maximumRunTime    = 5 * time.Minute
	maximumProbeTime  = 15 * time.Second
	minimumCredential = 8
)

var unresolvedProductionGates = []string{
	"end_to_end_mtls_dispatch",
	"managed_database_failover",
	"provider_credential_revocation",
	"signed_app_delivery_receipt",
}

type Candidate struct {
	Platform            accountauth.PushPlatform
	ApplicationID       string
	CurrentCredentialID string
	NextCredentialID    string
	Current             pushdelivery.Provider
	Next                pushdelivery.Provider
	ValidTarget         string
}

type RunConfig struct {
	QualificationID string
	Environment     string
	ConfigSHA256    string
	ToolSHA256      string
	DevelopmentOnly bool
	Candidates      []Candidate
}

type ProviderEvidence struct {
	Platform                accountauth.PushPlatform `json:"platform"`
	ApplicationID           string                   `json:"application_id"`
	CurrentCredentialID     string                   `json:"current_credential_id"`
	NextCredentialID        string                   `json:"next_credential_id"`
	CurrentAccepted         bool                     `json:"current_accepted"`
	NextAccepted            bool                     `json:"next_accepted"`
	InvalidTargetClassified bool                     `json:"invalid_target_classified"`
	CanceledRequestRetried  bool                     `json:"canceled_request_retried"`
	CurrentLatencyMS        int64                    `json:"current_latency_ms"`
	NextLatencyMS           int64                    `json:"next_latency_ms"`
	InvalidClassificationMS int64                    `json:"invalid_classification_ms"`
}

type Receipt struct {
	Schema                    uint32             `json:"schema"`
	QualificationID           string             `json:"qualification_id"`
	Result                    string             `json:"result"`
	Environment               string             `json:"environment"`
	ConfigSHA256              string             `json:"config_sha256"`
	QualificationToolSHA256   string             `json:"qualification_tool_sha256"`
	StartedAt                 string             `json:"started_at"`
	FinishedAt                string             `json:"finished_at"`
	DevelopmentOnly           bool               `json:"development_only"`
	SecretFree                bool               `json:"secret_free"`
	Providers                 []ProviderEvidence `json:"providers"`
	ProductionReady           bool               `json:"production_ready"`
	UnresolvedProductionGates []string           `json:"unresolved_production_gates"`
	SigningKeyID              string             `json:"signing_key_id"`
	SignatureAlgorithm        string             `json:"signature_algorithm"`
	SignatureB64URL           string             `json:"signature_b64url"`
}

type Runner struct {
	now    func() time.Time
	random io.Reader
}

func NewRunner() *Runner {
	return &Runner{now: time.Now, random: rand.Reader}
}

func (runner *Runner) Run(ctx context.Context, config RunConfig) (Receipt, error) {
	if runner == nil || runner.now == nil || runner.random == nil || ctx == nil ||
		!validRunConfig(config) {
		return Receipt{}, fmt.Errorf("invalid push qualification configuration")
	}
	started := runner.now().UTC()
	evidence := make([]ProviderEvidence, 0, len(config.Candidates))
	seenPlatforms := make(map[accountauth.PushPlatform]bool, len(config.Candidates))
	for _, candidate := range config.Candidates {
		if seenPlatforms[candidate.Platform] {
			return Receipt{}, fmt.Errorf("duplicate push qualification platform")
		}
		seenPlatforms[candidate.Platform] = true
		item, err := runner.qualifyCandidate(ctx, candidate)
		if err != nil {
			return Receipt{}, err
		}
		evidence = append(evidence, item)
	}
	finished := runner.now().UTC()
	if finished.Before(started) || finished.Sub(started) > maximumRunTime {
		return Receipt{}, fmt.Errorf("push qualification time window is invalid")
	}
	sort.Slice(evidence, func(left, right int) bool {
		return evidence[left].Platform < evidence[right].Platform
	})
	result := LiveResult
	if config.DevelopmentOnly {
		result = FixtureResult
	}
	return Receipt{
		Schema: ReceiptSchema, QualificationID: config.QualificationID,
		Result: result, Environment: config.Environment,
		ConfigSHA256:            config.ConfigSHA256,
		QualificationToolSHA256: config.ToolSHA256,
		StartedAt:               started.Format(time.RFC3339),
		FinishedAt:              finished.Format(time.RFC3339),
		DevelopmentOnly:         config.DevelopmentOnly, SecretFree: true,
		Providers: evidence, ProductionReady: false,
		UnresolvedProductionGates: append([]string(nil),
			unresolvedProductionGates...),
	}, nil
}

func (runner *Runner) qualifyCandidate(ctx context.Context,
	candidate Candidate) (ProviderEvidence, error) {
	evidence := ProviderEvidence{Platform: candidate.Platform,
		ApplicationID:       candidate.ApplicationID,
		CurrentCredentialID: candidate.CurrentCredentialID,
		NextCredentialID:    candidate.NextCredentialID}
	result, elapsed, err := sendTimed(ctx, runner.now, candidate.Current,
		candidate.ValidTarget)
	if err != nil || result != pushdelivery.DeliveryAccepted {
		return ProviderEvidence{}, fmt.Errorf("current provider credential was not accepted")
	}
	evidence.CurrentAccepted = true
	evidence.CurrentLatencyMS = elapsed
	result, elapsed, err = sendTimed(ctx, runner.now, candidate.Next,
		candidate.ValidTarget)
	if err != nil || result != pushdelivery.DeliveryAccepted {
		return ProviderEvidence{}, fmt.Errorf("next provider credential was not accepted")
	}
	evidence.NextAccepted = true
	evidence.NextLatencyMS = elapsed
	invalidTarget, err := runner.invalidTarget(candidate.Platform)
	if err != nil {
		return ProviderEvidence{}, err
	}
	result, elapsed, err = sendTimed(ctx, runner.now, candidate.Next,
		invalidTarget)
	if err != nil || result != pushdelivery.DeliveryInvalidInstallation {
		return ProviderEvidence{}, fmt.Errorf("provider did not classify an invalid target")
	}
	evidence.InvalidTargetClassified = true
	evidence.InvalidClassificationMS = elapsed
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	result, _, err = sendTimed(canceled, runner.now, candidate.Current,
		candidate.ValidTarget)
	if err == nil || result != pushdelivery.DeliveryRetry {
		return ProviderEvidence{}, fmt.Errorf("provider did not retry a canceled request")
	}
	evidence.CanceledRequestRetried = true
	return evidence, nil
}

func sendTimed(ctx context.Context, now func() time.Time,
	provider pushdelivery.Provider, target string) (
	pushdelivery.DeliveryResult, int64, error) {
	probeContext, cancel := context.WithTimeout(ctx, maximumProbeTime)
	defer cancel()
	started := now().UTC()
	result, err := provider.Send(probeContext, target)
	finished := now().UTC()
	if finished.Before(started) || finished.Sub(started) > maximumProbeTime {
		return pushdelivery.DeliveryRetry, 0,
			fmt.Errorf("provider probe time is invalid")
	}
	return result, finished.Sub(started).Milliseconds(), err
}

func (runner *Runner) invalidTarget(platform accountauth.PushPlatform) (string, error) {
	random := make([]byte, 32)
	if _, err := io.ReadFull(runner.random, random); err != nil {
		return "", fmt.Errorf("generate invalid provider target")
	}
	switch platform {
	case accountauth.PushPlatformAPNSProduction,
		accountauth.PushPlatformAPNSDevelopment:
		return hex.EncodeToString(random), nil
	case accountauth.PushPlatformFCM:
		return "m69-invalid:" + base64.RawURLEncoding.EncodeToString(random), nil
	default:
		return "", fmt.Errorf("unsupported push qualification platform")
	}
}

func validRunConfig(config RunConfig) bool {
	if !auth.ValidIdentifier(config.QualificationID, 64) ||
		(config.Environment != "staging" && config.Environment != "production") ||
		!validSHA256(config.ConfigSHA256) || !validSHA256(config.ToolSHA256) ||
		len(config.Candidates) < 1 || len(config.Candidates) > 3 ||
		(config.DevelopmentOnly && config.Environment != "staging") {
		return false
	}
	for _, candidate := range config.Candidates {
		if !accountauth.ValidPushPlatform(candidate.Platform) ||
			!auth.ValidIdentifier(candidate.ApplicationID, 128) ||
			!validCredentialID(candidate.CurrentCredentialID) ||
			!validCredentialID(candidate.NextCredentialID) ||
			candidate.CurrentCredentialID == candidate.NextCredentialID ||
			candidate.Current == nil || candidate.Next == nil ||
			!accountauth.ValidRawPushToken(candidate.Platform,
				candidate.ValidTarget) {
			return false
		}
	}
	return true
}

func validCredentialID(value string) bool {
	return len(value) >= minimumCredential && auth.ValidIdentifier(value, 128)
}

func validSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
