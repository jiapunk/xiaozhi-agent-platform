package providerrevocationqualification

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"time"

	"xiaozhi-agent-platform/gateway/internal/accountauth"
	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/pushdelivery"
	"xiaozhi-agent-platform/gateway/internal/strictjson"
)

const (
	maximumConfigBytes = int64(64 * 1024)
	maximumRunTime     = 5 * time.Minute
	maximumProbeTime   = 15 * time.Second
	minimumCredential  = 8
	zeroSHA256         = "0000000000000000000000000000000000000000000000000000000000000000"
)

type Candidate struct {
	Platform               accountauth.PushPlatform
	ApplicationID          string
	RevokedCredentialID    string
	ActiveCredentialID     string
	RevokedPublicKeySHA256 string
	ActivePublicKeySHA256  string
	ActiveBefore           pushdelivery.Provider
	Revoked                pushdelivery.Provider
	ActiveAfter            pushdelivery.Provider
	ValidTarget            string
}

type RunConfig struct {
	QualificationID string
	Environment     string
	DevelopmentOnly bool
	ConfigSHA256    string
	ToolSHA256      string
	Candidates      []Candidate
}

type liveConfigDocument struct {
	Schema                          uint32                 `json:"schema"`
	QualificationID                 string                 `json:"qualification_id"`
	Environment                     string                 `json:"environment"`
	AcknowledgeLiveCredentialRevoke bool                   `json:"acknowledge_live_credential_revocation"`
	Providers                       []liveProviderDocument `json:"providers"`
}

type liveProviderDocument struct {
	Platform              accountauth.PushPlatform `json:"platform"`
	ApplicationID         string                   `json:"application_id"`
	TeamID                string                   `json:"team_id,omitempty"`
	RevokedCredentialID   string                   `json:"revoked_credential_id"`
	RevokedCredentialFile string                   `json:"revoked_credential_file"`
	ActiveCredentialID    string                   `json:"active_credential_id"`
	ActiveCredentialFile  string                   `json:"active_credential_file"`
	ValidTargetFile       string                   `json:"valid_target_file"`
}

type Runner struct {
	now func() time.Time
}

func NewRunner() *Runner { return &Runner{now: time.Now} }

func LoadLiveConfig(path string, timeout time.Duration) (RunConfig, error) {
	payload, err := readRegular(path, maximumConfigBytes, true)
	if err != nil {
		return RunConfig{}, fmt.Errorf("provider revocation config: %w", err)
	}
	if err := strictjson.RejectDuplicateFields(payload); err != nil {
		return RunConfig{}, fmt.Errorf("provider revocation config is ambiguous")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var document liveConfigDocument
	if err := decoder.Decode(&document); err != nil {
		return RunConfig{}, fmt.Errorf("provider revocation config JSON is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF || document.Schema != 1 ||
		!document.AcknowledgeLiveCredentialRevoke ||
		len(document.Providers) < 1 || len(document.Providers) > 3 ||
		timeout < time.Second || timeout > 10*time.Second {
		return RunConfig{}, fmt.Errorf("provider revocation config fields are invalid")
	}
	config := RunConfig{QualificationID: document.QualificationID,
		Environment: document.Environment, ConfigSHA256: digest(payload),
		ToolSHA256: zeroSHA256,
		Candidates: make([]Candidate, 0, len(document.Providers))}
	for _, providerDocument := range document.Providers {
		if document.Environment == "production" &&
			providerDocument.Platform == accountauth.PushPlatformAPNSDevelopment {
			return RunConfig{}, fmt.Errorf("production revocation forbids APNs development")
		}
		candidate, err := loadLiveCandidate(providerDocument, timeout)
		if err != nil {
			return RunConfig{}, err
		}
		config.Candidates = append(config.Candidates, candidate)
	}
	if !validRunConfig(config) {
		return RunConfig{}, fmt.Errorf("provider revocation config identity is invalid")
	}
	return config, nil
}

func loadLiveCandidate(document liveProviderDocument,
	timeout time.Duration) (Candidate, error) {
	for _, path := range []string{document.RevokedCredentialFile,
		document.ActiveCredentialFile, document.ValidTargetFile} {
		if !filepath.IsAbs(path) {
			return Candidate{}, fmt.Errorf("provider revocation paths must be absolute")
		}
	}
	targetPayload, err := readRegular(document.ValidTargetFile, 8*1024, true)
	if err != nil || bytes.ContainsAny(targetPayload, "\r\n\t ") {
		return Candidate{}, fmt.Errorf("provider revocation target file is invalid")
	}
	if _, err := readRegular(document.RevokedCredentialFile, 64*1024, true); err != nil {
		return Candidate{}, fmt.Errorf("revoked provider credential file is invalid")
	}
	if _, err := readRegular(document.ActiveCredentialFile, 64*1024, true); err != nil {
		return Candidate{}, fmt.Errorf("active provider credential file is invalid")
	}
	candidate := Candidate{Platform: document.Platform,
		ApplicationID:       document.ApplicationID,
		RevokedCredentialID: document.RevokedCredentialID,
		ActiveCredentialID:  document.ActiveCredentialID,
		ValidTarget:         string(targetPayload)}
	client := qualificationHTTPClient(timeout)
	switch document.Platform {
	case accountauth.PushPlatformAPNSProduction,
		accountauth.PushPlatformAPNSDevelopment:
		if document.TeamID == "" {
			return Candidate{}, fmt.Errorf("APNs revocation team ID is required")
		}
		revokedSigner, loadErr := pushdelivery.LoadAPNsPrivateKey(
			document.RevokedCredentialFile)
		if loadErr != nil {
			return Candidate{}, loadErr
		}
		activeSigner, loadErr := pushdelivery.LoadAPNsPrivateKey(
			document.ActiveCredentialFile)
		if loadErr != nil {
			return Candidate{}, loadErr
		}
		candidate.RevokedPublicKeySHA256, loadErr = publicKeyDigest(revokedSigner)
		if loadErr == nil {
			candidate.ActivePublicKeySHA256, loadErr = publicKeyDigest(activeSigner)
		}
		if loadErr != nil {
			return Candidate{}, loadErr
		}
		environment := pushdelivery.APNsProduction
		if document.Platform == accountauth.PushPlatformAPNSDevelopment {
			environment = pushdelivery.APNsDevelopment
		}
		candidate.ActiveBefore, loadErr = newAPNsProvider(client, activeSigner,
			document.ActiveCredentialID, document.TeamID,
			document.ApplicationID, environment)
		if loadErr == nil {
			candidate.Revoked, loadErr = newAPNsProvider(client, revokedSigner,
				document.RevokedCredentialID, document.TeamID,
				document.ApplicationID, environment)
		}
		if loadErr == nil {
			candidate.ActiveAfter, loadErr = newAPNsProvider(client, activeSigner,
				document.ActiveCredentialID, document.TeamID,
				document.ApplicationID, environment)
		}
		if loadErr != nil {
			return Candidate{}, loadErr
		}
	case accountauth.PushPlatformFCM:
		if document.TeamID != "" {
			return Candidate{}, fmt.Errorf("FCM revocation forbids a team ID")
		}
		revokedCredential, loadErr :=
			pushdelivery.LoadGoogleServiceAccountCredential(
				document.RevokedCredentialFile)
		if loadErr != nil {
			return Candidate{}, loadErr
		}
		activeCredential, loadErr :=
			pushdelivery.LoadGoogleServiceAccountCredential(
				document.ActiveCredentialFile)
		if loadErr != nil {
			return Candidate{}, loadErr
		}
		if revokedCredential.ProjectID != document.ApplicationID ||
			activeCredential.ProjectID != document.ApplicationID ||
			revokedCredential.KeyID != document.RevokedCredentialID ||
			activeCredential.KeyID != document.ActiveCredentialID ||
			revokedCredential.Email != activeCredential.Email {
			return Candidate{}, fmt.Errorf("FCM revocation credential identity mismatch")
		}
		candidate.RevokedPublicKeySHA256, loadErr =
			publicKeyDigest(revokedCredential.Signer)
		if loadErr == nil {
			candidate.ActivePublicKeySHA256, loadErr =
				publicKeyDigest(activeCredential.Signer)
		}
		if loadErr != nil {
			return Candidate{}, loadErr
		}
		candidate.ActiveBefore, loadErr = newFCMProvider(client,
			activeCredential, document.ApplicationID)
		if loadErr == nil {
			candidate.Revoked, loadErr = newFCMProvider(client,
				revokedCredential, document.ApplicationID)
		}
		if loadErr == nil {
			candidate.ActiveAfter, loadErr = newFCMProvider(client,
				activeCredential, document.ApplicationID)
		}
		if loadErr != nil {
			return Candidate{}, loadErr
		}
	default:
		return Candidate{}, fmt.Errorf("unsupported provider revocation platform")
	}
	return candidate, nil
}

func newAPNsProvider(client *http.Client, signer crypto.Signer, keyID, teamID,
	topic string, environment pushdelivery.APNsEnvironment) (pushdelivery.Provider, error) {
	bearer, err := pushdelivery.NewAPNsJWTBearerProvider(signer, keyID, teamID)
	if err != nil {
		return nil, err
	}
	return pushdelivery.NewAPNsProvider(client, bearer, topic, environment)
}

func newFCMProvider(client *http.Client,
	credential pushdelivery.GoogleServiceAccountCredential,
	projectID string) (pushdelivery.Provider, error) {
	source, err := pushdelivery.NewGoogleServiceAccountTokenSource(client,
		credential.Signer, credential.Email, credential.KeyID)
	if err != nil {
		return nil, err
	}
	bearer, err := pushdelivery.NewCachedOAuthBearerProvider(source)
	if err != nil {
		return nil, err
	}
	return pushdelivery.NewFCMProvider(client, bearer, projectID)
}

func publicKeyDigest(signer crypto.Signer) (string, error) {
	if signer == nil || signer.Public() == nil {
		return "", fmt.Errorf("provider credential public key is unavailable")
	}
	der, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return "", fmt.Errorf("provider credential public key is invalid")
	}
	value := sha256.Sum256(der)
	return hex.EncodeToString(value[:]), nil
}

func qualificationHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		Proxy: nil, DisableCompression: true, ForceAttemptHTTP2: true,
		MaxIdleConns: 8, MaxIdleConnsPerHost: 4,
		IdleConnTimeout: 30 * time.Second,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func (runner *Runner) Run(ctx context.Context, config RunConfig) (
	Observation, error) {
	if runner == nil || runner.now == nil || ctx == nil || !validRunConfig(config) {
		return Observation{}, fmt.Errorf("invalid provider revocation run configuration")
	}
	started := runner.now().UTC().Truncate(time.Second)
	providers := make([]ProviderObservation, 0, len(config.Candidates))
	seen := make(map[accountauth.PushPlatform]bool, len(config.Candidates))
	for _, candidate := range config.Candidates {
		if seen[candidate.Platform] {
			return Observation{}, fmt.Errorf("duplicate provider revocation platform")
		}
		seen[candidate.Platform] = true
		provider, err := runner.qualifyCandidate(ctx, candidate)
		if err != nil {
			return Observation{}, err
		}
		providers = append(providers, provider)
	}
	sortObservations(providers)
	finished := runner.now().UTC().Truncate(time.Second)
	observation := Observation{Schema: ObservationSchema,
		QualificationID: config.QualificationID, Environment: config.Environment,
		DevelopmentOnly: config.DevelopmentOnly,
		ConfigSHA256:    config.ConfigSHA256, QualificationToolSHA256: config.ToolSHA256,
		Providers: providers, StartedAt: started.Format(time.RFC3339),
		FinishedAt: finished.Format(time.RFC3339), SecretFree: true}
	if err := validateObservation(observation); err != nil {
		return Observation{}, err
	}
	return observation, nil
}

func (runner *Runner) qualifyCandidate(ctx context.Context,
	candidate Candidate) (ProviderObservation, error) {
	evidence := ProviderObservation{Platform: candidate.Platform,
		ApplicationID:          candidate.ApplicationID,
		RevokedCredentialID:    candidate.RevokedCredentialID,
		ActiveCredentialID:     candidate.ActiveCredentialID,
		RevokedPublicKeySHA256: candidate.RevokedPublicKeySHA256,
		ActivePublicKeySHA256:  candidate.ActivePublicKeySHA256,
		RejectionClass:         rejectionClass(candidate.Platform)}
	result, elapsed, err := sendTimed(ctx, runner.now, candidate.ActiveBefore,
		candidate.ValidTarget)
	if err != nil || result != pushdelivery.DeliveryAccepted {
		return ProviderObservation{}, fmt.Errorf("active provider credential precheck failed")
	}
	evidence.ActiveBeforeAccepted = true
	evidence.ActiveBeforeLatencyMS = elapsed
	result, elapsed, err = sendTimed(ctx, runner.now, candidate.Revoked,
		candidate.ValidTarget)
	if result != pushdelivery.DeliveryRetry ||
		!errors.Is(err, pushdelivery.ErrCredentialRejected) ||
		!errors.Is(err, pushdelivery.ErrUnavailable) {
		return ProviderObservation{}, fmt.Errorf("revoked provider credential was not explicitly rejected")
	}
	evidence.RevokedCredentialRejected = true
	evidence.RevokedRejectionLatencyMS = elapsed
	result, elapsed, err = sendTimed(ctx, runner.now, candidate.ActiveAfter,
		candidate.ValidTarget)
	if err != nil || result != pushdelivery.DeliveryAccepted {
		return ProviderObservation{}, fmt.Errorf("active provider credential confirmation failed")
	}
	evidence.ActiveAfterAccepted = true
	evidence.ActiveAfterLatencyMS = elapsed
	return evidence, nil
}

func sendTimed(ctx context.Context, now func() time.Time,
	provider pushdelivery.Provider, target string) (
	pushdelivery.DeliveryResult, int64, error) {
	probe, cancel := context.WithTimeout(ctx, maximumProbeTime)
	defer cancel()
	started := now().UTC()
	result, err := provider.Send(probe, target)
	finished := now().UTC()
	if finished.Before(started) || finished.Sub(started) > maximumProbeTime {
		return pushdelivery.DeliveryRetry, 0,
			fmt.Errorf("provider revocation probe time is invalid")
	}
	return result, finished.Sub(started).Milliseconds(), err
}

func validRunConfig(config RunConfig) bool {
	if !auth.ValidIdentifier(config.QualificationID, 64) ||
		(config.Environment != "staging" && config.Environment != "production") ||
		(config.DevelopmentOnly && config.Environment != "staging") ||
		!validSHA256(config.ConfigSHA256) || !validSHA256(config.ToolSHA256) ||
		len(config.Candidates) < 1 || len(config.Candidates) > 3 {
		return false
	}
	for _, candidate := range config.Candidates {
		if !accountauth.ValidPushPlatform(candidate.Platform) ||
			!auth.ValidIdentifier(candidate.ApplicationID, 128) ||
			!validCredentialID(candidate.RevokedCredentialID) ||
			!validCredentialID(candidate.ActiveCredentialID) ||
			candidate.RevokedCredentialID == candidate.ActiveCredentialID ||
			!validSHA256(candidate.RevokedPublicKeySHA256) ||
			!validSHA256(candidate.ActivePublicKeySHA256) ||
			candidate.RevokedPublicKeySHA256 == candidate.ActivePublicKeySHA256 ||
			candidate.ActiveBefore == nil || candidate.Revoked == nil ||
			candidate.ActiveAfter == nil ||
			!accountauth.ValidRawPushToken(candidate.Platform, candidate.ValidTarget) {
			return false
		}
	}
	return true
}

func validCredentialID(value string) bool {
	return len(value) >= minimumCredential && auth.ValidIdentifier(value, 128)
}
