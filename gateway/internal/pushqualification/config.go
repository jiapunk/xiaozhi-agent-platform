package pushqualification

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"xiaozhi-agent-platform/gateway/internal/accountauth"
	"xiaozhi-agent-platform/gateway/internal/pushdelivery"
	"xiaozhi-agent-platform/gateway/internal/strictjson"
)

const maximumConfigBytes = 64 * 1024

type liveConfigDocument struct {
	Schema                       uint32                 `json:"schema"`
	QualificationID              string                 `json:"qualification_id"`
	Environment                  string                 `json:"environment"`
	AcknowledgeLiveProviderCalls bool                   `json:"acknowledge_live_provider_calls"`
	Providers                    []liveProviderDocument `json:"providers"`
}

type liveProviderDocument struct {
	Platform              accountauth.PushPlatform `json:"platform"`
	ApplicationID         string                   `json:"application_id"`
	TeamID                string                   `json:"team_id,omitempty"`
	CurrentCredentialID   string                   `json:"current_credential_id"`
	CurrentCredentialFile string                   `json:"current_credential_file"`
	NextCredentialID      string                   `json:"next_credential_id"`
	NextCredentialFile    string                   `json:"next_credential_file"`
	ValidTargetFile       string                   `json:"valid_target_file"`
}

// LoadLiveConfig constructs real provider clients from a private qualification
// config. The returned RunConfig contains provider tokens only in memory; the
// signed receipt contains neither the config paths nor target material.
func LoadLiveConfig(path string, timeout time.Duration) (RunConfig, error) {
	payload, err := readRegular(path, maximumConfigBytes, true)
	if err != nil {
		return RunConfig{}, fmt.Errorf("push qualification config: %w", err)
	}
	if err := strictjson.RejectDuplicateFields(payload); err != nil {
		return RunConfig{}, fmt.Errorf("push qualification config contains duplicate fields")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var document liveConfigDocument
	if err := decoder.Decode(&document); err != nil {
		return RunConfig{}, fmt.Errorf("push qualification config JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF || document.Schema != 1 ||
		!document.AcknowledgeLiveProviderCalls || len(document.Providers) < 1 ||
		len(document.Providers) > 3 || timeout < time.Second ||
		timeout > 10*time.Second {
		return RunConfig{}, fmt.Errorf("push qualification config fields are invalid")
	}
	digest := sha256.Sum256(payload)
	config := RunConfig{QualificationID: document.QualificationID,
		Environment:  document.Environment,
		ConfigSHA256: hex.EncodeToString(digest[:]),
		Candidates:   make([]Candidate, 0, len(document.Providers))}
	for _, providerDocument := range document.Providers {
		if document.Environment == "production" &&
			providerDocument.Platform == accountauth.PushPlatformAPNSDevelopment {
			return RunConfig{}, fmt.Errorf(
				"production qualification forbids APNs development")
		}
		candidate, err := loadLiveCandidate(providerDocument, timeout)
		if err != nil {
			return RunConfig{}, err
		}
		config.Candidates = append(config.Candidates, candidate)
	}
	return config, nil
}

func loadLiveCandidate(document liveProviderDocument,
	timeout time.Duration) (Candidate, error) {
	targetPayload, err := readRegular(document.ValidTargetFile, 8*1024, true)
	if err != nil || bytes.ContainsAny(targetPayload, "\r\n\t ") {
		return Candidate{}, fmt.Errorf("push qualification target file is invalid")
	}
	target := string(targetPayload)
	client := qualificationHTTPClient(timeout)
	candidate := Candidate{Platform: document.Platform,
		ApplicationID:       document.ApplicationID,
		CurrentCredentialID: document.CurrentCredentialID,
		NextCredentialID:    document.NextCredentialID, ValidTarget: target}
	if err := validatePrivateCredentialFile(
		document.CurrentCredentialFile); err != nil {
		return Candidate{}, err
	}
	if err := validatePrivateCredentialFile(
		document.NextCredentialFile); err != nil {
		return Candidate{}, err
	}
	switch document.Platform {
	case accountauth.PushPlatformAPNSProduction,
		accountauth.PushPlatformAPNSDevelopment:
		if document.TeamID == "" {
			return Candidate{}, fmt.Errorf("APNs qualification team ID is required")
		}
		currentSigner, loadErr := pushdelivery.LoadAPNsPrivateKey(
			document.CurrentCredentialFile)
		if loadErr != nil {
			return Candidate{}, loadErr
		}
		nextSigner, loadErr := pushdelivery.LoadAPNsPrivateKey(
			document.NextCredentialFile)
		if loadErr != nil {
			return Candidate{}, loadErr
		}
		currentBearer, loadErr := pushdelivery.NewAPNsJWTBearerProvider(
			currentSigner, document.CurrentCredentialID, document.TeamID)
		if loadErr != nil {
			return Candidate{}, loadErr
		}
		nextBearer, loadErr := pushdelivery.NewAPNsJWTBearerProvider(
			nextSigner, document.NextCredentialID, document.TeamID)
		if loadErr != nil {
			return Candidate{}, loadErr
		}
		environment := pushdelivery.APNsProduction
		if document.Platform == accountauth.PushPlatformAPNSDevelopment {
			environment = pushdelivery.APNsDevelopment
		}
		candidate.Current, loadErr = pushdelivery.NewAPNsProvider(client,
			currentBearer, document.ApplicationID, environment)
		if loadErr == nil {
			candidate.Next, loadErr = pushdelivery.NewAPNsProvider(client,
				nextBearer, document.ApplicationID, environment)
		}
		if loadErr != nil {
			return Candidate{}, loadErr
		}
	case accountauth.PushPlatformFCM:
		if document.TeamID != "" {
			return Candidate{}, fmt.Errorf("FCM qualification forbids a team ID")
		}
		currentCredential, loadErr :=
			pushdelivery.LoadGoogleServiceAccountCredential(
				document.CurrentCredentialFile)
		if loadErr != nil {
			return Candidate{}, loadErr
		}
		nextCredential, loadErr :=
			pushdelivery.LoadGoogleServiceAccountCredential(
				document.NextCredentialFile)
		if loadErr != nil {
			return Candidate{}, loadErr
		}
		if currentCredential.ProjectID != document.ApplicationID ||
			nextCredential.ProjectID != document.ApplicationID ||
			currentCredential.KeyID != document.CurrentCredentialID ||
			nextCredential.KeyID != document.NextCredentialID {
			return Candidate{}, fmt.Errorf("FCM qualification credential identity mismatch")
		}
		currentSource, loadErr :=
			pushdelivery.NewGoogleServiceAccountTokenSource(client,
				currentCredential.Signer, currentCredential.Email,
				currentCredential.KeyID)
		if loadErr != nil {
			return Candidate{}, loadErr
		}
		nextSource, loadErr := pushdelivery.NewGoogleServiceAccountTokenSource(
			client, nextCredential.Signer, nextCredential.Email,
			nextCredential.KeyID)
		if loadErr != nil {
			return Candidate{}, loadErr
		}
		currentBearer, loadErr :=
			pushdelivery.NewCachedOAuthBearerProvider(currentSource)
		if loadErr != nil {
			return Candidate{}, loadErr
		}
		nextBearer, loadErr :=
			pushdelivery.NewCachedOAuthBearerProvider(nextSource)
		if loadErr != nil {
			return Candidate{}, loadErr
		}
		candidate.Current, loadErr = pushdelivery.NewFCMProvider(client,
			currentBearer, document.ApplicationID)
		if loadErr == nil {
			candidate.Next, loadErr = pushdelivery.NewFCMProvider(client,
				nextBearer, document.ApplicationID)
		}
		if loadErr != nil {
			return Candidate{}, loadErr
		}
	default:
		return Candidate{}, fmt.Errorf("unsupported push qualification platform")
	}
	if !validRunConfig(RunConfig{QualificationID: "candidate-check",
		Environment: "staging", ConfigSHA256: stringsOfZeroSHA256,
		ToolSHA256: stringsOfZeroSHA256, DevelopmentOnly: true,
		Candidates: []Candidate{candidate}}) {
		return Candidate{}, fmt.Errorf("push qualification provider fields are invalid")
	}
	return candidate, nil
}

func validatePrivateCredentialFile(path string) error {
	status, err := os.Lstat(path)
	if err != nil || !status.Mode().IsRegular() || status.Size() <= 0 ||
		status.Size() > 64*1024 || status.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("push qualification credential file is not a private regular file")
	}
	return nil
}

const stringsOfZeroSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"

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

func DigestRegularFile(path string, maximum int64) (string, error) {
	payload, err := readRegular(path, maximum, false)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}
