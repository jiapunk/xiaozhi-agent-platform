package controlplane

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"xiaozhi-agent-platform/gateway/internal/accountauth"
	"xiaozhi-agent-platform/gateway/internal/actionconsent"
	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/deviceclaim"
	"xiaozhi-agent-platform/gateway/internal/firmwareorigin"
	"xiaozhi-agent-platform/gateway/internal/generation"
	productota "xiaozhi-agent-platform/gateway/internal/ota"
	"xiaozhi-agent-platform/gateway/internal/provisioning"
)

var (
	testDeviceSecret = []byte("device-secret-0123456789abcdef012345")
	testVoiceKey     = []byte("voice-token-key-0123456789abcdef01234")
	testAgentKey     = []byte("agent-token-key-0123456789abcdef01234")
	testOTAKey       = []byte("ota-token-key-0123456789abcdef0123456")
	testRolloutKey   = []byte("ota-rollout-key-0123456789abcdef0123")
	testAppKey       = []byte("companion-token-key-0123456789abcdef")
)

type testServiceEntitlements struct {
	grants map[accountauth.ProductService]accountauth.ServiceEntitlementGrant
	err    error
}

func (authorizer testServiceEntitlements) AuthorizeService(_ context.Context,
	principal accountauth.Principal, service accountauth.ProductService) (
	accountauth.ServiceEntitlementGrant, bool, error) {
	if authorizer.err != nil {
		return accountauth.ServiceEntitlementGrant{}, false, authorizer.err
	}
	if principal != (accountauth.Principal{
		TenantID: "tenant-1", Subject: "user-1"}) {
		return accountauth.ServiceEntitlementGrant{}, false, nil
	}
	grant, allowed := authorizer.grants[service]
	return grant, allowed, nil
}

const (
	testOTAReleaseID = "box3-development-0015"
	testOTAImageHash = "f600eca824e84a43f0691b267bd620e462c50da165c5b80e17aecb7a924f1fa8"
)

type staticOwnership map[string]deviceclaim.Ownership

func (ownership staticOwnership) Owner(deviceID string) (deviceclaim.Ownership, bool, error) {
	owner, found := ownership[deviceID]
	return owner, found, nil
}

type unavailableOwnership struct{}

func (unavailableOwnership) Owner(string) (deviceclaim.Ownership, bool, error) {
	return deviceclaim.Ownership{}, false, deviceclaim.ErrUnavailable
}

func (unavailableOwnership) VerifySchema() error {
	return deviceclaim.ErrUnavailable
}

type companionStatusFunc func(context.Context, auth.Claims, time.Time) error

func (function companionStatusFunc) Authorize(ctx context.Context,
	claims auth.Claims, now time.Time) error {
	return function(ctx, claims, now)
}

type unavailableActionConsents struct{}

func (unavailableActionConsents) Register(actionconsent.Challenge,
	time.Time) error {
	return actionconsent.ErrUnavailable
}

func (unavailableActionConsents) Pending(actionconsent.Actor,
	time.Time) (actionconsent.Record, bool, error) {
	return actionconsent.Record{}, false, actionconsent.ErrUnavailable
}

func (unavailableActionConsents) Decide(actionconsent.Actor,
	actionconsent.Request, time.Time) (actionconsent.Record, error) {
	return actionconsent.Record{}, actionconsent.ErrUnavailable
}

func (unavailableActionConsents) Consume(actionconsent.DeviceRequest,
	time.Time) (actionconsent.Record, error) {
	return actionconsent.Record{}, actionconsent.ErrUnavailable
}

func (unavailableActionConsents) VerifySchema() error {
	return actionconsent.ErrUnavailable
}

func testOwnedDevice() staticOwnership {
	return staticOwnership{
		"device-1": {OwnerID: "user-1", TenantID: "tenant-1",
			BindingID: "MDEyMzQ1Njc4OWFiY2RlZg", BindingRevision: 1},
	}
}

func testControlPlane(t *testing.T) (*Server, time.Time) {
	t.Helper()
	registryJSON := `{"version":1,"devices":[{"device_id":"` +
		"device-1" + `","secret_b64":"` +
		base64.RawURLEncoding.EncodeToString(testDeviceSecret) +
		`","disabled":false}]}`
	registry, err := provisioning.ParseRegistry(strings.NewReader(registryJSON))
	if err != nil {
		t.Fatal(err)
	}
	sessionProof, err := provisioning.NewScopedProofVerifier(registry,
		provisioning.SessionProofScope, time.Minute, 0)
	if err != nil {
		t.Fatal(err)
	}
	agentProof, err := provisioning.NewScopedProofVerifier(registry,
		provisioning.AgentTokenProofScope, time.Minute, 0)
	if err != nil {
		t.Fatal(err)
	}
	voiceIssuer, err := auth.NewIssuerForAudience(testVoiceKey,
		5*time.Minute, auth.VoiceAudience)
	if err != nil {
		t.Fatal(err)
	}
	agentIssuer, err := auth.NewIssuerForAudience(testAgentKey,
		5*time.Minute, auth.AgentAudience)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	server, err := New(Config{
		SessionProof: sessionProof, AgentProof: agentProof,
		VoiceIssuer: voiceIssuer, AgentIssuer: agentIssuer,
		Ownership:       testOwnedDevice(),
		PublicDeviceWSS: "wss://voice.example/v1/device",
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return server, now
}

func proofRequest(t *testing.T, scope provisioning.ProofScope,
	nonce []byte) *http.Request {
	t.Helper()
	path := "/v1/session"
	if scope == provisioning.AgentTokenProofScope {
		path = "/v1/agent-token"
	}
	request := httptest.NewRequest(http.MethodPost, path, nil)
	timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	nonceText := base64.RawURLEncoding.EncodeToString(nonce)
	request.Header.Set(provisioning.HeaderDeviceID, "device-1")
	request.Header.Set(provisioning.HeaderClientID, "client-1")
	request.Header.Set(provisioning.HeaderTimestamp, timestamp)
	request.Header.Set(provisioning.HeaderNonce, nonceText)
	mac := hmac.New(sha256.New, testDeviceSecret)
	_, _ = mac.Write([]byte(provisioning.CanonicalScopedProof(scope,
		"device-1", "client-1", timestamp, nonceText)))
	request.Header.Set(provisioning.HeaderSignature,
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	return request
}

type controlTestManifest struct {
	Schema                   int    `json:"schema"`
	ReleaseID                string `json:"release_id"`
	Project                  string `json:"project"`
	Board                    string `json:"board"`
	Channel                  string `json:"channel"`
	Version                  string `json:"version"`
	ReleaseSequence          uint32 `json:"release_sequence"`
	SecureVersion            uint32 `json:"secure_version"`
	ImageURL                 string `json:"image_url"`
	ImageSize                int64  `json:"image_size"`
	ImageSHA256              string `json:"image_sha256"`
	ResetQualificationSHA256 string `json:"reset_qualification_sha256"`
	NotBefore                int64  `json:"not_before"`
	ExpiresAt                int64  `json:"expires_at"`
	SigningKeyID             string `json:"signing_key_id"`
	SignatureAlgorithm       string `json:"signature_algorithm"`
	SignatureB64URL          string `json:"signature_b64url"`
}

func canonicalControlTestManifest(manifest controlTestManifest) []byte {
	return []byte("xiaozhi-product-ota-v2\n" +
		"board=" + manifest.Board + "\n" +
		"channel=" + manifest.Channel + "\n" +
		"expires_at=" + strconv.FormatInt(manifest.ExpiresAt, 10) + "\n" +
		"image_sha256=" + manifest.ImageSHA256 + "\n" +
		"image_size=" + strconv.FormatInt(manifest.ImageSize, 10) + "\n" +
		"image_url=" + manifest.ImageURL + "\n" +
		"not_before=" + strconv.FormatInt(manifest.NotBefore, 10) + "\n" +
		"project=" + manifest.Project + "\n" +
		"release_id=" + manifest.ReleaseID + "\n" +
		"release_sequence=" + strconv.FormatUint(
		uint64(manifest.ReleaseSequence), 10) + "\n" +
		"reset_qualification_sha256=" + manifest.ResetQualificationSHA256 + "\n" +
		"schema=" + strconv.Itoa(manifest.Schema) + "\n" +
		"secure_version=" + strconv.FormatUint(
		uint64(manifest.SecureVersion), 10) + "\n" +
		"signature_algorithm=" + manifest.SignatureAlgorithm + "\n" +
		"signing_key_id=" + manifest.SigningKeyID + "\n" +
		"version=" + manifest.Version + "\n")
}

func testOTARegistry(t *testing.T, enabled bool, basisPoints int,
	now time.Time) *productota.Registry {
	t.Helper()
	directory := t.TempDir()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{
		Type: "PUBLIC KEY", Bytes: publicDER,
	})
	if err := os.WriteFile(filepath.Join(directory, "release-public.pem"),
		publicPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := controlTestManifest{
		Schema: 2, ReleaseID: testOTAReleaseID,
		Project: "xiaozhi_agent_platform", Board: "esp32s3-box3",
		Channel: "development", Version: "0.15.0-dev",
		ReleaseSequence: 15, SecureVersion: 2,
		ImageURL:  "https://updates.example.com/firmware/box3/0015.bin",
		ImageSize: 4096, ImageSHA256: testOTAImageHash,
		ResetQualificationSHA256: strings.Repeat("b", 64),
		NotBefore:                now.Add(-time.Hour).Unix(),
		ExpiresAt:                now.Add(time.Hour).Unix(),
		SigningKeyID:             "release-key-2026",
		SignatureAlgorithm:       "ECDSA_P256_SHA256",
	}
	digest := sha256.Sum256(canonicalControlTestManifest(manifest))
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	manifest.SignatureB64URL = base64.RawURLEncoding.EncodeToString(signature)
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "manifest.json"),
		manifestBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	registryBytes, err := json.Marshal(map[string]any{
		"version": 1,
		"signing_keys": []map[string]any{{
			"key_id":          "release-key-2026",
			"public_key_file": "release-public.pem",
		}},
		"releases": []map[string]any{{
			"manifest_file": "manifest.json", "enabled": enabled,
			"rollout_basis_points": basisPoints,
			"retry_after_seconds":  900,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	registryPath := filepath.Join(directory, "releases.json")
	if err := os.WriteFile(registryPath, registryBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	registry, err := productota.LoadRegistry(registryPath)
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func testOTAControlPlane(t *testing.T, enabled bool,
	basisPoints int) (*Server, time.Time) {
	t.Helper()
	registryJSON := `{"version":1,"devices":[{"device_id":"device-1",` +
		`"secret_b64":"` + base64.RawURLEncoding.EncodeToString(testDeviceSecret) +
		`","board":"esp32s3-box3","ota_channel":"development"}]}`
	registry, err := provisioning.ParseRegistry(strings.NewReader(registryJSON))
	if err != nil {
		t.Fatal(err)
	}
	newProof := func(scope provisioning.ProofScope) *provisioning.ProofVerifier {
		proof, proofErr := provisioning.NewScopedProofVerifier(
			registry, scope, time.Minute, 0)
		if proofErr != nil {
			t.Fatal(proofErr)
		}
		return proof
	}
	voiceIssuer, err := auth.NewIssuerForAudience(testVoiceKey,
		5*time.Minute, auth.VoiceAudience)
	if err != nil {
		t.Fatal(err)
	}
	agentIssuer, err := auth.NewIssuerForAudience(testAgentKey,
		5*time.Minute, auth.AgentAudience)
	if err != nil {
		t.Fatal(err)
	}
	otaIssuer, err := auth.NewIssuerForAudience(testOTAKey,
		3*time.Minute, auth.OTAAudience)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	server, err := New(Config{
		SessionProof: newProof(provisioning.SessionProofScope),
		AgentProof:   newProof(provisioning.AgentTokenProofScope),
		VoiceIssuer:  voiceIssuer, AgentIssuer: agentIssuer,
		OTAProof:    newProof(provisioning.OTAOfferProofScope),
		OTARegistry: testOTARegistry(t, enabled, basisPoints, now),
		OTAIssuer:   otaIssuer, OTARolloutKey: testRolloutKey,
		Ownership:       testOwnedDevice(),
		GenerationGate:  generation.StaticGate(true),
		PublicDeviceWSS: "wss://voice.example/v1/device",
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return server, now
}

func otaControlProofRequest(t *testing.T, nonce []byte, board,
	sequence string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/v1/ota/offer", nil)
	timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	nonceText := base64.RawURLEncoding.EncodeToString(nonce)
	request.Header.Set(provisioning.HeaderDeviceID, "device-1")
	request.Header.Set(provisioning.HeaderClientID, "client-1")
	request.Header.Set(provisioning.HeaderTimestamp, timestamp)
	request.Header.Set(provisioning.HeaderNonce, nonceText)
	request.Header.Set(provisioning.HeaderOTABoard, board)
	request.Header.Set(provisioning.HeaderOTAChannel, "development")
	request.Header.Set(provisioning.HeaderOTASequence, sequence)
	request.Header.Set(provisioning.HeaderOTAVersion, "0.14.0-dev")
	mac := hmac.New(sha256.New, testDeviceSecret)
	_, _ = mac.Write([]byte(provisioning.CanonicalOTAProof(
		"device-1", "client-1", timestamp, nonceText, board, "development",
		sequence, "0.14.0-dev")))
	request.Header.Set(provisioning.HeaderSignature,
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	return request
}

func TestAuthenticatedTimeIsNonceBoundAndDeviceScoped(t *testing.T) {
	server, now := testControlPlane(t)
	nonce := base64.RawURLEncoding.EncodeToString(
		[]byte("0123456789abcdef"))
	request := httptest.NewRequest(http.MethodPost, "/v1/time", nil)
	request.Header.Set(provisioning.HeaderDeviceID, "device-1")
	request.Header.Set(provisioning.HeaderClientID, "client-1")
	request.Header.Set(provisioning.HeaderNonce, nonce)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("time response: status=%d headers=%v body=%s",
			response.Code, response.Header(), response.Body.String())
	}
	var decoded timeResponse
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Version != 1 || decoded.DeviceID != "device-1" ||
		decoded.ClientID != "client-1" || decoded.Nonce != nonce ||
		decoded.UnixSeconds != now.Unix() {
		t.Fatalf("unexpected time response: %#v", decoded)
	}

	unknown := httptest.NewRequest(http.MethodPost, "/v1/time", nil)
	unknown.Header.Set(provisioning.HeaderDeviceID, "unknown")
	unknown.Header.Set(provisioning.HeaderClientID, "client-1")
	unknown.Header.Set(provisioning.HeaderNonce, nonce)
	denied := httptest.NewRecorder()
	server.Handler().ServeHTTP(denied, unknown)
	if denied.Code != http.StatusBadRequest {
		t.Fatalf("unknown device status: %d", denied.Code)
	}

	duplicate := httptest.NewRequest(http.MethodPost, "/v1/time", nil)
	duplicate.Header.Set(provisioning.HeaderDeviceID, "device-1")
	duplicate.Header.Set(provisioning.HeaderClientID, "client-1")
	duplicate.Header.Add(provisioning.HeaderNonce, nonce)
	duplicate.Header.Add(provisioning.HeaderNonce, nonce)
	denied = httptest.NewRecorder()
	server.Handler().ServeHTTP(denied, duplicate)
	if denied.Code != http.StatusBadRequest {
		t.Fatalf("duplicate nonce status: %d", denied.Code)
	}
}

func TestVoiceAndAgentTokensAreCryptographicallyIsolated(t *testing.T) {
	server, _ := testControlPlane(t)
	voiceResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(voiceResponse, proofRequest(t,
		provisioning.SessionProofScope, []byte("0123456789abcdef")))
	if voiceResponse.Code != http.StatusOK {
		t.Fatalf("voice status=%d body=%s", voiceResponse.Code,
			voiceResponse.Body.String())
	}
	var voice sessionResponse
	if err := json.NewDecoder(voiceResponse.Body).Decode(&voice); err != nil {
		t.Fatal(err)
	}
	agentResponse := httptest.NewRecorder()
	agentRequest := proofRequest(t, provisioning.AgentTokenProofScope,
		[]byte("abcdef0123456789"))
	server.Handler().ServeHTTP(agentResponse, agentRequest)
	if agentResponse.Code != http.StatusOK {
		t.Fatalf("Agent status=%d body=%s", agentResponse.Code,
			agentResponse.Body.String())
	}
	var agent tokenResponse
	if err := json.NewDecoder(agentResponse.Body).Decode(&agent); err != nil {
		t.Fatal(err)
	}
	voiceVerifier, err := auth.NewVerifierForAudience(testVoiceKey,
		time.Hour, auth.VoiceAudience)
	if err != nil {
		t.Fatal(err)
	}
	agentVerifier, err := auth.NewVerifierForAudience(testAgentKey,
		time.Hour, auth.AgentAudience)
	if err != nil {
		t.Fatal(err)
	}
	voiceClaims, err := voiceVerifier.Verify(voice.Voice.BearerToken)
	if err != nil {
		t.Fatal(err)
	}
	agentClaims, err := agentVerifier.Verify(agent.BearerToken)
	if err != nil {
		t.Fatal(err)
	}
	for name, claims := range map[string]auth.Claims{
		"voice": voiceClaims,
		"agent": agentClaims,
	} {
		if claims.OwnerID != "user-1" || claims.TenantID != "tenant-1" {
			t.Fatalf("%s ownership claims: %#v", name, claims)
		}
		if scope, ok := auth.OwnedDeviceScope(claims); !ok ||
			scope != "MDEyMzQ1Njc4OWFiY2RlZg\x001\x00device-1" {
			t.Fatalf("%s ownership scope: %q %v", name, scope, ok)
		}
	}
	if _, err := voiceVerifier.Verify(agent.BearerToken); err == nil {
		t.Fatal("voice verifier accepted Agent token")
	}
	if _, err := agentVerifier.Verify(voice.Voice.BearerToken); err == nil {
		t.Fatal("Agent verifier accepted voice token")
	}
	if agent.Audience != auth.AgentAudience ||
		voice.Voice.URI != "wss://voice.example/v1/device" ||
		voice.Voice.BearerToken == agent.BearerToken {
		t.Fatalf("audience response mismatch: voice=%#v agent=%#v", voice, agent)
	}

	replay := httptest.NewRecorder()
	server.Handler().ServeHTTP(replay, agentRequest)
	if replay.Code != http.StatusConflict {
		t.Fatalf("Agent replay status: %d", replay.Code)
	}
}

func TestVoiceAndAgentIssuanceRequiresServiceEntitlement(t *testing.T) {
	server, now := testControlPlane(t)
	server.config.RequireServiceEntitlement = true
	server.config.ServiceEntitlements = testServiceEntitlements{grants: map[accountauth.ProductService]accountauth.ServiceEntitlementGrant{
		accountauth.ProductServiceVoice: {
			Revision: 4, State: accountauth.EntitlementGrace,
			ValidUntil: now.UTC().Add(2 * time.Minute),
		},
	}}
	voice := httptest.NewRecorder()
	server.Handler().ServeHTTP(voice, proofRequest(t,
		provisioning.SessionProofScope, []byte("entitledvoice001")))
	if voice.Code != http.StatusOK {
		t.Fatalf("entitled voice status=%d body=%s",
			voice.Code, voice.Body.String())
	}
	agent := httptest.NewRecorder()
	server.Handler().ServeHTTP(agent, proofRequest(t,
		provisioning.AgentTokenProofScope, []byte("agent-denied-001")))
	if agent.Code != http.StatusPaymentRequired ||
		strings.Contains(agent.Body.String(), "launch-plan") {
		t.Fatalf("unentitled Agent status=%d body=%s",
			agent.Code, agent.Body.String())
	}
	metrics := httptest.NewRecorder()
	server.Handler().ServeHTTP(metrics,
		httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metrics.Body.String(),
		"xiaozhi_control_service_entitlement_denied_total 1") ||
		!strings.Contains(metrics.Body.String(),
			"xiaozhi_control_service_entitlement_grace_total 1") {
		t.Fatalf("entitlement metrics: %s", metrics.Body.String())
	}

	server.config.ServiceEntitlements = testServiceEntitlements{
		err: accountauth.ErrUnavailable}
	unavailable := httptest.NewRecorder()
	server.Handler().ServeHTTP(unavailable, proofRequest(t,
		provisioning.AgentTokenProofScope, []byte("entitle-db-down1")))
	if unavailable.Code != http.StatusServiceUnavailable ||
		unavailable.Header().Get("Retry-After") != "1" {
		t.Fatalf("entitlement outage status=%d body=%s",
			unavailable.Code, unavailable.Body.String())
	}
}

func TestRequiredServiceEntitlementCannotBeOmitted(t *testing.T) {
	server, _ := testControlPlane(t)
	config := server.config
	config.RequireServiceEntitlement = true
	config.ServiceEntitlements = nil
	if _, err := New(config); err == nil ||
		!strings.Contains(err.Error(), "entitlement") {
		t.Fatalf("missing required entitlement authorizer: %v", err)
	}
}

func TestProofScopeMismatchAndMetrics(t *testing.T) {
	server, _ := testControlPlane(t)
	wrongScope := proofRequest(t, provisioning.SessionProofScope,
		[]byte("0123456789abcdef"))
	wrongScope.URL.Path = "/v1/agent-token"
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, wrongScope)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("wrong proof scope status: %d", response.Code)
	}
	metrics := httptest.NewRecorder()
	server.Handler().ServeHTTP(metrics,
		httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metrics.Body.String(),
		"xiaozhi_control_proofs_rejected_total 1") {
		t.Fatalf("metrics: %s", metrics.Body.String())
	}
}

func TestOwnershipOutageFailsIssuanceAndReadinessClosed(t *testing.T) {
	server, _ := testControlPlane(t)
	server.config.Ownership = unavailableOwnership{}
	issued := httptest.NewRecorder()
	server.Handler().ServeHTTP(issued, proofRequest(t,
		provisioning.AgentTokenProofScope, []byte("owner-db-down-01")))
	if issued.Code != http.StatusServiceUnavailable {
		t.Fatalf("ownership outage issuance status=%d body=%s",
			issued.Code, issued.Body.String())
	}
	ready := httptest.NewRecorder()
	server.Handler().ServeHTTP(ready,
		httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("ownership outage readiness status=%d body=%s",
			ready.Code, ready.Body.String())
	}
}

func TestOTAOfferIsSignedObjectBoundAndReplayProtected(t *testing.T) {
	server, _ := testOTAControlPlane(t, true, 10000)
	request := otaControlProofRequest(t, []byte("0123456789abcdef"),
		"esp32s3-box3", "14")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("OTA offer status=%d headers=%v body=%s",
			response.Code, response.Header(), response.Body.String())
	}
	var offer otaAvailableResponse
	if err := json.NewDecoder(response.Body).Decode(&offer); err != nil {
		t.Fatal(err)
	}
	if offer.Version != 1 || offer.Status != "available" ||
		offer.DeviceID != "device-1" || offer.ExpiresInSeconds != 180 ||
		offer.ManifestB64URL == "" || offer.DownloadToken == "" {
		t.Fatalf("unexpected OTA offer: %#v", offer)
	}
	manifestBytes, err := base64.RawURLEncoding.DecodeString(offer.ManifestB64URL)
	if err != nil {
		t.Fatal(err)
	}
	var manifest controlTestManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.ReleaseID != testOTAReleaseID ||
		manifest.ImageSHA256 != testOTAImageHash ||
		manifest.SignatureB64URL == "" {
		t.Fatalf("unexpected signed manifest: %#v", manifest)
	}
	verifier, err := auth.NewVerifierForAudience(testOTAKey,
		5*time.Minute, auth.OTAAudience)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := verifier.VerifyAuthorizationForRelease(
		"Bearer "+offer.DownloadToken, manifest.ReleaseID,
		manifest.ImageSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if claims.DeviceID != "device-1" || claims.ReleaseID != testOTAReleaseID {
		t.Fatalf("unexpected OTA token claims: %#v", claims)
	}
	image := bytes.Repeat([]byte{0xa5}, 4096)
	originDirectory := t.TempDir()
	if err := os.WriteFile(filepath.Join(originDirectory, "image.bin"),
		image, 0o444); err != nil {
		t.Fatal(err)
	}
	originCatalogBytes, err := json.Marshal(map[string]any{
		"version": 1,
		"objects": []map[string]any{{
			"release_id":   manifest.ReleaseID,
			"image_sha256": manifest.ImageSHA256,
			"image_size":   len(image),
			"url_path":     "/firmware/box3/0015.bin",
			"image_file":   "image.bin",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	originCatalogPath := filepath.Join(originDirectory, "catalog.json")
	if err := os.WriteFile(originCatalogPath, originCatalogBytes, 0o444); err != nil {
		t.Fatal(err)
	}
	originCatalog, err := firmwareorigin.LoadCatalog(originCatalogPath)
	if err != nil {
		t.Fatal(err)
	}
	origin, err := firmwareorigin.New(firmwareorigin.Config{
		Catalog: originCatalog, Verifier: verifier,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxConcurrent:   2,
		PublicAuthority: "updates.example",
		GenerationGate:  generation.StaticGate(true),
	})
	if err != nil {
		t.Fatal(err)
	}
	download := httptest.NewRequest(http.MethodGet,
		"/firmware/box3/0015.bin", nil)
	download.Host = "updates.example"
	download.Header.Set("Accept", "application/octet-stream")
	download.Header.Set("Authorization", "Bearer "+offer.DownloadToken)
	downloadResponse := httptest.NewRecorder()
	origin.Handler().ServeHTTP(downloadResponse, download)
	if downloadResponse.Code != http.StatusOK ||
		!bytes.Equal(downloadResponse.Body.Bytes(), image) {
		t.Fatalf("origin download status=%d size=%d",
			downloadResponse.Code, downloadResponse.Body.Len())
	}
	if _, err := verifier.VerifyAuthorizationForRelease(
		"Bearer "+offer.DownloadToken, manifest.ReleaseID,
		strings.Repeat("b", 64)); !errors.Is(err, auth.ErrClaims) {
		t.Fatalf("OTA token crossed image boundary: %v", err)
	}
	voiceVerifier, err := auth.NewVerifierForAudience(testOTAKey,
		5*time.Minute, auth.VoiceAudience)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := voiceVerifier.Verify(offer.DownloadToken); !errors.Is(err, auth.ErrClaims) {
		t.Fatalf("voice audience accepted OTA token: %v", err)
	}

	replay := httptest.NewRecorder()
	server.Handler().ServeHTTP(replay, request)
	if replay.Code != http.StatusConflict {
		t.Fatalf("OTA replay status=%d body=%s", replay.Code,
			replay.Body.String())
	}
	upToDate := httptest.NewRecorder()
	server.Handler().ServeHTTP(upToDate, otaControlProofRequest(t,
		[]byte("abcdef0123456789"), "esp32s3-box3", "15"))
	var wait otaWaitResponse
	if upToDate.Code != http.StatusOK ||
		json.NewDecoder(upToDate.Body).Decode(&wait) != nil ||
		wait.Status != "up_to_date" || wait.RetryAfterSeconds != 900 {
		t.Fatalf("up-to-date response=%d %#v", upToDate.Code, wait)
	}
	wrongBoard := httptest.NewRecorder()
	server.Handler().ServeHTTP(wrongBoard, otaControlProofRequest(t,
		[]byte("fedcba9876543210"), "esp32s3-n32r16", "14"))
	if wrongBoard.Code != http.StatusUnauthorized {
		t.Fatalf("wrong registered profile status=%d", wrongBoard.Code)
	}
	metrics := httptest.NewRecorder()
	server.Handler().ServeHTTP(metrics,
		httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, expected := range []string{
		"xiaozhi_control_ota_offered_total 1",
		"xiaozhi_control_ota_up_to_date_total 1",
		"xiaozhi_control_proof_replays_total 1",
	} {
		if !strings.Contains(metrics.Body.String(), expected) {
			t.Fatalf("missing %q in metrics: %s", expected,
				metrics.Body.String())
		}
	}
}

func TestOTARevocationAndZeroCohortDeferWithoutToken(t *testing.T) {
	for name, setup := range map[string]struct {
		enabled     bool
		basisPoints int
	}{
		"revoked":     {enabled: false, basisPoints: 10000},
		"zero-cohort": {enabled: true, basisPoints: 0},
	} {
		t.Run(name, func(t *testing.T) {
			server, _ := testOTAControlPlane(t, setup.enabled,
				setup.basisPoints)
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, otaControlProofRequest(t,
				[]byte("0123456789abcdef"), "esp32s3-box3", "14"))
			var body map[string]any
			if response.Code != http.StatusOK ||
				json.NewDecoder(response.Body).Decode(&body) != nil ||
				body["status"] != "deferred" || body["download_token"] != nil ||
				body["manifest_b64url"] != nil {
				t.Fatalf("deferred response=%d %#v", response.Code, body)
			}
		})
	}
}

func TestGenerationGateBlocksOTAWithoutConsumingDeviceProof(t *testing.T) {
	server, _ := testOTAControlPlane(t, true, 10000)
	server.config.GenerationGate = generation.StaticGate(false)
	request := otaControlProofRequest(t, []byte("gate-blocked-001"),
		"esp32s3-box3", "14")
	blocked := httptest.NewRecorder()
	server.Handler().ServeHTTP(blocked, request)
	if blocked.Code != http.StatusServiceUnavailable ||
		blocked.Header().Get("Retry-After") != "5" {
		t.Fatalf("blocked OTA status=%d headers=%v body=%s",
			blocked.Code, blocked.Header(), blocked.Body.String())
	}
	ready := httptest.NewRecorder()
	server.Handler().ServeHTTP(ready,
		httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("blocked readiness status=%d", ready.Code)
	}
	server.config.GenerationGate = generation.StaticGate(true)
	allowed := httptest.NewRecorder()
	server.Handler().ServeHTTP(allowed, request)
	if allowed.Code != http.StatusOK {
		t.Fatalf("generation gate consumed proof: status=%d body=%s",
			allowed.Code, allowed.Body.String())
	}
	metrics := httptest.NewRecorder()
	server.Handler().ServeHTTP(metrics,
		httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metrics.Body.String(),
		"xiaozhi_control_ota_generation_blocked_total 1") {
		t.Fatalf("missing generation metric: %s", metrics.Body.String())
	}
}

func testClaimControlPlane(t *testing.T) (*Server, *auth.Issuer, time.Time) {
	t.Helper()
	registryJSON := `{"version":1,"devices":[{"device_id":"device-1",` +
		`"secret_b64":"` + base64.RawURLEncoding.EncodeToString(
		testDeviceSecret) + `"}]}`
	registry, err := provisioning.ParseRegistry(strings.NewReader(registryJSON))
	if err != nil {
		t.Fatal(err)
	}
	newProof := func(scope provisioning.ProofScope) *provisioning.ProofVerifier {
		proof, proofErr := provisioning.NewScopedProofVerifier(
			registry, scope, time.Minute, 0)
		if proofErr != nil {
			t.Fatal(proofErr)
		}
		return proof
	}
	voiceIssuer, err := auth.NewIssuerForAudience(testVoiceKey,
		5*time.Minute, auth.VoiceAudience)
	if err != nil {
		t.Fatal(err)
	}
	agentIssuer, err := auth.NewIssuerForAudience(testAgentKey,
		5*time.Minute, auth.AgentAudience)
	if err != nil {
		t.Fatal(err)
	}
	appIssuer, err := auth.NewIssuerForAudience(testAppKey,
		5*time.Minute, auth.CompanionAudience)
	if err != nil {
		t.Fatal(err)
	}
	appVerifier, err := auth.NewVerifierForAudience(testAppKey,
		5*time.Minute, auth.CompanionAudience)
	if err != nil {
		t.Fatal(err)
	}
	store, err := deviceclaim.NewStore(5*time.Minute, 64)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	server, err := New(Config{
		SessionProof: newProof(provisioning.SessionProofScope),
		AgentProof:   newProof(provisioning.AgentTokenProofScope),
		ClaimProof:   newProof(provisioning.DeviceClaimProofScope),
		VoiceIssuer:  voiceIssuer, AgentIssuer: agentIssuer,
		AppVerifier: appVerifier, ClaimStore: store,
		PublicDeviceWSS: "wss://voice.example/v1/device",
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return server, appIssuer, now
}

func companionToken(t *testing.T, issuer *auth.Issuer, userID string) string {
	return companionTokenForTenant(t, issuer, userID, "tenant-1")
}

func companionTokenForTenant(t *testing.T, issuer *auth.Issuer, userID,
	tenantID string) string {
	t.Helper()
	token, _, err := issuer.IssueCompanion(userID, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func testActionConsentControlPlane(t *testing.T) (*Server,
	*actionconsent.Store, *auth.Issuer, time.Time) {
	t.Helper()
	base, now := testControlPlane(t)
	appIssuer, err := auth.NewIssuerForAudience(testAppKey,
		5*time.Minute, auth.CompanionAudience)
	if err != nil {
		t.Fatal(err)
	}
	appVerifier, err := auth.NewVerifierForAudience(testAppKey,
		5*time.Minute, auth.CompanionAudience)
	if err != nil {
		t.Fatal(err)
	}
	store, err := actionconsent.NewStore(64)
	if err != nil {
		t.Fatal(err)
	}
	base.config.AppVerifier = appVerifier
	base.config.ActionConsents = store
	base.config.ActionConsentChallengeProof, err =
		provisioning.NewScopedProofVerifier(base.config.SessionProof.Registry(),
			provisioning.ActionConsentChallengeProofScope, time.Minute, 0)
	if err != nil {
		t.Fatal(err)
	}
	base.config.ActionConsentResultProof, err =
		provisioning.NewScopedProofVerifier(base.config.SessionProof.Registry(),
			provisioning.ActionConsentResultProofScope, time.Minute, 0)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(base.config)
	if err != nil {
		t.Fatal(err)
	}
	return server, store, appIssuer, now
}

func registerActionConsent(t *testing.T, store *actionconsent.Store,
	now time.Time, challengeID string, indicatorOn bool) {
	t.Helper()
	err := store.Register(actionconsent.Challenge{
		ChallengeID: challengeID, DeviceID: "device-1",
		OwnerID: "user-1", TenantID: "tenant-1", OwnerRevision: 1,
		SessionID: "session-1", RequestID: 42,
		Action:    actionconsent.Action{IndicatorOn: indicatorOn},
		ExpiresAt: now.Add(20 * time.Second),
	}, now)
	if err != nil {
		t.Fatal(err)
	}
}

func actionConsentToken(t *testing.T, issuer *auth.Issuer, userID,
	tenantID, deviceID string) string {
	t.Helper()
	token, _, err := issuer.IssueCompanionActionConsent(
		userID, tenantID, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func actionConsentRequest(token, challengeID, body string) *http.Request {
	request := httptest.NewRequest(http.MethodPost,
		"/v1/devices/device-1/action-consents/"+challengeID+"/decision",
		strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("X-Xiaozhi-Action-Consent", actionconsent.Contract)
	return request
}

func actionConsentInboxRequest(token, deviceID string) *http.Request {
	request := httptest.NewRequest(http.MethodGet,
		"/v1/devices/"+deviceID+"/action-consents/pending", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("X-Xiaozhi-Action-Consent", actionconsent.Contract)
	return request
}

func canonicalActionConsentDecision(challengeID string, ownerRevision uint64,
	indicatorOn bool, decision string) string {
	return fmt.Sprintf(`{"version":1,"challenge_id":"%s","device_id":"device-1","owner_revision":%d,"session_id":"session-1","request_id":42,"capability":"device.set_indicator","arguments":{"on":%t},"decision":"%s"}`,
		challengeID, ownerRevision, indicatorOn, decision)
}

func TestActionConsentAcceptsOnlyExactOneUseDecision(t *testing.T) {
	server, store, issuer, now := testActionConsentControlPlane(t)
	challengeID := "MDEyMzQ1Njc4OWFiY2RlZg"
	registerActionConsent(t, store, now, challengeID, true)
	token := actionConsentToken(t, issuer,
		"user-1", "tenant-1", "device-1")
	body := canonicalActionConsentDecision(challengeID, 1, true, "approve")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response,
		actionConsentRequest(token, challengeID, body))
	wantBody := `{"version":1,"challenge_id":"` + challengeID +
		`","status":"accepted"}`
	if response.Code != http.StatusOK || response.Body.String() != wantBody ||
		response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("X-Xiaozhi-Action-Consent") !=
			actionconsent.Contract {
		t.Fatalf("action decision status=%d headers=%v body=%q",
			response.Code, response.Header(), response.Body.String())
	}
	replay := httptest.NewRecorder()
	server.Handler().ServeHTTP(replay,
		actionConsentRequest(token, challengeID, body))
	if replay.Code != http.StatusConflict {
		t.Fatalf("decision replay status=%d body=%s", replay.Code,
			replay.Body.String())
	}
	metrics := httptest.NewRecorder()
	server.Handler().ServeHTTP(metrics,
		httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, expected := range []string{
		"xiaozhi_control_action_consents_accepted_total 1",
		"xiaozhi_control_action_consents_rejected_total 1",
	} {
		if !strings.Contains(metrics.Body.String(), expected) {
			t.Fatalf("missing %q in metrics: %s", expected,
				metrics.Body.String())
		}
	}
}

func TestActionConsentRequiresLiveCompanionAccountAuthorization(t *testing.T) {
	for _, test := range []struct {
		name       string
		statusErr  error
		wantStatus int
		wantRetry  string
	}{
		{name: "revoked", statusErr: auth.ErrCompanionInactive,
			wantStatus: http.StatusUnauthorized},
		{name: "account unavailable", statusErr: auth.ErrCompanionUnavailable,
			wantStatus: http.StatusServiceUnavailable, wantRetry: "1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, store, issuer, now := testActionConsentControlPlane(t)
			challengeID := "MDEyMzQ1Njc4OWFiY2RlZg"
			registerActionConsent(t, store, now, challengeID, true)
			calls := 0
			server.config.CompanionStatus = companionStatusFunc(
				func(_ context.Context, claims auth.Claims,
					authorizationTime time.Time) error {
					calls++
					if claims.Action != auth.CompanionConsentAction ||
						claims.DeviceID != "device-1" ||
						!authorizationTime.Equal(now) {
						t.Fatalf("wrong introspection binding: %#v %v",
							claims, authorizationTime)
					}
					return test.statusErr
				})
			server, err := New(server.config)
			if err != nil {
				t.Fatal(err)
			}
			token := actionConsentToken(t, issuer,
				"user-1", "tenant-1", "device-1")
			body := canonicalActionConsentDecision(
				challengeID, 1, true, "approve")
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response,
				actionConsentRequest(token, challengeID, body))
			if response.Code != test.wantStatus ||
				response.Header().Get("Retry-After") != test.wantRetry || calls != 1 {
				t.Fatalf("status=%d retry=%q calls=%d body=%s",
					response.Code, response.Header().Get("Retry-After"),
					calls, response.Body.String())
			}
			if pending, found, err := store.Pending(actionconsent.Actor{
				DeviceID: "device-1", OwnerID: "user-1", TenantID: "tenant-1",
				OwnerRevision: 1,
			}, now); err != nil || !found ||
				pending.Challenge.ChallengeID != challengeID {
				t.Fatalf("rejected authorization consumed consent: %#v %v",
					pending, err)
			}
			metrics := httptest.NewRecorder()
			server.Handler().ServeHTTP(metrics,
				httptest.NewRequest(http.MethodGet, "/metrics", nil))
			metric := "xiaozhi_control_companion_tokens_revoked_total 1"
			if test.statusErr == auth.ErrCompanionUnavailable {
				metric = "xiaozhi_control_companion_authorization_unavailable_total 1"
			}
			if !strings.Contains(metrics.Body.String(), metric) {
				t.Fatalf("missing metric %q: %s", metric, metrics.Body.String())
			}
		})
	}

	server, store, issuer, now := testActionConsentControlPlane(t)
	challengeID := "MDEyMzQ1Njc4OWFiY2RlZg"
	registerActionConsent(t, store, now, challengeID, false)
	server.config.CompanionStatus = companionStatusFunc(
		func(context.Context, auth.Claims, time.Time) error { return nil })
	server, err := New(server.config)
	if err != nil {
		t.Fatal(err)
	}
	token := actionConsentToken(t, issuer,
		"user-1", "tenant-1", "device-1")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, actionConsentRequest(token,
		challengeID, canonicalActionConsentDecision(
			challengeID, 1, false, "deny")))
	if response.Code != http.StatusOK {
		t.Fatalf("active account status=%d body=%s",
			response.Code, response.Body.String())
	}
}

func TestActionConsentMutationFailsClosedWithoutConsuming(t *testing.T) {
	mutations := []struct {
		name       string
		body       func(string) string
		wantStatus int
	}{
		{name: "opposite argument", body: func(id string) string {
			return canonicalActionConsentDecision(id, 1, false, "approve")
		}, wantStatus: http.StatusConflict},
		{name: "stale owner revision", body: func(id string) string {
			return canonicalActionConsentDecision(id, 2, true, "approve")
		}, wantStatus: http.StatusNotFound},
		{name: "changed request", body: func(id string) string {
			return strings.Replace(canonicalActionConsentDecision(
				id, 1, true, "approve"), `"request_id":42`, `"request_id":43`, 1)
		}, wantStatus: http.StatusConflict},
		{name: "changed session", body: func(id string) string {
			return strings.Replace(canonicalActionConsentDecision(
				id, 1, true, "approve"), "session-1", "session-2", 1)
		}, wantStatus: http.StatusConflict},
		{name: "noncanonical JSON", body: func(id string) string {
			return canonicalActionConsentDecision(id, 1, true, "approve") + "\n"
		}, wantStatus: http.StatusBadRequest},
		{name: "unknown field", body: func(id string) string {
			return strings.Replace(canonicalActionConsentDecision(
				id, 1, true, "approve"), `{"version":1`, `{"extra":0,"version":1`, 1)
		}, wantStatus: http.StatusBadRequest},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			server, store, issuer, now := testActionConsentControlPlane(t)
			challengeID := "MDEyMzQ1Njc4OWFiY2RlZg"
			registerActionConsent(t, store, now, challengeID, true)
			token := actionConsentToken(t, issuer,
				"user-1", "tenant-1", "device-1")
			bad := httptest.NewRecorder()
			server.Handler().ServeHTTP(bad, actionConsentRequest(
				token, challengeID, mutation.body(challengeID)))
			if bad.Code != mutation.wantStatus {
				t.Fatalf("mutation status=%d want=%d body=%s",
					bad.Code, mutation.wantStatus, bad.Body.String())
			}
			good := httptest.NewRecorder()
			server.Handler().ServeHTTP(good, actionConsentRequest(token,
				challengeID, canonicalActionConsentDecision(
					challengeID, 1, true, "deny")))
			if good.Code != http.StatusOK {
				t.Fatalf("mutation consumed decision: status=%d body=%s",
					good.Code, good.Body.String())
			}
		})
	}
}

func TestActionConsentRequiresDeviceBoundOwnerTokenAndHeaders(t *testing.T) {
	server, store, issuer, now := testActionConsentControlPlane(t)
	challengeID := "MDEyMzQ1Njc4OWFiY2RlZg"
	registerActionConsent(t, store, now, challengeID, true)
	body := canonicalActionConsentDecision(challengeID, 1, true, "approve")
	claimToken := companionToken(t, issuer, "user-1")
	wrongAction := httptest.NewRecorder()
	server.Handler().ServeHTTP(wrongAction,
		actionConsentRequest(claimToken, challengeID, body))
	if wrongAction.Code != http.StatusUnauthorized {
		t.Fatalf("claim token status=%d", wrongAction.Code)
	}
	crossOwner := actionConsentToken(t, issuer,
		"user-2", "tenant-1", "device-1")
	denied := httptest.NewRecorder()
	server.Handler().ServeHTTP(denied,
		actionConsentRequest(crossOwner, challengeID, body))
	if denied.Code != http.StatusNotFound {
		t.Fatalf("cross-owner status=%d body=%s", denied.Code,
			denied.Body.String())
	}
	validToken := actionConsentToken(t, issuer,
		"user-1", "tenant-1", "device-1")
	missingContract := actionConsentRequest(validToken, challengeID, body)
	missingContract.Header.Del("X-Xiaozhi-Action-Consent")
	badHeader := httptest.NewRecorder()
	server.Handler().ServeHTTP(badHeader, missingContract)
	if badHeader.Code != http.StatusBadRequest {
		t.Fatalf("missing contract status=%d", badHeader.Code)
	}
	accepted := httptest.NewRecorder()
	server.Handler().ServeHTTP(accepted,
		actionConsentRequest(validToken, challengeID, body))
	if accepted.Code != http.StatusOK {
		t.Fatalf("failed requests consumed decision: %d %s",
			accepted.Code, accepted.Body.String())
	}
}

func canonicalDeviceActionConsentChallenge(challengeID string,
	indicatorOn bool, expiresAt int64) string {
	return fmt.Sprintf(`{"version":1,"challenge_id":"%s","session_id":"session-1","request_id":42,"capability":"device.set_indicator","arguments":{"on":%t},"expires_at_unix":%d}`,
		challengeID, indicatorOn, expiresAt)
}

func canonicalDeviceActionConsentResult(challengeID string,
	ownerRevision uint64, indicatorOn bool) string {
	return fmt.Sprintf(`{"version":1,"challenge_id":"%s","owner_revision":%d,"session_id":"session-1","request_id":42,"capability":"device.set_indicator","arguments":{"on":%t}}`,
		challengeID, ownerRevision, indicatorOn)
}

func signedDeviceActionConsentRequest(t *testing.T,
	scope provisioning.ProofScope, body string, nonce []byte) *http.Request {
	t.Helper()
	path := "/v1/action-consents/device/challenge"
	if scope == provisioning.ActionConsentResultProofScope {
		path = "/v1/action-consents/device/result"
	}
	request := httptest.NewRequest(http.MethodPost, path,
		strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("X-Xiaozhi-Action-Consent", actionconsent.Contract)
	timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	nonceText := base64.RawURLEncoding.EncodeToString(nonce)
	bodyDigest := sha256.Sum256([]byte(body))
	bodyDigestText := fmt.Sprintf("%x", bodyDigest[:])
	request.Header.Set(provisioning.HeaderDeviceID, "device-1")
	request.Header.Set(provisioning.HeaderClientID, "client-1")
	request.Header.Set(provisioning.HeaderTimestamp, timestamp)
	request.Header.Set(provisioning.HeaderNonce, nonceText)
	request.Header.Set(provisioning.HeaderActionConsentBodySHA256,
		bodyDigestText)
	mac := hmac.New(sha256.New, testDeviceSecret)
	_, _ = mac.Write([]byte(provisioning.CanonicalActionConsentProof(
		scope, "device-1", "client-1", timestamp, nonceText,
		bodyDigestText)))
	request.Header.Set(provisioning.HeaderSignature,
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	return request
}

func TestDeviceActionConsentRelayIsExactPendingAndOneUse(t *testing.T) {
	server, _, issuer, now := testActionConsentControlPlane(t)
	challengeID := "MDEyMzQ1Njc4OWFiY2RlZg"
	challengeBody := canonicalDeviceActionConsentChallenge(
		challengeID, true, now.Add(20*time.Second).Unix())
	registered := httptest.NewRecorder()
	server.Handler().ServeHTTP(registered, signedDeviceActionConsentRequest(t,
		provisioning.ActionConsentChallengeProofScope, challengeBody,
		[]byte("device-consent01")))
	wantChallenge := fmt.Sprintf(`{"version":1,"challenge_id":"%s","device_id":"device-1","owner_revision":1,"session_id":"session-1","request_id":42,"capability":"device.set_indicator","arguments":{"on":true},"expires_at_unix":%d}`,
		challengeID, now.Add(20*time.Second).Unix())
	if registered.Code != http.StatusCreated ||
		registered.Body.String() != wantChallenge ||
		registered.Header().Get("X-Xiaozhi-Action-Consent") !=
			actionconsent.Contract {
		t.Fatalf("register status=%d headers=%v body=%q",
			registered.Code, registered.Header(), registered.Body.String())
	}
	token := actionConsentToken(t, issuer,
		"user-1", "tenant-1", "device-1")
	inbox := httptest.NewRecorder()
	server.Handler().ServeHTTP(inbox,
		actionConsentInboxRequest(token, "device-1"))
	if inbox.Code != http.StatusOK || inbox.Body.String() != wantChallenge ||
		inbox.Header().Get("Cache-Control") != "no-store" ||
		inbox.Header().Get("X-Xiaozhi-Action-Consent") !=
			actionconsent.Contract {
		t.Fatalf("App inbox status=%d headers=%v body=%q",
			inbox.Code, inbox.Header(), inbox.Body.String())
	}

	resultBody := canonicalDeviceActionConsentResult(challengeID, 1, true)
	pending := httptest.NewRecorder()
	server.Handler().ServeHTTP(pending, signedDeviceActionConsentRequest(t,
		provisioning.ActionConsentResultProofScope, resultBody,
		[]byte("device-consent02")))
	wantPending := fmt.Sprintf(`{"version":1,"challenge_id":"%s","status":"pending","retry_after_seconds":1}`,
		challengeID)
	if pending.Code != http.StatusAccepted ||
		pending.Header().Get("Retry-After") != "1" ||
		pending.Body.String() != wantPending {
		t.Fatalf("pending status=%d headers=%v body=%q",
			pending.Code, pending.Header(), pending.Body.String())
	}

	decision := httptest.NewRecorder()
	server.Handler().ServeHTTP(decision, actionConsentRequest(token,
		challengeID,
		canonicalActionConsentDecision(challengeID, 1, true, "approve")))
	if decision.Code != http.StatusOK {
		t.Fatalf("App decision status=%d body=%s",
			decision.Code, decision.Body.String())
	}
	emptyInbox := httptest.NewRecorder()
	server.Handler().ServeHTTP(emptyInbox,
		actionConsentInboxRequest(token, "device-1"))
	if emptyInbox.Code != http.StatusNoContent || emptyInbox.Body.Len() != 0 {
		t.Fatalf("decided App inbox status=%d body=%q",
			emptyInbox.Code, emptyInbox.Body.String())
	}

	delivered := httptest.NewRecorder()
	server.Handler().ServeHTTP(delivered, signedDeviceActionConsentRequest(t,
		provisioning.ActionConsentResultProofScope, resultBody,
		[]byte("device-consent03")))
	wantDelivered := fmt.Sprintf(`{"version":1,"challenge_id":"%s","decision":"approve"}`,
		challengeID)
	if delivered.Code != http.StatusOK ||
		delivered.Body.String() != wantDelivered {
		t.Fatalf("delivered status=%d body=%q",
			delivered.Code, delivered.Body.String())
	}

	replay := httptest.NewRecorder()
	server.Handler().ServeHTTP(replay, signedDeviceActionConsentRequest(t,
		provisioning.ActionConsentResultProofScope, resultBody,
		[]byte("device-consent04")))
	if replay.Code != http.StatusConflict {
		t.Fatalf("device result replay status=%d body=%s",
			replay.Code, replay.Body.String())
	}

	metrics := httptest.NewRecorder()
	server.Handler().ServeHTTP(metrics,
		httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, expected := range []string{
		"xiaozhi_control_action_consent_challenges_registered_total 1",
		"xiaozhi_control_action_consent_device_pending_total 1",
		"xiaozhi_control_action_consent_device_delivered_total 1",
		"xiaozhi_control_action_consent_device_rejected_total 1",
		"xiaozhi_control_action_consent_inbox_delivered_total 1",
		"xiaozhi_control_action_consent_inbox_empty_total 1",
	} {
		if !strings.Contains(metrics.Body.String(), expected) {
			t.Fatalf("missing %q in metrics: %s", expected,
				metrics.Body.String())
		}
	}
}

func TestActionConsentInboxRequiresExactCurrentOwnerAndHeaders(t *testing.T) {
	server, store, issuer, now := testActionConsentControlPlane(t)
	challengeID := "MDEyMzQ1Njc4OWFiY2RlZg"
	registerActionConsent(t, store, now, challengeID, false)

	wrongOwner := actionConsentToken(t, issuer,
		"user-2", "tenant-1", "device-1")
	denied := httptest.NewRecorder()
	server.Handler().ServeHTTP(denied,
		actionConsentInboxRequest(wrongOwner, "device-1"))
	if denied.Code != http.StatusNotFound {
		t.Fatalf("cross-owner inbox status=%d body=%s",
			denied.Code, denied.Body.String())
	}

	validToken := actionConsentToken(t, issuer,
		"user-1", "tenant-1", "device-1")
	bad := actionConsentInboxRequest(validToken, "device-1")
	bad.Header.Del("Cache-Control")
	badResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(badResponse, bad)
	if badResponse.Code != http.StatusBadRequest {
		t.Fatalf("missing inbox header status=%d", badResponse.Code)
	}

	query := actionConsentInboxRequest(validToken, "device-1")
	query.URL.RawQuery = "cursor=1"
	queryResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(queryResponse, query)
	if queryResponse.Code != http.StatusBadRequest {
		t.Fatalf("query inbox status=%d", queryResponse.Code)
	}

	accepted := httptest.NewRecorder()
	server.Handler().ServeHTTP(accepted,
		actionConsentInboxRequest(validToken, "device-1"))
	if accepted.Code != http.StatusOK ||
		!strings.Contains(accepted.Body.String(), `"on":false`) {
		t.Fatalf("failed inbox requests changed challenge: %d %s",
			accepted.Code, accepted.Body.String())
	}
}

func TestDeviceActionConsentProofAndBindingMutationFailClosed(t *testing.T) {
	server, _, issuer, now := testActionConsentControlPlane(t)
	challengeID := "MDEyMzQ1Njc4OWFiY2RlZg"
	challengeBody := canonicalDeviceActionConsentChallenge(
		challengeID, true, now.Add(20*time.Second).Unix())
	tamperedBody := canonicalDeviceActionConsentChallenge(
		challengeID, false, now.Add(20*time.Second).Unix())
	tamperedRequest := signedDeviceActionConsentRequest(t,
		provisioning.ActionConsentChallengeProofScope, challengeBody,
		[]byte("device-consent05"))
	tamperedRequest.Body = io.NopCloser(strings.NewReader(tamperedBody))
	tamperedRequest.ContentLength = int64(len(tamperedBody))
	tampered := httptest.NewRecorder()
	server.Handler().ServeHTTP(tampered, tamperedRequest)
	if tampered.Code != http.StatusBadRequest {
		t.Fatalf("body tamper status=%d body=%s",
			tampered.Code, tampered.Body.String())
	}

	registered := httptest.NewRecorder()
	server.Handler().ServeHTTP(registered, signedDeviceActionConsentRequest(t,
		provisioning.ActionConsentChallengeProofScope, challengeBody,
		[]byte("device-consent06")))
	if registered.Code != http.StatusCreated {
		t.Fatalf("tamper registered challenge: %d %s",
			registered.Code, registered.Body.String())
	}
	token := actionConsentToken(t, issuer,
		"user-1", "tenant-1", "device-1")
	decision := httptest.NewRecorder()
	server.Handler().ServeHTTP(decision, actionConsentRequest(token,
		challengeID,
		canonicalActionConsentDecision(challengeID, 1, true, "deny")))
	if decision.Code != http.StatusOK {
		t.Fatal(decision.Body.String())
	}

	wrongResult := canonicalDeviceActionConsentResult(challengeID, 1, false)
	wrong := httptest.NewRecorder()
	server.Handler().ServeHTTP(wrong, signedDeviceActionConsentRequest(t,
		provisioning.ActionConsentResultProofScope, wrongResult,
		[]byte("device-consent07")))
	if wrong.Code != http.StatusConflict {
		t.Fatalf("argument mutation status=%d body=%s",
			wrong.Code, wrong.Body.String())
	}
	validResult := canonicalDeviceActionConsentResult(challengeID, 1, true)
	valid := httptest.NewRecorder()
	server.Handler().ServeHTTP(valid, signedDeviceActionConsentRequest(t,
		provisioning.ActionConsentResultProofScope, validResult,
		[]byte("device-consent08")))
	if valid.Code != http.StatusOK ||
		!strings.Contains(valid.Body.String(), `"decision":"deny"`) {
		t.Fatalf("mutation consumed result: %d %s",
			valid.Code, valid.Body.String())
	}
}

func TestActionConsentRejectsPartialDeviceRelayConfiguration(t *testing.T) {
	base, _ := testControlPlane(t)
	base.config.ActionConsents, _ = actionconsent.NewStore(8)
	if _, err := New(base.config); err == nil {
		t.Fatal("store without device proofs was accepted")
	}
	proof, err := provisioning.NewScopedProofVerifier(
		base.config.SessionProof.Registry(),
		provisioning.ActionConsentChallengeProofScope, time.Minute, 0)
	if err != nil {
		t.Fatal(err)
	}
	base.config.ActionConsentChallengeProof = proof
	if _, err := New(base.config); err == nil {
		t.Fatal("one-sided device proof configuration was accepted")
	}
}

func TestActionConsentDurableStoreOutageFailsReadinessClosed(t *testing.T) {
	base, _, _, _ := testActionConsentControlPlane(t)
	config := base.config
	config.ActionConsents = unavailableActionConsents{}
	server, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	ready := httptest.NewRecorder()
	server.Handler().ServeHTTP(ready,
		httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable ||
		!strings.Contains(ready.Body.String(), "action consent unavailable") {
		t.Fatalf("action store outage readiness=%d body=%s",
			ready.Code, ready.Body.String())
	}
}

func appClaimRequest(token, deviceID, claim, appNonce string) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/v1/device-claim/app", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set(provisioning.HeaderDeviceID, deviceID)
	request.Header.Set(provisioning.HeaderDeviceClaim, claim)
	request.Header.Set("X-App-Nonce", appNonce)
	return request
}

func signedDeviceClaimRequest(t *testing.T, claim string, nonce []byte) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost,
		"/v1/device-claim/device", nil)
	timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	nonceText := base64.RawURLEncoding.EncodeToString(nonce)
	request.Header.Set(provisioning.HeaderDeviceID, "device-1")
	request.Header.Set(provisioning.HeaderClientID, "client-1")
	request.Header.Set(provisioning.HeaderTimestamp, timestamp)
	request.Header.Set(provisioning.HeaderNonce, nonceText)
	request.Header.Set(provisioning.HeaderDeviceClaim, claim)
	mac := hmac.New(sha256.New, testDeviceSecret)
	_, _ = mac.Write([]byte(provisioning.CanonicalDeviceClaimProof(
		"device-1", "client-1", timestamp, nonceText, claim)))
	request.Header.Set(provisioning.HeaderSignature,
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	return request
}

func TestDeviceClaimRequiresUserIntentAndLiveDeviceProof(t *testing.T) {
	server, appIssuer, _ := testClaimControlPlane(t)
	claim := base64.RawURLEncoding.EncodeToString(
		[]byte("0123456789abcdef0123456789abcdef"))
	appNonce := base64.RawURLEncoding.EncodeToString(
		[]byte("app-nonce-000001"))
	token := companionToken(t, appIssuer, "user-1")
	begin := appClaimRequest(token, "device-1", claim, appNonce)
	beginResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(beginResponse, begin)
	if beginResponse.Code != http.StatusOK ||
		beginResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("begin status=%d headers=%v body=%s", beginResponse.Code,
			beginResponse.Header(), beginResponse.Body.String())
	}
	var pending claimResponse
	if err := json.NewDecoder(beginResponse.Body).Decode(&pending); err != nil {
		t.Fatal(err)
	}
	if pending.Version != 1 || pending.DeviceID != "device-1" ||
		pending.Status != deviceclaim.StatusPending ||
		!deviceclaim.ValidRequestID(pending.RequestID) ||
		pending.ExpiresInSeconds != 300 {
		t.Fatalf("pending response: %#v", pending)
	}
	unownedToken := httptest.NewRecorder()
	server.Handler().ServeHTTP(unownedToken, proofRequest(
		t, provisioning.AgentTokenProofScope,
		[]byte("agent-before-001")))
	if unownedToken.Code != http.StatusForbidden {
		t.Fatalf("unowned agent-token status=%d body=%s",
			unownedToken.Code, unownedToken.Body.String())
	}

	replay := httptest.NewRecorder()
	server.Handler().ServeHTTP(replay, begin)
	if replay.Code != http.StatusConflict {
		t.Fatalf("app nonce replay status=%d", replay.Code)
	}

	otherToken := companionToken(t, appIssuer, "user-2")
	crossUser := httptest.NewRequest(http.MethodGet,
		"/v1/device-claim/status", nil)
	crossUser.Header.Set("Authorization", "Bearer "+otherToken)
	crossUser.Header.Set("X-Claim-Request-ID", pending.RequestID)
	crossResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(crossResponse, crossUser)
	if crossResponse.Code != http.StatusNotFound {
		t.Fatalf("cross-user status=%d", crossResponse.Code)
	}
	crossTenant := httptest.NewRequest(http.MethodGet,
		"/v1/device-claim/status", nil)
	crossTenant.Header.Set("Authorization", "Bearer "+
		companionTokenForTenant(t, appIssuer, "user-1", "tenant-2"))
	crossTenant.Header.Set("X-Claim-Request-ID", pending.RequestID)
	crossTenantResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(crossTenantResponse, crossTenant)
	if crossTenantResponse.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant status=%d", crossTenantResponse.Code)
	}

	confirm := httptest.NewRecorder()
	server.Handler().ServeHTTP(confirm, signedDeviceClaimRequest(t, claim,
		[]byte("device-nonce-001")))
	if confirm.Code != http.StatusOK {
		t.Fatalf("device confirm status=%d body=%s", confirm.Code,
			confirm.Body.String())
	}
	var deviceResult deviceClaimResponse
	if err := json.NewDecoder(confirm.Body).Decode(&deviceResult); err != nil {
		t.Fatal(err)
	}
	if deviceResult.DeviceID != "device-1" ||
		deviceResult.Status != deviceclaim.StatusBound {
		t.Fatalf("device result: %#v", deviceResult)
	}
	ownedToken := httptest.NewRecorder()
	server.Handler().ServeHTTP(ownedToken, proofRequest(
		t, provisioning.AgentTokenProofScope,
		[]byte("agent-after--001")))
	if ownedToken.Code != http.StatusOK {
		t.Fatalf("owned agent-token status=%d body=%s",
			ownedToken.Code, ownedToken.Body.String())
	}

	status := httptest.NewRequest(http.MethodGet,
		"/v1/device-claim/status", nil)
	status.Header.Set("Authorization", "Bearer "+token)
	status.Header.Set("X-Claim-Request-ID", pending.RequestID)
	statusResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(statusResponse, status)
	var bound claimResponse
	if statusResponse.Code != http.StatusOK ||
		json.NewDecoder(statusResponse.Body).Decode(&bound) != nil ||
		bound.Status != deviceclaim.StatusBound ||
		bound.RequestID != pending.RequestID {
		t.Fatalf("bound status=%d body=%s decoded=%#v", statusResponse.Code,
			statusResponse.Body.String(), bound)
	}

	metrics := httptest.NewRecorder()
	server.Handler().ServeHTTP(metrics,
		httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, expected := range []string{
		"xiaozhi_control_device_claims_started_total 1",
		"xiaozhi_control_device_claims_bound_total 1",
		"xiaozhi_control_device_claims_rejected_total 3",
		"xiaozhi_control_ownership_denied_total 1",
	} {
		if !strings.Contains(metrics.Body.String(), expected) {
			t.Fatalf("missing %q in metrics: %s", expected, metrics.Body.String())
		}
	}
}

func TestOwnershipReleaseRequiresDeviceBoundActionToken(t *testing.T) {
	server, appIssuer, _ := testClaimControlPlane(t)
	claim := base64.RawURLEncoding.EncodeToString(
		[]byte("0123456789abcdef0123456789abcdef"))
	claimToken := companionToken(t, appIssuer, "user-1")
	begin := httptest.NewRecorder()
	server.Handler().ServeHTTP(begin, appClaimRequest(
		claimToken, "device-1", claim,
		base64.RawURLEncoding.EncodeToString([]byte("app-nonce-000001"))))
	if begin.Code != http.StatusOK {
		t.Fatalf("begin status=%d body=%s", begin.Code, begin.Body.String())
	}
	confirmed := httptest.NewRecorder()
	server.Handler().ServeHTTP(confirmed, signedDeviceClaimRequest(
		t, claim, []byte("device-nonce-001")))
	if confirmed.Code != http.StatusOK {
		t.Fatalf("confirm status=%d body=%s", confirmed.Code,
			confirmed.Body.String())
	}

	releaseRequest := func(token, deviceID string) *http.Request {
		request := httptest.NewRequest(http.MethodPost,
			"/v1/device-ownership/release", nil)
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set(provisioning.HeaderDeviceID, deviceID)
		return request
	}
	wrongAction := httptest.NewRecorder()
	server.Handler().ServeHTTP(wrongAction,
		releaseRequest(claimToken, "device-1"))
	if wrongAction.Code != http.StatusUnauthorized {
		t.Fatalf("claim token released ownership: %d", wrongAction.Code)
	}
	releaseToken, _, err := appIssuer.IssueCompanionRelease(
		"user-1", "tenant-1", "device-1")
	if err != nil {
		t.Fatal(err)
	}
	wrongDevice := httptest.NewRecorder()
	server.Handler().ServeHTTP(wrongDevice,
		releaseRequest(releaseToken, "device-2"))
	if wrongDevice.Code != http.StatusBadRequest {
		t.Fatalf("cross-device release status=%d", wrongDevice.Code)
	}
	released := httptest.NewRecorder()
	server.Handler().ServeHTTP(released,
		releaseRequest(releaseToken, "device-1"))
	var response ownershipReleaseResponse
	if released.Code != http.StatusOK ||
		json.NewDecoder(released.Body).Decode(&response) != nil ||
		response.Status != "released" || response.BindingRevision != 2 {
		t.Fatalf("release status=%d body=%s decoded=%#v", released.Code,
			released.Body.String(), response)
	}
	denied := httptest.NewRecorder()
	server.Handler().ServeHTTP(denied, proofRequest(
		t, provisioning.AgentTokenProofScope, []byte("post-release-001")))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("released device remained serviceable: %d %s",
			denied.Code, denied.Body.String())
	}
	replayed := httptest.NewRecorder()
	server.Handler().ServeHTTP(replayed,
		releaseRequest(releaseToken, "device-1"))
	if replayed.Code != http.StatusOK {
		t.Fatalf("idempotent release status=%d body=%s",
			replayed.Code, replayed.Body.String())
	}
}

func TestDeviceClaimAcceptsOnlyConfiguredAsymmetricAccountIssuer(t *testing.T) {
	server, legacyIssuer, _ := testClaimControlPlane(t)
	seed := sha256.Sum256([]byte("control-plane-account-jwt-test-key"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	accountIssuer, err := auth.NewCompanionJWTIssuer(privateKey,
		"account-key-1", "https://accounts.example/product", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	accountVerifier, err := auth.NewCompanionJWTVerifier(
		map[string]ed25519.PublicKey{
			"account-key-1": privateKey.Public().(ed25519.PublicKey),
		}, "https://accounts.example/product", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	server.config.AppVerifier = accountVerifier
	token, claims, err := accountIssuer.Issue("user-1", "tenant-1")
	if err != nil || claims.Issuer != "https://accounts.example/product" {
		t.Fatalf("account token: %#v %v", claims, err)
	}
	claim := base64.RawURLEncoding.EncodeToString(
		[]byte("0123456789abcdef0123456789abcdef"))
	begin := appClaimRequest(token, "device-1", claim,
		base64.RawURLEncoding.EncodeToString([]byte("app-nonce-000001")))
	accepted := httptest.NewRecorder()
	server.Handler().ServeHTTP(accepted, begin)
	if accepted.Code != http.StatusOK {
		t.Fatalf("asymmetric account token status=%d body=%s",
			accepted.Code, accepted.Body.String())
	}
	legacy := appClaimRequest(companionToken(t, legacyIssuer, "user-1"),
		"device-1", claim,
		base64.RawURLEncoding.EncodeToString([]byte("app-nonce-000002")))
	rejected := httptest.NewRecorder()
	server.Handler().ServeHTTP(rejected, legacy)
	if rejected.Code != http.StatusUnauthorized {
		t.Fatalf("legacy HMAC account token status=%d", rejected.Code)
	}
}

func TestDeviceClaimRejectsMissingIntentTamperAndPartialConfiguration(t *testing.T) {
	server, appIssuer, _ := testClaimControlPlane(t)
	claim := base64.RawURLEncoding.EncodeToString(
		[]byte("0123456789abcdef0123456789abcdef"))
	noIntent := httptest.NewRecorder()
	server.Handler().ServeHTTP(noIntent, signedDeviceClaimRequest(t, claim,
		[]byte("device-nonce-001")))
	if noIntent.Code != http.StatusNotFound {
		t.Fatalf("device-only claim status=%d", noIntent.Code)
	}
	unauthorized := appClaimRequest("invalid", "device-1", claim,
		base64.RawURLEncoding.EncodeToString([]byte("app-nonce-000001")))
	unauthorizedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthorizedResponse, unauthorized)
	if unauthorizedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("invalid app token status=%d", unauthorizedResponse.Code)
	}
	valid := appClaimRequest(companionToken(t, appIssuer, "user-1"),
		"device-1", claim,
		base64.RawURLEncoding.EncodeToString([]byte("app-nonce-000002")))
	validResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(validResponse, valid)
	if validResponse.Code != http.StatusOK {
		t.Fatalf("valid intent status=%d", validResponse.Code)
	}
	tampered := signedDeviceClaimRequest(t, claim,
		[]byte("device-nonce-002"))
	tampered.Header.Set(provisioning.HeaderDeviceClaim,
		base64.RawURLEncoding.EncodeToString(
			[]byte("fedcba9876543210fedcba9876543210")))
	tamperedResponse := httptest.NewRecorder()
	server.Handler().ServeHTTP(tamperedResponse, tampered)
	if tamperedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("tampered device proof status=%d", tamperedResponse.Code)
	}

	base, _ := testControlPlane(t)
	base.config.ClaimStore, _ = deviceclaim.NewStore(5*time.Minute, 8)
	if _, err := New(base.config); err == nil {
		t.Fatal("partial device claim configuration was accepted")
	}
}
