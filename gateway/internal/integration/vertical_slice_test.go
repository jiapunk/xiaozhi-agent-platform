package integration_test

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"xiaozhi-agent-platform/gateway/internal/agentproxy"
	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/controlplane"
	"xiaozhi-agent-platform/gateway/internal/deviceclaim"
	"xiaozhi-agent-platform/gateway/internal/provisioning"
)

type integrationOwnership map[string]deviceclaim.Ownership

func (ownership integrationOwnership) Owner(deviceID string) (deviceclaim.Ownership, bool, error) {
	owner, found := ownership[deviceID]
	return owner, found, nil
}

func integrationAccessSnapshot(t *testing.T, revision uint64, disabled bool,
	now time.Time) *provisioning.Snapshot {
	t.Helper()
	seed := sha256.Sum256([]byte("integration-access-snapshot-test-key"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	unsigned := fmt.Sprintf(
		`{"version":2,"revision":%d,"purpose":"access",`+
			`"issued_at":"%s","valid_until":"%s",`+
			`"devices":[{"device_id":"device-1","disabled":%t}]}`,
		revision, now.Add(-time.Minute).Format(time.RFC3339),
		now.Add(10*time.Minute).Format(time.RFC3339), disabled)
	signed, err := provisioning.SignRegistrySnapshot(strings.NewReader(unsigned),
		"integration-access-test", privateKey, now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := provisioning.ParseSignedRegistrySnapshot(
		strings.NewReader(string(signed)), publicKey,
		"integration-access-test", now)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestDeviceProofToAgentProviderVerticalSlice(t *testing.T) {
	deviceSecret := []byte("device-secret-0123456789abcdef012345")
	voiceKey := []byte("voice-token-key-0123456789abcdef01234")
	agentKey := []byte("agent-token-key-0123456789abcdef01234")
	registryJSON := `{"version":1,"devices":[{"device_id":"device-1",` +
		`"secret_b64":"` + base64.RawURLEncoding.EncodeToString(
		deviceSecret) + `"}]}`
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
	voiceIssuer, err := auth.NewIssuerForAudience(voiceKey,
		5*time.Minute, auth.VoiceAudience)
	if err != nil {
		t.Fatal(err)
	}
	agentIssuer, err := auth.NewIssuerForAudience(agentKey,
		5*time.Minute, auth.AgentAudience)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	control, err := controlplane.New(controlplane.Config{
		SessionProof: sessionProof, AgentProof: agentProof,
		VoiceIssuer: voiceIssuer, AgentIssuer: agentIssuer,
		Ownership: integrationOwnership{
			"device-1": {OwnerID: "user-1", TenantID: "tenant-1",
				BindingID: "MDEyMzQ1Njc4OWFiY2RlZg", BindingRevision: 1},
		},
		PublicDeviceWSS: "wss://voice.example/v1/device", Logger: logger,
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/v1/agent-token", nil)
	timestamp := strconv.FormatInt(time.Now().UTC().Unix(), 10)
	nonce := base64.RawURLEncoding.EncodeToString(
		[]byte("0123456789abcdef"))
	request.Header.Set(provisioning.HeaderDeviceID, "device-1")
	request.Header.Set(provisioning.HeaderClientID, "client-1")
	request.Header.Set(provisioning.HeaderTimestamp, timestamp)
	request.Header.Set(provisioning.HeaderNonce, nonce)
	mac := hmac.New(sha256.New, deviceSecret)
	_, _ = mac.Write([]byte(provisioning.CanonicalScopedProof(
		provisioning.AgentTokenProofScope, "device-1", "client-1",
		timestamp, nonce)))
	request.Header.Set(provisioning.HeaderSignature,
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	issued := httptest.NewRecorder()
	control.Handler().ServeHTTP(issued, request)
	if issued.Code != http.StatusOK {
		t.Fatalf("Agent token status=%d body=%s", issued.Code,
			issued.Body.String())
	}
	var token struct {
		Audience    string `json:"audience"`
		BearerToken string `json:"bearer_token"`
	}
	if err := json.NewDecoder(issued.Body).Decode(&token); err != nil {
		t.Fatal(err)
	}
	if token.Audience != auth.AgentAudience || token.BearerToken == "" {
		t.Fatalf("unexpected Agent token response: %#v", token)
	}
	issuedVerifier, err := auth.NewVerifierForAudience(agentKey,
		time.Hour, auth.AgentAudience)
	if err != nil {
		t.Fatal(err)
	}
	issuedClaims, err := issuedVerifier.Verify(token.BearerToken)
	if err != nil || issuedClaims.OwnerID != "user-1" ||
		issuedClaims.TenantID != "tenant-1" {
		t.Fatalf("unexpected owned Agent claims: %#v %v", issuedClaims, err)
	}

	providerCalls := 0
	provider := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter, providerRequest *http.Request) {
		providerCalls++
		if providerRequest.Header.Get("Authorization") !=
			"Bearer provider-secret" {
			t.Errorf("provider credential was not substituted")
		}
		if providerRequest.Header.Get("Owner-Id") != "" ||
			providerRequest.Header.Get("Tenant-Id") != "" {
			t.Errorf("product ownership identity leaked to provider")
		}
		var body map[string]any
		if err := json.NewDecoder(providerRequest.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body["model"] != "provider-model" || body["store"] != false {
			t.Errorf("provider policy missing: %#v", body)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"choices":[{"message":` +
			`{"role":"assistant","content":"agent-ready"}}]}`))
	}))
	defer provider.Close()
	verifier, err := auth.NewVerifierForAudience(agentKey,
		time.Hour, auth.AgentAudience)
	if err != nil {
		t.Fatal(err)
	}
	identityNow := time.Now().UTC().Truncate(time.Second)
	accessRegistry, err := provisioning.NewRegistryFromSnapshot(
		integrationAccessSnapshot(t, 100, false, identityNow),
		func() time.Time { return identityNow })
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := agentproxy.New(agentproxy.Config{
		Verifier: verifier, IdentityRegistry: accessRegistry,
		Ownership: integrationOwnership{
			"device-1": {OwnerID: "user-1", TenantID: "tenant-1",
				BindingID: "MDEyMzQ1Njc4OWFiY2RlZg", BindingRevision: 1},
		},
		AllowInsecure:  true,
		ProviderURL:    provider.URL + "/v1/chat/completions",
		ProviderAPIKey: "provider-secret", ProviderModel: "provider-model",
		PublicModel: "product-agent", Logger: logger,
		MaxOutputTokens: 512, MaxRequestBytes: 64 * 1024,
		MaxResponseBytes: 64 * 1024, RequestTimeout: 5 * time.Second,
		MaxConcurrent: 2, MaxRequestsMinute: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	chat := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"product-agent","messages":[`+
			`{"role":"user","content":"hello"}]}`))
	chat.Header.Set("Authorization", "Bearer "+token.BearerToken)
	chat.Header.Set("Content-Type", "application/json")
	answer := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(answer, chat)
	if answer.Code != http.StatusOK || providerCalls != 1 ||
		!strings.Contains(answer.Body.String(), "agent-ready") {
		t.Fatalf("vertical slice status=%d calls=%d body=%s",
			answer.Code, providerCalls, answer.Body.String())
	}
	if changed, err := accessRegistry.ApplySnapshot(
		integrationAccessSnapshot(t, 101, true, identityNow)); err != nil || !changed {
		t.Fatalf("apply downstream revoke: changed=%v err=%v", changed, err)
	}
	if canceled := proxy.ReconcileIdentity(); canceled != 0 {
		t.Fatalf("completed Agent request remained active: %d", canceled)
	}
	replay := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"product-agent","messages":[`+
			`{"role":"user","content":"after revoke"}]}`))
	replay.Header.Set("Authorization", "Bearer "+token.BearerToken)
	replay.Header.Set("Content-Type", "application/json")
	denied := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(denied, replay)
	if denied.Code != http.StatusUnauthorized || providerCalls != 1 {
		t.Fatalf("revoked old token status=%d calls=%d body=%s",
			denied.Code, providerCalls, denied.Body.String())
	}
}
