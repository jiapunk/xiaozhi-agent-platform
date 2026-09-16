package agentproxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/deviceclaim"
	"xiaozhi-agent-platform/gateway/internal/provisioning"
	"xiaozhi-agent-platform/gateway/internal/runtimecoordination"
)

type agentTestCoordinator struct {
	verifyError  error
	acquireError error
	acquired     int
	released     int
	subject      string
	rate         int
	maximum      int
	ttl          time.Duration
}

func (coordinator *agentTestCoordinator) VerifySchema(context.Context) error {
	return coordinator.verifyError
}
func (*agentTestCoordinator) ReserveProof(context.Context, uint8, string, string,
	time.Duration, time.Duration) error {
	return nil
}
func (*agentTestCoordinator) ConsumeVoiceToken(context.Context, string, string,
	time.Time) error {
	return nil
}
func (*agentTestCoordinator) AcquireVoice(context.Context, string, int,
	time.Duration) (runtimecoordination.Lease, error) {
	return runtimecoordination.Lease{}, nil
}
func (coordinator *agentTestCoordinator) AcquireAgent(_ context.Context,
	subject string, rate, maximum int,
	ttl time.Duration) (runtimecoordination.Lease, error) {
	coordinator.acquired++
	coordinator.subject, coordinator.rate = subject, rate
	coordinator.maximum, coordinator.ttl = maximum, ttl
	if coordinator.acquireError != nil {
		return runtimecoordination.Lease{}, coordinator.acquireError
	}
	return runtimecoordination.Lease{Kind: runtimecoordination.AgentLease,
		HolderID: "test-replica"}, nil
}
func (*agentTestCoordinator) Renew(context.Context, runtimecoordination.Lease,
	time.Duration) (runtimecoordination.Lease, error) {
	return runtimecoordination.Lease{}, nil
}
func (coordinator *agentTestCoordinator) Release(_ context.Context,
	_ runtimecoordination.Lease) error {
	coordinator.released++
	return nil
}

var testAgentTokenKey = []byte("agent-token-key-0123456789abcdef01234")

type proxyTestOwnership map[string]deviceclaim.Ownership

func (ownership proxyTestOwnership) Owner(deviceID string) (
	deviceclaim.Ownership, bool, error) {
	owner, found := ownership[deviceID]
	return owner, found, nil
}

func testOwnership() proxyTestOwnership {
	return proxyTestOwnership{
		"device-1": {OwnerID: "user-1", TenantID: "tenant-1",
			BindingID: "MDEyMzQ1Njc4OWFiY2RlZg", BindingRevision: 1},
	}
}

type mutableProxyOwnership struct {
	mu        sync.RWMutex
	ownership deviceclaim.Ownership
	found     bool
	err       error
}

func (ownership *mutableProxyOwnership) Owner(_ string) (
	deviceclaim.Ownership, bool, error) {
	ownership.mu.RLock()
	defer ownership.mu.RUnlock()
	return ownership.ownership, ownership.found, ownership.err
}

func (ownership *mutableProxyOwnership) set(current deviceclaim.Ownership,
	found bool, err error) {
	ownership.mu.Lock()
	ownership.ownership = current
	ownership.found = found
	ownership.err = err
	ownership.mu.Unlock()
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type blockingRequestBody struct {
	started chan struct{}
	closed  chan struct{}
	once    sync.Once
	stop    sync.Once
}

func newBlockingRequestBody() *blockingRequestBody {
	return &blockingRequestBody{
		started: make(chan struct{}),
		closed:  make(chan struct{}),
	}
}

func (body *blockingRequestBody) Read(_ []byte) (int, error) {
	body.once.Do(func() { close(body.started) })
	<-body.closed
	return 0, io.ErrClosedPipe
}

func (body *blockingRequestBody) Close() error {
	body.stop.Do(func() { close(body.closed) })
	return nil
}

func agentAuthorization(t *testing.T, audience string) string {
	t.Helper()
	issuer, err := auth.NewIssuerForAudience(testAgentTokenKey,
		5*time.Minute, audience)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := issuer.IssueOwned("device-1", "user-1", "tenant-1",
		"MDEyMzQ1Njc4OWFiY2RlZg", 1)
	if err != nil {
		t.Fatal(err)
	}
	return "Bearer " + token
}

func testProxy(t *testing.T, providerURL string,
	maxRequests int) *Proxy {
	return testProxyWithIdentity(t, providerURL, maxRequests, nil)
}

func testProxyWithIdentity(t *testing.T, providerURL string,
	maxRequests int, identity *provisioning.Registry) *Proxy {
	t.Helper()
	verifier, err := auth.NewVerifierForAudience(testAgentTokenKey,
		time.Hour, auth.AgentAudience)
	if err != nil {
		t.Fatal(err)
	}
	proxy, err := New(Config{
		Verifier: verifier, IdentityRegistry: identity,
		Ownership:     testOwnership(),
		AllowInsecure: true, ProviderURL: providerURL,
		ProviderAPIKey: "provider-secret", ProviderModel: "gpt-product",
		PublicModel: "product-agent", Logger: slog.New(
			slog.NewTextHandler(io.Discard, nil)),
		MaxOutputTokens: 1024, MaxRequestBytes: 64 * 1024,
		MaxResponseBytes: 64 * 1024, RequestTimeout: 5 * time.Second,
		MaxConcurrent: 4, MaxRequestsMinute: maxRequests,
	})
	if err != nil {
		t.Fatal(err)
	}
	return proxy
}

func agentAccessSnapshot(t *testing.T, revision uint64, disabled bool,
	now time.Time) *provisioning.Snapshot {
	t.Helper()
	seed := sha256.Sum256([]byte("agent-proxy-access-snapshot-test-key"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	unsigned := fmt.Sprintf(
		`{"version":2,"revision":%d,"purpose":"access",`+
			`"issued_at":"%s","valid_until":"%s",`+
			`"devices":[{"device_id":"device-1","disabled":%t}]}`,
		revision, now.Add(-time.Minute).Format(time.RFC3339),
		now.Add(10*time.Minute).Format(time.RFC3339), disabled)
	signed, err := provisioning.SignRegistrySnapshot(strings.NewReader(unsigned),
		"agent-access-test", privateKey, now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := provisioning.ParseSignedRegistrySnapshot(
		strings.NewReader(string(signed)), publicKey, "agent-access-test", now)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func chatRequest(t *testing.T, handler http.Handler,
	authorization string, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost,
		"/v1/chat/completions", strings.NewReader(body))
	request.Header.Set("Authorization", authorization)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestProxyRewritesPolicyAndKeepsProviderKeyServerSide(t *testing.T) {
	var providerBody map[string]any
	provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter,
		request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer provider-secret" ||
			strings.Contains(request.Header.Get("Authorization"), "device-1") {
			t.Errorf("unexpected provider authorization")
		}
		if err := json.NewDecoder(request.Body).Decode(&providerBody); err != nil {
			t.Error(err)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"id":"chat-1","choices":[` +
			`{"message":{"role":"assistant","content":"hello"}}]}`))
	}))
	defer provider.Close()
	proxy := testProxy(t, provider.URL+"/v1/chat/completions", 30)
	response := chatRequest(t, proxy.Handler(),
		agentAuthorization(t, auth.AgentAudience),
		`{"model":"product-agent","messages":[`+
			`{"role":"system","content":"safe"},`+
			`{"role":"user","content":"hello"}],`+
			`"max_tokens":300}`)
	if response.Code != http.StatusOK ||
		response.Header().Get("Cache-Control") != "no-store" ||
		!strings.Contains(response.Body.String(), `"content":"hello"`) {
		t.Fatalf("proxy response status=%d headers=%v body=%s",
			response.Code, response.Header(), response.Body.String())
	}
	if providerBody["model"] != "gpt-product" ||
		providerBody["store"] != false ||
		providerBody["max_completion_tokens"] != float64(300) {
		t.Fatalf("provider policy not applied: %#v", providerBody)
	}
	if _, exists := providerBody["max_tokens"]; exists {
		t.Fatalf("device max_tokens leaked instead of normalized: %#v",
			providerBody)
	}
}

func TestProxyUsesSharedAgentPermitAndFailsClosed(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter,
		_ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"choices":[{"message":` +
			`{"role":"assistant","content":"ok"}}]}`))
	}))
	defer provider.Close()
	proxy := testProxy(t, provider.URL+"/v1/chat/completions", 7)
	coordinator := &agentTestCoordinator{}
	proxy.config.RuntimeCoordinator = coordinator
	body := `{"model":"product-agent","messages":[` +
		`{"role":"user","content":"hello"}]}`
	response := chatRequest(t, proxy.Handler(),
		agentAuthorization(t, auth.AgentAudience), body)
	if response.Code != http.StatusOK || coordinator.acquired != 1 ||
		coordinator.released != 1 || coordinator.subject == "" ||
		coordinator.rate != 7 || coordinator.maximum != 4 ||
		coordinator.ttl != 20*time.Second {
		t.Fatalf("shared Agent permit status=%d coordinator=%#v body=%s",
			response.Code, coordinator, response.Body.String())
	}
	coordinator.acquireError = runtimecoordination.ErrUnavailable
	unavailable := chatRequest(t, proxy.Handler(),
		agentAuthorization(t, auth.AgentAudience), body)
	if unavailable.Code != http.StatusServiceUnavailable ||
		coordinator.released != 1 {
		t.Fatalf("coordination outage status=%d releases=%d",
			unavailable.Code, coordinator.released)
	}
	coordinator.verifyError = runtimecoordination.ErrUnavailable
	ready := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(ready,
		httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("coordination readiness=%d", ready.Code)
	}
	metrics := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(metrics,
		httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metrics.Body.String(),
		"xiaozhi_agent_proxy_coordination_failures_total 1") {
		t.Fatalf("coordination metric: %s", metrics.Body.String())
	}
}

func TestProxyRejectsVoiceTokenAndRequestPolicyViolations(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter,
		_ *http.Request) {
		t.Fatal("provider must not be called")
	}))
	defer provider.Close()
	validBody := `{"model":"product-agent","messages":[` +
		`{"role":"user","content":"hello"}]}`
	proxy := testProxy(t, provider.URL+"/v1/chat/completions", 30)
	voice := chatRequest(t, proxy.Handler(),
		agentAuthorization(t, auth.VoiceAudience), validBody)
	if voice.Code != http.StatusUnauthorized {
		t.Fatalf("voice token status: %d", voice.Code)
	}
	cases := []string{
		`{"model":"other","messages":[{"role":"user"}]}`,
		`{"model":"product-agent","messages":[{"role":"user"}],"stream":true}`,
		`{"model":"product-agent","messages":[{"role":"user"}],"max_tokens":1,"max_completion_tokens":1}`,
		`{"model":"product-agent","messages":[{"role":"user"}],"unknown":true}`,
		`{"model":"product-agent","messages":[{"role":"user"}],"max_tokens":1025}`,
	}
	for _, body := range cases {
		response := chatRequest(t, proxy.Handler(),
			agentAuthorization(t, auth.AgentAudience), body)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body=%s status=%d response=%s", body,
				response.Code, response.Body.String())
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(validBody))
	request.Header.Set("Authorization",
		agentAuthorization(t, auth.AgentAudience))
	missingType := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(missingType, request)
	if missingType.Code != http.StatusBadRequest {
		t.Fatalf("missing content type status: %d", missingType.Code)
	}
}

func TestProxySanitizesProviderFailureAndBoundsResponse(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter,
		_ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = writer.Write([]byte(`{"error":{"message":"provider detail"}}`))
	}))
	defer provider.Close()
	proxy := testProxy(t, provider.URL+"/v1/chat/completions", 30)
	response := chatRequest(t, proxy.Handler(),
		agentAuthorization(t, auth.AgentAudience),
		`{"model":"product-agent","messages":[{"role":"user"}]}`)
	if response.Code != http.StatusBadGateway ||
		strings.Contains(response.Body.String(), "provider detail") {
		t.Fatalf("provider failure leaked: status=%d body=%s",
			response.Code, response.Body.String())
	}

	largeProvider := httptest.NewServer(http.HandlerFunc(
		func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.Copy(writer, bytes.NewReader(bytes.Repeat([]byte("x"),
				64*1024+1)))
		}))
	defer largeProvider.Close()
	proxy = testProxy(t, largeProvider.URL+"/v1/chat/completions", 30)
	response = chatRequest(t, proxy.Handler(),
		agentAuthorization(t, auth.AgentAudience),
		`{"model":"product-agent","messages":[{"role":"user"}]}`)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("large response status: %d", response.Code)
	}
}

func TestProxyAppliesPerDeviceRateLimit(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter,
		_ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"choices":[{"message":` +
			`{"role":"assistant","content":"ok"}}]}`))
	}))
	defer provider.Close()
	proxy := testProxy(t, provider.URL+"/v1/chat/completions", 1)
	body := `{"model":"product-agent","messages":[{"role":"user"}]}`
	if first := chatRequest(t, proxy.Handler(),
		agentAuthorization(t, auth.AgentAudience), body); first.Code != http.StatusOK {
		t.Fatalf("first status: %d", first.Code)
	}
	if second := chatRequest(t, proxy.Handler(),
		agentAuthorization(t, auth.AgentAudience), body); second.Code != http.StatusTooManyRequests {
		t.Fatalf("second status: %d", second.Code)
	}
}

func TestProxyRejectsStaleBindingOnNextRequest(t *testing.T) {
	var providerCalls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter,
		_ *http.Request) {
		providerCalls.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"choices":[{"message":` +
			`{"role":"assistant","content":"ok"}}]}`))
	}))
	defer provider.Close()
	ownership := &mutableProxyOwnership{}
	ownership.set(deviceclaim.Ownership{
		OwnerID: "user-1", TenantID: "tenant-1",
		BindingID: "MDEyMzQ1Njc4OWFiY2RlZg", BindingRevision: 1,
	}, true, nil)
	proxy := testProxy(t, provider.URL+"/v1/chat/completions", 30)
	proxy.config.Ownership = ownership
	authorization := agentAuthorization(t, auth.AgentAudience)
	body := `{"model":"product-agent","messages":[{"role":"user"}]}`
	if response := chatRequest(t, proxy.Handler(), authorization, body); response.Code != http.StatusOK {
		t.Fatalf("initial request status=%d body=%s",
			response.Code, response.Body.String())
	}

	ownership.set(deviceclaim.Ownership{}, false, deviceclaim.ErrUnavailable)
	if response := chatRequest(t, proxy.Handler(), authorization, body); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("ownership outage status=%d body=%s",
			response.Code, response.Body.String())
	}
	ownership.set(deviceclaim.Ownership{
		OwnerID: "user-2", TenantID: "tenant-2",
		BindingID: "ZmVkY2JhOTg3NjU0MzIxMA", BindingRevision: 3,
	}, true, nil)
	if response := chatRequest(t, proxy.Handler(), authorization, body); response.Code != http.StatusUnauthorized {
		t.Fatalf("stale binding status=%d body=%s",
			response.Code, response.Body.String())
	}
	if providerCalls.Load() != 1 {
		t.Fatalf("provider calls=%d, want 1", providerCalls.Load())
	}
}

func TestProxyConstructorRejectsUnsafeHeaders(t *testing.T) {
	verifier, err := auth.NewVerifierForAudience(testAgentTokenKey,
		time.Hour, auth.AgentAudience)
	if err != nil {
		t.Fatal(err)
	}
	base := Config{
		Verifier: verifier, Ownership: testOwnership(), AllowInsecure: true,
		ProviderURL:    "http://localhost/v1/chat/completions",
		ProviderAPIKey: "provider-secret", ProviderModel: "gpt-product",
		PublicModel: "product-agent",
	}
	unsafeKey := base
	unsafeKey.ProviderAPIKey = "provider\nkey"
	if _, err := New(unsafeKey); err == nil {
		t.Fatal("expected unsafe API key rejection")
	}
	unsafeOrganization := base
	unsafeOrganization.ProviderOrganization = "org\r\nInjected: true"
	if _, err := New(unsafeOrganization); err == nil {
		t.Fatal("expected unsafe organization rejection")
	}
}

func TestIdentityRevokeCancelsInflightAgentRequestAndRejectsOldToken(t *testing.T) {
	clock := time.Now().UTC().Truncate(time.Second)
	identity, err := provisioning.NewRegistryFromSnapshot(
		agentAccessSnapshot(t, 30, false, clock), func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	providerStarted := make(chan struct{})
	providerCanceled := make(chan struct{})
	var providerCalls atomic.Int32
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		providerCalls.Add(1)
		close(providerStarted)
		<-request.Context().Done()
		close(providerCanceled)
		return nil, request.Context().Err()
	})
	proxy := testProxyWithIdentity(t, "http://provider.local/v1/chat/completions",
		30, identity)
	proxy.config.HTTPClient = &http.Client{Transport: transport}
	authorization := agentAuthorization(t, auth.AgentAudience)
	body := `{"model":"product-agent","messages":[{"role":"user","content":"hello"}]}`
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		result <- chatRequest(t, proxy.Handler(), authorization, body)
	}()
	select {
	case <-providerStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("Agent provider request did not start")
	}
	if changed, err := identity.ApplySnapshot(
		agentAccessSnapshot(t, 31, true, clock)); err != nil || !changed {
		t.Fatalf("apply identity revoke: changed=%v err=%v", changed, err)
	}
	if canceled := proxy.ReconcileIdentity(); canceled != 1 {
		t.Fatalf("canceled Agent requests=%d", canceled)
	}
	select {
	case <-providerCanceled:
	case <-time.After(5 * time.Second):
		t.Fatal("identity revoke did not cancel provider context")
	}
	response := <-result
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked inflight status=%d body=%s",
			response.Code, response.Body.String())
	}
	denied := chatRequest(t, proxy.Handler(), authorization, body)
	if denied.Code != http.StatusUnauthorized || providerCalls.Load() != 1 {
		t.Fatalf("old token admission status=%d provider_calls=%d",
			denied.Code, providerCalls.Load())
	}
	metrics := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(metrics,
		httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, expected := range []string{
		"xiaozhi_agent_proxy_identity_rejected_total 2",
		"xiaozhi_agent_proxy_identity_canceled_total 1",
	} {
		if !strings.Contains(metrics.Body.String(), expected) {
			t.Fatalf("missing %q in metrics: %s", expected, metrics.Body.String())
		}
	}
}

func TestIdentityRevokeClosesSlowAgentRequestBody(t *testing.T) {
	clock := time.Now().UTC().Truncate(time.Second)
	identity, err := provisioning.NewRegistryFromSnapshot(
		agentAccessSnapshot(t, 35, false, clock), func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	proxy := testProxyWithIdentity(t,
		"http://provider.local/v1/chat/completions", 30, identity)
	body := newBlockingRequestBody()
	request := httptest.NewRequest(http.MethodPost,
		"/v1/chat/completions", body)
	request.ContentLength = 1
	request.Header.Set("Authorization",
		agentAuthorization(t, auth.AgentAudience))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		proxy.Handler().ServeHTTP(response, request)
		close(done)
	}()
	select {
	case <-body.started:
	case <-time.After(5 * time.Second):
		t.Fatal("Agent request body read did not start")
	}
	if changed, err := identity.ApplySnapshot(
		agentAccessSnapshot(t, 36, true, clock)); err != nil || !changed {
		t.Fatalf("apply identity revoke: changed=%v err=%v", changed, err)
	}
	if canceled := proxy.ReconcileIdentity(); canceled != 1 {
		t.Fatalf("canceled Agent requests=%d", canceled)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("identity revoke did not unblock slow Agent request body")
	}
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked slow request status=%d body=%s",
			response.Code, response.Body.String())
	}
}

func TestExpiredIdentityFailsAgentProxyReadiness(t *testing.T) {
	clock := time.Now().UTC().Truncate(time.Second)
	identity, err := provisioning.NewRegistryFromSnapshot(
		agentAccessSnapshot(t, 40, false, clock), func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	proxy := testProxyWithIdentity(t,
		"http://localhost:9010/v1/chat/completions", 30, identity)
	clock = clock.Add(11 * time.Minute)
	ready := httptest.NewRecorder()
	proxy.Handler().ServeHTTP(ready,
		httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("expired identity readiness=%d", ready.Code)
	}
}
