package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/deviceclaim"
	"xiaozhi-agent-platform/gateway/internal/protocol"
	"xiaozhi-agent-platform/gateway/internal/provisioning"
	"xiaozhi-agent-platform/gateway/internal/runtimecoordination"
	"xiaozhi-agent-platform/gateway/internal/speechbudget"
	"xiaozhi-agent-platform/gateway/internal/tts"
)

type gatewayTestCoordinator struct {
	mu          sync.Mutex
	active      map[string]runtimecoordination.Lease
	tokens      map[string]struct{}
	sequence    byte
	verifyError error
}

func newGatewayTestCoordinator() *gatewayTestCoordinator {
	return &gatewayTestCoordinator{
		active: make(map[string]runtimecoordination.Lease),
		tokens: make(map[string]struct{}),
	}
}

func (coordinator *gatewayTestCoordinator) VerifySchema(context.Context) error {
	return coordinator.verifyError
}
func (*gatewayTestCoordinator) ReserveProof(context.Context, uint8, string,
	string, time.Duration, time.Duration) error {
	return nil
}
func (coordinator *gatewayTestCoordinator) ConsumeVoiceToken(_ context.Context,
	subject, token string, _ time.Time) error {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	key := subject + "\x00" + token
	if _, exists := coordinator.tokens[key]; exists {
		return runtimecoordination.ErrReplay
	}
	coordinator.tokens[key] = struct{}{}
	return nil
}
func (coordinator *gatewayTestCoordinator) AcquireVoice(_ context.Context,
	subject string, maximum int,
	ttl time.Duration) (runtimecoordination.Lease, error) {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if _, exists := coordinator.active[subject]; exists {
		return runtimecoordination.Lease{}, runtimecoordination.ErrConflict
	}
	if len(coordinator.active) >= maximum {
		return runtimecoordination.Lease{}, runtimecoordination.ErrRateLimited
	}
	coordinator.sequence++
	lease := runtimecoordination.Lease{Kind: runtimecoordination.VoiceLease,
		SubjectSHA256: subject, HolderID: "test-replica",
		ExpiresAt: time.Now().Add(ttl)}
	lease.LeaseID[15] = coordinator.sequence
	coordinator.active[subject] = lease
	return lease, nil
}
func (*gatewayTestCoordinator) AcquireAgent(context.Context, string, int, int,
	time.Duration) (runtimecoordination.Lease, error) {
	return runtimecoordination.Lease{}, nil
}
func (coordinator *gatewayTestCoordinator) Renew(_ context.Context,
	lease runtimecoordination.Lease,
	ttl time.Duration) (runtimecoordination.Lease, error) {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	current, exists := coordinator.active[lease.SubjectSHA256]
	if !exists || current.LeaseID != lease.LeaseID {
		return runtimecoordination.Lease{}, runtimecoordination.ErrLeaseLost
	}
	lease.ExpiresAt = time.Now().Add(ttl)
	coordinator.active[lease.SubjectSHA256] = lease
	return lease, nil
}
func (coordinator *gatewayTestCoordinator) Release(_ context.Context,
	lease runtimecoordination.Lease) error {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	current, exists := coordinator.active[lease.SubjectSHA256]
	if !exists || current.LeaseID != lease.LeaseID {
		return runtimecoordination.ErrLeaseLost
	}
	delete(coordinator.active, lease.SubjectSHA256)
	return nil
}
func (coordinator *gatewayTestCoordinator) activeCount() int {
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	return len(coordinator.active)
}

type fakeSynthesizer struct {
	frames [][]byte
}

func (synthesizer *fakeSynthesizer) Stream(ctx context.Context, _ tts.Request, emit tts.EmitFrame) error {
	for _, frame := range synthesizer.frames {
		if err := emit(frame); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
	return nil
}

func (*fakeSynthesizer) Ready(context.Context) error { return nil }

type fakeVoiceBackend struct{}

var gatewayTokenIDs atomic.Uint64

type fakeVoiceSession struct {
	emitter VoiceEmitter
}

func (fakeVoiceBackend) Open(_ context.Context, _ VoiceSessionConfig, emitter VoiceEmitter) (VoiceSession, error) {
	return &fakeVoiceSession{emitter: emitter}, nil
}

func (fakeVoiceBackend) Ready(context.Context) error { return nil }

func (session *fakeVoiceSession) HandleAudio(ctx context.Context, _ []byte) error {
	return session.emitter.SendSTT(ctx, "turn on")
}

func (*fakeVoiceSession) HandleControl(context.Context, []byte) error { return nil }
func (*fakeVoiceSession) Close() error                                { return nil }

func signGatewayToken(t *testing.T, secret []byte, deviceID string) string {
	t.Helper()
	now := time.Now()
	return signGatewayTokenUntil(t, secret, deviceID,
		now.Add(5*time.Minute))
}

func signGatewayTokenUntil(t *testing.T, secret []byte, deviceID string,
	expiresAt time.Time) string {
	t.Helper()
	now := time.Now()
	claims := auth.Claims{
		DeviceID: deviceID, OwnerID: "user-1", TenantID: "tenant-1",
		BindingID: "MDEyMzQ1Njc4OWFiY2RlZg", BindingRevision: 1,
		Audience: auth.VoiceAudience,
		TokenID:  "token-" + strconv.FormatUint(gatewayTokenIDs.Add(1), 10),
		IssuedAt: now.Add(-time.Minute).Unix(), Expires: expiresAt.Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	input := "v3." + encoded
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestVoiceTokenExpiryClosesActiveWebSocket(t *testing.T) {
	gateway, secret := testGateway(t)
	server := httptest.NewServer(gateway.Handler())
	defer server.Close()
	token := signGatewayTokenUntil(t, secret, "device-expiry",
		time.Now().Add(2*time.Second))
	socket := dialDeviceToken(t, server.URL, token, "device-expiry")
	defer socket.CloseNow()
	_ = sendHello(t, socket)
	readContext, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	_, _, readErr := socket.Read(readContext)
	if websocket.CloseStatus(readErr) != websocket.StatusPolicyViolation {
		t.Fatalf("unexpected expiry close: %v", readErr)
	}
	metrics := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(metrics,
		httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metrics.Body.String(),
		"xiaozhi_gateway_voice_token_expirations_total 1") {
		t.Fatalf("expiry metrics: %s", metrics.Body.String())
	}
}

func testGateway(t *testing.T) (*Server, []byte) {
	return testGatewayWithSynth(t, &fakeSynthesizer{frames: [][]byte{{1, 2}, {3, 4, 5}}})
}

func testGatewayWithSynth(t *testing.T, synthesizer tts.Synthesizer) (*Server, []byte) {
	t.Helper()
	secret := []byte("0123456789abcdef0123456789abcdef")
	verifier, err := auth.NewVerifier(secret, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{
		Verifier: verifier,
		Ownership: gatewayTestOwnership{
			"*": {OwnerID: "user-1", TenantID: "tenant-1",
				BindingID: "MDEyMzQ1Njc4OWFiY2RlZg", BindingRevision: 1},
		},
		Synthesizer:    synthesizer,
		VoiceBackend:   fakeVoiceBackend{},
		Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxConnections: 10, MaxMessagesMinute: 30,
	})
	if err != nil {
		t.Fatal(err)
	}
	return server, secret
}

type bargeInSynthesizer struct {
	calls      atomic.Int32
	postCancel chan error
}

type gatewayTestOwnership map[string]deviceclaim.Ownership

func (ownership gatewayTestOwnership) Owner(deviceID string) (deviceclaim.Ownership, bool, error) {
	owner, found := ownership[deviceID]
	if !found {
		owner, found = ownership["*"]
	}
	return owner, found, nil
}

type mutableGatewayOwnership struct {
	mu         sync.RWMutex
	ownership  deviceclaim.Ownership
	found      bool
	err        error
	batchCalls int
}

func (ownership *mutableGatewayOwnership) Owners(deviceIDs []string) (
	map[string]deviceclaim.Ownership, error) {
	ownership.mu.Lock()
	defer ownership.mu.Unlock()
	ownership.batchCalls++
	if ownership.err != nil {
		return nil, ownership.err
	}
	owners := make(map[string]deviceclaim.Ownership, len(deviceIDs))
	if ownership.found {
		for _, deviceID := range deviceIDs {
			owners[deviceID] = ownership.ownership
		}
	}
	return owners, nil
}

func (ownership *mutableGatewayOwnership) batches() int {
	ownership.mu.RLock()
	defer ownership.mu.RUnlock()
	return ownership.batchCalls
}

func (ownership *mutableGatewayOwnership) Owner(_ string) (
	deviceclaim.Ownership, bool, error) {
	ownership.mu.RLock()
	defer ownership.mu.RUnlock()
	return ownership.ownership, ownership.found, ownership.err
}

func (ownership *mutableGatewayOwnership) set(current deviceclaim.Ownership,
	found bool, err error) {
	ownership.mu.Lock()
	ownership.ownership = current
	ownership.found = found
	ownership.err = err
	ownership.mu.Unlock()
}

func (synthesizer *bargeInSynthesizer) Stream(ctx context.Context, _ tts.Request, emit tts.EmitFrame) error {
	if synthesizer.calls.Add(1) == 1 {
		if err := emit([]byte{1}); err != nil {
			return err
		}
		<-ctx.Done()
		synthesizer.postCancel <- emit([]byte{99})
		return ctx.Err()
	}
	return emit([]byte{2})
}

func (*bargeInSynthesizer) Ready(context.Context) error { return nil }

func dialDevice(t *testing.T, serverURL string, secret []byte, deviceID string) *websocket.Conn {
	t.Helper()
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+signGatewayToken(t, secret, deviceID))
	headers.Set("Device-Id", deviceID)
	headers.Set("Client-Id", "client-1")
	headers.Set("Protocol-Version", "1")
	socket, response, err := websocket.Dial(context.Background(),
		"ws"+strings.TrimPrefix(serverURL, "http")+"/v1/device",
		&websocket.DialOptions{HTTPHeader: headers})
	if err != nil {
		if response != nil {
			t.Fatalf("dial failed with status %d: %v", response.StatusCode, err)
		}
		t.Fatal(err)
	}
	return socket
}

func dialDeviceToken(t *testing.T, serverURL, token, deviceID string) *websocket.Conn {
	t.Helper()
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+token)
	headers.Set("Device-Id", deviceID)
	headers.Set("Client-Id", "client-1")
	headers.Set("Protocol-Version", "1")
	socket, response, err := websocket.Dial(context.Background(),
		"ws"+strings.TrimPrefix(serverURL, "http")+"/v1/device",
		&websocket.DialOptions{HTTPHeader: headers})
	if err != nil {
		if response != nil {
			t.Fatalf("dial failed with status %d: %v", response.StatusCode, err)
		}
		t.Fatal(err)
	}
	return socket
}

func testSessionGateway(t *testing.T, disabled bool) (*Server, []byte, []byte) {
	t.Helper()
	tokenSecret := []byte("0123456789abcdef0123456789abcdef")
	deviceSecret := []byte("device-secret-0123456789abcdef012345")
	registryJSON := `{"version":1,"devices":[{"device_id":"device-1","secret_b64":"` +
		base64.RawURLEncoding.EncodeToString(deviceSecret) + `","disabled":` +
		map[bool]string{true: "true", false: "false"}[disabled] + `}]}`
	registry, err := provisioning.ParseRegistry(strings.NewReader(registryJSON))
	if err != nil {
		t.Fatal(err)
	}
	proof, err := provisioning.NewProofVerifier(registry, time.Minute, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := auth.NewIssuer(tokenSecret, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := auth.NewVerifier(tokenSecret, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{
		Verifier: verifier, Synthesizer: &fakeSynthesizer{},
		VoiceBackend: fakeVoiceBackend{},
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		SessionProof: proof, SessionIssuer: issuer,
		Ownership: gatewayTestOwnership{
			"*": {OwnerID: "user-1", TenantID: "tenant-1",
				BindingID: "MDEyMzQ1Njc4OWFiY2RlZg", BindingRevision: 1},
		},
		PublicDeviceWSS: "ws://voice.example/v1/device",
	})
	if err != nil {
		t.Fatal(err)
	}
	return server, tokenSecret, deviceSecret
}

func signedSessionRequest(t *testing.T, endpoint string, now time.Time,
	nonce, secret []byte) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, endpoint+"/v1/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := strconv.FormatInt(now.Unix(), 10)
	nonceText := base64.RawURLEncoding.EncodeToString(nonce)
	request.Header.Set(provisioning.HeaderDeviceID, "device-1")
	request.Header.Set(provisioning.HeaderClientID, "client-1")
	request.Header.Set(provisioning.HeaderTimestamp, timestamp)
	request.Header.Set(provisioning.HeaderNonce, nonceText)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(provisioning.CanonicalProof(
		"device-1", "client-1", timestamp, nonceText)))
	request.Header.Set(provisioning.HeaderSignature,
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	return request
}

func sendHello(t *testing.T, socket *websocket.Conn) string {
	t.Helper()
	hello := []byte(`{"type":"hello","version":1,"transport":"websocket",` +
		`"features":{"device_agent":{"version":1,"request_correlation":true}},` +
		`"audio_params":{"format":"opus","sample_rate":16000,"channels":1,"frame_duration":60}}`)
	if err := socket.Write(context.Background(), websocket.MessageText, hello); err != nil {
		t.Fatal(err)
	}
	messageType, payload, err := socket.Read(context.Background())
	if err != nil || messageType != websocket.MessageText {
		t.Fatalf("read server hello: %v %v", messageType, err)
	}
	var response protocol.ServerHello
	if err := json.Unmarshal(payload, &response); err != nil {
		t.Fatal(err)
	}
	if response.Type != "hello" || response.Transport != "websocket" ||
		!response.Features.DeviceAgent.RequestCorrelation || response.SessionID == "" {
		t.Fatalf("invalid server hello: %s", payload)
	}
	return response.SessionID
}

func TestWebSocketEndToEndSTTAgentTTS(t *testing.T) {
	gateway, secret := testGateway(t)
	httpServer := httptest.NewServer(gateway.Handler())
	defer httpServer.Close()
	socket := dialDevice(t, httpServer.URL, secret, "device-1")
	defer socket.CloseNow()
	sessionID := sendHello(t, socket)

	if err := socket.Write(context.Background(), websocket.MessageBinary, []byte{9, 8}); err != nil {
		t.Fatal(err)
	}
	messageType, payload, err := socket.Read(context.Background())
	if err != nil || messageType != websocket.MessageText {
		t.Fatalf("read STT: %v %v", messageType, err)
	}
	var stt map[string]any
	if err := json.Unmarshal(payload, &stt); err != nil || stt["type"] != "stt" ||
		stt["session_id"] != sessionID || stt["text"] != "turn on" {
		t.Fatalf("invalid STT: %s", payload)
	}

	request, _ := json.Marshal(map[string]any{
		"session_id": sessionID, "type": "tts_request",
		"request_id": 42, "text": "Done",
	})
	if err := socket.Write(context.Background(), websocket.MessageText, request); err != nil {
		t.Fatal(err)
	}
	expectedStates := []string{"start", "sentence_start"}
	for _, expected := range expectedStates {
		messageType, payload, err = socket.Read(context.Background())
		if err != nil || messageType != websocket.MessageText {
			t.Fatalf("read %s: %v %v", expected, messageType, err)
		}
		var event protocol.TTSEvent
		if err := json.Unmarshal(payload, &event); err != nil || event.State != expected ||
			event.RequestID != 42 || event.SessionID != sessionID {
			t.Fatalf("invalid %s event: %s", expected, payload)
		}
	}
	for _, expected := range [][]byte{{1, 2}, {3, 4, 5}} {
		messageType, payload, err = socket.Read(context.Background())
		if err != nil || messageType != websocket.MessageBinary || string(payload) != string(expected) {
			t.Fatalf("invalid audio frame: %v %v %v", messageType, payload, err)
		}
	}
	messageType, payload, err = socket.Read(context.Background())
	var stop protocol.TTSEvent
	if err != nil || messageType != websocket.MessageText || json.Unmarshal(payload, &stop) != nil ||
		stop.State != "stop" || stop.RequestID != 42 {
		t.Fatalf("invalid stop event: %v %s %v", messageType, payload, err)
	}
}

func TestSharedCoordinatorBlocksCrossReplicaVoiceAndTokenReplay(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	verifier, err := auth.NewVerifier(secret, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	coordinator := newGatewayTestCoordinator()
	newReplica := func() *Server {
		server, err := New(Config{
			Verifier: verifier, Synthesizer: &fakeSynthesizer{},
			VoiceBackend: fakeVoiceBackend{}, RuntimeCoordinator: coordinator,
			RuntimeLeaseTTL: 15 * time.Second,
			Ownership: gatewayTestOwnership{"*": {
				OwnerID: "user-1", TenantID: "tenant-1",
				BindingID: "MDEyMzQ1Njc4OWFiY2RlZg", BindingRevision: 1,
			}},
			Logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
			MaxConnections: 10,
		})
		if err != nil {
			t.Fatal(err)
		}
		return server
	}
	replicaA := httptest.NewServer(newReplica().Handler())
	defer replicaA.Close()
	replicaB := httptest.NewServer(newReplica().Handler())
	defer replicaB.Close()
	firstToken := signGatewayToken(t, secret, "device-1")
	first := dialDeviceToken(t, replicaA.URL, firstToken, "device-1")
	_ = sendHello(t, first)

	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+signGatewayToken(t, secret, "device-1"))
	headers.Set("Device-Id", "device-1")
	headers.Set("Client-Id", "client-1")
	headers.Set("Protocol-Version", "1")
	blocked, response, dialErr := websocket.Dial(context.Background(),
		"ws"+strings.TrimPrefix(replicaB.URL, "http")+"/v1/device",
		&websocket.DialOptions{HTTPHeader: headers})
	if blocked != nil {
		blocked.CloseNow()
	}
	if dialErr == nil || response == nil || response.StatusCode != http.StatusConflict {
		t.Fatalf("cross-replica voice status=%v err=%v", response, dialErr)
	}
	_ = first.Close(websocket.StatusNormalClosure, "test complete")
	deadline := time.Now().Add(2 * time.Second)
	for coordinator.activeCount() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("shared voice lease was not released")
		}
		time.Sleep(10 * time.Millisecond)
	}

	replayHeaders := headers.Clone()
	replayHeaders.Set("Authorization", "Bearer "+firstToken)
	replayed, replayResponse, replayErr := websocket.Dial(context.Background(),
		"ws"+strings.TrimPrefix(replicaB.URL, "http")+"/v1/device",
		&websocket.DialOptions{HTTPHeader: replayHeaders})
	if replayed != nil {
		replayed.CloseNow()
	}
	if replayErr == nil || replayResponse == nil ||
		replayResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cross-replica replay status=%v err=%v",
			replayResponse, replayErr)
	}
	if coordinator.activeCount() != 0 {
		t.Fatal("replayed token leaked a shared voice lease")
	}
}

func TestSessionIssuanceAuthorizesVoiceAndRejectsReplay(t *testing.T) {
	gateway, tokenSecret, deviceSecret := testSessionGateway(t, false)
	httpServer := httptest.NewServer(gateway.Handler())
	defer httpServer.Close()
	now := time.Now().UTC()
	nonce := []byte("0123456789abcdef")
	request := signedSessionRequest(t, httpServer.URL, now, nonce, deviceSecret)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK ||
		response.Header.Get("Cache-Control") != "no-store" ||
		response.Header.Get("Pragma") != "no-cache" {
		t.Fatalf("session response: status=%d headers=%v",
			response.StatusCode, response.Header)
	}
	var issued sessionResponse
	if err := json.NewDecoder(response.Body).Decode(&issued); err != nil {
		t.Fatal(err)
	}
	if issued.Version != 2 || issued.DeviceID != "device-1" ||
		issued.BindingID != "MDEyMzQ1Njc4OWFiY2RlZg" ||
		issued.BindingRevision != 1 ||
		issued.Voice.URI != "ws://voice.example/v1/device" ||
		issued.Voice.BearerToken == "" || issued.Voice.ExpiresInSeconds != 600 {
		t.Fatalf("unexpected session: %#v", issued)
	}
	verifier, err := auth.NewVerifier(tokenSecret, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := verifier.Verify(issued.Voice.BearerToken)
	if err != nil || claims.DeviceID != "device-1" || claims.TokenID == "" {
		t.Fatalf("issued token: claims=%#v err=%v", claims, err)
	}

	socket := dialDeviceToken(t, httpServer.URL, issued.Voice.BearerToken, "device-1")
	_ = sendHello(t, socket)
	_ = socket.Close(websocket.StatusNormalClosure, "test complete")
	deadline := time.Now().Add(2 * time.Second)
	for !gateway.registry.acquire("device-1") {
		if time.Now().After(deadline) {
			t.Fatal("voice connection did not release device ownership")
		}
		time.Sleep(10 * time.Millisecond)
	}
	gateway.registry.release("device-1")
	replayHeaders := make(http.Header)
	replayHeaders.Set("Authorization", "Bearer "+issued.Voice.BearerToken)
	replayHeaders.Set("Device-Id", "device-1")
	replayHeaders.Set("Client-Id", "client-1")
	replayHeaders.Set("Protocol-Version", "1")
	secondSocket, replayUpgradeResponse, replayUpgradeErr := websocket.Dial(
		context.Background(),
		"ws"+strings.TrimPrefix(httpServer.URL, "http")+"/v1/device",
		&websocket.DialOptions{HTTPHeader: replayHeaders})
	if secondSocket != nil {
		secondSocket.CloseNow()
	}
	if replayUpgradeErr == nil || replayUpgradeResponse == nil ||
		replayUpgradeResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("voice token replay: response=%v err=%v",
			replayUpgradeResponse, replayUpgradeErr)
	}
	_ = replayUpgradeResponse.Body.Close()

	replay := signedSessionRequest(t, httpServer.URL, now, nonce, deviceSecret)
	replayResponse, err := http.DefaultClient.Do(replay)
	if err != nil {
		t.Fatal(err)
	}
	_ = replayResponse.Body.Close()
	if replayResponse.StatusCode != http.StatusConflict {
		t.Fatalf("replay status: %d", replayResponse.StatusCode)
	}

	rateLimited := signedSessionRequest(t, httpServer.URL, time.Now().UTC(),
		[]byte("abcdef0123456789"), deviceSecret)
	rateResponse, err := http.DefaultClient.Do(rateLimited)
	if err != nil {
		t.Fatal(err)
	}
	_ = rateResponse.Body.Close()
	if rateResponse.StatusCode != http.StatusTooManyRequests ||
		rateResponse.Header.Get("Retry-After") == "" {
		t.Fatalf("rate response: status=%d headers=%v",
			rateResponse.StatusCode, rateResponse.Header)
	}

	metricsResponse, err := http.Get(httpServer.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	metricsBody, err := io.ReadAll(metricsResponse.Body)
	_ = metricsResponse.Body.Close()
	if err != nil || !strings.Contains(string(metricsBody),
		"xiaozhi_gateway_session_issued_total 1") ||
		!strings.Contains(string(metricsBody), "xiaozhi_gateway_session_replays_total 1") ||
		!strings.Contains(string(metricsBody), "xiaozhi_gateway_session_rate_limited_total 1") ||
		!strings.Contains(string(metricsBody), "xiaozhi_gateway_voice_token_replays_total 1") {
		t.Fatalf("metrics: %s err=%v", metricsBody, err)
	}
}

func TestSessionIssuanceRejectsDisabledDevice(t *testing.T) {
	gateway, tokenSecret, deviceSecret := testSessionGateway(t, true)
	httpServer := httptest.NewServer(gateway.Handler())
	defer httpServer.Close()
	response, err := http.DefaultClient.Do(signedSessionRequest(t, httpServer.URL,
		time.Now().UTC(), []byte("0123456789abcdef"), deviceSecret))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("disabled device status: %d", response.StatusCode)
	}
	voiceRequest, err := http.NewRequest(http.MethodGet,
		httpServer.URL+"/v1/device", nil)
	if err != nil {
		t.Fatal(err)
	}
	voiceRequest.Header.Set("Authorization", "Bearer "+
		signGatewayToken(t, tokenSecret, "device-1"))
	voiceRequest.Header.Set("Device-Id", "device-1")
	voiceRequest.Header.Set("Client-Id", "client-1")
	voiceRequest.Header.Set("Protocol-Version", "1")
	voiceResponse, err := http.DefaultClient.Do(voiceRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = voiceResponse.Body.Close()
	if voiceResponse.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked voice token status: %d", voiceResponse.StatusCode)
	}
}

func TestSessionIssuanceRequiresCompleteValidConfiguration(t *testing.T) {
	gateway, _ := testGateway(t)
	request := httptest.NewRequest(http.MethodPost, "/v1/session", nil)
	response := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled session route status: %d", response.Code)
	}

	configured, _, _ := testSessionGateway(t, false)
	configured.config.SessionProof = nil
	if _, err := New(configured.config); err == nil {
		t.Fatal("expected partial session configuration rejection")
	}
	configured, _, _ = testSessionGateway(t, false)
	configured.config.PublicDeviceWSS = "https://voice.example/v1/device"
	if _, err := New(configured.config); err == nil {
		t.Fatal("expected invalid public WebSocket URL rejection")
	}
}

func TestRejectsInvalidAuthenticationBeforeUpgrade(t *testing.T) {
	gateway, _ := testGateway(t)
	httpServer := httptest.NewServer(gateway.Handler())
	defer httpServer.Close()
	request, _ := http.NewRequest(http.MethodGet, httpServer.URL+"/v1/device", nil)
	request.Header.Set("Authorization", "Bearer invalid")
	request.Header.Set("Device-Id", "device-1")
	request.Header.Set("Client-Id", "client-1")
	request.Header.Set("Protocol-Version", "1")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("got status %d", response.StatusCode)
	}
}

func TestBargeInDropsOldAudioAndAllowsNextRequest(t *testing.T) {
	synthesizer := &bargeInSynthesizer{postCancel: make(chan error, 1)}
	gateway, secret := testGatewayWithSynth(t, synthesizer)
	httpServer := httptest.NewServer(gateway.Handler())
	defer httpServer.Close()
	socket := dialDevice(t, httpServer.URL, secret, "device-barge")
	defer socket.CloseNow()
	sessionID := sendHello(t, socket)

	sendRequest := func(requestID int, messageType string, fields map[string]any) {
		message := map[string]any{
			"session_id": sessionID, "type": messageType, "request_id": requestID,
		}
		for key, value := range fields {
			message[key] = value
		}
		payload, _ := json.Marshal(message)
		if err := socket.Write(context.Background(), websocket.MessageText, payload); err != nil {
			t.Fatal(err)
		}
	}

	sendRequest(1, "tts_request", map[string]any{"text": "first"})
	for range 2 {
		messageType, _, err := socket.Read(context.Background())
		if err != nil || messageType != websocket.MessageText {
			t.Fatalf("read first lifecycle: %v %v", messageType, err)
		}
	}
	messageType, payload, err := socket.Read(context.Background())
	if err != nil || messageType != websocket.MessageBinary || string(payload) != string([]byte{1}) {
		t.Fatalf("read first audio: %v %v %v", messageType, payload, err)
	}

	sendRequest(1, "tts_abort", map[string]any{"reason": "barge_in"})
	select {
	case staleErr := <-synthesizer.postCancel:
		if !errors.Is(staleErr, protocol.ErrStale) {
			t.Fatalf("post-cancel write returned %v", staleErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("synthesizer did not observe cancellation")
	}

	sendRequest(2, "tts_request", map[string]any{"text": "second"})
	for index := 0; index < 4; index++ {
		messageType, payload, err = socket.Read(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if messageType == websocket.MessageBinary {
			if string(payload) != string([]byte{2}) {
				t.Fatalf("stale audio escaped after abort: %v", payload)
			}
			continue
		}
		var event protocol.TTSEvent
		if err := json.Unmarshal(payload, &event); err != nil || event.RequestID != 2 {
			t.Fatalf("stale lifecycle escaped after abort: %s", payload)
		}
	}
}

func TestHealthReadinessAndMetrics(t *testing.T) {
	gateway, _ := testGateway(t)
	server := httptest.NewServer(gateway.Handler())
	defer server.Close()
	for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
		response, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("%s returned %d", path, response.StatusCode)
		}
	}
}

func TestSpeechBudgetErrorsAreContentFreeAndDoNotCountAsProtocolViolations(t *testing.T) {
	gateway, secret := testGateway(t)
	pricing := speechbudget.Pricing{
		ProfileID:                       "speech-contract-test",
		STTMicrousdPerMillionAudioMS:    1_000_000,
		TTSMicrousdPerMillionCharacters: 1_000_000,
		DailyBudgetMicrousd:             1,
		STTReservationChunkAudioMS:      1_000,
		TTSMaxOutputAudioMS:             1_000,
		ReservationTTL:                  time.Minute,
	}
	ledger, err := speechbudget.NewMemoryLedger(pricing,
		[]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	gateway.config.SpeechPricing = pricing
	gateway.config.SpeechUsageLedger = ledger
	httpServer := httptest.NewServer(gateway.Handler())
	defer httpServer.Close()
	socket := dialDevice(t, httpServer.URL, secret, "device-budget")
	defer socket.CloseNow()
	sessionID := sendHello(t, socket)

	payload, _ := json.Marshal(map[string]any{
		"session_id": sessionID, "type": "tts_request",
		"request_id": 1, "text": "hello",
	})
	if err := socket.Write(context.Background(), websocket.MessageText, payload); err != nil {
		t.Fatal(err)
	}
	messageType, response, err := socket.Read(context.Background())
	if err != nil || messageType != websocket.MessageText {
		t.Fatalf("TTS budget response type=%v err=%v", messageType, err)
	}
	var event protocol.ErrorEvent
	if err := json.Unmarshal(response, &event); err != nil ||
		event.Type != "error" || event.Code != "speech_budget_exceeded" {
		t.Fatalf("TTS budget response=%s err=%v", response, err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(response, &fields); err != nil || len(fields) != 2 {
		t.Fatalf("TTS budget response is not content-free: %s err=%v", response, err)
	}
	if err := socket.Write(context.Background(), websocket.MessageBinary,
		[]byte{0x18, 0x00}); err != nil {
		t.Fatal(err)
	}
	messageType, response, err = socket.Read(context.Background())
	if err != nil || messageType != websocket.MessageText {
		t.Fatalf("STT budget response type=%v err=%v", messageType, err)
	}
	if err := json.Unmarshal(response, &event); err != nil ||
		event.Code != "speech_budget_exceeded" {
		t.Fatalf("STT budget response=%s err=%v", response, err)
	}
	if err := json.Unmarshal(response, &fields); err != nil || len(fields) != 2 {
		t.Fatalf("STT budget response is not content-free: %s err=%v", response, err)
	}
	payload, _ = json.Marshal(map[string]any{
		"session_id": sessionID, "type": "tts_request",
		"request_id": 2, "text": "still open",
	})
	if err := socket.Write(context.Background(), websocket.MessageText, payload); err != nil {
		t.Fatalf("write after STT budget rejection: %v", err)
	}
	messageType, response, err = socket.Read(context.Background())
	if err != nil || messageType != websocket.MessageText ||
		json.Unmarshal(response, &event) != nil ||
		event.Code != "speech_budget_exceeded" {
		t.Fatalf("connection after STT budget rejection type=%v response=%s err=%v",
			messageType, response, err)
	}
	if gateway.metrics.speechBudgetRejected.Load() != 3 ||
		gateway.metrics.protocolViolations.Load() != 0 {
		t.Fatalf("rejected=%d violations=%d",
			gateway.metrics.speechBudgetRejected.Load(),
			gateway.metrics.protocolViolations.Load())
	}
}

func TestAudioPacketsDoNotConsumeControlMessageLimit(t *testing.T) {
	gateway, secret := testGateway(t)
	gateway.config.MaxMessagesMinute = 1
	gateway.config.MaxAudioMinute = 10
	server := httptest.NewServer(gateway.Handler())
	defer server.Close()
	socket := dialDevice(t, server.URL, secret, "device-rate")
	defer socket.CloseNow()
	_ = sendHello(t, socket)

	for range 2 {
		if err := socket.Write(context.Background(), websocket.MessageBinary, []byte{1}); err != nil {
			t.Fatal(err)
		}
		messageType, payload, err := socket.Read(context.Background())
		if err != nil || messageType != websocket.MessageText ||
			!strings.Contains(string(payload), `"type":"stt"`) {
			t.Fatalf("audio was incorrectly rate-limited: %v %s %v", messageType, payload, err)
		}
	}
}

func TestShutdownClosesActiveWebSockets(t *testing.T) {
	gateway, secret := testGateway(t)
	server := httptest.NewServer(gateway.Handler())
	defer server.Close()
	socket := dialDevice(t, server.URL, secret, "device-shutdown")
	defer socket.CloseNow()
	_ = sendHello(t, socket)
	closeResult := make(chan error, 1)
	go func() {
		_, _, err := socket.Read(context.Background())
		closeResult <- err
	}()

	shutdownContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := gateway.Shutdown(shutdownContext); err != nil {
		t.Fatal(err)
	}
	err := <-closeResult
	if websocket.CloseStatus(err) != websocket.StatusGoingAway {
		t.Fatalf("unexpected close error: %v", err)
	}
}

func TestOwnershipChangeClosesActiveWebSocketAndRejectsOldToken(t *testing.T) {
	gateway, tokenSecret := testGateway(t)
	ownership := &mutableGatewayOwnership{}
	ownership.set(deviceclaim.Ownership{
		OwnerID: "user-1", TenantID: "tenant-1",
		BindingID: "MDEyMzQ1Njc4OWFiY2RlZg", BindingRevision: 1,
	}, true, nil)
	gateway.config.Ownership = ownership
	server := httptest.NewServer(gateway.Handler())
	defer server.Close()
	socket := dialDevice(t, server.URL, tokenSecret, "device-transfer")
	defer socket.CloseNow()
	_ = sendHello(t, socket)

	ownership.set(deviceclaim.Ownership{}, false, deviceclaim.ErrUnavailable)
	if count := gateway.ReconcileOwnership(); count != 0 {
		t.Fatalf("database outage revoked %d connections", count)
	}
	ownership.set(deviceclaim.Ownership{
		OwnerID: "user-2", TenantID: "tenant-2",
		BindingID: "ZmVkY2JhOTg3NjU0MzIxMA", BindingRevision: 3,
	}, true, nil)
	if count := gateway.ReconcileOwnership(); count != 1 {
		t.Fatalf("ownership change revoked %d connections, want 1", count)
	}
	if ownership.batches() != 2 {
		t.Fatalf("ownership batch calls=%d, want 2", ownership.batches())
	}
	readContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _, readErr := socket.Read(readContext)
	if websocket.CloseStatus(readErr) != websocket.StatusPolicyViolation {
		t.Fatalf("unexpected ownership close: %v", readErr)
	}
	if count := gateway.ReconcileOwnership(); count != 0 {
		t.Fatalf("duplicate ownership reconciliation counted %d", count)
	}
	metrics := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(metrics,
		httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metrics.Body.String(),
		"xiaozhi_gateway_ownership_revocations_total 1") {
		t.Fatalf("ownership metrics: %s", metrics.Body.String())
	}

	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+signGatewayToken(
		t, tokenSecret, "device-transfer"))
	headers.Set("Device-Id", "device-transfer")
	headers.Set("Client-Id", "client-1")
	headers.Set("Protocol-Version", "1")
	denied, response, dialErr := websocket.Dial(context.Background(),
		"ws"+strings.TrimPrefix(server.URL, "http")+"/v1/device",
		&websocket.DialOptions{HTTPHeader: headers})
	if denied != nil {
		denied.CloseNow()
	}
	if dialErr == nil || response == nil ||
		response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("stale ownership admission: response=%v err=%v",
			response, dialErr)
	}
}

func gatewayIdentitySnapshot(t *testing.T, revision uint64, disabled bool,
	now time.Time) *provisioning.Snapshot {
	t.Helper()
	seed := sha256.Sum256([]byte("gateway-identity-revocation-test-key"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	disabledText := map[bool]string{true: "true", false: "false"}[disabled]
	unsigned := `{"version":2,"revision":` + strconv.FormatUint(revision, 10) +
		`,"purpose":"access"` +
		`,"issued_at":"` + now.Add(-time.Minute).UTC().Format(time.RFC3339) +
		`","valid_until":"` + now.Add(10*time.Minute).UTC().Format(time.RFC3339) +
		`","devices":[{"device_id":"device-revoke","disabled":` +
		disabledText + `}]}`
	signed, err := provisioning.SignRegistrySnapshot(strings.NewReader(unsigned),
		"gateway-identity-test", privateKey, now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := provisioning.ParseSignedRegistrySnapshot(
		strings.NewReader(string(signed)), publicKey, "gateway-identity-test", now)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestIdentityUpdateClosesActiveWebSocketAndSealsAdmissionRace(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	initial := gatewayIdentitySnapshot(t, 10, false, now)
	identity, err := provisioning.NewRegistryFromSnapshot(initial,
		func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	gateway, tokenSecret := testGateway(t)
	gateway.config.IdentityRegistry = identity
	server := httptest.NewServer(gateway.Handler())
	defer server.Close()
	socket := dialDevice(t, server.URL, tokenSecret, "device-revoke")
	defer socket.CloseNow()
	_ = sendHello(t, socket)

	revoked := gatewayIdentitySnapshot(t, 11, true, now)
	if changed, err := identity.ApplySnapshot(revoked); err != nil || !changed {
		t.Fatalf("apply revoke: changed=%v err=%v", changed, err)
	}
	if gateway.addConnection("device-revoke", &connection{}) {
		t.Fatal("final admission gate accepted a revoked device")
	}
	started := time.Now()
	if count := gateway.ReconcileIdentity(); count != 1 {
		t.Fatalf("revoked connections=%d, want 1", count)
	}
	readContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _, readErr := socket.Read(readContext)
	if websocket.CloseStatus(readErr) != websocket.StatusPolicyViolation {
		t.Fatalf("unexpected revoke close: %v", readErr)
	}
	if time.Since(started) > time.Second {
		t.Fatal("local identity reconciliation exceeded one second")
	}
	if count := gateway.ReconcileIdentity(); count != 0 {
		t.Fatalf("duplicate reconciliation counted %d revocations", count)
	}

	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+signGatewayToken(
		t, tokenSecret, "device-revoke"))
	headers.Set("Device-Id", "device-revoke")
	headers.Set("Client-Id", "client-1")
	headers.Set("Protocol-Version", "1")
	denied, response, dialErr := websocket.Dial(context.Background(),
		"ws"+strings.TrimPrefix(server.URL, "http")+"/v1/device",
		&websocket.DialOptions{HTTPHeader: headers})
	if denied != nil {
		denied.CloseNow()
	}
	if dialErr == nil || response == nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked admission: response=%v err=%v", response, dialErr)
	}
	metrics := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(metrics,
		httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metrics.Body.String(),
		"xiaozhi_gateway_identity_revocations_total 1") {
		t.Fatalf("identity metrics: %s", metrics.Body.String())
	}
}

func TestExpiredIdentitySnapshotFailsReadinessAndClosesConnection(t *testing.T) {
	clock := time.Now().UTC().Truncate(time.Second)
	initial := gatewayIdentitySnapshot(t, 20, false, clock)
	identity, err := provisioning.NewRegistryFromSnapshot(initial,
		func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	gateway, tokenSecret := testGateway(t)
	gateway.config.IdentityRegistry = identity
	server := httptest.NewServer(gateway.Handler())
	defer server.Close()
	socket := dialDevice(t, server.URL, tokenSecret, "device-revoke")
	defer socket.CloseNow()
	_ = sendHello(t, socket)

	clock = clock.Add(11 * time.Minute)
	ready := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(ready,
		httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("expired identity readiness=%d", ready.Code)
	}
	if count := gateway.ReconcileIdentity(); count != 1 {
		t.Fatalf("expired identity revoked %d connections", count)
	}
	readContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, _, readErr := socket.Read(readContext)
	if websocket.CloseStatus(readErr) != websocket.StatusPolicyViolation {
		t.Fatalf("expired identity close: %v", readErr)
	}
}
