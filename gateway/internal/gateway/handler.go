package gateway

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"

	"xiaozhi-agent-platform/gateway/internal/auth"
	"xiaozhi-agent-platform/gateway/internal/deviceclaim"
	"xiaozhi-agent-platform/gateway/internal/protocol"
	"xiaozhi-agent-platform/gateway/internal/provisioning"
	"xiaozhi-agent-platform/gateway/internal/runtimecoordination"
	"xiaozhi-agent-platform/gateway/internal/speechbudget"
	"xiaozhi-agent-platform/gateway/internal/tts"
)

type Config struct {
	Verifier           *auth.Verifier
	Synthesizer        tts.Synthesizer
	VoiceBackend       VoiceBackend
	Logger             *slog.Logger
	MaxConnections     int
	HelloTimeout       time.Duration
	WriteTimeout       time.Duration
	SynthesisTimeout   time.Duration
	OutputSampleRate   int
	OutputFrameMillis  int
	MaxMessagesMinute  int
	MaxAudioMinute     int
	IdentityRegistry   *provisioning.Registry
	SessionProof       *provisioning.ProofVerifier
	SessionIssuer      *auth.Issuer
	Ownership          deviceclaim.OwnershipResolver
	PublicDeviceWSS    string
	RuntimeCoordinator runtimecoordination.Coordinator
	RuntimeLeaseTTL    time.Duration
	SpeechUsageLedger  speechbudget.Ledger
	SpeechPricing      speechbudget.Pricing
}

type Server struct {
	config        Config
	registry      *registry
	metrics       Metrics
	mux           *http.ServeMux
	connectionsMu sync.Mutex
	connections   map[string]*connection
	tokenReplay   *tokenReplayGuard
	stopping      bool
}

type activeTTS struct {
	requestID uint32
	cancel    context.CancelFunc
}

type connection struct {
	server             *Server
	websocket          *websocket.Conn
	context            context.Context
	deviceID           string
	ownedScope         string
	ownerID            string
	tenantID           string
	bindingID          string
	bindingRevision    uint64
	clientID           string
	sessionID          string
	protocolVersion    int
	voice              VoiceSession
	sttMeter           *sttUsageMeter
	inputFrameMillis   int
	writeMu            sync.Mutex
	stateMu            sync.Mutex
	active             *activeTTS
	controlWindowStart time.Time
	controlMessages    int
	audioWindowStart   time.Time
	audioPackets       int
	violations         int
	headerVersion      int
	identityRevoked    bool
	ownershipRevoked   bool
}

func New(config Config) (*Server, error) {
	if config.Verifier == nil || config.Synthesizer == nil ||
		config.VoiceBackend == nil || config.Ownership == nil {
		return nil, fmt.Errorf("verifier, synthesizer, voice backend, and ownership resolver are required")
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.MaxConnections <= 0 {
		config.MaxConnections = 1000
	}
	if config.HelloTimeout <= 0 {
		config.HelloTimeout = 5 * time.Second
	}
	if config.WriteTimeout <= 0 {
		config.WriteTimeout = 5 * time.Second
	}
	if config.SynthesisTimeout <= 0 {
		config.SynthesisTimeout = 35 * time.Second
	}
	if config.OutputSampleRate <= 0 {
		config.OutputSampleRate = 24000
	}
	if config.OutputFrameMillis <= 0 {
		config.OutputFrameMillis = 60
	}
	if config.MaxMessagesMinute <= 0 {
		config.MaxMessagesMinute = 120
	}
	if config.MaxAudioMinute <= 0 {
		config.MaxAudioMinute = 4000
	}
	if config.RuntimeLeaseTTL <= 0 {
		config.RuntimeLeaseTTL = 30 * time.Second
	}
	if config.RuntimeLeaseTTL < 15*time.Second ||
		config.RuntimeLeaseTTL > 5*time.Minute {
		return nil, fmt.Errorf("runtime voice lease TTL is invalid")
	}
	if config.SpeechUsageLedger != nil && config.SpeechPricing.Validate() != nil {
		return nil, fmt.Errorf("speech usage pricing is invalid")
	}
	if config.SpeechUsageLedger != nil &&
		config.SpeechPricing.ReservationTTL < config.SynthesisTimeout+15*time.Second {
		return nil, fmt.Errorf("speech usage reservation TTL is shorter than provider ambiguity window")
	}
	sessionParts := 0
	if config.SessionProof != nil {
		sessionParts++
	}
	if config.SessionIssuer != nil {
		sessionParts++
	}
	if config.PublicDeviceWSS != "" {
		sessionParts++
	}
	if sessionParts != 0 && sessionParts != 3 {
		return nil, fmt.Errorf("session proof, issuer, and public device WSS URL must be configured together")
	}
	if sessionParts == 3 {
		endpoint, err := url.Parse(config.PublicDeviceWSS)
		if err != nil || (endpoint.Scheme != "wss" && endpoint.Scheme != "ws") ||
			endpoint.Host == "" || endpoint.Path != "/v1/device" ||
			endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
			return nil, fmt.Errorf("public device WSS URL is invalid")
		}
	}
	if config.IdentityRegistry == nil && config.SessionProof != nil {
		config.IdentityRegistry = config.SessionProof.Registry()
	}

	server := &Server{
		config: config, registry: newRegistry(config.MaxConnections),
		connections: make(map[string]*connection),
		tokenReplay: newTokenReplayGuard(config.MaxConnections * 8),
	}
	server.mux = http.NewServeMux()
	server.mux.HandleFunc("GET /healthz", server.health)
	server.mux.HandleFunc("GET /readyz", server.ready)
	server.mux.Handle("GET /metrics", &server.metrics)
	server.mux.HandleFunc("GET /v1/device", server.device)
	if sessionParts == 3 {
		server.mux.HandleFunc("POST /v1/session", server.session)
	}
	return server, nil
}

func (server *Server) Handler() http.Handler { return server.mux }

func (server *Server) Shutdown(ctx context.Context) error {
	server.connectionsMu.Lock()
	server.stopping = true
	connections := make([]*connection, 0, len(server.connections))
	for _, connection := range server.connections {
		connections = append(connections, connection)
	}
	server.connectionsMu.Unlock()
	for _, activeConnection := range connections {
		activeConnection.cancelActive()
		go func(current *connection) {
			_ = current.closeWith(websocket.StatusGoingAway, "gateway shutting down")
		}(activeConnection)
	}

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		server.connectionsMu.Lock()
		remaining := len(server.connections)
		server.connectionsMu.Unlock()
		if remaining == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			for _, connection := range connections {
				_ = connection.websocket.CloseNow()
			}
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (server *Server) health(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "application/json")
	_, _ = writer.Write([]byte(`{"status":"ok"}`))
}

func (server *Server) ready(writer http.ResponseWriter, request *http.Request) {
	if server.config.IdentityRegistry != nil &&
		!server.config.IdentityRegistry.Ready() {
		http.Error(writer, "identity snapshot unavailable", http.StatusServiceUnavailable)
		return
	}
	if ownership, ok := server.config.Ownership.(deviceclaim.ReadyOwnershipResolver); ok &&
		ownership.VerifySchema() != nil {
		http.Error(writer, "ownership unavailable", http.StatusServiceUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
	defer cancel()
	if server.config.RuntimeCoordinator != nil {
		if err := server.config.RuntimeCoordinator.VerifySchema(ctx); err != nil {
			http.Error(writer, "runtime coordination unavailable",
				http.StatusServiceUnavailable)
			return
		}
	}
	if server.config.SpeechUsageLedger != nil {
		if err := server.config.SpeechUsageLedger.VerifySchema(ctx); err != nil {
			http.Error(writer, "speech usage budget unavailable",
				http.StatusServiceUnavailable)
			return
		}
	}
	if err := server.config.Synthesizer.Ready(ctx); err != nil {
		http.Error(writer, "not ready", http.StatusServiceUnavailable)
		return
	}
	if err := server.config.VoiceBackend.Ready(ctx); err != nil {
		http.Error(writer, "not ready", http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	_, _ = writer.Write([]byte(`{"status":"ready"}`))
}

func (server *Server) device(writer http.ResponseWriter, request *http.Request) {
	claims, err := server.config.Verifier.VerifyAuthorization(request.Header.Get("Authorization"))
	if err != nil {
		server.metrics.authFailures.Add(1)
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	ownedScope, ok := auth.OwnedDeviceScope(claims)
	if !ok {
		server.metrics.authFailures.Add(1)
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	ownership, owned, ownershipErr := server.config.Ownership.Owner(claims.DeviceID)
	if ownershipErr != nil {
		http.Error(writer, "ownership unavailable", http.StatusServiceUnavailable)
		return
	}
	if !owned || !ownership.Matches(claims.OwnerID, claims.TenantID,
		claims.BindingID, claims.BindingRevision) {
		server.metrics.authFailures.Add(1)
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	deviceID := request.Header.Get("Device-Id")
	clientID := request.Header.Get("Client-Id")
	sessionExpiresAt := time.Unix(claims.Expires, 0).UTC()
	headerVersion, versionErr := strconv.Atoi(request.Header.Get("Protocol-Version"))
	if deviceID != claims.DeviceID || !safeIdentifier(clientID, 64) ||
		versionErr != nil || headerVersion < 1 || headerVersion > 3 ||
		!sessionExpiresAt.After(time.Now().UTC()) {
		server.metrics.authFailures.Add(1)
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	if server.config.IdentityRegistry != nil &&
		!server.config.IdentityRegistry.DeviceAllowed(deviceID) {
		server.metrics.authFailures.Add(1)
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !server.registry.acquire(deviceID) {
		http.Error(writer, "device connection already active", http.StatusConflict)
		return
	}
	defer server.registry.release(deviceID)
	var runtimeLease runtimecoordination.Lease
	if server.config.RuntimeCoordinator != nil {
		runtimeLease, err = server.config.RuntimeCoordinator.AcquireVoice(
			request.Context(), deviceID, server.config.MaxConnections,
			server.config.RuntimeLeaseTTL)
		if err != nil {
			if errors.Is(err, runtimecoordination.ErrConflict) {
				http.Error(writer, "device connection already active",
					http.StatusConflict)
				return
			}
			if !errors.Is(err, runtimecoordination.ErrRateLimited) {
				server.metrics.runtimeCoordinationFailures.Add(1)
			}
			http.Error(writer, "voice coordination unavailable",
				http.StatusServiceUnavailable)
			return
		}
		defer server.releaseRuntimeLease(runtimeLease)
		err = server.config.RuntimeCoordinator.ConsumeVoiceToken(
			request.Context(), ownedScope, claims.TokenID,
			time.Unix(claims.Expires+tokenReplayRetentionSeconds, 0).UTC())
		if err != nil {
			if errors.Is(err, runtimecoordination.ErrReplay) {
				server.metrics.voiceTokenReplays.Add(1)
				server.metrics.authFailures.Add(1)
				http.Error(writer, "unauthorized", http.StatusUnauthorized)
				return
			}
			server.metrics.runtimeCoordinationFailures.Add(1)
			http.Error(writer, "voice coordination unavailable",
				http.StatusServiceUnavailable)
			return
		}
	} else if !server.tokenReplay.consume(claims) {
		server.metrics.authFailures.Add(1)
		server.metrics.voiceTokenReplays.Add(1)
		http.Error(writer, "unauthorized", http.StatusUnauthorized)
		return
	}

	socket, err := websocket.Accept(writer, request, nil)
	if err != nil {
		return
	}
	socket.SetReadLimit(protocol.MaxControlBytes + 32)
	defer socket.CloseNow()
	server.metrics.connections.Add(1)
	defer server.metrics.connections.Add(-1)
	leaseContext, stopLease := context.WithCancel(request.Context())
	leaseDone := make(chan struct{})
	if server.config.RuntimeCoordinator != nil {
		go server.renewRuntimeLease(leaseContext, socket, runtimeLease, leaseDone)
	} else {
		close(leaseDone)
	}
	defer func() {
		stopLease()
		<-leaseDone
	}()

	connection := &connection{
		server: server, websocket: socket, context: request.Context(),
		deviceID: deviceID, ownedScope: ownedScope,
		ownerID: claims.OwnerID, tenantID: claims.TenantID,
		bindingID: claims.BindingID, bindingRevision: claims.BindingRevision,
		clientID:           clientID,
		controlWindowStart: time.Now(), audioWindowStart: time.Now(),
		headerVersion: headerVersion,
	}
	if !server.addConnection(deviceID, connection) {
		_ = socket.Close(websocket.StatusGoingAway, "gateway shutting down")
		return
	}
	defer server.removeConnection(deviceID, connection)
	expiryCanceled := make(chan struct{})
	expiryDone := make(chan struct{})
	go connection.enforceTokenExpiry(
		sessionExpiresAt, expiryCanceled, expiryDone)
	defer func() {
		close(expiryCanceled)
		<-expiryDone
	}()
	if err := connection.run(); err != nil &&
		!errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		server.config.Logger.Info("device session ended",
			"device_id", deviceID, "session_id", connection.sessionID,
			"error_class", classifyError(err))
	}
}

func (connection *connection) enforceTokenExpiry(expiresAt time.Time,
	canceled <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	delay := time.Until(expiresAt)
	if delay < 0 {
		delay = 0
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-canceled:
		return
	case <-timer.C:
		connection.server.metrics.voiceTokenExpirations.Add(1)
		connection.cancelActive()
		_ = connection.closeWith(websocket.StatusPolicyViolation,
			"voice token expired")
	}
}

func (server *Server) renewRuntimeLease(ctx context.Context,
	socket *websocket.Conn, lease runtimecoordination.Lease, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(server.config.RuntimeLeaseTTL / 3)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			renewed, err := server.config.RuntimeCoordinator.Renew(ctx, lease,
				server.config.RuntimeLeaseTTL)
			if err != nil {
				server.metrics.runtimeCoordinationFailures.Add(1)
				_ = socket.Close(websocket.StatusTryAgainLater,
					"voice coordination lost")
				return
			}
			lease = renewed
		}
	}
}

func (server *Server) releaseRuntimeLease(lease runtimecoordination.Lease) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := server.config.RuntimeCoordinator.Release(ctx, lease); err != nil &&
		!errors.Is(err, runtimecoordination.ErrLeaseLost) {
		server.metrics.runtimeCoordinationFailures.Add(1)
	}
}

func (server *Server) addConnection(deviceID string, connection *connection) bool {
	server.connectionsMu.Lock()
	defer server.connectionsMu.Unlock()
	if server.stopping || (server.config.IdentityRegistry != nil &&
		!server.config.IdentityRegistry.DeviceAllowed(deviceID)) {
		return false
	}
	server.connections[deviceID] = connection
	return true
}

func (server *Server) ReconcileIdentity() int {
	if server == nil || server.config.IdentityRegistry == nil {
		return 0
	}
	server.connectionsMu.Lock()
	revoked := make([]*connection, 0)
	for deviceID, activeConnection := range server.connections {
		if !activeConnection.identityRevoked &&
			!server.config.IdentityRegistry.DeviceAllowed(deviceID) {
			activeConnection.identityRevoked = true
			revoked = append(revoked, activeConnection)
		}
	}
	server.connectionsMu.Unlock()
	for _, activeConnection := range revoked {
		activeConnection.cancelActive()
		go func(current *connection) {
			_ = current.closeWith(websocket.StatusPolicyViolation,
				"device access revoked")
		}(activeConnection)
	}
	server.metrics.identityRevocations.Add(int64(len(revoked)))
	return len(revoked)
}

// ReconcileOwnership closes active voice sessions after a release or
// re-binding. Lookup failures leave sessions untouched and are surfaced by
// readiness; a transient database outage must not masquerade as a revocation.
func (server *Server) ReconcileOwnership() int {
	if server == nil || server.config.Ownership == nil {
		return 0
	}
	server.connectionsMu.Lock()
	active := make([]*connection, 0, len(server.connections))
	for _, current := range server.connections {
		active = append(active, current)
	}
	server.connectionsMu.Unlock()
	resolved := make(map[string]deviceclaim.Ownership, len(active))
	if batch, ok := server.config.Ownership.(deviceclaim.BatchOwnershipResolver); ok {
		deviceIDs := make([]string, 0, len(active))
		for _, current := range active {
			deviceIDs = append(deviceIDs, current.deviceID)
		}
		var err error
		resolved, err = batch.Owners(deviceIDs)
		if err != nil {
			return 0
		}
	}
	revoked := make([]*connection, 0)
	for _, current := range active {
		ownership, owned := resolved[current.deviceID]
		if _, batch := server.config.Ownership.(deviceclaim.BatchOwnershipResolver); !batch {
			var err error
			ownership, owned, err = server.config.Ownership.Owner(current.deviceID)
			if err != nil {
				continue
			}
		}
		if owned && ownership.Matches(current.ownerID, current.tenantID,
			current.bindingID, current.bindingRevision) {
			continue
		}
		server.connectionsMu.Lock()
		if server.connections[current.deviceID] == current &&
			!current.ownershipRevoked {
			current.ownershipRevoked = true
			revoked = append(revoked, current)
		}
		server.connectionsMu.Unlock()
	}
	for _, current := range revoked {
		current.cancelActive()
		go func(connection *connection) {
			_ = connection.closeWith(websocket.StatusPolicyViolation,
				"device ownership changed")
		}(current)
	}
	server.metrics.ownershipRevocations.Add(int64(len(revoked)))
	return len(revoked)
}

func (server *Server) removeConnection(deviceID string, connection *connection) {
	server.connectionsMu.Lock()
	if server.connections[deviceID] == connection {
		delete(server.connections, deviceID)
	}
	server.connectionsMu.Unlock()
}

func (connection *connection) run() error {
	helloContext, cancel := context.WithTimeout(connection.context, connection.server.config.HelloTimeout)
	defer cancel()
	messageType, payload, err := connection.websocket.Read(helloContext)
	if err != nil {
		return err
	}
	if messageType != websocket.MessageText {
		return connection.closeViolation("invalid_hello")
	}
	hello, protocolVersion, err := protocol.DecodeClientHello(payload)
	if err != nil {
		return connection.closeViolation(classifyError(err))
	}
	if connection.headerVersion != protocolVersion {
		return connection.closeViolation("protocol_version_mismatch")
	}
	connection.protocolVersion = protocolVersion
	connection.inputFrameMillis = hello.AudioParams.FrameDuration
	connection.sessionID, err = newSessionID()
	if err != nil {
		return err
	}
	connection.sttMeter = newSTTUsageMeter(connection.server.config.SpeechUsageLedger,
		connection.server.config.SpeechPricing, connection.ownedScope,
		&connection.server.metrics)
	defer connection.sttMeter.Close()
	connection.voice, err = connection.server.config.VoiceBackend.Open(
		connection.context,
		VoiceSessionConfig{
			DeviceID: connection.deviceID, OwnerID: connection.ownerID,
			TenantID: connection.tenantID, ClientID: connection.clientID,
			SessionID: connection.sessionID, SampleRate: hello.AudioParams.SampleRate,
			FrameDuration:   hello.AudioParams.FrameDuration,
			ProtocolVersion: protocolVersion,
		}, connection,
	)
	if err != nil {
		return connection.closeWith(websocket.StatusTryAgainLater, "voice backend unavailable")
	}
	defer connection.voice.Close()

	serverHello, err := protocol.NewServerHello(
		connection.sessionID, connection.server.config.OutputSampleRate,
		connection.server.config.OutputFrameMillis)
	if err != nil {
		return err
	}
	if err := connection.writeJSON(connection.context, serverHello); err != nil {
		return err
	}

	for {
		messageType, payload, err = connection.websocket.Read(connection.context)
		if err != nil {
			connection.cancelActive()
			return err
		}
		if messageType == websocket.MessageBinary {
			if !connection.allowAudioPacket() {
				return connection.closeViolation("audio_rate_limit")
			}
			opus, decodeErr := protocol.DecodeAudioPacket(connection.protocolVersion, payload)
			if decodeErr != nil {
				if err := connection.reportViolation(decodeErr); err != nil {
					return err
				}
				continue
			}
			if err := connection.sttMeter.HandleAudio(connection.context,
				connection.inputFrameMillis, func() error {
					return connection.voice.HandleAudio(connection.context, opus)
				}); err != nil {
				if errors.Is(err, speechbudget.ErrBudgetExceeded) {
					if writeErr := connection.writeJSON(connection.context,
						protocol.ErrorEvent{Type: "error",
							Code: "speech_budget_exceeded"}); writeErr != nil {
						return writeErr
					}
					continue
				}
				if isSpeechBudgetError(err) {
					_ = connection.writeJSON(connection.context,
						protocol.ErrorEvent{Type: "error",
							Code: "speech_budget_unavailable"})
					return connection.closeWith(websocket.StatusTryAgainLater,
						"speech_budget_unavailable")
				}
				return err
			}
			continue
		}
		if messageType != websocket.MessageText {
			return connection.closeViolation("unsupported_frame")
		}
		if len(payload) > protocol.MaxControlBytes {
			return connection.closeViolation("control_frame_too_large")
		}
		if !connection.allowControlMessage() {
			return connection.closeViolation("control_rate_limit")
		}
		if err := connection.handleText(payload); err != nil {
			if err := connection.reportViolation(err); err != nil {
				return err
			}
		}
	}
}

func (connection *connection) handleText(payload []byte) error {
	var routing struct {
		Type      string `json:"type"`
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(payload, &routing); err != nil || routing.Type == "" {
		return &protocol.Violation{Code: "invalid_json", Detail: "missing message type"}
	}
	if routing.SessionID != connection.sessionID {
		return fmt.Errorf("%w: session_id mismatch", protocol.ErrStale)
	}
	switch routing.Type {
	case "tts_request", "tts_abort":
		message, requestID, err := protocol.DecodeControl(payload, connection.sessionID)
		if err != nil {
			return err
		}
		if message.Type == "tts_request" {
			return connection.startTTS(requestID, message.Text)
		}
		return connection.abortTTS(requestID)
	case "hello":
		return &protocol.Violation{Code: "duplicate_hello", Detail: "hello is only allowed once"}
	default:
		return connection.voice.HandleControl(connection.context, append([]byte(nil), payload...))
	}
}

func (connection *connection) startTTS(requestID uint32, text string) error {
	connection.stateMu.Lock()
	if connection.active != nil {
		connection.stateMu.Unlock()
		return &protocol.Violation{Code: "request_in_progress", Detail: "only one TTS request is allowed"}
	}
	characters := int64(utf8.RuneCountInString(text))
	reservation, err := connection.server.reserveTTS(connection.context,
		connection.ownedScope, characters)
	if err != nil {
		connection.stateMu.Unlock()
		code := "speech_budget_unavailable"
		if errors.Is(err, speechbudget.ErrBudgetExceeded) {
			code = "speech_budget_exceeded"
		}
		return connection.writeJSON(connection.context,
			protocol.ErrorEvent{Type: "error", Code: code})
	}
	ctx, cancel := context.WithTimeout(connection.context, connection.server.config.SynthesisTimeout)
	connection.active = &activeTTS{requestID: requestID, cancel: cancel}
	connection.stateMu.Unlock()
	connection.server.metrics.ttsRequests.Add(1)
	go connection.streamTTS(ctx, requestID, text, characters, reservation)
	return nil
}

func (connection *connection) streamTTS(ctx context.Context, requestID uint32,
	text string, characters int64, reservation speechbudget.Reservation) {
	providerContacted := false
	reservationFinished := false
	defer func() {
		if reservationFinished {
			return
		}
		if providerContacted {
			connection.server.uncertainTTS(context.Background(), reservation)
			return
		}
		connection.server.releaseTTS(context.Background(), reservation)
	}()
	if err := connection.writeTTSEvent(ctx, protocol.TTSEvent{
		SessionID: connection.sessionID, Type: "tts", State: "start", RequestID: requestID,
	}); err != nil {
		connection.handleTTSError(ctx, requestID, err)
		return
	}
	if err := connection.writeTTSEvent(ctx, protocol.TTSEvent{
		SessionID: connection.sessionID, Type: "tts", State: "sentence_start",
		RequestID: requestID, Text: text,
	}); err != nil {
		connection.handleTTSError(ctx, requestID, err)
		return
	}
	providerContacted = true
	var frames int64
	err := connection.server.config.Synthesizer.Stream(ctx, tts.Request{
		DeviceID: connection.deviceID, SessionID: connection.sessionID,
		RequestID: requestID, Text: text,
	}, func(opus []byte) error {
		frames++
		packet, encodeErr := protocol.EncodeAudioPacket(connection.protocolVersion, opus)
		if encodeErr != nil {
			return encodeErr
		}
		return connection.writeTTSFrame(ctx, requestID, packet)
	})
	if err != nil {
		connection.handleTTSError(ctx, requestID, err)
		return
	}
	outputAudioMS := frames * int64(connection.server.config.OutputFrameMillis)
	if err := connection.server.settleTTS(context.Background(), reservation,
		characters, outputAudioMS); err != nil {
		connection.handleTTSError(ctx, requestID, err)
		return
	}
	reservationFinished = true
	_ = connection.finishTTS(ctx, requestID, "stop", "")
}

func (connection *connection) abortTTS(requestID uint32) error {
	connection.stateMu.Lock()
	defer connection.stateMu.Unlock()
	if connection.active == nil || connection.active.requestID != requestID {
		return fmt.Errorf("%w: request_id mismatch", protocol.ErrStale)
	}
	connection.active.cancel()
	connection.active = nil
	connection.server.metrics.ttsAborts.Add(1)
	return nil
}

func (connection *connection) writeTTSEvent(ctx context.Context, event protocol.TTSEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	return connection.writeIfActive(ctx, event.RequestID, websocket.MessageText, payload)
}

func (connection *connection) writeTTSFrame(ctx context.Context, requestID uint32, payload []byte) error {
	return connection.writeIfActive(ctx, requestID, websocket.MessageBinary, payload)
}

func (connection *connection) writeIfActive(ctx context.Context, requestID uint32, messageType websocket.MessageType, payload []byte) error {
	connection.stateMu.Lock()
	defer connection.stateMu.Unlock()
	if connection.active == nil || connection.active.requestID != requestID {
		return protocol.ErrStale
	}
	return connection.write(ctx, messageType, payload)
}

func (connection *connection) finishTTS(ctx context.Context, requestID uint32, state, code string) error {
	connection.stateMu.Lock()
	defer connection.stateMu.Unlock()
	if connection.active == nil || connection.active.requestID != requestID {
		return protocol.ErrStale
	}
	payload, err := json.Marshal(protocol.TTSEvent{
		SessionID: connection.sessionID, Type: "tts", State: state,
		RequestID: requestID, Code: code,
	})
	if err == nil {
		err = connection.write(ctx, websocket.MessageText, payload)
	}
	connection.active.cancel()
	connection.active = nil
	return err
}

func (connection *connection) handleTTSError(ctx context.Context, requestID uint32, cause error) {
	if errors.Is(cause, context.Canceled) || errors.Is(cause, protocol.ErrStale) {
		return
	}
	connection.server.metrics.ttsErrors.Add(1)
	_ = connection.finishTTS(ctx, requestID, "error", "synthesis_failed")
}

func (connection *connection) cancelActive() {
	connection.stateMu.Lock()
	if connection.active != nil {
		connection.active.cancel()
		connection.active = nil
	}
	connection.stateMu.Unlock()
}

func (connection *connection) SendSTT(ctx context.Context, text string) error {
	if !utf8.ValidString(text) || strings.TrimSpace(text) == "" || len([]byte(text)) > protocol.MaxSTTTextBytes {
		return fmt.Errorf("invalid STT text")
	}
	return connection.writeJSON(ctx, struct {
		SessionID string `json:"session_id"`
		Type      string `json:"type"`
		Text      string `json:"text"`
	}{connection.sessionID, "stt", text})
}

func (connection *connection) SendJSON(ctx context.Context, payload []byte) error {
	if len(payload) == 0 || len(payload) > protocol.MaxControlBytes {
		return fmt.Errorf("invalid voice JSON size")
	}
	var envelope struct {
		Type      string `json:"type"`
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return fmt.Errorf("invalid voice JSON")
	}
	switch envelope.Type {
	case "llm", "mcp", "system", "alert":
	default:
		return fmt.Errorf("voice backend message type is not allowed")
	}
	if envelope.SessionID != connection.sessionID {
		return fmt.Errorf("voice backend message violates Agent ownership")
	}
	return connection.write(ctx, websocket.MessageText, append([]byte(nil), payload...))
}

func (connection *connection) FailVoice(_ error) {
	_ = connection.closeWith(websocket.StatusTryAgainLater, "voice backend disconnected")
}

func (connection *connection) writeJSON(ctx context.Context, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return connection.write(ctx, websocket.MessageText, payload)
}

func (connection *connection) write(ctx context.Context, messageType websocket.MessageType, payload []byte) error {
	connection.writeMu.Lock()
	defer connection.writeMu.Unlock()
	writeContext, cancel := context.WithTimeout(ctx, connection.server.config.WriteTimeout)
	defer cancel()
	return connection.websocket.Write(writeContext, messageType, payload)
}

func (connection *connection) reportViolation(cause error) error {
	connection.server.metrics.protocolViolations.Add(1)
	code := classifyError(cause)
	_ = connection.writeJSON(connection.context, protocol.ErrorEvent{Type: "error", Code: code})
	connection.violations++
	if connection.violations >= 3 {
		return connection.closeViolation("too_many_protocol_violations")
	}
	return nil
}

func (connection *connection) closeViolation(code string) error {
	connection.server.metrics.protocolViolations.Add(1)
	return connection.closeWith(websocket.StatusPolicyViolation, code)
}

func (connection *connection) closeWith(code websocket.StatusCode, reason string) error {
	return connection.websocket.Close(code, reason)
}

func (connection *connection) allowControlMessage() bool {
	now := time.Now()
	if now.Sub(connection.controlWindowStart) >= time.Minute {
		connection.controlWindowStart = now
		connection.controlMessages = 0
	}
	connection.controlMessages++
	return connection.controlMessages <= connection.server.config.MaxMessagesMinute
}

func (connection *connection) allowAudioPacket() bool {
	now := time.Now()
	if now.Sub(connection.audioWindowStart) >= time.Minute {
		connection.audioWindowStart = now
		connection.audioPackets = 0
	}
	connection.audioPackets++
	return connection.audioPackets <= connection.server.config.MaxAudioMinute
}

func newSessionID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("generate session ID: %w", err)
	}
	return "voice:" + hex.EncodeToString(random[:]), nil
}

func safeIdentifier(value string, max int) bool {
	if value == "" || len(value) > max {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == ':' || char == '-' ||
			char == '_' || char == '.' {
			continue
		}
		return false
	}
	return true
}

func classifyError(err error) string {
	var violation *protocol.Violation
	if errors.As(err, &violation) {
		return violation.Code
	}
	if errors.Is(err, protocol.ErrStale) {
		return "stale_event"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "operation_failed"
}

func isSpeechBudgetError(err error) bool {
	return errors.Is(err, speechbudget.ErrInvalid) ||
		errors.Is(err, speechbudget.ErrUnavailable) ||
		errors.Is(err, speechbudget.ErrReservationLost) ||
		errors.Is(err, speechbudget.ErrUsageExceeded)
}
