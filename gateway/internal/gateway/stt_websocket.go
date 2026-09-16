package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"xiaozhi-agent-platform/gateway/internal/opuspacket"
	"xiaozhi-agent-platform/gateway/internal/protocol"
	"xiaozhi-agent-platform/gateway/internal/speechcontract"
)

type WebSocketSTTConfig struct {
	Endpoint       string
	HealthURL      string
	BearerToken    string
	HTTPClient     *http.Client
	AllowInsecure  bool
	ConnectTimeout time.Duration
	WriteTimeout   time.Duration
}

type WebSocketSTT struct {
	config WebSocketSTTConfig
}

type webSocketSTTSession struct {
	backend       *WebSocketSTT
	socket        *websocket.Conn
	emitter       VoiceEmitter
	ctx           context.Context
	cancel        context.CancelFunc
	writeMu       sync.Mutex
	once          sync.Once
	frameDuration int
}

func NewWebSocketSTT(config WebSocketSTTConfig) (*WebSocketSTT, error) {
	if err := validateWebSocketURL(config.Endpoint, config.AllowInsecure); err != nil {
		return nil, fmt.Errorf("STT endpoint: %w", err)
	}
	if config.HealthURL != "" {
		if err := validateHTTPURL(config.HealthURL, config.AllowInsecure); err != nil {
			return nil, fmt.Errorf("STT health URL: %w", err)
		}
	}
	if strings.TrimSpace(config.BearerToken) == "" {
		return nil, fmt.Errorf("STT bearer token is required")
	}
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{Timeout: 35 * time.Second}
	}
	if config.ConnectTimeout <= 0 {
		config.ConnectTimeout = 5 * time.Second
	}
	if config.WriteTimeout <= 0 {
		config.WriteTimeout = 5 * time.Second
	}
	return &WebSocketSTT{config: config}, nil
}

func (backend *WebSocketSTT) Open(ctx context.Context, config VoiceSessionConfig, emitter VoiceEmitter) (VoiceSession, error) {
	if backend == nil || emitter == nil {
		return nil, fmt.Errorf("invalid STT session")
	}
	connectContext, connectCancel := context.WithTimeout(ctx, backend.config.ConnectTimeout)
	defer connectCancel()
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+backend.config.BearerToken)
	headers.Set(speechcontract.Header, speechcontract.STTVersion)
	headers.Set("Device-Id", config.DeviceID)
	headers.Set("Client-Id", config.ClientID)
	socket, response, err := websocket.Dial(connectContext, backend.config.Endpoint, &websocket.DialOptions{
		HTTPClient: backend.config.HTTPClient,
		HTTPHeader: headers,
	})
	if response != nil && response.Body != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("connect STT upstream: %w", err)
	}
	if response == nil || response.Header.Get(speechcontract.Header) !=
		speechcontract.STTVersion {
		_ = socket.CloseNow()
		return nil, fmt.Errorf("STT upstream contract mismatch")
	}
	socket.SetReadLimit(protocol.MaxControlBytes)
	sessionContext, cancel := context.WithCancel(ctx)
	session := &webSocketSTTSession{
		backend: backend, socket: socket, emitter: emitter,
		ctx: sessionContext, cancel: cancel, frameDuration: config.FrameDuration,
	}
	start := struct {
		Type            string `json:"type"`
		Contract        string `json:"contract"`
		SessionID       string `json:"session_id"`
		Format          string `json:"format"`
		SampleRate      int    `json:"sample_rate"`
		FrameDurationMS int    `json:"frame_duration_ms"`
	}{
		Type: "start", Contract: speechcontract.STTVersion,
		SessionID: config.SessionID, Format: "opus", SampleRate: config.SampleRate,
		FrameDurationMS: config.FrameDuration,
	}
	payload, err := json.Marshal(start)
	if err != nil || session.write(websocket.MessageText, payload) != nil {
		_ = socket.CloseNow()
		cancel()
		return nil, fmt.Errorf("start STT upstream session")
	}
	go session.readLoop()
	return session, nil
}

func (backend *WebSocketSTT) Ready(ctx context.Context) error {
	if backend == nil {
		return ErrVoiceBackendUnavailable
	}
	if backend.config.HealthURL == "" {
		return nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, backend.config.HealthURL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+backend.config.BearerToken)
	request.Header.Set(speechcontract.Header, speechcontract.STTVersion)
	response, err := backend.config.HTTPClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("STT health status %d", response.StatusCode)
	}
	if response.Header.Get(speechcontract.Header) != speechcontract.STTVersion {
		return fmt.Errorf("STT health contract mismatch")
	}
	return nil
}

func (session *webSocketSTTSession) HandleAudio(ctx context.Context, opus []byte) error {
	if len(opus) == 0 || len(opus) > protocol.MaxOpusPacketBytes {
		return fmt.Errorf("invalid STT audio packet")
	}
	if err := opuspacket.ValidateMonoDuration(opus, session.frameDuration); err != nil {
		return fmt.Errorf("invalid STT Opus packet: %w", err)
	}
	return session.writeWithContext(ctx, websocket.MessageBinary, append([]byte(nil), opus...))
}

func (session *webSocketSTTSession) HandleControl(ctx context.Context, payload []byte) error {
	var envelope struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return fmt.Errorf("invalid STT control JSON")
	}
	switch envelope.Type {
	case "listen", "abort":
		return session.writeWithContext(ctx, websocket.MessageText, append([]byte(nil), payload...))
	default:
		return fmt.Errorf("unsupported STT control type")
	}
}

func (session *webSocketSTTSession) Close() error {
	var closeErr error
	session.once.Do(func() {
		session.cancel()
		closeErr = session.socket.Close(websocket.StatusNormalClosure, "session closed")
	})
	return closeErr
}

func (session *webSocketSTTSession) readLoop() {
	for {
		messageType, payload, err := session.socket.Read(session.ctx)
		if err != nil {
			if session.ctx.Err() == nil {
				session.emitter.FailVoice(err)
			}
			return
		}
		if messageType != websocket.MessageText {
			session.emitter.FailVoice(fmt.Errorf("STT upstream sent a non-JSON frame"))
			return
		}
		var event struct {
			Type  string `json:"type"`
			Text  string `json:"text"`
			Final bool   `json:"final"`
		}
		if err := json.Unmarshal(payload, &event); err != nil || event.Type != "stt" {
			session.emitter.FailVoice(fmt.Errorf("invalid STT upstream event"))
			return
		}
		if event.Final {
			if err := session.emitter.SendSTT(session.ctx, event.Text); err != nil {
				return
			}
		}
	}
}

func (session *webSocketSTTSession) write(messageType websocket.MessageType, payload []byte) error {
	return session.writeWithContext(session.ctx, messageType, payload)
}

func (session *webSocketSTTSession) writeWithContext(parent context.Context, messageType websocket.MessageType, payload []byte) error {
	session.writeMu.Lock()
	defer session.writeMu.Unlock()
	ctx, cancel := context.WithTimeout(parent, session.backend.config.WriteTimeout)
	defer cancel()
	return session.socket.Write(ctx, messageType, payload)
}

func validateWebSocketURL(raw string, allowInsecure bool) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" ||
		parsed.RawQuery != "" {
		return fmt.Errorf("invalid URL")
	}
	if parsed.Scheme != "wss" && !(allowInsecure && parsed.Scheme == "ws") {
		return fmt.Errorf("WSS is required")
	}
	return nil
}

func validateHTTPURL(raw string, allowInsecure bool) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" ||
		parsed.RawQuery != "" {
		return fmt.Errorf("invalid URL")
	}
	if parsed.Scheme != "https" && !(allowInsecure && parsed.Scheme == "http") {
		return fmt.Errorf("HTTPS is required")
	}
	return nil
}
