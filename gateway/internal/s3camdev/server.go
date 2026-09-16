package s3camdev

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"
)

const (
	maxBootstrapBytes = 16 * 1024
	// ESP32 tools/list pages are capped at 8 KiB before the surrounding MCP
	// envelope is added. Keep a strict but compatible ceiling so a richer watch
	// tool catalog is not mistaken for an oversized WebSocket message and closed.
	maxControlBytes    = 16 * 1024
	voiceFrameDuration = 60 * time.Millisecond
	// Prime only a bounded device jitter window. The ESP32 decode queue holds 40
	// packets; a larger burst plus faster-than-playout pacing eventually filled
	// it, while absolute-clock catch-up bursts alternated overflow with underrun.
	voiceInitialJitterBurstFrames = 12
	voiceSpeechPacketInterval     = voiceFrameDuration
	voiceMusicPacketInterval      = voiceFrameDuration
	voicePlaybackDrainMargin      = 120 * time.Millisecond
	deviceKeepaliveInterval       = 45 * time.Second
	// The device normally sends listen/stop. If that single control frame is
	// lost after audio has ceased, finalize the turn instead of leaving the
	// watch in THINKING until the packet-count compatibility limit is reached.
	voiceInputIdleFallback = 5 * time.Second
)

// testSpeechPacketsBase64 is a development-only 24 kHz, mono, 60 ms Opus
// response saying "收到語音". It proves intelligible speech playback without
// claiming that a real STT, model, or TTS provider has been integrated.
var testSpeechPacketsBase64 = []string{
	"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",
}

type Config struct {
	PublicWebSocketURL          string
	TextLocale                  string
	GlyphProviderURL            string
	ExpectedDeviceID            string
	AllowedDeviceIDs            []string
	BootstrapToken              string
	DeviceBootstrapTokens       map[string]string
	RequireTLS                  bool
	Token                       string
	TriggerAudioPackets         int
	TonePackets                 int
	VoicePipeline               VoicePipeline
	Realtime                    *OpenAIRealtimeGateway
	Memory                      *AgentMemory
	SpeakerIdentity             *SpeakerIdentityService
	VoiceClone                  *VoiceCloneService
	WebToolsEnabled             bool
	DeviceTimezoneOffsetMinutes int
	Logger                      *slog.Logger
	deviceKeepalive             time.Duration
}

// VoicePipeline keeps the development Gateway provider-neutral. The current
// Mac implementation is local-only; a production deployment can replace it
// without changing the device protocol.
type VoicePipeline interface {
	Transcribe(context.Context, [][]byte) (string, error)
	Reply(context.Context, string) (string, error)
	Synthesize(context.Context, string) ([][]byte, error)
}

type VoiceSynthesisChunk struct {
	Text                 string
	Packets              [][]byte
	Err                  error
	Music                bool
	TextReadyAt          time.Time
	SynthesisStartedAt   time.Time
	SynthesisCompletedAt time.Time
}

// ChunkedVoicePipeline allows the Gateway to begin playback after the first
// sentence while later sentences are still being synthesized.
type ChunkedVoicePipeline interface {
	SynthesizeChunks(context.Context, string) (<-chan VoiceSynthesisChunk, error)
}

type PublicStatus struct {
	Gateway         string `json:"gateway"`
	Device          string `json:"device"`
	Microphone      string `json:"microphone"`
	ESPClaw         string `json:"esp_claw"`
	VoiceClone      string `json:"voice_clone"`
	SpeakerIdentity string `json:"speaker_identity"`
	WebAccess       string `json:"web_access"`
	AudioPackets    int    `json:"audio_packets"`
	CompletedTurns  int    `json:"completed_turns"`
	LastEvent       string `json:"last_event"`
	UpdatedAt       string `json:"updated_at"`
}

type Server struct {
	config                Config
	textLocalizer         *TextLocalizer
	glyphProvider         *GlyphProvider
	allowedDevices        map[string]struct{}
	deviceBootstrapTokens map[string]string
	token                 string
	speech                [][]byte
	mux                   *http.ServeMux
	memory                *AgentMemory
	speakerIdentity       *SpeakerIdentityService

	statusMu             sync.RWMutex
	status               PublicStatus
	connectionGeneration uint64
}

func New(config Config) (*Server, error) {
	endpoint, err := url.Parse(config.PublicWebSocketURL)
	if err != nil || endpoint.Host == "" || endpoint.Path != "/v1/device" ||
		(endpoint.Scheme != "ws" && endpoint.Scheme != "wss") ||
		endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, fmt.Errorf("public WebSocket URL must be an exact ws(s) /v1/device URL")
	}
	if config.RequireTLS && endpoint.Scheme != "wss" {
		return nil, fmt.Errorf("public WebSocket URL must use WSS in cloud mode")
	}
	textLocalizer, err := NewTextLocalizer(config.TextLocale)
	if err != nil {
		return nil, err
	}
	config.TextLocale = textLocalizer.Locale()
	var glyphProvider *GlyphProvider
	if config.GlyphProviderURL != "" {
		glyphProvider, err = NewGlyphProvider(config.GlyphProviderURL)
		if err != nil {
			return nil, err
		}
	}
	allowedDevices := make(map[string]struct{}, len(config.AllowedDeviceIDs)+1)
	deviceIDs := append([]string(nil), config.AllowedDeviceIDs...)
	if config.ExpectedDeviceID != "" {
		deviceIDs = append(deviceIDs, config.ExpectedDeviceID)
	}
	for _, deviceID := range deviceIDs {
		if strings.TrimSpace(deviceID) != deviceID || deviceID == "" ||
			len(deviceID) > 64 || strings.ContainsAny(deviceID, "\t\r\n\x00") {
			return nil, fmt.Errorf("allowed development device ID is invalid")
		}
		allowedDevices[deviceID] = struct{}{}
	}
	if len(allowedDevices) == 0 {
		return nil, fmt.Errorf("at least one allowed development device ID is required")
	}
	deviceBootstrapTokens := make(map[string]string, len(config.DeviceBootstrapTokens))
	for deviceID, token := range config.DeviceBootstrapTokens {
		if _, allowed := allowedDevices[deviceID]; !allowed {
			return nil, fmt.Errorf("device bootstrap token has no matching allowed device")
		}
		if !validConfiguredBootstrapToken(token) {
			return nil, fmt.Errorf("device bootstrap token is invalid")
		}
		deviceBootstrapTokens[deviceID] = token
	}
	if config.BootstrapToken != "" {
		if !validConfiguredBootstrapToken(config.BootstrapToken) {
			return nil, fmt.Errorf("bootstrap token is invalid")
		}
	}
	if config.TriggerAudioPackets <= 0 {
		// Endpointing normally happens on the ESP32 after trailing silence.
		// Keep a 48-second server-side failsafe so a stale or older device can
		// never stream an unbounded turn.
		config.TriggerAudioPackets = 800
	}
	if config.TonePackets <= 0 {
		config.TonePackets = len(testSpeechPacketsBase64)
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.deviceKeepalive <= 0 {
		config.deviceKeepalive = deviceKeepaliveInterval
	}
	token := config.Token
	if token == "" {
		material := make([]byte, 32)
		if _, err := rand.Read(material); err != nil {
			return nil, fmt.Errorf("generate development session token: %w", err)
		}
		token = base64.RawURLEncoding.EncodeToString(material)
	}
	if len(token) < 16 || strings.TrimSpace(token) != token ||
		strings.ContainsAny(token, " \t\r\n\x00") {
		return nil, fmt.Errorf("development session token is invalid")
	}
	speech := make([][]byte, 0, len(testSpeechPacketsBase64))
	for _, encoded := range testSpeechPacketsBase64 {
		packet, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decode development Opus speech: %w", err)
		}
		speech = append(speech, packet)
	}
	memory := config.Memory
	if memory == nil {
		memory, err = NewAgentMemory("", "")
		if err != nil {
			return nil, err
		}
	}
	server := &Server{
		config: config, textLocalizer: textLocalizer,
		glyphProvider: glyphProvider, allowedDevices: allowedDevices,
		deviceBootstrapTokens: deviceBootstrapTokens, token: token,
		speech: speech, memory: memory,
		speakerIdentity: config.SpeakerIdentity,
	}
	server.status = PublicStatus{
		Gateway: "運作中", Device: "等待裝置", Microphone: "尚未測試",
		ESPClaw: "等待能力回報", SpeakerIdentity: "未啟用",
		WebAccess: "尚未啟用",
		LastEvent: "Gateway 已啟動",
		UpdatedAt: time.Now().Format(time.RFC3339),
	}
	if config.WebToolsEnabled {
		server.status.WebAccess = "即時搜尋與網頁讀取可用"
	}
	if config.SpeakerIdentity != nil {
		server.status.SpeakerIdentity = "等待註冊"
		if count := config.SpeakerIdentity.ProfileCount(); count > 0 {
			server.status.SpeakerIdentity = fmt.Sprintf("已啟用（%d 位）", count)
		}
	}
	server.mux = http.NewServeMux()
	server.mux.HandleFunc("GET /", server.dashboard)
	server.mux.HandleFunc("GET /healthz", server.health)
	server.mux.HandleFunc("GET /status", server.publicStatus)
	server.mux.HandleFunc("POST /xiaozhi/ota/", server.bootstrap)
	server.mux.HandleFunc("GET /v1/device", server.device)
	if config.VoiceClone != nil {
		config.VoiceClone.RegisterHandlers(server.mux)
	}
	return server, nil
}

func (server *Server) Handler() http.Handler { return server.mux }

func (server *Server) Snapshot() PublicStatus {
	server.statusMu.RLock()
	status := server.status
	server.statusMu.RUnlock()
	if server.config.VoiceClone == nil {
		status.VoiceClone = "等待專用服務金鑰"
	} else {
		voice := server.config.VoiceClone.Status()
		if voice["active"] == true && voice["selected"] == true {
			status.VoiceClone = "我的音色使用中"
		} else if voice["active"] == true {
			status.VoiceClone = "已建立，目前用預設音色"
		} else {
			status.VoiceClone = "可建立我的音色"
		}
	}
	if server.speakerIdentity != nil {
		if count := server.speakerIdentity.ProfileCount(); count > 0 {
			status.SpeakerIdentity = fmt.Sprintf("已啟用（%d 位）", count)
		} else {
			status.SpeakerIdentity = "等待註冊"
		}
	}
	return status
}

func (server *Server) update(mutator func(*PublicStatus)) {
	server.statusMu.Lock()
	mutator(&server.status)
	server.status.UpdatedAt = time.Now().Format(time.RFC3339)
	server.statusMu.Unlock()
}

func (server *Server) beginDeviceConnection() uint64 {
	server.statusMu.Lock()
	defer server.statusMu.Unlock()
	server.connectionGeneration++
	server.status.Device = "已連線"
	server.status.LastEvent = "ESP32 WebSocket 已連上自建 Gateway"
	server.status.UpdatedAt = time.Now().Format(time.RFC3339)
	return server.connectionGeneration
}

func (server *Server) endDeviceConnection(generation uint64) {
	server.statusMu.Lock()
	defer server.statusMu.Unlock()
	if generation != server.connectionGeneration {
		return
	}
	server.status.Device = "已中斷"
	server.status.LastEvent = "ESP32 WebSocket 已中斷"
	server.status.UpdatedAt = time.Now().Format(time.RFC3339)
}

func (server *Server) health(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	_, _ = writer.Write([]byte(`{"status":"ok","profile":"s3cam-gateway"}`))
}

func (server *Server) publicStatus(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(writer).Encode(server.Snapshot())
}

func (server *Server) dashboard(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(writer, dashboardHTML)
}

func (server *Server) bootstrap(writer http.ResponseWriter, request *http.Request) {
	deviceID := request.Header.Get("Device-Id")
	bootstrapToken := server.config.BootstrapToken
	if token, exists := server.deviceBootstrapTokens[deviceID]; exists {
		bootstrapToken = token
	}
	if !server.deviceAllowed(deviceID) ||
		strings.TrimSpace(request.Header.Get("Client-Id")) == "" ||
		len(request.Header.Get("Client-Id")) > 128 ||
		!validBearer(request.Header.Get("Authorization"), bootstrapToken) {
		http.Error(writer, "development device rejected", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxBootstrapBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxBootstrapBytes || !json.Valid(body) {
		http.Error(writer, "invalid bootstrap request", http.StatusBadRequest)
		return
	}
	server.update(func(status *PublicStatus) {
		status.Device = "已取得連線設定"
		status.LastEvent = "ESP32 已向自己的 Gateway 取得一次性連線權杖"
	})
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"server_time": map[string]any{
			"timestamp":       time.Now().UnixMilli(),
			"timezone_offset": server.config.DeviceTimezoneOffsetMinutes,
		},
		"websocket": map[string]string{
			"url": server.config.PublicWebSocketURL, "token": server.token,
		},
	})
}

func validConfiguredBootstrapToken(token string) bool {
	return len(token) >= 32 && len(token) <= 256 &&
		strings.TrimSpace(token) == token &&
		!strings.ContainsAny(token, " \t\r\n\x00")
}

func (server *Server) deviceAllowed(deviceID string) bool {
	_, allowed := server.allowedDevices[deviceID]
	return allowed
}

func validBearer(header, expected string) bool {
	if expected == "" {
		return true
	}
	actual := strings.TrimPrefix(header, "Bearer ")
	if actual == header || len(actual) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) == 1
}

type clientHello struct {
	Type      string `json:"type"`
	Version   int    `json:"version"`
	Transport string `json:"transport"`
	Features  struct {
		MCP       bool `json:"mcp"`
		GlyphPush bool `json:"glyph_push"`
	} `json:"features"`
	TextFont struct {
		Bundle  string `json:"bundle"`
		Charset string `json:"charset"`
		Size    int    `json:"size"`
		BPP     int    `json:"bpp"`
	} `json:"text_font"`
	AudioParams struct {
		Format        string `json:"format"`
		SampleRate    int    `json:"sample_rate"`
		Channels      int    `json:"channels"`
		FrameDuration int    `json:"frame_duration"`
	} `json:"audio_params"`
}

type controlEnvelope struct {
	SessionID              string          `json:"session_id"`
	Type                   string          `json:"type"`
	State                  string          `json:"state"`
	Mode                   string          `json:"mode"`
	Text                   string          `json:"text"`
	RequestID              string          `json:"request_id"`
	Format                 string          `json:"format"`
	Width                  int             `json:"width"`
	Height                 int             `json:"height"`
	Bytes                  int             `json:"bytes"`
	ReceivedPackets        uint32          `json:"received_packets"`
	DroppedPackets         uint32          `json:"dropped_packets"`
	DecodeErrors           uint32          `json:"decode_errors"`
	OutputErrors           uint32          `json:"output_errors"`
	PlaybackUnderruns      uint32          `json:"playback_underruns"`
	PlayedPackets          uint32          `json:"played_packets"`
	DecodeQueueHighWater   uint32          `json:"decode_queue_high_water"`
	PlaybackQueueHighWater uint32          `json:"playback_queue_high_water"`
	Payload                json.RawMessage `json:"payload"`
}

func (server *Server) device(writer http.ResponseWriter, request *http.Request) {
	deviceID := request.Header.Get("Device-Id")
	if !server.deviceAllowed(deviceID) ||
		request.Header.Get("Authorization") != "Bearer "+server.token ||
		request.Header.Get("Protocol-Version") != "1" {
		http.Error(writer, "development voice authorization rejected", http.StatusUnauthorized)
		return
	}
	connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	defer connection.CloseNow()
	connection.SetReadLimit(maxControlBytes)
	generation := server.beginDeviceConnection()
	defer server.endDeviceConnection(generation)

	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	messageType, payload, err := connection.Read(ctx)
	cancel()
	if err != nil || messageType != websocket.MessageText || len(payload) > maxControlBytes {
		_ = connection.Close(websocket.StatusPolicyViolation, "invalid hello")
		return
	}
	var hello clientHello
	if json.Unmarshal(payload, &hello) != nil || hello.Type != "hello" ||
		hello.Version != 1 || hello.Transport != "websocket" || !hello.Features.MCP ||
		hello.AudioParams.Format != "opus" || hello.AudioParams.SampleRate != 16000 ||
		hello.AudioParams.Channels != 1 || hello.AudioParams.FrameDuration != 60 {
		_ = connection.Close(websocket.StatusPolicyViolation, "unsupported hello")
		return
	}
	sessionID, err := randomSessionID()
	if err != nil {
		_ = connection.Close(websocket.StatusInternalError, "session unavailable")
		return
	}
	session := newDeviceSession(server, connection, sessionID)
	var realtime *realtimeDeviceIngress
	if server.config.Realtime != nil {
		realtime = newRealtimeDeviceIngress(request.Context(), server.config.Realtime, session)
	}
	defer func() {
		if realtime != nil {
			realtime.Close()
		}
	}()
	session.textFont = TextFontCapability{
		GlyphPush: hello.Features.GlyphPush,
		Bundle:    hello.TextFont.Bundle, Charset: hello.TextFont.Charset,
		Size: hello.TextFont.Size, BPP: hello.TextFont.BPP,
	}
	if hello.Features.GlyphPush && !session.textFont.Valid() {
		server.config.Logger.Warn("device advertised invalid text font capability")
		session.textFont = TextFontCapability{}
	}
	if session.writeJSON(request.Context(), map[string]any{
		"type": "hello", "version": 1, "transport": "websocket",
		"session_id": sessionID,
		// The device uses this authenticated hello as its resilient UTC time
		// source when the optional OTA/bootstrap request was unavailable.
		"server_time": map[string]any{"timestamp": time.Now().UnixMilli()},
		"audio_params": map[string]any{
			"format": "opus", "sample_rate": 24000,
			"channels": 1, "frame_duration": 60,
		},
	}) != nil || session.sendMCP(request.Context(), 1,
		"initialize", map[string]any{}) != nil {
		return
	}
	go session.keepaliveLoop(request.Context(), server.config.deviceKeepalive)

	listening := false
	responded := false
	audioPackets := 0
	var capturedPackets [][]byte
	var voiceMu sync.Mutex
	var voiceGeneration uint64
	lastAudioAt := time.Time{}
	finishVoiceTurn := func(notifyDevice bool, expectedGeneration uint64) error {
		voiceMu.Lock()
		if expectedGeneration != 0 && voiceGeneration != expectedGeneration {
			voiceMu.Unlock()
			return nil
		}
		if !listening || responded {
			voiceMu.Unlock()
			return nil
		}
		responded = true
		listening = false
		packets := append([][]byte(nil), capturedPackets...)
		voiceMu.Unlock()
		if notifyDevice {
			if err := session.writeJSON(request.Context(), map[string]any{
				"session_id": session.sessionID,
				"type":       "listen",
				"state":      "stop",
			}); err != nil {
				return err
			}
		}
		if len(packets) == 0 {
			return session.writeJSON(request.Context(), map[string]any{
				"session_id": session.sessionID,
				"type":       "error",
				"code":       "no_audio",
			})
		}
		server.update(func(status *PublicStatus) {
			status.Microphone = "音訊已收到"
			status.LastEvent = "語音輸入完成，正在辨識"
		})
		turnContext, finishTurn := session.beginTurn(request.Context())
		go func() {
			defer finishTurn()
			var turnErr error
			if server.config.VoicePipeline != nil {
				turnErr = server.sendAgentTurn(
					turnContext, session, packets)
			} else {
				turnErr = server.sendTestTurn(turnContext, session)
			}
			if turnErr != nil {
				if errors.Is(turnErr, context.Canceled) {
					server.config.Logger.Info("voice turn cancelled")
					return
				}
				server.config.Logger.Error("voice turn failed",
					"error", turnErr)
				// Never leave the device in THINKING after a provider,
				// synthesis, or transport failure. The public error is
				// deliberately content-free; provider details remain in the
				// restricted service journal.
				errorContext, cancelError := context.WithTimeout(
					request.Context(), 3*time.Second)
				_ = session.writeJSON(errorContext, map[string]any{
					"session_id": session.sessionID,
					"type":       "error",
					"code":       "agent_turn_failed",
				})
				cancelError()
				server.update(func(status *PublicStatus) {
					status.Microphone = "音訊已收到"
					status.LastEvent = "AI 處理失敗；內容未寫入紀錄"
				})
			}
		}()
		return nil
	}
	startVoiceIdleWatchdog := func(generation uint64) {
		go func() {
			ticker := time.NewTicker(250 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-request.Context().Done():
					return
				case <-ticker.C:
					voiceMu.Lock()
					active := listening && !responded &&
						voiceGeneration == generation
					packets := audioPackets
					lastPacket := lastAudioAt
					voiceMu.Unlock()
					if !active {
						return
					}
					if packets > 0 && !lastPacket.IsZero() &&
						time.Since(lastPacket) >= voiceInputIdleFallback {
						server.config.Logger.Warn(
							"listen stop missing; finalizing idle voice input",
							"audio_packets", packets)
						if err := finishVoiceTurn(true, generation); err != nil {
							server.config.Logger.Warn(
								"idle voice input fallback failed", "error", err)
							_ = connection.CloseNow()
						}
						return
					}
				}
			}
		}()
	}
	for {
		messageType, payload, err = connection.Read(request.Context())
		if err != nil {
			return
		}
		if messageType == websocket.MessageBinary {
			if session.appendImage(payload) {
				continue
			}
			if realtime.Enabled() {
				if err := realtime.push("opus", payload, ""); err != nil {
					realtime.reportFailure(err)
					return
				}
				server.update(func(status *PublicStatus) {
					status.AudioPackets++
					status.Microphone = "即時接收中"
					status.LastEvent = "語音正串流至 Realtime 模型"
				})
				continue
			}
			voiceMu.Lock()
			if !listening || responded || len(payload) == 0 || len(payload) > 4096 {
				voiceMu.Unlock()
				continue
			}
			audioPackets++
			capturedPackets = append(capturedPackets, append([]byte(nil), payload...))
			lastAudioAt = time.Now()
			triggerFallback := audioPackets >= server.config.TriggerAudioPackets
			voiceMu.Unlock()
			server.update(func(status *PublicStatus) {
				status.AudioPackets++
				status.Microphone = "正在接收"
				status.LastEvent = "正在接收 ESP32 麥克風 Opus 音訊"
			})
			if triggerFallback {
				// This is only the compatibility failsafe. Current firmware ends
				// the turn itself after detecting trailing silence.
				if err := finishVoiceTurn(true, 0); err != nil {
					return
				}
			}
			continue
		}
		if messageType != websocket.MessageText || len(payload) > maxControlBytes {
			continue
		}
		var envelope controlEnvelope
		if json.Unmarshal(payload, &envelope) != nil ||
			envelope.SessionID != sessionID {
			continue
		}
		switch envelope.Type {
		case "listen":
			if envelope.State == "start" {
				session.cancelTurn()
				if envelope.Mode == "realtime" {
					if server.config.Realtime == nil {
						_ = session.writeJSON(request.Context(), map[string]any{
							"session_id": session.sessionID, "type": "error",
							"code": "realtime_unavailable",
						})
						continue
					}
					if err := realtime.Start(); err != nil {
						realtime.reportFailure(err)
						return
					}
					continue
				}
				if realtime.Enabled() {
					if err := realtime.Stop(); err != nil {
						realtime.reportFailure(err)
						return
					}
				}
				voiceMu.Lock()
				listening, responded, audioPackets = true, false, 0
				capturedPackets = capturedPackets[:0]
				lastAudioAt = time.Time{}
				voiceGeneration++
				generation := voiceGeneration
				voiceMu.Unlock()
				startVoiceIdleWatchdog(generation)
				server.update(func(status *PublicStatus) {
					status.Microphone = "等待語音"
					status.LastEvent = "裝置已開始一輪語音測試"
				})
			} else if envelope.State == "detect" {
				if realtime.Enabled() {
					if err := realtime.push("wake", nil, envelope.Text); err != nil {
						realtime.reportFailure(err)
						return
					}
				}
			} else if envelope.State == "stop" {
				if realtime.Enabled() {
					// semantic_vad owns turn completion in full-duplex mode.
					continue
				}
				if err := finishVoiceTurn(false, 0); err != nil {
					return
				}
			} else if envelope.State == "speech_start" {
				if realtime.Enabled() {
					// This is one half of the confirmation pair. It never
					// interrupts playback without a matching provider candidate.
					if err := realtime.push("speech_start", nil, ""); err != nil {
						realtime.reportFailure(err)
						return
					}
					continue
				}
			} else if envelope.State == "speech_stop" {
				if realtime.Enabled() {
					if err := realtime.push("speech_stop", nil, ""); err != nil {
						realtime.reportFailure(err)
						return
					}
					// Never turn the compact watch's local VAD edge into a turn
					// boundary. Semantic VAD still owns completion and receives the
					// uninterrupted PCM stream.
					continue
				}
			}
		case "audio_stats":
			attributes := []any{
				"received_packets", envelope.ReceivedPackets,
				"dropped_packets", envelope.DroppedPackets,
				"decode_errors", envelope.DecodeErrors,
				"output_errors", envelope.OutputErrors,
				"playback_underruns", envelope.PlaybackUnderruns,
				"played_packets", envelope.PlayedPackets,
				"decode_queue_high_water", envelope.DecodeQueueHighWater,
				"playback_queue_high_water", envelope.PlaybackQueueHighWater,
			}
			if envelope.DroppedPackets > 0 || envelope.DecodeErrors > 0 || envelope.OutputErrors > 0 ||
				envelope.PlaybackUnderruns > 0 {
				server.config.Logger.Warn("ESP32 playback integrity report",
					attributes...)
			} else {
				server.config.Logger.Info("ESP32 playback integrity report",
					attributes...)
			}
		case "abort":
			if realtime.Enabled() {
				if err := realtime.push("abort", nil, ""); err != nil {
					realtime.reportFailure(err)
					return
				}
				continue
			}
			session.cancelTurn()
			voiceMu.Lock()
			listening, responded, audioPackets = false, true, 0
			capturedPackets = capturedPackets[:0]
			voiceMu.Unlock()
		case "mcp":
			if server.handleMCP(request.Context(), session,
				envelope.Payload) != nil {
				return
			}
		case "image":
			if envelope.State == "begin" {
				if session.beginImage(envelope.RequestID, envelope.Format,
					envelope.Width, envelope.Height, envelope.Bytes) {
					server.update(func(status *PublicStatus) {
						status.LastEvent = "已取得拍照確認，正在接收 ESP32 影像"
					})
				}
			} else if envelope.State == "end" || envelope.State == "abort" {
				if session.finishImage(envelope.RequestID, envelope.State) {
					server.update(func(status *PublicStatus) {
						status.LastEvent = "ESP32 相機影像已安全送達 Gateway"
					})
				}
			}
		case "consent":
			session.deliverConsent(envelope.RequestID, envelope.State)
		case "tts":
			if envelope.State == "drained" {
				session.deliverPlaybackDrained()
			}
		}
	}
}

func (server *Server) sendAgentTurn(ctx context.Context,
	session *deviceSession, capturedPackets [][]byte) error {
	turnContext, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	turnStarted := time.Now()
	type identityResult struct {
		match SpeakerMatch
		err   error
	}
	identityChannel := make(chan identityResult, 1)
	if server.speakerIdentity != nil {
		go func() {
			identityContext, cancelIdentity := context.WithTimeout(turnContext, 2*time.Second)
			defer cancelIdentity()
			match, identifyErr := server.speakerIdentity.Identify(
				identityContext, capturedPackets)
			identityChannel <- identityResult{match: match, err: identifyErr}
		}()
	} else {
		identityChannel <- identityResult{}
	}

	transcript, err := server.config.VoicePipeline.Transcribe(
		turnContext, capturedPackets)
	if err != nil {
		return fmt.Errorf("transcribe voice turn: %w", err)
	}
	transcript = strings.TrimSpace(server.textLocalizer.Normalize(transcript))
	if transcript == "" || !utf8.ValidString(transcript) {
		return fmt.Errorf("transcribe voice turn: invalid localized transcript")
	}
	identity := <-identityChannel
	if identity.err != nil {
		server.config.Logger.Warn("speaker identification unavailable for voice turn",
			"error", identity.err)
		identity.match = SpeakerMatch{}
	}
	session.setCurrentVoiceTurn(identity.match, capturedPackets)
	defer session.clearCurrentVoiceTurn()
	historyWindow := session.historyForSpeaker(identity.match)
	historyEntries, historyRunes := historyWindow.Metrics()
	sttMessage := map[string]any{
		"session_id": session.sessionID, "type": "stt", "text": transcript,
	}
	if identity.match.Known {
		sttMessage["speaker"] = identity.match.DisplayName
	}
	if err := session.writeTextJSON(turnContext, sttMessage, transcript); err != nil {
		return err
	}
	server.update(func(status *PublicStatus) {
		status.Microphone = "語音辨識通過"
		status.LastEvent = "語音辨識已完成；逐字稿不留存"
	})
	asrFinished := time.Now()

	history := historyWindow.Snapshot()
	onlineMusicRequested := isOnlineMusicIntent(transcript)
	originalSingingRequested := isSingingIntent(transcript) &&
		!onlineMusicRequested
	onlineMusicTranscript := transcript
	if classifier, ok := server.config.VoicePipeline.(MediaIntentClassifier); ok &&
		mayNeedMediaClassification(transcript) {
		classificationContext, cancelClassification := context.WithTimeout(
			turnContext, 5*time.Second)
		mediaIntent, classificationErr := classifier.ClassifyMediaIntent(
			classificationContext, transcript)
		cancelClassification()
		if classificationErr != nil {
			server.config.Logger.Warn("semantic media routing unavailable",
				"error", classificationErr)
		} else {
			server.config.Logger.Info("semantic media intent classified",
				"kind", mediaIntent.Kind,
				"query_present", strings.TrimSpace(mediaIntent.Query) != "")
			switch mediaIntent.Kind {
			case "online_music":
				onlineMusicRequested = true
				originalSingingRequested = false
				onlineMusicTranscript = canonicalOnlineMusicTranscript(mediaIntent)
			case "original_singing":
				onlineMusicRequested = false
				originalSingingRequested = true
			}
		}
	}
	var reply string
	var chunks <-chan VoiceSynthesisChunk
	var streamedSummary <-chan voiceReplySummary
	var agentFinished time.Time
	var firstTextAt time.Time
	var synthesisStarted time.Time
	if pipeline, ok := server.config.VoicePipeline.(SingingVoicePipeline); ok &&
		originalSingingRequested {
		server.config.Logger.Info("voice turn routed", "route", "original_singing")
		synthesisStarted = time.Now()
		performance, singErr := pipeline.Sing(
			turnContext, transcript, history, session)
		if singErr != nil {
			return fmt.Errorf("generate Agent singing performance: %w", singErr)
		}
		reply = strings.TrimSpace(server.textLocalizer.Normalize(
			performance.DisplayText))
		if reply == "" || !utf8.ValidString(reply) ||
			utf8.RuneCountInString(reply) > maxSpokenReplyRunes ||
			len(performance.Packets) == 0 {
			return fmt.Errorf("generate Agent singing performance: invalid output")
		}
		agentFinished = time.Now()
		firstTextAt = agentFinished
		historyWindow.Add(transcript, reply)
		performanceChunks := make(chan VoiceSynthesisChunk, 1)
		performanceChunks <- VoiceSynthesisChunk{
			Text: reply, Packets: performance.Packets,
			Music:       performance.Music,
			TextReadyAt: firstTextAt, SynthesisStartedAt: synthesisStarted,
			SynthesisCompletedAt: agentFinished,
		}
		close(performanceChunks)
		chunks = performanceChunks
	} else if pipeline, ok := server.config.VoicePipeline.(OnlineMusicVoicePipeline); ok && onlineMusicRequested {
		server.config.Logger.Info("voice turn routed", "route", "online_music")
		server.update(func(status *PublicStatus) {
			status.Microphone = "歌曲搜尋中"
			status.LastEvent = "已進入網路歌曲播放路徑；正在搜尋與轉換音訊"
		})
		synthesisStarted = time.Now()
		performance, playErr := pipeline.PlayOnlineMusic(
			turnContext, onlineMusicTranscript)
		if playErr != nil {
			return fmt.Errorf("play online music: %w", playErr)
		}
		reply = strings.TrimSpace(server.textLocalizer.Normalize(
			performance.DisplayText))
		if reply == "" || !utf8.ValidString(reply) ||
			utf8.RuneCountInString(reply) > maxSpokenReplyRunes ||
			len(performance.Packets) == 0 {
			return fmt.Errorf("play online music: invalid output")
		}
		agentFinished = time.Now()
		firstTextAt = agentFinished
		historyWindow.Add(transcript, reply)
		performanceChunks := make(chan VoiceSynthesisChunk, 1)
		performanceChunks <- VoiceSynthesisChunk{
			Text: reply, Packets: performance.Packets,
			Music:       performance.Music,
			TextReadyAt: firstTextAt, SynthesisStartedAt: synthesisStarted,
			SynthesisCompletedAt: agentFinished,
		}
		close(performanceChunks)
		chunks = performanceChunks
	} else if pipeline, ok := server.config.VoicePipeline.(StreamingToolAwareVoicePipeline); ok {
		server.config.Logger.Info("voice turn routed", "route", "agent")
		replyChunks, streamErr := pipeline.ReplyWithToolsStream(
			turnContext, transcript, history, session)
		if streamErr != nil {
			return fmt.Errorf("start streaming Agent reply: %w", streamErr)
		}
		var streamedChunks <-chan VoiceSynthesisChunk
		replyChunks = localizedReplyStream(turnContext,
			server.textLocalizer, replyChunks)
		streamedChunks, streamedSummary = synthesizeReplyStream(
			turnContext, server.config.VoicePipeline, replyChunks)
		chunks = primeVoiceSynthesis(
			turnContext, streamedChunks, ttsStartupPrimeTimeout)
	} else {
		if pipeline, ok := server.config.VoicePipeline.(ToolAwareVoicePipeline); ok {
			reply, err = pipeline.ReplyWithTools(
				turnContext, transcript, history, session)
		} else {
			reply, err = server.config.VoicePipeline.Reply(turnContext, transcript)
		}
		if err != nil {
			return fmt.Errorf("generate Agent reply: %w", err)
		}
		reply = strings.TrimSpace(server.textLocalizer.Normalize(reply))
		if reply == "" || !utf8.ValidString(reply) {
			return fmt.Errorf("generate Agent reply: invalid localized output")
		}
		agentFinished = time.Now()
		firstTextAt = agentFinished
		historyWindow.Add(transcript, reply)
		synthesisStarted = time.Now()
		chunks, err = synthesisChunks(
			turnContext, server.config.VoicePipeline, reply)
		if err != nil {
			return fmt.Errorf("start Agent speech synthesis: %w", err)
		}
	}
	pacer := &voicePacketPacer{}
	chunkCount := 0
	packetCount := 0
	for chunk := range chunks {
		if chunk.Err != nil {
			return fmt.Errorf("synthesize Agent reply: %w", chunk.Err)
		}
		chunk.Text = strings.TrimSpace(chunk.Text)
		if chunk.Text == "" || len(chunk.Packets) == 0 {
			return fmt.Errorf("synthesize Agent reply: invalid empty chunk")
		}
		if firstTextAt.IsZero() && !chunk.TextReadyAt.IsZero() {
			firstTextAt = chunk.TextReadyAt
			synthesisStarted = chunk.TextReadyAt
		}
		synthesisMS := int64(-1)
		readyAheadMS := int64(-1)
		if !chunk.SynthesisStartedAt.IsZero() &&
			!chunk.SynthesisCompletedAt.IsZero() {
			synthesisMS = chunk.SynthesisCompletedAt.Sub(
				chunk.SynthesisStartedAt).Milliseconds()
			readyAheadMS = time.Since(chunk.SynthesisCompletedAt).Milliseconds()
		}
		server.config.Logger.Info("TTS chunk ready for ordered playback",
			"chunk", chunkCount+1, "packets", len(chunk.Packets),
			"synthesis_ms", synthesisMS, "ready_ahead_ms", readyAheadMS)
		if chunkCount == 0 {
			if chunk.Music {
				pacer.packetInterval = voiceMusicPacketInterval
			}
			if err := session.writeJSON(turnContext, map[string]any{
				"session_id": session.sessionID, "type": "tts", "state": "start",
			}); err != nil {
				return err
			}
		}
		if err := session.writeTextJSON(turnContext, map[string]any{
			"session_id": session.sessionID, "type": "tts",
			"state": "sentence_start", "text": chunk.Text,
		}, chunk.Text); err != nil {
			return err
		}
		if err := pacer.Send(turnContext, session, chunk.Packets); err != nil {
			return err
		}
		chunkCount++
		packetCount += len(chunk.Packets)
	}
	if streamedSummary != nil {
		summary := <-streamedSummary
		if summary.Err != nil {
			return fmt.Errorf("stream Agent reply: %w", summary.Err)
		}
		reply = summary.Reply
		agentFinished = summary.CompletedAt
		if firstTextAt.IsZero() {
			firstTextAt = summary.FirstTextAt
		}
		if synthesisStarted.IsZero() {
			synthesisStarted = firstTextAt
		}
		historyWindow.Add(transcript, reply)
	}
	if chunkCount == 0 || pacer.firstPacketAt.IsZero() {
		return fmt.Errorf("synthesize Agent reply: no audio chunks")
	}
	if err := session.waitForPlaybackDrain(turnContext); err != nil {
		if turnContext.Err() != nil {
			return turnContext.Err()
		}
		// Compatibility fallback for an older firmware during a rolling update.
		// Current firmware acknowledges only after its Opus queue and I2S DMA
		// tail are empty, so the normal path does not rely on a guessed delay.
		server.config.Logger.Warn("device playback drain acknowledgement missing",
			"error", err)
		if err := pacer.WaitForPlaybackDrain(turnContext); err != nil {
			return err
		}
	}
	if err := session.writeJSON(turnContext, map[string]any{
		"session_id": session.sessionID, "type": "tts", "state": "stop",
	}); err != nil {
		return err
	}
	server.update(func(status *PublicStatus) {
		status.Microphone = "語音對話通過"
		status.CompletedTurns++
		status.LastEvent = "Agent 回覆已送達 ESP32；對話內容不留存"
	})
	historyEntriesAfter, historyRunesAfter := historyWindow.Metrics()
	server.config.Logger.Info("Agent voice turn completed",
		"audio_input_packets", len(capturedPackets),
		"history_entries_before", historyEntries,
		"history_runes_before", historyRunes,
		"history_entries_after", historyEntriesAfter,
		"history_runes_after", historyRunesAfter,
		"speaker_known", identity.match.Known,
		"speaker_similarity", math.Round(identity.match.Similarity*1000)/1000,
		"asr_ms", asrFinished.Sub(turnStarted).Milliseconds(),
		"agent_ms", agentFinished.Sub(asrFinished).Milliseconds(),
		"agent_first_sentence_ms", firstTextAt.Sub(asrFinished).Milliseconds(),
		"tts_first_audio_ms", pacer.firstPacketAt.Sub(synthesisStarted).Milliseconds(),
		"first_audio_ms", pacer.firstPacketAt.Sub(turnStarted).Milliseconds(),
		"tts_chunks", chunkCount,
		"audio_output_packets", packetCount,
		"total_ms", time.Since(turnStarted).Milliseconds())
	return nil
}

func synthesisChunks(ctx context.Context, pipeline VoicePipeline,
	reply string) (<-chan VoiceSynthesisChunk, error) {
	if chunked, ok := pipeline.(ChunkedVoicePipeline); ok {
		return chunked.SynthesizeChunks(ctx, reply)
	}
	channel := make(chan VoiceSynthesisChunk, 1)
	packets, err := pipeline.Synthesize(ctx, reply)
	channel <- VoiceSynthesisChunk{Text: reply, Packets: packets, Err: err}
	close(channel)
	return channel, nil
}

type voicePacketPacer struct {
	sent           int
	packetInterval time.Duration
	nextPacketAt   time.Time
	firstPacketAt  time.Time
}

func (pacer *voicePacketPacer) interval() time.Duration {
	if pacer.packetInterval > 0 {
		return pacer.packetInterval
	}
	// Match the encoded frame's playout clock. Sending even two milliseconds
	// faster accumulates more than a full second of backlog in a long answer.
	return voiceSpeechPacketInterval
}

func (pacer *voicePacketPacer) packetDeadline(now time.Time) time.Time {
	if pacer.sent < voiceInitialJitterBurstFrames || pacer.nextPacketAt.IsZero() ||
		pacer.nextPacketAt.Before(now) {
		// A late source delta represents a real generation/network pause. Shift
		// the clock forward instead of bursting every allegedly overdue packet.
		return now
	}
	return pacer.nextPacketAt
}

func (pacer *voicePacketPacer) Send(ctx context.Context,
	session *deviceSession, packets [][]byte) error {
	return pacer.send(ctx, ctx, session, packets)
}

// send separates pacing cancellation from the WebSocket frame write. A
// Realtime barge-in may cancel a pending playback timer, but cancelling a
// coder/websocket Write midway also closes the whole device connection. The
// stable write context lets an in-flight frame finish before old generations
// are discarded.
func (pacer *voicePacketPacer) send(pacingContext, writeContext context.Context,
	session *deviceSession, packets [][]byte) error {
	interval := pacer.interval()
	for _, packet := range packets {
		deadline := pacer.packetDeadline(time.Now())
		if delay := time.Until(deadline); delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-pacingContext.Done():
				timer.Stop()
				return pacingContext.Err()
			case <-timer.C:
			}
		}
		if err := session.writeBinary(writeContext, packet); err != nil {
			return err
		}
		sentAt := time.Now()
		if pacer.firstPacketAt.IsZero() {
			pacer.firstPacketAt = sentAt
		}
		pacer.sent++
		// Base the next deadline on the actual completed write. This prevents a
		// delayed WebSocket write from creating an immediate catch-up burst.
		pacer.nextPacketAt = sentAt.Add(interval)
	}
	return nil
}

func (pacer *voicePacketPacer) WaitForPlaybackDrain(ctx context.Context) error {
	if pacer.sent < voiceInitialJitterBurstFrames {
		// The ESP32 intentionally waits for TTS stop before playing a response
		// shorter than its jitter prebuffer.
		return nil
	}
	timer := time.NewTimer(
		time.Duration(voiceInitialJitterBurstFrames)*pacer.interval() +
			voicePlaybackDrainMargin)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func sendVoicePackets(ctx context.Context, session *deviceSession,
	packets [][]byte) error {
	return (&voicePacketPacer{}).Send(ctx, session, packets)
}

func (server *Server) handleMCP(ctx context.Context, session *deviceSession,
	payload json.RawMessage) error {
	var response mcpWireResponse
	if json.Unmarshal(payload, &response) != nil || response.ID < 1 ||
		(response.ID < firstDynamicMCPID && len(response.Error) > 0) {
		return nil
	}
	if response.ID >= firstDynamicMCPID {
		session.deliverMCP(response)
		return nil
	}
	switch response.ID {
	case 1:
		server.update(func(status *PublicStatus) {
			status.ESPClaw = "MCP 已初始化"
			status.LastEvent = "Gateway 正在查詢裝置能力"
		})
		return session.sendMCP(ctx, 2, "tools/list",
			map[string]any{"cursor": "", "withUserTools": true})
	case 2:
		var result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		}
		if json.Unmarshal(response.Result, &result) != nil {
			return nil
		}
		statusTool := ""
		names := make([]string, 0, len(result.Tools))
		for _, tool := range result.Tools {
			if statusTool == "" && (tool.Name == "device.get_status" ||
				tool.Name == "self.get_device_status") {
				statusTool = tool.Name
			}
			names = append(names, tool.Name)
		}
		session.setTools(names)
		_, hasVolume := session.firstTool(
			"device.set_volume", "self.audio_speaker.set_volume")
		_, hasReboot := session.firstTool("device.reboot", "self.reboot")
		server.config.Logger.Info("Device MCP tool catalog received",
			"tools", len(names), "status", statusTool != "",
			"volume", hasVolume, "reboot", hasReboot)
		if statusTool == "" {
			server.update(func(status *PublicStatus) {
				status.ESPClaw = "找不到狀態能力"
			})
			return nil
		}
		return session.sendMCP(ctx, 3, "tools/call",
			map[string]any{"name": statusTool, "arguments": map[string]any{}})
	case 3:
		server.update(func(status *PublicStatus) {
			status.ESPClaw = "狀態能力通過"
			status.LastEvent = "ESP32 裝置狀態能力已由 Gateway 呼叫成功"
		})
	}
	return nil
}

func (server *Server) sendTestTurn(ctx context.Context,
	session *deviceSession) error {
	sttText := server.textLocalizer.Normalize("本機 Gateway 已收到語音")
	if err := session.writeTextJSON(ctx, map[string]any{
		"session_id": session.sessionID, "type": "stt",
		"text": sttText,
	}, sttText); err != nil {
		return err
	}
	for _, state := range []string{"start", "sentence_start"} {
		message := map[string]any{
			"session_id": session.sessionID, "type": "tts", "state": state,
		}
		if state == "sentence_start" {
			message["text"] = server.textLocalizer.Normalize(
				"本機 Gateway 音訊通道測試成功")
		}
		text, _ := message["text"].(string)
		if err := session.writeTextJSON(ctx, message, text); err != nil {
			return err
		}
	}
	packets := make([][]byte, server.config.TonePackets)
	for index := range packets {
		packets[index] = server.speech[index%len(server.speech)]
	}
	if err := sendVoicePackets(ctx, session, packets); err != nil {
		return err
	}
	if err := session.writeJSON(ctx, map[string]any{
		"session_id": session.sessionID, "type": "tts", "state": "stop",
	}); err != nil {
		return err
	}
	server.update(func(status *PublicStatus) {
		status.Microphone = "音訊上傳通過"
		status.CompletedTurns++
		status.LastEvent = "Gateway 已回傳可辨識的人聲測試"
	})
	return nil
}

func (server *Server) writeJSON(ctx context.Context, connection *websocket.Conn,
	value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return connection.Write(ctx, websocket.MessageText, payload)
}

func randomSessionID() (string, error) {
	value := make([]byte, 12)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return "gateway-" + hex.EncodeToString(value), nil
}

const dashboardHTML = `<!doctype html>
<html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ESP32 Gateway 測試</title><style>
:root{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#eaf7f1;background:#07130f}body{margin:0;padding:28px}main{max-width:780px;margin:auto}.hero{padding:26px;border:1px solid #285746;border-radius:18px;background:linear-gradient(135deg,#102a22,#0b1d18)}h1{font-size:28px;margin:0 0 8px}p{color:#a9c8bb}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;margin-top:18px}.card{padding:18px;border-radius:14px;background:#10231d;border:1px solid #24483b}.label{font-size:13px;color:#83aa9b}.value{font-size:21px;font-weight:650;margin-top:7px}.event{margin-top:14px;padding:16px;border-radius:12px;background:#162a24;color:#d7eee5}.ok{color:#62e6aa}.foot{font-size:12px;color:#719486;margin-top:15px}</style></head>
<body><main><section class="hero"><h1>ESP32 自建 Gateway</h1><p>語音由自己的 Gateway 管理；AI 供應商金鑰不會進入 ESP32，對話內容不由 Gateway 留存。</p>
<div class="grid"><div class="card"><div class="label">Gateway</div><div class="value ok" id="gateway">讀取中</div></div>
<div class="card"><div class="label">ESP32 裝置</div><div class="value" id="device">讀取中</div></div>
<div class="card"><div class="label">麥克風通道</div><div class="value" id="microphone">讀取中</div></div>
<div class="card"><div class="label">ESP-Claw Agent 工具</div><div class="value" id="esp_claw">讀取中</div></div>
<div class="card"><div class="label">個人音色</div><div class="value" id="voice_clone">讀取中</div></div>
<div class="card"><div class="label">說話者身份</div><div class="value" id="speaker_identity">讀取中</div></div>
<div class="card"><div class="label">連網查詢</div><div class="value" id="web_access">讀取中</div></div></div>
<div class="event" id="last_event">等待狀態</div><div class="foot"><span id="counts"></span> · <span id="updated_at"></span></div></section></main>
<script>async function refresh(){try{const r=await fetch('/status',{cache:'no-store'}),s=await r.json();for(const k of ['gateway','device','microphone','esp_claw','voice_clone','speaker_identity','web_access','last_event','updated_at'])document.getElementById(k).textContent=s[k];document.getElementById('counts').textContent='收到 '+s.audio_packets+' 個音訊封包，完成 '+s.completed_turns+' 輪測試'}catch(e){document.getElementById('gateway').textContent='無法連線'}}refresh();setInterval(refresh,1000)</script></body></html>`
