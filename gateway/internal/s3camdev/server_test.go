package s3camdev

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type integrationToolPipeline struct{}

type failingReplyPipeline struct{}

type integrationSingingPipeline struct {
	singCalls       atomic.Int32
	replyCalls      atomic.Int32
	synthesizeCalls atomic.Int32
}

func (pipeline *integrationSingingPipeline) Transcribe(
	context.Context, [][]byte) (string, error) {
	return "請唱一首關於小智的原創短歌", nil
}

func (pipeline *integrationSingingPipeline) Reply(
	context.Context, string) (string, error) {
	pipeline.replyCalls.Add(1)
	return "ordinary reply must not run", nil
}

func (pipeline *integrationSingingPipeline) Synthesize(
	context.Context, string) ([][]byte, error) {
	pipeline.synthesizeCalls.Add(1)
	return nil, io.ErrUnexpectedEOF
}

func (pipeline *integrationSingingPipeline) Sing(context.Context, string,
	[]ConversationTurn, AgentToolExecutor) (SongPerformance, error) {
	pipeline.singCalls.Add(1)
	return SongPerformance{
		DisplayText: "原創短歌《小智出發》\n跟著晨光一起出發",
		Packets:     [][]byte{{0x01, 0x02, 0x03}},
		Music:       true,
	}, nil
}

func TestMusicPlaybackPacingPreservesDeviceQueueHeadroom(t *testing.T) {
	if voiceInitialJitterBurstFrames > 12 {
		t.Fatalf("initial burst leaves too little queue headroom: %d",
			voiceInitialJitterBurstFrames)
	}
	pacer := &voicePacketPacer{packetInterval: voiceMusicPacketInterval}
	if pacer.interval() != voiceFrameDuration {
		t.Fatalf("music pacing must match the encoded playout clock: %s",
			pacer.interval())
	}
	if ordinary := (&voicePacketPacer{}).interval(); ordinary != voiceFrameDuration {
		t.Fatalf("ordinary speech pacing drifts from playout: %s", ordinary)
	}
}

func TestVoicePacketPacerShiftsLateClockWithoutCatchUpBurst(t *testing.T) {
	now := time.Unix(123, 0)
	pacer := &voicePacketPacer{
		sent:         voiceInitialJitterBurstFrames,
		nextPacketAt: now.Add(-500 * time.Millisecond),
	}
	if deadline := pacer.packetDeadline(now); !deadline.Equal(now) {
		t.Fatalf("late packet retained stale catch-up deadline: got=%s want=%s",
			deadline, now)
	}
	pacer.nextPacketAt = now.Add(voiceFrameDuration)
	if deadline := pacer.packetDeadline(now); !deadline.Equal(pacer.nextPacketAt) {
		t.Fatalf("on-time packet lost stable pacing deadline: got=%s want=%s",
			deadline, pacer.nextPacketAt)
	}
}

func (failingReplyPipeline) Transcribe(context.Context, [][]byte) (string, error) {
	return "測試失敗回復", nil
}

func (failingReplyPipeline) Reply(context.Context, string) (string, error) {
	return "", io.ErrUnexpectedEOF
}

func (failingReplyPipeline) Synthesize(context.Context, string) ([][]byte, error) {
	return nil, io.ErrUnexpectedEOF
}

func (integrationToolPipeline) Transcribe(context.Context, [][]byte) (string, error) {
	return "音量調成百分之五十", nil
}

func (integrationToolPipeline) Reply(context.Context, string) (string, error) {
	return "unused", nil
}

func (integrationToolPipeline) ReplyWithTools(ctx context.Context, _ string,
	_ []ConversationTurn, executor AgentToolExecutor) (string, error) {
	result, err := executor.ExecuteTool(ctx, "device_set_volume",
		json.RawMessage(`{"level":50}`))
	if err != nil {
		return "", err
	}
	if !strings.Contains(result, `"level":50`) {
		return "", io.ErrUnexpectedEOF
	}
	return "音量已調成百分之五十。", nil
}

func (integrationToolPipeline) ReplyWithToolsStream(ctx context.Context,
	transcript string, history []ConversationTurn,
	executor AgentToolExecutor) (<-chan VoiceReplyChunk, error) {
	chunks := make(chan VoiceReplyChunk, 1)
	go func() {
		defer close(chunks)
		reply, err := (integrationToolPipeline{}).ReplyWithTools(
			ctx, transcript, history, executor)
		if err != nil {
			chunks <- VoiceReplyChunk{Err: err}
			return
		}
		chunks <- VoiceReplyChunk{Text: reply}
	}()
	return chunks, nil
}

func (integrationToolPipeline) Synthesize(context.Context, string) ([][]byte, error) {
	return [][]byte{{0x01, 0x02, 0x03}}, nil
}

func TestLocalGatewayBootstrapVoiceAndMCP(t *testing.T) {
	const (
		deviceID = "20:6e:f1:b3:9c:c4"
		token    = "0123456789abcdef0123456789abcdef"
	)
	gateway, err := New(Config{
		PublicWebSocketURL:          "ws://192.168.1.171:8766/v1/device",
		ExpectedDeviceID:            deviceID,
		Token:                       token,
		TriggerAudioPackets:         100,
		TonePackets:                 2,
		DeviceTimezoneOffsetMinutes: 480,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway.Handler())
	defer server.Close()

	request, err := http.NewRequest(http.MethodPost, server.URL+"/xiaozhi/ota/",
		bytes.NewBufferString(`{"version":2}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Device-Id", deviceID)
	request.Header.Set("Client-Id", "test-client")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var bootstrap struct {
		ServerTime struct {
			Timestamp      int64 `json:"timestamp"`
			TimezoneOffset int   `json:"timezone_offset"`
		} `json:"server_time"`
		WebSocket struct {
			URL   string `json:"url"`
			Token string `json:"token"`
		} `json:"websocket"`
	}
	if response.StatusCode != http.StatusOK ||
		json.NewDecoder(response.Body).Decode(&bootstrap) != nil ||
		bootstrap.WebSocket.URL != "ws://192.168.1.171:8766/v1/device" ||
		bootstrap.WebSocket.Token != token ||
		bootstrap.ServerTime.Timestamp <= 0 ||
		bootstrap.ServerTime.TimezoneOffset != 480 ||
		response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("invalid bootstrap response: status=%d response=%+v",
			response.StatusCode, bootstrap)
	}

	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+token)
	headers.Set("Protocol-Version", "1")
	headers.Set("Device-Id", deviceID)
	headers.Set("Client-Id", "test-client")
	socket, _, err := websocket.Dial(context.Background(),
		"ws"+strings.TrimPrefix(server.URL, "http")+"/v1/device",
		&websocket.DialOptions{HTTPHeader: headers})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hello := `{"type":"hello","version":1,"features":{"mcp":true},` +
		`"transport":"websocket","audio_params":{"format":"opus",` +
		`"sample_rate":16000,"channels":1,"frame_duration":60}}`
	if err := socket.Write(ctx, websocket.MessageText, []byte(hello)); err != nil {
		t.Fatal(err)
	}
	serverHello := readJSON(t, ctx, socket)
	sessionID, _ := serverHello["session_id"].(string)
	if serverHello["type"] != "hello" || sessionID == "" {
		t.Fatalf("invalid server hello: %+v", serverHello)
	}
	serverTime, _ := serverHello["server_time"].(map[string]any)
	if timestamp, ok := serverTime["timestamp"].(float64); !ok || timestamp < 1577836800000 {
		t.Fatalf("server hello is missing a valid clock source: %+v", serverHello)
	}
	initialize := readJSON(t, ctx, socket)
	assertMCPMethod(t, initialize, "initialize")
	writeMCPResult(t, ctx, socket, sessionID, 1, map[string]any{})
	list := readJSON(t, ctx, socket)
	assertMCPMethod(t, list, "tools/list")
	writeMCPResult(t, ctx, socket, sessionID, 2, map[string]any{
		"tools": []map[string]any{{"name": "device.get_status"}},
	})
	call := readJSON(t, ctx, socket)
	assertMCPMethod(t, call, "tools/call")
	writeMCPResult(t, ctx, socket, sessionID, 3, map[string]any{
		"content": []map[string]any{{"type": "text", "text": "status omitted"}},
		"isError": false,
	})

	writeJSON(t, ctx, socket, map[string]any{
		"session_id": sessionID, "type": "listen", "state": "start", "mode": "auto",
	})
	for range 2 {
		if err := socket.Write(ctx, websocket.MessageBinary, []byte{0x78, 0x01}); err != nil {
			t.Fatal(err)
		}
	}
	// Current firmware performs endpointing and explicitly closes a turn once
	// trailing silence is detected. The Gateway must process the audio instead
	// of merely switching its receiver off.
	writeJSON(t, ctx, socket, map[string]any{
		"session_id": sessionID, "type": "listen", "state": "stop",
	})
	if event := readJSON(t, ctx, socket); event["type"] != "stt" {
		t.Fatalf("missing STT event: %+v", event)
	}
	for _, expected := range []string{"start", "sentence_start"} {
		event := readJSON(t, ctx, socket)
		if event["type"] != "tts" || event["state"] != expected {
			t.Fatalf("invalid TTS %s event: %+v", expected, event)
		}
	}
	for range 2 {
		messageType, payload, err := socket.Read(ctx)
		if err != nil || messageType != websocket.MessageBinary || len(payload) != 180 {
			t.Fatalf("invalid Opus test frame: type=%v bytes=%d err=%v",
				messageType, len(payload), err)
		}
	}
	if event := readJSON(t, ctx, socket); event["type"] != "tts" || event["state"] != "stop" {
		t.Fatalf("missing TTS stop: %+v", event)
	}
	status := gateway.Snapshot()
	if status.ESPClaw != "狀態能力通過" || status.AudioPackets != 2 ||
		status.CompletedTurns != 1 || status.Microphone != "音訊上傳通過" {
		t.Fatalf("unexpected public status: %+v", status)
	}
}

func TestGatewayKeepsIdleDeviceSessionAlive(t *testing.T) {
	const (
		deviceID = "20:6e:f1:b3:9c:c4"
		token    = "0123456789abcdef0123456789abcdef"
	)
	gateway, err := New(Config{
		PublicWebSocketURL: "ws://127.0.0.1:8766/v1/device",
		ExpectedDeviceID:   deviceID, Token: token,
		deviceKeepalive: 80 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway.Handler())
	defer server.Close()
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+token)
	headers.Set("Protocol-Version", "1")
	headers.Set("Device-Id", deviceID)
	socket, _, err := websocket.Dial(context.Background(),
		"ws"+strings.TrimPrefix(server.URL, "http")+"/v1/device",
		&websocket.DialOptions{HTTPHeader: headers})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	hello := `{"type":"hello","version":1,"features":{"mcp":true},` +
		`"transport":"websocket","audio_params":{"format":"opus",` +
		`"sample_rate":16000,"channels":1,"frame_duration":60}}`
	if err := socket.Write(ctx, websocket.MessageText, []byte(hello)); err != nil {
		t.Fatal(err)
	}
	serverHello := readJSON(t, ctx, socket)
	sessionID, _ := serverHello["session_id"].(string)
	initialize := readJSON(t, ctx, socket)
	assertMCPMethod(t, initialize, "initialize")
	writeMCPResult(t, ctx, socket, sessionID, 1, map[string]any{})
	list := readJSON(t, ctx, socket)
	assertMCPMethod(t, list, "tools/list")
	writeMCPResult(t, ctx, socket, sessionID, 2,
		map[string]any{"tools": []map[string]any{}})
	for {
		event := readJSON(t, ctx, socket)
		if event["type"] == "tts" && event["state"] == "keepalive" {
			if event["session_id"] != sessionID {
				t.Fatalf("keepalive has wrong session: %+v", event)
			}
			return
		}
	}
}

func TestOldConnectionCannotOverwriteNewConnectionStatus(t *testing.T) {
	gateway, err := New(Config{
		PublicWebSocketURL: "ws://192.168.1.171:8766/v1/device",
		ExpectedDeviceID:   "20:6e:f1:b3:9c:c4",
		Token:              "0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		t.Fatal(err)
	}
	oldGeneration := gateway.beginDeviceConnection()
	newGeneration := gateway.beginDeviceConnection()
	gateway.endDeviceConnection(oldGeneration)
	if status := gateway.Snapshot(); status.Device != "已連線" {
		t.Fatalf("old connection overwrote new status: %+v", status)
	}
	gateway.endDeviceConnection(newGeneration)
	if status := gateway.Snapshot(); status.Device != "已中斷" {
		t.Fatalf("latest connection did not update status: %+v", status)
	}
}

func TestAgentFailureReturnsDeviceErrorInsteadOfLeavingThinking(t *testing.T) {
	const (
		deviceID = "20:6e:f1:b3:9c:c4"
		token    = "0123456789abcdef0123456789abcdef"
	)
	gateway, err := New(Config{
		PublicWebSocketURL: "ws://192.168.1.171:8766/v1/device",
		ExpectedDeviceID:   deviceID, Token: token, TriggerAudioPackets: 1,
		VoicePipeline: failingReplyPipeline{},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway.Handler())
	defer server.Close()
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+token)
	headers.Set("Protocol-Version", "1")
	headers.Set("Device-Id", deviceID)
	socket, _, err := websocket.Dial(context.Background(),
		"ws"+strings.TrimPrefix(server.URL, "http")+"/v1/device",
		&websocket.DialOptions{HTTPHeader: headers})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hello := `{"type":"hello","version":1,"features":{"mcp":true},` +
		`"transport":"websocket","audio_params":{"format":"opus",` +
		`"sample_rate":16000,"channels":1,"frame_duration":60}}`
	if err := socket.Write(ctx, websocket.MessageText, []byte(hello)); err != nil {
		t.Fatal(err)
	}
	serverHello := readJSON(t, ctx, socket)
	sessionID, _ := serverHello["session_id"].(string)
	if sessionID == "" {
		t.Fatalf("missing session ID: %+v", serverHello)
	}
	_ = readJSON(t, ctx, socket) // Initial MCP capability negotiation.
	writeJSON(t, ctx, socket, map[string]any{
		"session_id": sessionID, "type": "listen", "state": "start",
	})
	if err := socket.Write(ctx, websocket.MessageBinary, []byte{0x01}); err != nil {
		t.Fatal(err)
	}
	if event := readJSON(t, ctx, socket); event["type"] != "listen" ||
		event["state"] != "stop" {
		t.Fatalf("missing automatic listen stop: %+v", event)
	}
	if event := readJSON(t, ctx, socket); event["type"] != "stt" {
		t.Fatalf("missing STT event: %+v", event)
	}
	event := readJSON(t, ctx, socket)
	if event["type"] != "error" || event["code"] != "agent_turn_failed" {
		t.Fatalf("failure left device without a recovery event: %+v", event)
	}
}

func TestExplicitSingingUsesPreparedPerformanceWithoutSecondTTS(t *testing.T) {
	const (
		deviceID = "20:6e:f1:b3:9c:c4"
		token    = "0123456789abcdef0123456789abcdef"
	)
	pipeline := &integrationSingingPipeline{}
	gateway, err := New(Config{
		PublicWebSocketURL: "ws://192.168.1.171:8766/v1/device",
		ExpectedDeviceID:   deviceID, Token: token, TriggerAudioPackets: 1,
		VoicePipeline: pipeline,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway.Handler())
	defer server.Close()
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+token)
	headers.Set("Protocol-Version", "1")
	headers.Set("Device-Id", deviceID)
	socket, _, err := websocket.Dial(context.Background(),
		"ws"+strings.TrimPrefix(server.URL, "http")+"/v1/device",
		&websocket.DialOptions{HTTPHeader: headers})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hello := `{"type":"hello","version":1,"features":{"mcp":true},` +
		`"transport":"websocket","audio_params":{"format":"opus",` +
		`"sample_rate":16000,"channels":1,"frame_duration":60}}`
	if err := socket.Write(ctx, websocket.MessageText, []byte(hello)); err != nil {
		t.Fatal(err)
	}
	serverHello := readJSON(t, ctx, socket)
	sessionID, _ := serverHello["session_id"].(string)
	if sessionID == "" {
		t.Fatalf("missing session ID: %+v", serverHello)
	}
	_ = readJSON(t, ctx, socket) // Initial MCP capability negotiation.
	writeJSON(t, ctx, socket, map[string]any{
		"session_id": sessionID, "type": "listen", "state": "start",
	})
	if err := socket.Write(ctx, websocket.MessageBinary, []byte{0x01}); err != nil {
		t.Fatal(err)
	}
	if event := readJSON(t, ctx, socket); event["type"] != "listen" ||
		event["state"] != "stop" {
		t.Fatalf("missing automatic listen stop: %+v", event)
	}
	if event := readJSON(t, ctx, socket); event["type"] != "stt" {
		t.Fatalf("missing singing STT event: %+v", event)
	}
	if event := readJSON(t, ctx, socket); event["type"] != "tts" ||
		event["state"] != "start" {
		t.Fatalf("missing singing TTS start: %+v", event)
	}
	sentence := readJSON(t, ctx, socket)
	if sentence["type"] != "tts" || sentence["state"] != "sentence_start" ||
		!strings.Contains(sentence["text"].(string), "原創短歌") {
		t.Fatalf("invalid singing display event: %+v", sentence)
	}
	messageType, _, err := socket.Read(ctx)
	if err != nil || messageType != websocket.MessageBinary {
		t.Fatalf("missing singing audio: type=%v err=%v", messageType, err)
	}
	finish := readJSON(t, ctx, socket)
	if finish["type"] != "tts" || finish["state"] != "finish" {
		t.Fatalf("missing singing playback finish: %+v", finish)
	}
	writeJSON(t, ctx, socket, map[string]any{
		"session_id": sessionID, "type": "tts", "state": "drained",
	})
	if event := readJSON(t, ctx, socket); event["state"] != "stop" {
		t.Fatalf("missing singing TTS stop: %+v", event)
	}
	if pipeline.singCalls.Load() != 1 || pipeline.replyCalls.Load() != 0 ||
		pipeline.synthesizeCalls.Load() != 0 {
		t.Fatalf("singing route was not isolated: sing=%d reply=%d tts=%d",
			pipeline.singCalls.Load(), pipeline.replyCalls.Load(),
			pipeline.synthesizeCalls.Load())
	}
}

func TestLowRiskVolumeToolExecutesWithoutConfirmation(t *testing.T) {
	const (
		deviceID = "20:6e:f1:b3:9c:c4"
		token    = "0123456789abcdef0123456789abcdef"
	)
	gateway, err := New(Config{
		PublicWebSocketURL: "ws://192.168.1.171:8766/v1/device",
		ExpectedDeviceID:   deviceID, Token: token, TriggerAudioPackets: 1,
		VoicePipeline: integrationToolPipeline{},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway.Handler())
	defer server.Close()
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+token)
	headers.Set("Protocol-Version", "1")
	headers.Set("Device-Id", deviceID)
	socket, _, err := websocket.Dial(context.Background(),
		"ws"+strings.TrimPrefix(server.URL, "http")+"/v1/device",
		&websocket.DialOptions{HTTPHeader: headers})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hello := `{"type":"hello","version":1,"features":{"mcp":true},` +
		`"transport":"websocket","audio_params":{"format":"opus",` +
		`"sample_rate":16000,"channels":1,"frame_duration":60}}`
	if err := socket.Write(ctx, websocket.MessageText, []byte(hello)); err != nil {
		t.Fatal(err)
	}
	serverHello := readJSON(t, ctx, socket)
	sessionID := serverHello["session_id"].(string)
	initialize := readJSON(t, ctx, socket)
	assertMCPMethod(t, initialize, "initialize")
	writeMCPResult(t, ctx, socket, sessionID, 1, map[string]any{})
	list := readJSON(t, ctx, socket)
	assertMCPMethod(t, list, "tools/list")
	listParams := list["payload"].(map[string]any)["params"].(map[string]any)
	if listParams["withUserTools"] != true {
		t.Fatalf("native user-only tools were not requested: %+v", listParams)
	}
	writeMCPResult(t, ctx, socket, sessionID, 2, map[string]any{
		"tools": []map[string]any{
			{"name": "self.get_device_status"},
			{"name": "self.audio_speaker.set_volume"},
			{"name": "self.reboot"},
		},
	})
	bootstrapCall := readJSON(t, ctx, socket)
	assertMCPMethod(t, bootstrapCall, "tools/call")
	bootstrapParams := bootstrapCall["payload"].(map[string]any)["params"].(map[string]any)
	if bootstrapParams["name"] != "self.get_device_status" {
		t.Fatalf("native status alias was not used: %+v", bootstrapParams)
	}
	writeMCPResult(t, ctx, socket, sessionID, 3, map[string]any{
		"content": []map[string]any{{"type": "text", "text": `{"ok":true}`}},
		"isError": false,
	})
	writeJSON(t, ctx, socket, map[string]any{
		"session_id": sessionID, "type": "listen", "state": "start",
	})
	if err := socket.Write(ctx, websocket.MessageBinary, []byte{0x01}); err != nil {
		t.Fatal(err)
	}
	if event := readJSON(t, ctx, socket); event["type"] != "listen" ||
		event["state"] != "stop" {
		t.Fatalf("missing automatic listen stop: %+v", event)
	}
	if event := readJSON(t, ctx, socket); event["type"] != "stt" {
		t.Fatalf("missing STT event: %+v", event)
	}
	actionCall := readJSON(t, ctx, socket)
	assertMCPMethod(t, actionCall, "tools/call")
	payload := actionCall["payload"].(map[string]any)
	params := payload["params"].(map[string]any)
	arguments := params["arguments"].(map[string]any)
	if params["name"] != "self.audio_speaker.set_volume" ||
		arguments["volume"] != float64(50) {
		t.Fatalf("wrong volume action: %+v", params)
	}
	writeMCPResult(t, ctx, socket, sessionID, int(payload["id"].(float64)),
		map[string]any{
			"content": []map[string]any{{"type": "text", "text": `{"ok":true,"level":50}`}},
			"isError": false,
		})
	for _, expected := range []string{"start", "sentence_start"} {
		event := readJSON(t, ctx, socket)
		if event["type"] != "tts" || event["state"] != expected {
			t.Fatalf("missing TTS %s: %+v", expected, event)
		}
	}
	messageType, _, err := socket.Read(ctx)
	if err != nil || messageType != websocket.MessageBinary {
		t.Fatalf("missing TTS audio: type=%v err=%v", messageType, err)
	}
	finish := readJSON(t, ctx, socket)
	if finish["type"] != "tts" || finish["state"] != "finish" {
		t.Fatalf("missing playback finish: %+v", finish)
	}
	writeJSON(t, ctx, socket, map[string]any{
		"session_id": sessionID, "type": "tts", "state": "drained",
	})
	if event := readJSON(t, ctx, socket); event["state"] != "stop" {
		t.Fatalf("missing TTS stop: %+v", event)
	}
}

func TestBootstrapTokenIsRequiredWhenConfigured(t *testing.T) {
	const (
		deviceID       = "20:6e:f1:b3:9c:c4"
		bootstrapToken = "bootstrap-0123456789abcdef0123456789abcdef"
	)
	gateway, err := New(Config{
		PublicWebSocketURL: "wss://voice.example.com/v1/device",
		ExpectedDeviceID:   deviceID,
		BootstrapToken:     bootstrapToken,
		Token:              "0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway.Handler())
	defer server.Close()

	makeRequest := func(authorization string) *http.Response {
		t.Helper()
		request, requestErr := http.NewRequest(http.MethodPost,
			server.URL+"/xiaozhi/ota/", bytes.NewBufferString(`{"version":2}`))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Header.Set("Device-Id", deviceID)
		request.Header.Set("Client-Id", "test-client")
		if authorization != "" {
			request.Header.Set("Authorization", authorization)
		}
		response, requestErr := http.DefaultClient.Do(request)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		return response
	}

	for _, authorization := range []string{"", "Bearer wrong-token"} {
		response := makeRequest(authorization)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("bootstrap accepted %q: status=%d",
				authorization, response.StatusCode)
		}
	}
	response := makeRequest("Bearer " + bootstrapToken)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("valid bootstrap token was rejected: status=%d",
			response.StatusCode)
	}
}

func TestCloudModeRejectsPlaintextWebSocket(t *testing.T) {
	_, err := New(Config{
		PublicWebSocketURL: "ws://voice.example.com/v1/device",
		ExpectedDeviceID:   "20:6e:f1:b3:9c:c4",
		RequireTLS:         true,
	})
	if err == nil {
		t.Fatal("cloud mode accepted a plaintext public WebSocket URL")
	}
}

func TestAllowedDeviceIDsExtendLegacyDevice(t *testing.T) {
	const (
		legacyDeviceID = "20:6e:f1:b3:9c:c4"
		watchDeviceID  = "28:84:85:b4:ed:10"
		legacyToken    = "legacy-0123456789abcdef0123456789abcdef"
		watchToken     = "watch-0123456789abcdef0123456789abcdef"
	)
	gateway, err := New(Config{
		PublicWebSocketURL:    "wss://voice.example.com/v1/device",
		ExpectedDeviceID:      legacyDeviceID,
		AllowedDeviceIDs:      []string{watchDeviceID},
		BootstrapToken:        legacyToken,
		DeviceBootstrapTokens: map[string]string{watchDeviceID: watchToken},
		Token:                 "0123456789abcdef0123456789abcdef",
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway.Handler())
	defer server.Close()

	bootstrapStatus := func(deviceID, bootstrapToken string) int {
		t.Helper()
		request, requestErr := http.NewRequest(http.MethodPost,
			server.URL+"/xiaozhi/ota/", bytes.NewBufferString(`{"version":2}`))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		request.Header.Set("Device-Id", deviceID)
		request.Header.Set("Client-Id", "test-client")
		request.Header.Set("Authorization", "Bearer "+bootstrapToken)
		response, requestErr := http.DefaultClient.Do(request)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		defer response.Body.Close()
		return response.StatusCode
	}

	for deviceID, bootstrapToken := range map[string]string{
		legacyDeviceID: legacyToken,
		watchDeviceID:  watchToken,
	} {
		if status := bootstrapStatus(deviceID, bootstrapToken); status != http.StatusOK {
			t.Fatalf("allowed device %q was rejected: status=%d", deviceID, status)
		}
	}
	if status := bootstrapStatus(watchDeviceID, legacyToken); status != http.StatusUnauthorized {
		t.Fatalf("watch accepted legacy device token: status=%d", status)
	}
	if status := bootstrapStatus("unknown-device", watchToken); status != http.StatusUnauthorized {
		t.Fatalf("unknown device was accepted: status=%d", status)
	}
}

func readJSON(t *testing.T, ctx context.Context, socket *websocket.Conn) map[string]any {
	t.Helper()
	messageType, payload, err := socket.Read(ctx)
	if err != nil || messageType != websocket.MessageText {
		t.Fatalf("read JSON: type=%v err=%v", messageType, err)
	}
	var output map[string]any
	if err := json.Unmarshal(payload, &output); err != nil {
		t.Fatalf("decode JSON: %v payload=%s", err, payload)
	}
	return output
}

func writeJSON(t *testing.T, ctx context.Context, socket *websocket.Conn, value any) {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil || socket.Write(ctx, websocket.MessageText, payload) != nil {
		t.Fatalf("write JSON: %v", err)
	}
}

func writeMCPResult(t *testing.T, ctx context.Context, socket *websocket.Conn,
	sessionID string, id int, result any) {
	t.Helper()
	writeJSON(t, ctx, socket, map[string]any{
		"session_id": sessionID, "type": "mcp",
		"payload": map[string]any{"jsonrpc": "2.0", "id": id, "result": result},
	})
}

func assertMCPMethod(t *testing.T, envelope map[string]any, expected string) {
	t.Helper()
	payload, ok := envelope["payload"].(map[string]any)
	if !ok || payload["method"] != expected {
		t.Fatalf("expected MCP %s: %+v", expected, envelope)
	}
}
