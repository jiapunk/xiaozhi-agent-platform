package s3camdev

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"
)

func TestRealtimeProviderSpeechStartAuthorizesNativeBargeAndRetainsPreRoll(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session := &openAIRealtimeSession{
		gateway: &OpenAIRealtimeGateway{config: OpenAIRealtimeConfig{
			TranscriptFirst: true, Logger: slog.Default(),
		}},
		device: &deviceSession{server: &Server{}}, ctx: ctx, cancel: cancel,
	}
	for index := 0; index < realtimeRecentInputPackets; index++ {
		session.captureInputPacket([]byte{byte(index)}, false)
	}
	session.responsePlaying = true
	if !session.beginSpeechCapture("provider_only") {
		t.Fatal("playback-overlapping provider candidate was not recorded")
	}
	session.inputMu.Lock()
	retained := len(session.turnInput)
	session.inputMu.Unlock()
	if retained != realtimeBargePreRollPackets {
		t.Fatalf("barge pre-roll=%d want=%d", retained,
			realtimeBargePreRollPackets)
	}
	session.stateMu.Lock()
	authorized := session.inputBargeInAuthorized
	candidate := session.inputBargeCandidate
	blocked := session.responseBlocked
	session.stateMu.Unlock()
	if !authorized || candidate || blocked {
		t.Fatalf("native provider speech edge was not authoritative: "+
			"authorized=%v candidate=%v blocked=%v",
			authorized, candidate, blocked)
	}
}

func TestRealtimeDeviceVADDoesNotCreateSecondBargeCandidate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session := &openAIRealtimeSession{
		gateway: &OpenAIRealtimeGateway{config: OpenAIRealtimeConfig{
			TranscriptFirst: true, Logger: slog.Default(),
		}},
		device: &deviceSession{server: &Server{}}, ctx: ctx, cancel: cancel,
	}
	session.responsePlaying = true
	if !session.beginSpeechCapture("device_vad_only") {
		t.Fatal("playback-overlapping provider candidate was not recorded")
	}
	session.MarkDeviceVoiceActivity(true)
	session.stateMu.Lock()
	authorized := session.inputBargeInAuthorized
	candidate := session.inputBargeCandidate
	blocked := session.responseBlocked
	strongFrames := session.inputBargeStrongFrames
	session.stateMu.Unlock()
	if !authorized || candidate || blocked || strongFrames != 0 {
		t.Fatalf("device VAD created a competing barge state: "+
			"authorized=%v candidate=%v blocked=%v strong=%d",
			authorized, candidate, blocked, strongFrames)
	}
}

func TestRealtimePlaybackWarmupCannotReopenNativeBargeCandidate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session := &openAIRealtimeSession{
		gateway: &OpenAIRealtimeGateway{config: OpenAIRealtimeConfig{
			TranscriptFirst: true, Logger: slog.Default(),
		}},
		device: &deviceSession{server: &Server{}}, ctx: ctx, cancel: cancel,
	}
	session.responsePlaying = true
	session.playbackStartedAt = time.Now()
	if !session.beginSpeechCapture("speaker_startup") {
		t.Fatal("playback-overlapping provider candidate was not recorded")
	}
	session.MarkDeviceVoiceActivity(true)
	for index := 0; index < realtimeBargeStrongPCMFrames+2; index++ {
		session.observeBargePCM(1200, 16000, time.Now())
	}
	session.stateMu.Lock()
	authorized := session.inputBargeInAuthorized
	candidate := session.inputBargeCandidate
	strongFrames := session.inputBargeStrongFrames
	session.stateMu.Unlock()
	if !authorized || candidate || strongFrames != 0 {
		t.Fatalf("speaker warmup reopened a second barge candidate: "+
			"authorized=%v candidate=%v strong=%d",
			authorized, candidate, strongFrames)
	}
}

func TestRealtimeWarmupFloorDoesNotBlockQuietRealBargeIn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session := &openAIRealtimeSession{
		gateway: &OpenAIRealtimeGateway{config: OpenAIRealtimeConfig{
			TranscriptFirst: true, Logger: slog.Default(),
		}},
		device: &deviceSession{server: &Server{}}, ctx: ctx, cancel: cancel,
	}
	started := time.Now()
	session.responsePlaying = true
	session.playbackStartedAt = started
	// The leading amplifier transient is deliberately much louder than the
	// later residual floor and must not poison the per-response calibration.
	session.observeBargePCM(2000, 30000, started.Add(100*time.Millisecond))
	for index := 0; index < 8; index++ {
		session.observeBargePCM(20+index, 260+index*5,
			started.Add(realtimeBargeCalibrationDelay+
				time.Duration(index)*20*time.Millisecond))
	}
	session.playbackStartedAt = time.Now().Add(-realtimeBargePlaybackWarmup -
		50*time.Millisecond)
	for index := 0; index < realtimeBargeStrongPCMFrames; index++ {
		session.observeBargePCM(96, 1800, time.Now())
	}
	session.stateMu.Lock()
	strongFrames := session.bargeRecentStrongFrames
	baselineMean := session.bargeBaselineMean
	meanThreshold := session.bargeLastMeanThreshold
	session.stateMu.Unlock()
	if strongFrames < realtimeBargeStrongPCMFrames {
		t.Fatalf("quiet real barge-in energy remained blocked: strong=%d "+
			"baseline_mean=%d mean_threshold=%d", strongFrames, baselineMean,
			meanThreshold)
	}
}

func TestRealtimeMeasuredPeak899QualifiesForBargeIn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session := &openAIRealtimeSession{
		gateway: &OpenAIRealtimeGateway{config: OpenAIRealtimeConfig{
			TranscriptFirst: true, Logger: slog.Default(),
		}},
		device: &deviceSession{server: &Server{}}, ctx: ctx, cancel: cancel,
		responsePlaying: true,
		playbackStartedAt: time.Now().Add(-realtimeBargePlaybackWarmup -
			50*time.Millisecond),
		bargeBaselineMean: 30, bargeBaselinePeak: 118,
	}
	for index := 0; index < realtimeBargeStrongPCMFrames; index++ {
		session.observeBargePCM(254, 899, time.Now())
	}
	session.stateMu.Lock()
	strongFrames := session.bargeRecentStrongFrames
	peakThreshold := session.bargeLastPeakThreshold
	session.stateMu.Unlock()
	if strongFrames != realtimeBargeStrongPCMFrames || peakThreshold >= 899 {
		t.Fatalf("measured real interruption still fails energy gate: "+
			"strong=%d peak_threshold=%d", strongFrames, peakThreshold)
	}
}

func TestRealtimeBargeEnergySurvivesShortWeakGaps(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session := &openAIRealtimeSession{
		gateway: &OpenAIRealtimeGateway{config: OpenAIRealtimeConfig{
			TranscriptFirst: true, Logger: slog.Default(),
		}},
		device: &deviceSession{server: &Server{}}, ctx: ctx, cancel: cancel,
		responsePlaying: true,
		playbackStartedAt: time.Now().Add(-realtimeBargePlaybackWarmup -
			50*time.Millisecond),
		bargeBaselineMean: 24, bargeBaselinePeak: 100,
	}
	started := time.Now()
	for index := 0; index < realtimeBargeStrongPCMFrames; index++ {
		session.observeBargePCM(110, 1800,
			started.Add(time.Duration(index)*180*time.Millisecond))
		if index+1 < realtimeBargeStrongPCMFrames {
			session.observeBargePCM(30, 220,
				started.Add(time.Duration(index)*180*time.Millisecond+
					90*time.Millisecond))
		}
	}
	session.stateMu.Lock()
	strongFrames := session.bargeRecentStrongFrames
	lastStrongAt := session.bargeRecentStrongAt
	session.stateMu.Unlock()
	if strongFrames != realtimeBargeStrongPCMFrames || lastStrongAt.IsZero() {
		t.Fatalf("short AEC gaps erased real barge-in energy: strong=%d last=%v",
			strongFrames, lastStrongAt)
	}

	// A genuinely quiet interval must still reset the rolling evidence.
	session.observeBargePCM(28, 210,
		lastStrongAt.Add(realtimeBargePCMFreshness+time.Millisecond))
	session.stateMu.Lock()
	strongFrames = session.bargeRecentStrongFrames
	session.stateMu.Unlock()
	if strongFrames != 0 {
		t.Fatalf("stale barge-in energy survived freshness window: strong=%d",
			strongFrames)
	}
}

func TestInterruptionContinuationCueClassification(t *testing.T) {
	for _, text := range []string{
		"等等", "等一下。", "先等一下", "不是！", "不對", "停一下",
	} {
		if !isInterruptionContinuationCue(text) {
			t.Fatalf("continuation cue was not recognized: %q", text)
		}
	}
	for _, text := range []string{
		"等等，改成查台北天氣", "不對，我要問香港", "停止播放音樂", "今天幾號",
	} {
		if isInterruptionContinuationCue(text) {
			t.Fatalf("complete request was reduced to a continuation cue: %q", text)
		}
	}
}

func TestRealtimeResponseResetsBargeFloor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session := &openAIRealtimeSession{
		gateway: &OpenAIRealtimeGateway{config: OpenAIRealtimeConfig{
			TranscriptFirst: true, Logger: slog.Default(),
		}},
		device: &deviceSession{server: &Server{}}, ctx: ctx, cancel: cancel,
		bargeBaselineMean: 1800, bargeBaselinePeak: 30000,
	}
	session.beginResponse("reset_floor")
	session.stateMu.Lock()
	baselineMean := session.bargeBaselineMean
	baselinePeak := session.bargeBaselinePeak
	session.stateMu.Unlock()
	if baselineMean != 0 || baselinePeak != 0 {
		t.Fatalf("new response retained stale barge floor: mean=%d peak=%d",
			baselineMean, baselinePeak)
	}
}

func TestOpenAIRealtimeNativeSpeechStartInterruptsWithoutTranscript(t *testing.T) {
	ffmpeg, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg is unavailable")
	}
	upstreamReady := make(chan map[string]any, 1)
	sendResponse := make(chan struct{})
	sendInterruption := make(chan struct{})
	speechStartedSent := make(chan struct{})
	truncateReceived := make(chan map[string]any, 1)
	releaseUpstream := make(chan struct{})
	defer close(releaseUpstream)
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer realtime-test-key" ||
			request.URL.Query().Get("model") != defaultOpenAIRealtimeModel {
			http.Error(writer, "unauthorized", http.StatusUnauthorized)
			return
		}
		connection, acceptErr := websocket.Accept(writer, request,
			&websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
		if acceptErr != nil {
			return
		}
		defer connection.CloseNow()
		ctx, cancel := context.WithTimeout(request.Context(), 8*time.Second)
		defer cancel()
		_, payload, readErr := connection.Read(ctx)
		if readErr != nil {
			return
		}
		var update map[string]any
		if json.Unmarshal(payload, &update) != nil {
			return
		}
		upstreamReady <- update
		<-sendResponse
		writeFakeRealtimeEvent(t, ctx, connection, map[string]any{
			"type": "response.created", "response": map[string]any{"id": "resp_1"},
		})
		writeFakeRealtimeEvent(t, ctx, connection, map[string]any{
			"type": "response.output_item.added", "response_id": "resp_1",
			"item": map[string]any{
				"id": "item_1", "type": "message", "role": "assistant",
			},
		})
		writeFakeRealtimeEvent(t, ctx, connection, map[string]any{
			"type": "response.output_audio.delta", "response_id": "resp_1",
			"delta": base64.StdEncoding.EncodeToString(
				make([]byte, realtimePCMFrameBytes*(realtimeDevicePrebufferFrames+2))),
		})
		<-sendInterruption
		writeFakeRealtimeEvent(t, ctx, connection, map[string]any{
			"type": "input_audio_buffer.speech_started", "item_id": "user_2",
		})
		close(speechStartedSent)
		for {
			messageType, message, eventErr := connection.Read(ctx)
			if eventErr != nil {
				return
			}
			if messageType != websocket.MessageText {
				continue
			}
			var event map[string]any
			if json.Unmarshal(message, &event) == nil &&
				event["type"] == "conversation.item.truncate" {
				truncateReceived <- event
				<-releaseUpstream
				return
			}
		}
	}))
	defer upstreamServer.Close()
	realtime, err := NewOpenAIRealtimeGateway(OpenAIRealtimeConfig{
		APIKey:          "realtime-test-key",
		URL:             "ws" + strings.TrimPrefix(upstreamServer.URL, "http"),
		FFmpegPath:      ffmpeg,
		TranscriptFirst: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	const (
		deviceID = "20:6e:f1:b3:9c:c4"
		token    = "0123456789abcdef0123456789abcdef"
	)
	gateway, err := New(Config{
		PublicWebSocketURL: "ws://127.0.0.1:8766/v1/device",
		ExpectedDeviceID:   deviceID, Token: token, Realtime: realtime,
	})
	if err != nil {
		t.Fatal(err)
	}
	deviceServer := httptest.NewServer(gateway.Handler())
	defer deviceServer.Close()
	device := dialRealtimeTestDevice(t, deviceServer.URL, deviceID, token)
	defer device.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	serverHello := readJSON(t, ctx, device)
	sessionID, _ := serverHello["session_id"].(string)
	initialize := readJSON(t, ctx, device)
	assertMCPMethod(t, initialize, "initialize")
	writeMCPResult(t, ctx, device, sessionID, 1, map[string]any{})
	list := readJSON(t, ctx, device)
	assertMCPMethod(t, list, "tools/list")
	writeMCPResult(t, ctx, device, sessionID, 2,
		map[string]any{"tools": []map[string]any{}})
	writeJSON(t, ctx, device, map[string]any{
		"session_id": sessionID, "type": "listen", "state": "start",
		"mode": "realtime",
	})
	update := <-upstreamReady
	assertRealtimeSessionUpdate(t, update)
	close(sendResponse)
	if event := readJSON(t, ctx, device); event["type"] != "tts" ||
		event["state"] != "start" {
		t.Fatalf("missing Realtime TTS start: %+v", event)
	}
	messageType, packet, err := device.Read(ctx)
	if err != nil || messageType != websocket.MessageBinary || len(packet) == 0 {
		t.Fatalf("missing streamed Realtime Opus packet: type=%v bytes=%d err=%v",
			messageType, len(packet), err)
	}
	time.Sleep(realtimeBargePlaybackWarmup + 50*time.Millisecond)
	close(sendInterruption)
	<-speechStartedSent
	interruptionAt := time.Now()
	writeJSON(t, ctx, device, map[string]any{
		"session_id": sessionID, "type": "listen", "state": "speech_start",
	})
	// Device VAD and PCM may still arrive as diagnostics, but they are not a
	// second cancellation authority after native Realtime speech_started.
	for index := 0; index < 4; index++ {
		packet, decodeErr := base64.StdEncoding.DecodeString(
			testSpeechPacketsBase64[index])
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if writeErr := device.Write(ctx, websocket.MessageBinary, packet); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	for {
		messageType, payload, readErr := device.Read(ctx)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if messageType != websocket.MessageText {
			continue
		}
		var event map[string]any
		if json.Unmarshal(payload, &event) == nil && event["type"] == "tts" &&
			event["state"] == "interrupt" {
			break
		}
	}
	interruptionLatency := time.Since(interruptionAt)
	if interruptionLatency > 250*time.Millisecond {
		t.Fatalf("native barge-in was not mirrored promptly: %s",
			interruptionLatency)
	}
	truncate := <-truncateReceived
	if truncate["item_id"] != "item_1" || truncate["content_index"] != float64(0) {
		t.Fatalf("invalid Realtime truncation: %+v", truncate)
	}
	maximumProviderMS := float64(
		(realtimeDevicePrebufferFrames + 2) * opusFrameDurationMS)
	if played, ok := truncate["audio_end_ms"].(float64); !ok ||
		played < 0 || played > maximumProviderMS {
		t.Fatalf("invalid played-audio boundary: %+v", truncate)
	}
}

func TestNormalizeRealtimePCMUsesBoundedNonClippingGain(t *testing.T) {
	encode := func(values ...int16) []byte {
		pcm := make([]byte, len(values)*2)
		for index, value := range values {
			u := uint16(value)
			pcm[index*2] = byte(u)
			pcm[index*2+1] = byte(u >> 8)
		}
		return pcm
	}
	decode := func(pcm []byte, index int) int16 {
		return int16(uint16(pcm[index*2]) | uint16(pcm[index*2+1])<<8)
	}
	quiet := normalizeRealtimePCM(encode(1000, -1000), 4, 12000)
	if decode(quiet, 0) != 4000 || decode(quiet, 1) != -4000 {
		t.Fatalf("quiet PCM was not raised with bounded gain: %v", quiet)
	}
	medium := normalizeRealtimePCM(encode(5000, -5000), 4, 12000)
	if decode(medium, 0) != 10000 || decode(medium, 1) != -10000 {
		t.Fatalf("medium PCM did not honor target peak: %v", medium)
	}
	loudInput := encode(15000, -15000)
	loud := normalizeRealtimePCM(loudInput, 4, 12000)
	if !bytes.Equal(loud, loudInput) {
		t.Fatalf("loud PCM should remain unchanged: %v", loud)
	}
}

func TestRealtimeInputIdleDelayAdaptsAndCaps(t *testing.T) {
	short := realtimeInputIdleDelay(10)
	long := realtimeInputIdleDelay(100)
	veryLong := realtimeInputIdleDelay(1000)
	if short <= realtimeInputIdleBase || long <= short {
		t.Fatalf("idle delay did not adapt: short=%s long=%s", short, long)
	}
	if veryLong != realtimeInputIdleMaximum {
		t.Fatalf("idle delay did not cap: got=%s want=%s",
			veryLong, realtimeInputIdleMaximum)
	}
}

func TestOpenAIRealtimeAddsTrailingSilenceAfterGatedDeviceAudio(t *testing.T) {
	ffmpeg, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg is unavailable")
	}
	silenceReceived := make(chan struct{}, 1)
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter, request *http.Request) {
		connection, acceptErr := websocket.Accept(writer, request,
			&websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
		if acceptErr != nil {
			return
		}
		defer connection.CloseNow()
		ctx, cancel := context.WithTimeout(request.Context(), 6*time.Second)
		defer cancel()
		for {
			messageType, payload, readErr := connection.Read(ctx)
			if readErr != nil {
				return
			}
			if messageType != websocket.MessageText {
				continue
			}
			var event map[string]any
			if json.Unmarshal(payload, &event) != nil ||
				event["type"] != "input_audio_buffer.append" {
				continue
			}
			encoded, _ := event["audio"].(string)
			pcm, decodeErr := base64.StdEncoding.DecodeString(encoded)
			if decodeErr == nil && len(pcm) == realtimePCMFrameBytes &&
				bytes.Equal(pcm, make([]byte, len(pcm))) {
				select {
				case silenceReceived <- struct{}{}:
				default:
				}
				return
			}
		}
	}))
	defer upstreamServer.Close()
	realtime, err := NewOpenAIRealtimeGateway(OpenAIRealtimeConfig{
		APIKey: "realtime-test-key", URL: "ws" +
			strings.TrimPrefix(upstreamServer.URL, "http"), FFmpegPath: ffmpeg,
		LegacyGatedInput: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	const (
		deviceID = "20:6e:f1:b3:9c:c4"
		token    = "0123456789abcdef0123456789abcdef"
	)
	gateway, err := New(Config{
		PublicWebSocketURL: "ws://127.0.0.1:8766/v1/device",
		ExpectedDeviceID:   deviceID, Token: token, Realtime: realtime,
	})
	if err != nil {
		t.Fatal(err)
	}
	deviceServer := httptest.NewServer(gateway.Handler())
	defer deviceServer.Close()
	device := dialRealtimeTestDevice(t, deviceServer.URL, deviceID, token)
	defer device.CloseNow()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverHello := readJSON(t, ctx, device)
	sessionID, _ := serverHello["session_id"].(string)
	initialize := readJSON(t, ctx, device)
	assertMCPMethod(t, initialize, "initialize")
	writeMCPResult(t, ctx, device, sessionID, 1, map[string]any{})
	list := readJSON(t, ctx, device)
	assertMCPMethod(t, list, "tools/list")
	writeMCPResult(t, ctx, device, sessionID, 2,
		map[string]any{"tools": []map[string]any{}})
	writeJSON(t, ctx, device, map[string]any{
		"session_id": sessionID, "type": "listen", "state": "start",
		"mode": "realtime",
	})
	for index := 0; index < 2; index++ {
		packet, decodeErr := base64.StdEncoding.DecodeString(
			testSpeechPacketsBase64[index])
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if err := device.Write(ctx, websocket.MessageBinary, packet); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-silenceReceived:
	case <-ctx.Done():
		t.Fatal("Gateway did not bridge gated microphone audio to Realtime VAD")
	}
}

func dialRealtimeTestDevice(t *testing.T, serverURL, deviceID,
	token string) *websocket.Conn {
	t.Helper()
	headers := make(http.Header)
	headers.Set("Authorization", "Bearer "+token)
	headers.Set("Protocol-Version", "1")
	headers.Set("Device-Id", deviceID)
	connection, _, err := websocket.Dial(context.Background(),
		"ws"+strings.TrimPrefix(serverURL, "http")+"/v1/device",
		&websocket.DialOptions{HTTPHeader: headers})
	if err != nil {
		t.Fatal(err)
	}
	hello := `{"type":"hello","version":1,"features":{"mcp":true},` +
		`"transport":"websocket","audio_params":{"format":"opus",` +
		`"sample_rate":16000,"channels":1,"frame_duration":60}}`
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := connection.Write(ctx, websocket.MessageText, []byte(hello)); err != nil {
		connection.CloseNow()
		t.Fatal(err)
	}
	return connection
}

func writeFakeRealtimeEvent(t *testing.T, ctx context.Context,
	connection *websocket.Conn, event map[string]any) {
	t.Helper()
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if err := connection.Write(ctx, websocket.MessageText, payload); err != nil {
		t.Fatal(err)
	}
}

func assertRealtimeSessionUpdate(t *testing.T, update map[string]any) {
	t.Helper()
	if update["type"] != "session.update" {
		t.Fatalf("missing Realtime session update: %+v", update)
	}
	session, _ := update["session"].(map[string]any)
	audio, _ := session["audio"].(map[string]any)
	input, _ := audio["input"].(map[string]any)
	output, _ := audio["output"].(map[string]any)
	outputFormat, _ := output["format"].(map[string]any)
	turnDetection, _ := input["turn_detection"].(map[string]any)
	if session["model"] != defaultOpenAIRealtimeModel ||
		turnDetection["type"] != "semantic_vad" ||
		turnDetection["eagerness"] != "medium" ||
		turnDetection["create_response"] != true ||
		turnDetection["interrupt_response"] != true ||
		outputFormat["rate"] != float64(24000) {
		t.Fatalf("Realtime session lacks native semantic barge-in: %+v", update)
	}
	transcription, _ := input["transcription"].(map[string]any)
	if transcription["model"] != "gpt-transcribe" ||
		transcription["language"] != "zh" || transcription["prompt"] == "" {
		t.Fatalf("Realtime session lacks accurate Chinese transcription: %+v", update)
	}
}

func TestOpenAIRealtimeCustomVoiceValue(t *testing.T) {
	gateway, err := NewOpenAIRealtimeGateway(OpenAIRealtimeConfig{
		APIKey: "realtime-test-key", VoiceID: "voice_product_test",
	})
	if err != nil {
		t.Fatal(err)
	}
	voice := gateway.outputVoice()
	custom, ok := voice.(map[string]any)
	if !ok || custom["id"] != "voice_product_test" {
		t.Fatalf("custom Realtime voice was not selected: %#v", voice)
	}
}

func TestRealtimePlaybackWaitsForPrebufferOrCompletion(t *testing.T) {
	if realtimePlaybackShouldStart(realtimeDevicePrebufferFrames-1, false) {
		t.Fatal("Realtime playback started before its jitter buffer was ready")
	}
	if !realtimePlaybackShouldStart(realtimeDevicePrebufferFrames, false) {
		t.Fatal("Realtime playback did not start with a full jitter buffer")
	}
	if !realtimePlaybackShouldStart(1, true) {
		t.Fatal("short completed Realtime response was left buffered")
	}
	if realtimePlaybackShouldStart(0, true) {
		t.Fatal("empty Realtime response started device playback")
	}
}

func TestRealtimeStartupEchoGuardIsShortAndBounded(t *testing.T) {
	started := time.Unix(100, 0)
	if !shouldSuppressRealtimeInput(true, started,
		started.Add(realtimePlaybackEchoGuard-time.Millisecond)) {
		t.Fatal("speaker startup echo was not suppressed")
	}
	if shouldSuppressRealtimeInput(true, started,
		started.Add(realtimePlaybackEchoGuard)) {
		t.Fatal("echo guard blocked a valid later barge-in")
	}
	if shouldSuppressRealtimeInput(false, started, started.Add(time.Millisecond)) {
		t.Fatal("echo guard blocked input while playback was idle")
	}
}

func TestRealtimeTruncationNeverExceedsProviderAudio(t *testing.T) {
	providerBytes := int64(16850 * 24000 * 2 / 1000)
	if got := safeRealtimeTruncationMilliseconds(16920, providerBytes); got != 16850 {
		t.Fatalf("truncation exceeded provider audio: got=%d want=16850", got)
	}
	if got := safeRealtimeTruncationMilliseconds(900, providerBytes); got != 900 {
		t.Fatalf("valid playback boundary changed: got=%d want=900", got)
	}
	if got := safeRealtimeTruncationMilliseconds(900, 0); got != 0 {
		t.Fatalf("empty provider audio produced a boundary: got=%d", got)
	}
}

func TestRealtimeCaptionTargetsFollowPlaybackClock(t *testing.T) {
	sentences := []string{"第一句字幕。", "第二句字幕會晚一點顯示。"}
	targets, next := realtimeCaptionTargets(sentences, 4200, 0)
	if len(targets) != 2 || targets[0] != realtimeCaptionInitialDelayMS ||
		targets[1] <= targets[0] {
		t.Fatalf("caption targets are not ordered: targets=%v", targets)
	}
	if next <= targets[1] {
		t.Fatalf("next caption target did not advance: targets=%v next=%d", targets, next)
	}
	following, _ := realtimeCaptionTargets([]string{"第三句。"}, 12000, next)
	if following[0] != next {
		t.Fatalf("provider generation clock moved caption: got=%d want=%d",
			following[0], next)
	}
}

func TestRealtimeToolBatchUsesProgressiveOnlyForParallelSafeTools(t *testing.T) {
	tests := []struct {
		name  string
		batch *realtimeToolBatch
		want  bool
	}{
		{name: "parallel searches", batch: &realtimeToolBatch{
			sourceDone: true, total: 3, allProgressiveSafe: true,
		}, want: true},
		{name: "source response still active", batch: &realtimeToolBatch{
			total: 3, allProgressiveSafe: true,
		}},
		{name: "single search", batch: &realtimeToolBatch{
			sourceDone: true, total: 1, allProgressiveSafe: true,
		}},
		{name: "mixed side effect tools", batch: &realtimeToolBatch{
			sourceDone: true, total: 3,
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := realtimeToolBatchUsesProgressive(test.batch); got != test.want {
				t.Fatalf("progressive=%v want=%v", got, test.want)
			}
		})
	}
	for _, tool := range []string{"web_search", "web_fetch", "market_quote"} {
		if !realtimeProgressiveToolSafe(tool) {
			t.Fatalf("informational tool %q was not progressive-safe", tool)
		}
	}
	if realtimeProgressiveToolSafe("set_volume") {
		t.Fatal("device mutation was incorrectly marked progressive-safe")
	}
}

func TestRealtimeProgressiveResponseUsesOutOfBandIntermediateAndFinalInBand(t *testing.T) {
	result := []realtimeToolResult{{
		CallID: "call_1", Name: "web_search", Arguments: `{"query":"東京天氣"}`,
		Output: `{"temperature":31}`, Succeeded: true,
	}}
	intermediate := realtimeProgressiveResponse(
		7, "比較三地天氣", result, result, false)
	intermediateResponse := intermediate["response"].(map[string]any)
	if intermediateResponse["conversation"] != "none" ||
		intermediateResponse["tool_choice"] != "none" {
		t.Fatalf("intermediate response can pollute or call tools: %+v",
			intermediateResponse)
	}
	metadata := intermediateResponse["metadata"].(map[string]string)
	if metadata["xiaozhi_batch_id"] != "7" || metadata["xiaozhi_final"] != "false" {
		t.Fatalf("missing progressive response identity: %+v", metadata)
	}

	final := realtimeProgressiveResponse(
		7, "比較三地天氣", result, result, true)
	finalResponse := final["response"].(map[string]any)
	if _, outOfBand := finalResponse["conversation"]; outOfBand {
		t.Fatal("final response did not close the default tool conversation")
	}
	if !strings.Contains(finalResponse["instructions"].(string),
		"以上查詢都完成了") {
		t.Fatal("final response can end without a clear completion signal")
	}
}

func TestRealtimeMultiMarketCompletionRequiresEveryRequestedQuote(t *testing.T) {
	results := []realtimeToolResult{
		{Name: "market_quote", Arguments: `{"query":"特斯拉"}`, Succeeded: true},
		{Name: "market_quote", Arguments: `{"query":"spacex"}`, Succeeded: false},
		{Name: "market_quote", Arguments: `{"query":"台積電"}`, Succeeded: true},
	}
	instruction := realtimeFinalCompletionInstruction(
		"一次查詢特斯拉 SpaceX 跟台積電的股價", results)
	for _, required := range []string{"3 個標的", "2 個取得", "spacex", "不得說全部完成"} {
		if !strings.Contains(instruction, required) {
			t.Fatalf("incomplete batch omitted %q: %q", required, instruction)
		}
	}
	for index := range results {
		results[index].Succeeded = true
	}
	instruction = realtimeFinalCompletionInstruction(
		"一次查詢特斯拉 SpaceX 跟台積電的股價", results)
	if !strings.Contains(instruction, "以上 3 項行情都已查到") {
		t.Fatalf("complete batch did not report its exact count: %q", instruction)
	}
}

func TestRealtimeCaptionerEmitsReadablePhrasesBeforeSentenceEnd(t *testing.T) {
	var caption realtimeCaptioner
	if got := caption.Append("我是你的穿戴式"); len(got) != 0 {
		t.Fatalf("caption emitted a short unfinished fragment: %q", got)
	}
	got := caption.Append("語音助理，可以跟你聊天、回答問題。")
	want := []string{"我是你的穿戴式語音助理，", "可以跟你聊天、回答問題。"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("caption phrases=%q want=%q", got, want)
	}
}

func TestRealtimeCaptionerBoundsUnpunctuatedText(t *testing.T) {
	var caption realtimeCaptioner
	got := caption.Append("這是一段沒有任何標點而且仍然需要即時顯示的字幕內容")
	if len(got) == 0 {
		t.Fatal("long unpunctuated caption was not emitted")
	}
	for _, phrase := range got {
		if utf8.RuneCountInString(phrase) > realtimeCaptionMaximumRunes {
			t.Fatalf("caption fragment too long: %q", phrase)
		}
	}
	if remaining := caption.Flush(); remaining == "" {
		t.Fatal("captioner lost the final partial fragment")
	}
}

func TestRealtimeCaptionWindowRetainsReadableContext(t *testing.T) {
	var segments []string
	var display string
	for _, next := range []string{
		"香港目前多雲。", "東京有短暫陣雨。", "台北午後雷陣雨。", "外出記得帶傘。",
	} {
		segments, display = realtimeCaptionWindow(segments, next)
	}
	if len(segments) != realtimeCaptionWindowSegments {
		t.Fatalf("caption window segments=%d want=%d: %q",
			len(segments), realtimeCaptionWindowSegments, display)
	}
	if strings.Contains(display, "香港") || !strings.Contains(display, "東京") ||
		!strings.Contains(display, "外出") || !strings.Contains(display, "\n") {
		t.Fatalf("caption window did not roll predictably: %q", display)
	}
	if utf8.RuneCountInString(display) > realtimeCaptionWindowRunes {
		t.Fatalf("caption window is too long: runes=%d text=%q",
			utf8.RuneCountInString(display), display)
	}
}

func TestOpenAIRealtimeRejectsInvalidCustomVoiceID(t *testing.T) {
	if _, err := NewOpenAIRealtimeGateway(OpenAIRealtimeConfig{
		APIKey: "realtime-test-key", VoiceID: "voice_bad value",
	}); err == nil {
		t.Fatal("invalid custom Realtime voice ID was accepted")
	}
}

func TestRealtimeResponseReplacementCancelsOldToolWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session := &openAIRealtimeSession{ctx: ctx}
	session.beginResponse("response-old")
	session.stateMu.Lock()
	oldWork := session.responseWorkContext
	oldGeneration := session.responseGeneration
	session.stateMu.Unlock()
	session.beginResponse("response-new")
	select {
	case <-oldWork.Done():
	case <-time.After(time.Second):
		t.Fatal("old Realtime tool work was not cancelled")
	}
	if _, active := session.activeResponseGeneration("response-old"); active {
		t.Fatal("stale response was still allowed to continue a tool")
	}
	if generation, active := session.activeResponseGeneration("response-new"); !active || generation == oldGeneration {
		t.Fatalf("new response generation is inactive: generation=%d active=%v",
			generation, active)
	}
}

func TestRealtimeActiveResponseRaceIsRecoverable(t *testing.T) {
	if !isRecoverableRealtimeError("conversation_already_has_active_response") {
		t.Fatal("active-response race would close the Realtime session")
	}
	if !isRecoverableRealtimeError("response_cancel_not_active") {
		t.Fatal("duplicate response cancellation would close the Realtime session")
	}
	if isRecoverableRealtimeError("invalid_request_error") {
		t.Fatal("unrelated Realtime error was incorrectly ignored")
	}
}

func TestRealtimeTranscriptFirstAcceptsOnlyNewestTurn(t *testing.T) {
	session := &openAIRealtimeSession{
		gateway: &OpenAIRealtimeGateway{config: OpenAIRealtimeConfig{
			TranscriptFirst: true,
		}},
		inputTurnGeneration: 2,
		inputItemID:         "input-new",
	}
	if session.claimInputTurn("input-old") {
		t.Fatal("stale transcript was accepted as the current user turn")
	}
	if !session.claimInputTurn("input-new") {
		t.Fatal("current transcript was not accepted")
	}
	if session.claimInputTurn("input-new") {
		t.Fatal("duplicate transcript created a second response")
	}
}

func TestStripWakeActivationPrefix(t *testing.T) {
	tests := []struct {
		input          string
		want           string
		activationOnly bool
	}{
		{input: "你好星辰", want: "", activationOnly: true},
		{input: "你好，星辰。", want: "", activationOnly: true},
		{input: "你好星辰，東京今天天氣如何？", want: "東京今天天氣如何？"},
		{input: "你好 星晨 調高音量", want: "調高音量"},
		{input: "你好，今天過得如何？", want: "你好，今天過得如何？"},
	}
	for _, test := range tests {
		got, activationOnly := stripWakeActivationPrefix(test.input)
		if got != test.want || activationOnly != test.activationOnly {
			t.Fatalf("stripWakeActivationPrefix(%q)=(%q,%v), want (%q,%v)",
				test.input, got, activationOnly, test.want, test.activationOnly)
		}
	}
}

func TestPendingWakePreambleSuppressesApproximateGreeting(t *testing.T) {
	session := &openAIRealtimeSession{
		pendingWakeWord:  "你好星辰",
		pendingWakeUntil: time.Now().Add(time.Second),
	}
	if got, only := session.consumePendingWakePreamble("你好。"); got != "" || !only {
		t.Fatalf("approximate wake preamble was not suppressed: (%q,%v)", got, only)
	}
	// A wake-only item must leave the hint available for a separately committed
	// query immediately following the cached activation audio.
	if got, only := session.consumePendingWakePreamble("你好，現在幾點？"); got != "現在幾點？" || only {
		t.Fatalf("wake greeting was not removed from query: (%q,%v)", got, only)
	}
	if session.pendingWakeWord != "" || !session.pendingWakeUntil.IsZero() {
		t.Fatal("pending wake hint was not consumed by the real query")
	}
}

func TestRealtimeAdaptiveRoutingSelectsSmartOnlyWhenUseful(t *testing.T) {
	gateway, err := NewOpenAIRealtimeGateway(OpenAIRealtimeConfig{
		APIKey: "realtime-test-key", TranscriptFirst: true,
		AdaptiveRouting: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		transcript string
		history    []ConversationTurn
		wantMode   string
		wantReason string
	}{
		{name: "ordinary greeting", transcript: "你好，今天過得如何？",
			wantMode: "fast", wantReason: "ordinary_turn"},
		{name: "live weather", transcript: "東京今天的天氣如何？",
			wantMode: "smart", wantReason: "tool_or_live_data"},
		{name: "device control", transcript: "把音量調到八十",
			wantMode: "smart", wantReason: "tool_or_live_data"},
		{name: "durable memory", transcript: "請記住我喜歡簡短回答",
			wantMode: "smart", wantReason: "tool_or_live_data"},
		{name: "complex analysis", transcript: "比較日本和香港 Gateway 的優缺點",
			wantMode: "smart", wantReason: "complex_request"},
		{name: "tool followup", transcript: "再大一點",
			history:  []ConversationTurn{{Role: "user", Content: "把音量調大"}},
			wantMode: "smart", wantReason: "tool_or_live_data"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			route := gateway.routeForTurn(test.transcript, test.history)
			if route.mode != test.wantMode || route.reason != test.wantReason {
				t.Fatalf("unexpected route: got=%+v want_mode=%s want_reason=%s",
					route, test.wantMode, test.wantReason)
			}
			if route.mode == "smart" &&
				(route.model != defaultOpenAIRealtimeSmartModel || route.reasoning != "low") {
				t.Fatalf("smart route lost full low-reasoning model: %+v", route)
			}
			if route.mode == "fast" &&
				(route.model != defaultOpenAIRealtimeModel || route.reasoning != "minimal") {
				t.Fatalf("fast route lost mini minimal-reasoning model: %+v", route)
			}
		})
	}
}

func TestRealtimeAdaptiveRouteUpdatePrecedesResponse(t *testing.T) {
	events := make(chan map[string]any, 2)
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter, request *http.Request) {
		connection, err := websocket.Accept(writer, request,
			&websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
		if err != nil {
			return
		}
		defer connection.CloseNow()
		ctx, cancel := context.WithTimeout(request.Context(), 3*time.Second)
		defer cancel()
		for range 2 {
			messageType, payload, readErr := connection.Read(ctx)
			if readErr != nil || messageType != websocket.MessageText {
				return
			}
			var event map[string]any
			if json.Unmarshal(payload, &event) != nil {
				return
			}
			events <- event
		}
	}))
	defer upstreamServer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	upstream, _, err := websocket.Dial(ctx,
		"ws"+strings.TrimPrefix(upstreamServer.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.CloseNow()
	gateway, err := NewOpenAIRealtimeGateway(OpenAIRealtimeConfig{
		APIKey: "realtime-test-key", TranscriptFirst: true,
		AdaptiveRouting: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	session := &openAIRealtimeSession{
		gateway: gateway, ctx: ctx, upstream: upstream,
		currentModel:     gateway.config.Model,
		currentReasoning: gateway.config.FastReasoning,
	}
	session.stateMu.Lock()
	err = session.applyModelRouteLocked(
		gateway.routeForTurn("請規劃一個完整方案", nil))
	if err == nil {
		err = session.writeUpstream(map[string]any{"type": "response.create"})
	}
	session.stateMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	update := <-events
	response := <-events
	configuration, _ := update["session"].(map[string]any)
	reasoning, _ := configuration["reasoning"].(map[string]any)
	if update["type"] != "session.update" ||
		configuration["model"] != defaultOpenAIRealtimeSmartModel ||
		reasoning["effort"] != "low" {
		t.Fatalf("invalid smart route update: %+v", update)
	}
	if response["type"] != "response.create" {
		t.Fatalf("model route did not precede response creation: %+v", response)
	}
}

func TestRealtimeAdaptiveRoutingRequiresCanonicalTranscript(t *testing.T) {
	if _, err := NewOpenAIRealtimeGateway(OpenAIRealtimeConfig{
		APIKey: "realtime-test-key", AdaptiveRouting: true,
	}); err == nil {
		t.Fatal("adaptive routing was enabled without transcript-first mode")
	}
	if _, err := NewOpenAIRealtimeGateway(OpenAIRealtimeConfig{
		APIKey: "realtime-test-key", TranscriptFirst: true,
		AdaptiveRouting: true, SmartReasoning: "maximum",
	}); err == nil {
		t.Fatal("unsupported Realtime reasoning effort was accepted")
	}
}
