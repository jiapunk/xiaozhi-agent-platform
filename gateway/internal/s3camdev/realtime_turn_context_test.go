package s3camdev

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func newRealtimeTurnTestSession(t *testing.T) (*openAIRealtimeSession, *websocket.Conn, *websocket.Conn) {
	t.Helper()
	upstream, provider := realtimeLifecycleSocketPair(t)
	connection, device := realtimeLifecycleSocketPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	t.Cleanup(cancel)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := &Server{config: Config{Logger: logger}}
	session := &openAIRealtimeSession{
		gateway: &OpenAIRealtimeGateway{config: OpenAIRealtimeConfig{Logger: logger}},
		device:  newDeviceSession(server, connection, "turn-test"),
		ctx:     ctx, cancel: cancel, upstream: upstream,
		captions:   make(chan realtimeCaptionEvent, 64),
		pcmIngress: newRealtimeIngressQueue(ctx, "test", 64),
	}
	return session, provider, device
}

func acceptRealtimeTurnText(t *testing.T, session *openAIRealtimeSession, item, text string) {
	t.Helper()
	turn, accepted := session.claimTranscriptInput(item)
	if !accepted {
		t.Fatalf("current transcript rejected: %s", item)
	}
	session.stateMu.Lock()
	accepted = session.acceptTurnTranscriptLocked(turn, text)
	session.stateMu.Unlock()
	if !accepted {
		t.Fatalf("current transcript not applied: %s", item)
	}
}

func TestRealtimeNativeLateASRCannotReplaceCurrentQuestion(t *testing.T) {
	session, _, device := newRealtimeTurnTestSession(t)
	session.beginSpeechCapture("fx")
	if err := session.handleInputTranscript("fx", "美元兌台幣匯率"); err != nil {
		t.Fatal(err)
	}
	_ = readJSON(t, session.ctx, device)
	session.beginSpeechCapture("math")
	if session.lastUserTranscript != "" {
		t.Fatal("new question retained the old transcript")
	}
	if err := session.handleInputTranscript("fx", "美元兌台幣匯率"); err != nil {
		t.Fatal(err)
	}
	if session.lastUserTranscript != "" {
		t.Fatal("late previous ASR became the new question")
	}
	if err := session.handleInputTranscript("math", "一加一等於多少"); err != nil {
		t.Fatal(err)
	}
	event := readJSON(t, session.ctx, device)
	if event["text"] != "一加一等於多少" {
		t.Fatalf("wrong current caption: %v", event)
	}
	if _, accepted := session.claimTranscriptInput("math"); accepted {
		t.Fatal("duplicate native ASR accepted")
	}
}

func TestRealtimeOldTranscriptEventsCannotMutateNewResponse(t *testing.T) {
	session, _, _ := newRealtimeTurnTestSession(t)
	session.beginSpeechCapture("old-input")
	acceptRealtimeTurnText(t, session, "old-input", "查匯率")
	session.beginResponse("old-response")
	session.beginSpeechCapture("math-input")
	acceptRealtimeTurnText(t, session, "math-input", "一加一")
	session.beginResponse("math-response")
	for _, event := range []openAIRealtimeEvent{
		{Type: "response.output_audio_transcript.delta", ResponseID: "old-response", Delta: "舊匯率"},
		{Type: "response.output_audio_transcript.done", ResponseID: "old-response", Transcript: "舊匯率"},
		{Type: "response.output_audio_transcript.done", Transcript: "沒有回應ID"},
	} {
		if err := session.handleEvent(event); err != nil {
			t.Fatal(err)
		}
	}
	if session.responseTranscript.Len() != 0 || len(session.captions) != 0 || len(session.device.history.Snapshot()) != 0 {
		t.Fatal("stale/missing-ID output changed current captions/history")
	}
	if err := session.finishOutputTranscript("math-response", "等於二。"); err != nil {
		t.Fatal(err)
	}
	if err := session.finishOutputTranscript("math-response", "重複完成"); err != nil {
		t.Fatal(err)
	}
	history := session.device.history.Snapshot()
	if len(history) != 2 || history[0].Content != "一加一" || history[1].Content != "等於二。" {
		t.Fatalf("wrong or duplicate history: %+v", history)
	}
}

func TestRealtimeHistoryWaitsForBoundTranscriptNotLatestString(t *testing.T) {
	session, _, _ := newRealtimeTurnTestSession(t)
	session.beginSpeechCapture("math")
	session.beginResponse("answer")
	// Native generation may complete before independent ASR. It must not use
	// this compatibility field, even if some caller has stale data in it.
	session.lastUserTranscript = "舊匯率問題"
	if err := session.finishOutputTranscript("answer", "二。"); err != nil {
		t.Fatal(err)
	}
	if len(session.device.history.Snapshot()) != 0 {
		t.Fatal("answer paired before its own ASR")
	}
	acceptRealtimeTurnText(t, session, "math", "一加一")
	history := session.device.history.Snapshot()
	if len(history) != 2 || history[0].Content != "一加一" || history[1].Content != "二。" {
		t.Fatalf("late ASR history mismatch: %+v", history)
	}
}

func newRealtimeTurnTestBatch(session *openAIRealtimeSession) *realtimeToolBatch {
	session.stateMu.Lock()
	defer session.stateMu.Unlock()
	ctx, cancel := context.WithCancel(session.ctx)
	batch := &realtimeToolBatch{inputGeneration: session.inputTurnGeneration,
		inputTurn: session.currentInputTurnLocked(), ctx: ctx, cancel: cancel,
		id: 1, pending: 1, total: 1, sourceDone: true}
	session.toolBatch = batch
	return batch
}

func TestRealtimeToolBeforeASRWaitsForSameInputOnly(t *testing.T) {
	session, _, _ := newRealtimeTurnTestSession(t)
	session.beginSpeechCapture("old")
	acceptRealtimeTurnText(t, session, "old", "查美元匯率")
	session.beginSpeechCapture("math")
	batch := newRealtimeTurnTestBatch(session)
	result := make(chan string, 1)
	errResult := make(chan error, 1)
	go func() {
		text, err := session.waitForToolTranscript(session.ctx, batch)
		result <- text
		errResult <- err
	}()
	select {
	case got := <-result:
		t.Fatalf("returned before current ASR: %q", got)
	case <-time.After(20 * time.Millisecond):
	}
	acceptRealtimeTurnText(t, session, "math", "再加三")
	if got := <-result; got != "再加三" {
		t.Fatalf("wrong bound tool question: %q", got)
	}
	if err := <-errResult; err != nil {
		t.Fatal(err)
	}
	if batch.userTranscript != "再加三" {
		t.Fatal("batch did not receive its own late ASR")
	}
}

func TestRealtimeToolTranscriptWaitCancelsOnNewInput(t *testing.T) {
	session, _, _ := newRealtimeTurnTestSession(t)
	session.beginSpeechCapture("old")
	batch := newRealtimeTurnTestBatch(session)
	result := make(chan error, 1)
	go func() { _, err := session.waitForToolTranscript(session.ctx, batch); result <- err }()
	session.beginSpeechCapture("new")
	select {
	case err := <-result:
		if !errors.Is(err, errRealtimeTurnSuperseded) && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("superseded tool remained blocked")
	}
}

func TestRealtimeToolGuardRefusesWrongLookupAndScopesFollowup(t *testing.T) {
	session, provider, _ := newRealtimeTurnTestSession(t)
	session.beginSpeechCapture("sum")
	acceptRealtimeTurnText(t, session, "sum", "一加一")
	session.beginResponse("sum-answer")
	if err := session.finishOutputTranscript("sum-answer", "等於二。"); err != nil {
		t.Fatal(err)
	}
	session.beginSpeechCapture("math")
	acceptRealtimeTurnText(t, session, "math", "再加三")
	batch := newRealtimeTurnTestBatch(session)
	session.executeTool("wrong-search", "web_search", `{"query":"美元兌台幣匯率"}`, batch)
	result := readJSON(t, session.ctx, provider)
	encoded, _ := json.Marshal(result)
	if !bytes.Contains(encoded, []byte(ToolConflictArithmeticLookup)) {
		t.Fatalf("not blocked by arithmetic guard: %s", encoded)
	}
	followup := readJSON(t, session.ctx, provider)
	response, _ := followup["response"].(map[string]any)
	input, _ := response["input"].([]any)
	if response["tool_choice"] != "none" || len(input) != 3 {
		t.Fatalf("followup lost context or permits tool loop: %v", followup)
	}
	last, _ := json.Marshal(input[len(input)-1])
	if !bytes.Contains(last, []byte("再加三")) || bytes.Contains(last, []byte("匯率")) {
		t.Fatalf("wrong canonical followup: %s", last)
	}
	if session.IsClosed() {
		t.Fatal("guard refusal failed the session")
	}
}

func TestRealtimeUnknownSpeakerKeepsLiveArithmeticContinuation(t *testing.T) {
	session, _, _ := newRealtimeTurnTestSession(t)
	session.device.server.speakerIdentity = &SpeakerIdentityService{}
	session.beginSpeechCapture("sum")
	acceptRealtimeTurnText(t, session, "sum", "一加一")
	session.beginResponse("sum-answer")
	if err := session.finishOutputTranscript("sum-answer", "等於二。"); err != nil {
		t.Fatal(err)
	}
	session.beginSpeechCapture("more")
	acceptRealtimeTurnText(t, session, "more", "再加三")
	batch := newRealtimeTurnTestBatch(session)
	batch.userTranscript = "再加三"
	batch.guardReason = ToolConflictArithmeticLookup
	session.stateMu.Lock()
	request := session.guardedToolResponseLocked(batch)
	session.stateMu.Unlock()
	encoded, _ := json.Marshal(request)
	if !bytes.Contains(encoded, []byte("一加一")) || !bytes.Contains(encoded, []byte("等於二")) || !bytes.Contains(encoded, []byte("再加三")) {
		t.Fatalf("unknown speaker lost valid live context: %s", encoded)
	}
	if len(session.device.historyForSpeaker(SpeakerMatch{}).Snapshot()) != 0 || len(session.device.histories) != 0 {
		t.Fatal("live unknown-speaker context leaked into identity history")
	}
}

func TestRealtimeNativeToolBatchBindsQuestionBeforeASR(t *testing.T) {
	session, provider, _ := newRealtimeTurnTestSession(t)
	session.beginSpeechCapture("fx")
	acceptRealtimeTurnText(t, session, "fx", "美元兌台幣")
	session.beginSpeechCapture("sum")
	session.beginResponse("sum-answer")
	session.startToolCall("late-asr-tool", "web_search", `{"query":"美元兌台幣"}`, session.responseGeneration)
	session.stateMu.Lock()
	batch := session.toolBatch
	if batch == nil || batch.inputTurn.itemID != "sum" || batch.userTranscript != "" {
		session.stateMu.Unlock()
		t.Fatal("tool copied the previous question before current ASR")
	}
	session.stateMu.Unlock()
	acceptRealtimeTurnText(t, session, "sum", "一加一")
	if err := session.handleResponseDone("sum-answer"); err != nil {
		t.Fatal(err)
	}
	result := readJSON(t, session.ctx, provider)
	encoded, _ := json.Marshal(result)
	if !bytes.Contains(encoded, []byte(ToolConflictArithmeticLookup)) {
		t.Fatalf("late ASR not used for guard: %s", encoded)
	}
	_ = readJSON(t, session.ctx, provider)
}

func TestRealtimeUnknownTranscriptToolClarifiesWithoutFailingSession(t *testing.T) {
	session, provider, _ := newRealtimeTurnTestSession(t)
	session.beginSpeechCapture("unresolved")
	batch := newRealtimeTurnTestBatch(session)
	started := time.Now()
	session.executeTool("unclear-search", "web_search", `{"query":"匯率"}`, batch)
	if elapsed := time.Since(started); elapsed < realtimeToolTranscriptWait || elapsed > 3*time.Second {
		t.Fatalf("unbounded or missing ASR wait: %v", elapsed)
	}
	_ = readJSON(t, session.ctx, provider)
	followup := readJSON(t, session.ctx, provider)
	encoded, _ := json.Marshal(followup)
	if !bytes.Contains(encoded, []byte("none")) || !bytes.Contains(encoded, []byte("先詢問")) || session.IsClosed() {
		t.Fatalf("missing safe clarification: %s", encoded)
	}
}

func TestRealtimeHistoryRestoredOnceAtOriginalRoles(t *testing.T) {
	session, provider, _ := newRealtimeTurnTestSession(t)
	session.device.history.Add("一加一", "等於二。")
	if strings.Contains(session.instructions(), "等於二") {
		t.Fatal("history remains in system instructions")
	}
	if err := session.seedConversationHistory(); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"user", "assistant"} {
		event := readJSON(t, session.ctx, provider)
		item, _ := event["item"].(map[string]any)
		if item["role"] != role {
			t.Fatalf("wrong history authority: %v", item)
		}
	}
	// A marker after the second call must be the next event, not duplicated history.
	if err := session.seedConversationHistory(); err != nil {
		t.Fatal(err)
	}
	if err := session.writeUpstream(map[string]string{"type": "test.marker"}); err != nil {
		t.Fatal(err)
	}
	if event := readJSON(t, session.ctx, provider); event["type"] != "test.marker" {
		t.Fatalf("history restored twice: %v", event)
	}
}

func TestRealtimeLateSpeakerMatchCannotReplaceNewTurn(t *testing.T) {
	session, provider, _ := newRealtimeTurnTestSession(t)
	session.beginSpeechCapture("old")
	old := session.inputTurnContext
	session.beginSpeechCapture("new")
	if session.applySpeakerMatch(old, SpeakerMatch{Known: true, ID: "old-person", DisplayName: "Old"}, nil) {
		t.Fatal("stale speaker published")
	}
	if session.device.speakerState().Known {
		t.Fatal("old identity leaked into new turn")
	}
	if err := session.writeUpstream(map[string]string{"type": "test.marker"}); err != nil {
		t.Fatal(err)
	}
	if event := readJSON(t, session.ctx, provider); event["type"] != "test.marker" {
		t.Fatalf("stale speaker updated upstream: %v", event)
	}
}

func TestRealtimeContinuousInputNeverAddsSyntheticSilence(t *testing.T) {
	session, provider, _ := newRealtimeTurnTestSession(t)
	session.responsePlaying = true
	session.inputPackets = 10
	session.lastInputAt = time.Now().Add(-10 * time.Second)
	// The default continuous path exits even when explicitly called by a legacy
	// caller; neither an idle gap nor a local VAD edge creates fabricated audio.
	session.inputIdleLoop()
	session.responsePlaying = false
	if err := session.FinalizeInputByDevice(); err != nil {
		t.Fatal(err)
	}
	session.responsePlaying = true
	if err := session.FinalizeInputByDevice(); err != nil {
		t.Fatal(err)
	}
	frames := [][]byte{{1, 2, 3, 4}, {5, 6, 7, 8}, {9, 10, 11, 12}}
	for _, frame := range frames {
		if err := session.queueInputPCM(frame); err != nil {
			t.Fatal(err)
		}
	}
	if len(session.pcmIngress.events) != len(frames) {
		t.Fatal("continuous input gained synthetic PCM")
	}
	for _, want := range frames {
		event := <-session.pcmIngress.events
		if !bytes.Equal(event.data, want) {
			t.Fatalf("PCM order/data changed: %v", event.data)
		}
		if err := session.sendInputPCM(event.data); err != nil {
			t.Fatal(err)
		}
		up := readJSON(t, session.ctx, provider)
		encoded, _ := up["audio"].(string)
		got, _ := base64.StdEncoding.DecodeString(encoded)
		if !bytes.Equal(got, want) {
			t.Fatalf("provider received modified PCM: %v", got)
		}
	}
	before := time.Now()
	session.captureInputPacket([]byte{1, 2}, false)
	if session.lastInputAt.Before(before) {
		t.Fatal("playback overlap not counted as real transport activity")
	}
}

func TestRealtimeLateScopedResponseCreatedCannotBindNewQuestion(t *testing.T) {
	session, provider, _ := newRealtimeTurnTestSession(t)
	session.beginSpeechCapture("old")
	oldGeneration := session.inputTurnGeneration
	session.beginSpeechCapture("new")
	session.beginResponse("new-answer")
	generation := session.responseGeneration
	turn := session.responseInputTurn
	session.beginResponse("late-guarded", map[string]string{
		"xiaozhi_mode": "guarded_tool", "xiaozhi_input_generation": fmt.Sprint(oldGeneration),
	})
	session.beginResponse("late-progressive", map[string]string{
		"xiaozhi_mode": "progressive_tool", "xiaozhi_batch_id": "old-batch",
		"xiaozhi_input_generation": fmt.Sprint(session.inputTurnGeneration),
	})
	if session.responseID != "new-answer" || session.responseGeneration != generation || session.responseInputTurn != turn {
		t.Fatal("stale scoped response replaced or rebound current output")
	}
	for _, id := range []string{"late-guarded", "late-progressive"} {
		event := readJSON(t, session.ctx, provider)
		if event["type"] != "response.cancel" || event["response_id"] != id {
			t.Fatalf("cancel was not scoped to stale response: %v", event)
		}
	}
}

func queueRealtimeScopedRetry(t *testing.T, session *openAIRealtimeSession, provider *websocket.Conn) map[string]any {
	t.Helper()
	session.beginSpeechCapture("math")
	acceptRealtimeTurnText(t, session, "math", "一加一")
	session.beginResponse("active-response")
	batch := newRealtimeTurnTestBatch(session)
	batch.userTranscript = "一加一"
	batch.guardReason = ToolConflictArithmeticLookup
	session.stateMu.Lock()
	err := session.writeResponseRequestLocked(session.guardedToolResponseLocked(batch))
	session.stateMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	request := readJSON(t, session.ctx, provider)
	event := openAIRealtimeEvent{Type: "error"}
	event.Error.Code = "conversation_already_has_active_response"
	event.Error.EventID, _ = request["event_id"].(string)
	if err := session.handleEvent(event); err != nil {
		t.Fatal(err)
	}
	if !session.retryResponseAfterActive || session.retryResponseRequest == nil {
		t.Fatal("full scoped retry not saved")
	}
	return request
}

func TestRealtimeActiveConflictRetryPreservesScopedGuardRequest(t *testing.T) {
	session, provider, _ := newRealtimeTurnTestSession(t)
	original := queueRealtimeScopedRetry(t, session, provider)
	if err := session.handleResponseDone("active-response"); err != nil {
		t.Fatal(err)
	}
	retried := readJSON(t, session.ctx, provider)
	first, _ := original["response"].(map[string]any)
	second, _ := retried["response"].(map[string]any)
	firstInput, _ := json.Marshal(first["input"])
	secondInput, _ := json.Marshal(second["input"])
	if second["tool_choice"] != "none" || !bytes.Equal(firstInput, secondInput) || second["instructions"] != first["instructions"] {
		t.Fatalf("retry dropped guard/canonical context: %v", retried)
	}
	if retried["event_id"] == original["event_id"] {
		t.Fatal("retry reused correlation ID")
	}
}

func TestRealtimeNewSpeechOrBlockedOutputCannotRetryOldRequest(t *testing.T) {
	for _, mode := range []string{"new-input", "blocked-output"} {
		t.Run(mode, func(t *testing.T) {
			session, provider, _ := newRealtimeTurnTestSession(t)
			queueRealtimeScopedRetry(t, session, provider)
			if mode == "new-input" {
				session.beginSpeechCapture("replacement")
			} else {
				session.responseBlocked = true
			}
			if err := session.handleResponseDone("active-response"); err != nil {
				t.Fatal(err)
			}
			if err := session.writeUpstream(map[string]string{"type": "test.marker"}); err != nil {
				t.Fatal(err)
			}
			if event := readJSON(t, session.ctx, provider); event["type"] != "test.marker" {
				t.Fatalf("old response restarted: %v", event)
			}
		})
	}
}

func TestRealtimeUntrackedConflictDoesNotPoisonNextNativeTurn(t *testing.T) {
	session, _, _ := newRealtimeTurnTestSession(t)
	session.beginSpeechCapture("old")
	event := openAIRealtimeEvent{Type: "error"}
	event.Error.Code = "conversation_already_has_active_response"
	event.Error.EventID = "unknown-request"
	if err := session.handleEvent(event); err != nil {
		t.Fatal(err)
	}
	if session.retryResponseAfterActive || session.IsClosed() {
		t.Fatal("untracked conflict forced retry or closed session")
	}
	session.beginSpeechCapture("new")
	acceptRealtimeTurnText(t, session, "new", "二加三")
	session.beginResponse("native-new-answer")
	if err := session.finishOutputTranscript("native-new-answer", "等於五。"); err != nil {
		t.Fatal(err)
	}
	history := session.conversationHistory.Snapshot()
	if len(history) != 2 || history[0].Content != "二加三" || history[1].Content != "等於五。" {
		t.Fatalf("native next turn was poisoned: %+v", history)
	}
}
