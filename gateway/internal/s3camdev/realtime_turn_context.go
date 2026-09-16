package s3camdev

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const realtimeToolTranscriptWait = 2 * time.Second

var errRealtimeTurnSuperseded = errors.New("Realtime input turn superseded")

type realtimeResponseRequest struct {
	inputGeneration uint64
	payload         map[string]any
	attempts        int
}

// Preserve the complete request across an already-active response race. A bare
// response.create retry would discard single-response safety/intent overrides.
// All callers hold stateMu, keeping request identity tied to the input boundary.
func (session *openAIRealtimeSession) writeResponseRequestLocked(request map[string]any, attempt ...int) error {
	encoded, err := json.Marshal(request)
	if err != nil {
		return err
	}
	var payload map[string]any
	if err := json.Unmarshal(encoded, &payload); err != nil {
		return err
	}
	response, _ := payload["response"].(map[string]any)
	if response == nil {
		response = make(map[string]any)
		payload["response"] = response
	}
	metadata, _ := response["metadata"].(map[string]any)
	if metadata == nil {
		metadata = make(map[string]any)
		response["metadata"] = metadata
	}
	session.nextResponseRequestID++
	id := fmt.Sprintf("xiaozhi_response_%d", session.nextResponseRequestID)
	payload["event_id"] = id
	metadata["xiaozhi_input_generation"] = fmt.Sprint(session.inputTurnGeneration)
	metadata["xiaozhi_request_id"] = id
	attempts := 0
	if len(attempt) > 0 {
		attempts = attempt[0]
	}
	if session.pendingResponseRequests == nil {
		session.pendingResponseRequests = make(map[string]*realtimeResponseRequest)
	}
	// Only a handful of explicit responses may be awaiting acknowledgement.
	// Never retain an unbounded history of request bodies in a long session.
	if len(session.pendingResponseRequests) >= 8 {
		return fmt.Errorf("too many unacknowledged Realtime response requests")
	}
	if err := session.writeUpstream(payload); err != nil {
		return err
	}
	session.pendingResponseRequests[id] = &realtimeResponseRequest{
		inputGeneration: session.inputTurnGeneration, payload: payload, attempts: attempts,
	}
	return nil
}

func (session *openAIRealtimeSession) queueResponseRetryLocked(eventID string) bool {
	if session.responseBlocked || session.closed.Load() {
		return false
	}
	request := session.pendingResponseRequests[eventID]
	if eventID == "" {
		// Compatibility with providers omitting error.event_id is safe only if
		// exactly one current request exists; never guess between scoped requests.
		for id, pending := range session.pendingResponseRequests {
			if pending.inputGeneration != session.inputTurnGeneration {
				continue
			}
			if request != nil {
				return false
			}
			eventID, request = id, pending
		}
	}
	if request == nil || request.inputGeneration != session.inputTurnGeneration {
		return false
	}
	delete(session.pendingResponseRequests, eventID)
	if request.attempts >= 2 {
		if batch := session.toolBatch; batch != nil && batch.awaitingResponse &&
			batch.inputGeneration == session.inputTurnGeneration {
			batch.cancel()
			session.toolBatch = nil
		}
		session.device.server.update(func(status *PublicStatus) {
			status.LastEvent = "本次回應未能開始，請再說一次"
		})
		return false
	}
	session.retryResponseRequest = request
	session.retryResponseAfterActive = true
	return true
}

func (session *openAIRealtimeSession) acceptResponseMetadataLocked(metadata map[string]string) bool {
	if session.closed.Load() {
		return false
	}
	if value := metadata["xiaozhi_input_generation"]; value != "" {
		generation, err := strconv.ParseUint(value, 10, 64)
		if err != nil || generation != session.inputTurnGeneration {
			return false
		}
	}
	if metadata["xiaozhi_mode"] == "progressive_tool" {
		batch := session.toolBatch
		if batch == nil || !batch.awaitingResponse || batch.ctx.Err() != nil ||
			batch.inputGeneration != session.inputTurnGeneration ||
			metadata["xiaozhi_batch_id"] != fmt.Sprint(batch.id) {
			return false
		}
	}
	if requestID := metadata["xiaozhi_request_id"]; requestID != "" {
		request := session.pendingResponseRequests[requestID]
		if request == nil || request.inputGeneration != session.inputTurnGeneration {
			return false
		}
		delete(session.pendingResponseRequests, requestID)
	}
	return true
}

// Every field is protected by session.stateMu. Identity is fixed at the input
// boundary; responses and tool batches retain this object rather than reading
// the mutable latest transcript of a different turn.
type realtimeInputTurnContext struct {
	generation         uint64
	itemID             string
	transcript         string
	transcriptReady    chan struct{}
	transcriptResolved bool
	notified           bool
	superseded         bool
	speaker            SpeakerMatch
	speakerResolved    bool
	history            []realtimeTurnHistory
}

type realtimeTurnHistory struct {
	responseID  string
	assistant   string
	localStored bool
	stored      bool
}

func (turn *realtimeInputTurnContext) notifyLocked() {
	if !turn.notified {
		close(turn.transcriptReady)
		turn.notified = true
	}
}

func (session *openAIRealtimeSession) currentInputTurnLocked() *realtimeInputTurnContext {
	if turn := session.inputTurnContext; turn != nil &&
		turn.generation == session.inputTurnGeneration && turn.itemID == session.inputItemID {
		return turn
	}
	turn := &realtimeInputTurnContext{
		generation: session.inputTurnGeneration, itemID: session.inputItemID,
		transcriptReady: make(chan struct{}),
	}
	if session.device != nil && session.device.server != nil {
		turn.speakerResolved = session.device.server.speakerIdentity == nil
	}
	session.inputTurnContext = turn
	return turn
}

func (session *openAIRealtimeSession) inputTurnCurrentLocked(turn *realtimeInputTurnContext) bool {
	return turn != nil && !turn.superseded && !session.closed.Load() &&
		session.inputTurnContext == turn && turn.generation == session.inputTurnGeneration &&
		turn.itemID == session.inputItemID
}

// Used for both native and transcript-first ASR. Native responses remain fully
// audio-driven; this gate only prevents stale captions/tool context/history.
func (session *openAIRealtimeSession) claimTranscriptInput(itemID string) (*realtimeInputTurnContext, bool) {
	session.stateMu.Lock()
	defer session.stateMu.Unlock()
	if session.closed.Load() || itemID == "" ||
		(session.inputItemID != "" && session.inputItemID != itemID) {
		return nil, false
	}
	if session.gateway.config.TranscriptFirst && session.inputTurnHandled {
		return nil, false
	}
	if session.inputItemID == "" {
		session.inputItemID = itemID
	}
	turn := session.currentInputTurnLocked()
	if turn.transcriptResolved || turn.superseded {
		return nil, false
	}
	if session.gateway.config.TranscriptFirst {
		session.inputTurnHandled = true
	}
	return turn, true
}

func (session *openAIRealtimeSession) acceptTurnTranscriptLocked(turn *realtimeInputTurnContext, text string) bool {
	if !session.inputTurnCurrentLocked(turn) || turn.transcriptResolved {
		return false
	}
	turn.transcript = text
	turn.transcriptResolved = true
	turn.notifyLocked()
	session.lastUserTranscript = text
	if batch := session.toolBatch; batch != nil && batch.inputTurn == turn {
		batch.userTranscript = text
	}
	session.flushTurnHistoryLocked(turn)
	return true
}

func (session *openAIRealtimeSession) rememberTurnResponseLocked(
	turn *realtimeInputTurnContext, responseID, assistant string) {
	if turn == nil || turn.superseded || assistant == "" {
		return
	}
	for _, record := range turn.history {
		if record.responseID == responseID {
			return
		}
	}
	turn.history = append(turn.history, realtimeTurnHistory{
		responseID: responseID, assistant: assistant,
	})
	session.flushTurnHistoryLocked(turn)
}

func (session *openAIRealtimeSession) flushTurnHistoryLocked(turn *realtimeInputTurnContext) {
	if turn == nil || turn.superseded || turn.transcript == "" {
		return
	}
	for index := range turn.history {
		record := &turn.history[index]
		if !record.localStored {
			// Conversational continuity is not identity memory. Retain only this
			// live upstream session's bounded, correctly paired turns, including
			// unknown speakers; never persist or expose them as someone's profile.
			session.conversationHistory.Add(turn.transcript, record.assistant)
			record.localStored = true
		}
		if !record.stored && turn.speakerResolved {
			session.device.historyForSpeaker(turn.speaker).Add(turn.transcript, record.assistant)
			record.stored = true
		}
	}
}

func (session *openAIRealtimeSession) waitForToolTranscript(ctx context.Context,
	batch *realtimeToolBatch) (string, error) {
	waitContext, cancel := context.WithTimeout(ctx, realtimeToolTranscriptWait)
	defer cancel()
	for {
		session.stateMu.Lock()
		turn := batch.inputTurn
		if !session.inputTurnCurrentLocked(turn) || batch.inputGeneration != turn.generation ||
			session.toolBatch != batch || batch.ctx.Err() != nil {
			session.stateMu.Unlock()
			return "", errRealtimeTurnSuperseded
		}
		if turn.transcriptResolved {
			text := turn.transcript
			batch.userTranscript = text
			session.stateMu.Unlock()
			if text == "" {
				return "", fmt.Errorf("current Realtime transcript is empty")
			}
			return text, nil
		}
		ready := turn.transcriptReady
		session.stateMu.Unlock()
		select {
		case <-waitContext.Done():
			return "", waitContext.Err()
		case <-session.ctx.Done():
			return "", session.ctx.Err()
		case <-ready:
		}
	}
}

// Reconnection restores a bounded snapshot once, at its original user/assistant
// authority. Never splice conversation content into persistent system policy.
func (session *openAIRealtimeSession) seedConversationHistory() error {
	if session.historySeeded {
		return nil
	}
	history := session.device.historyForSpeaker(session.device.speakerState()).Snapshot()
	for _, turn := range history {
		if (turn.Role != "user" && turn.Role != "assistant") || strings.TrimSpace(turn.Content) == "" {
			continue
		}
		contentType := "input_text"
		if turn.Role == "assistant" {
			contentType = "output_text"
		}
		if err := session.writeUpstream(map[string]any{
			"type": "conversation.item.create", "item": map[string]any{
				"type": "message", "role": turn.Role,
				"content": []map[string]any{{"type": contentType, "text": turn.Content}},
			},
		}); err != nil {
			return fmt.Errorf("restore Realtime conversation history: %w", err)
		}
	}
	session.conversationHistory.mu.Lock()
	session.conversationHistory.turns = append([]ConversationTurn(nil), history...)
	session.conversationHistory.mu.Unlock()
	session.historySeeded = true
	return nil
}

// The identity lookup may finish after another utterance. Validate and publish
// under the same lock used to advance input identity, including the upstream
// update, so an old lookup cannot replace a new speaker's personalization.
func (session *openAIRealtimeSession) applySpeakerMatch(turn *realtimeInputTurnContext,
	match SpeakerMatch, packets [][]byte) bool {
	session.stateMu.Lock()
	defer session.stateMu.Unlock()
	if !session.inputTurnCurrentLocked(turn) {
		return false
	}
	turn.speaker = match
	turn.speakerResolved = true
	session.device.setCurrentVoiceTurn(match, packets)
	session.flushTurnHistoryLocked(turn)
	_ = session.writeUpstream(map[string]any{
		"type": "session.update", "session": map[string]any{
			"type": "realtime", "instructions": session.instructions(),
		},
	})
	return true
}

func realtimeToolGuardInstruction(reason string) string {
	switch reason {
	case ToolConflictArithmeticLookup:
		return "本輪是計算問題，不需查匯率或網路。回答本輪算式；若是『再加三』等延續問題，只依最近有效算式計算，缺少有效前文就先問清楚，不得套用舊的金融話題。"
	case ToolConflictCurrencyPair:
		return "本輪未提供可確定的來源與目標幣別。請詢問要換算哪兩種貨幣，不得猜測幣別或報價。"
	default:
		return "本輪使用者意圖尚未確定，不能根據上一輪內容擅自查詢。簡短請使用者說清楚這次問題；不得假裝已搜尋或已取得結果。"
	}
}

func realtimeToolGuardResult(reason string) string {
	encoded, _ := json.Marshal(map[string]any{
		"ok": false, "error": "tool_request_conflict", "reason": reason,
		"message": realtimeToolGuardInstruction(reason),
	})
	return string(encoded)
}

func realtimeToolTranscriptClass(text, reason string) string {
	if reason != "" {
		return reason
	}
	if strings.TrimSpace(text) == "" {
		return "unavailable"
	}
	return "current_turn_available"
}

func (session *openAIRealtimeSession) guardedToolResponseLocked(batch *realtimeToolBatch) map[string]any {
	input := make([]map[string]any, 0, 7)
	// These entries have already been paired with a fixed input turn. Include
	// them at their original roles so arithmetic followups retain valid context.
	for _, previous := range session.conversationHistory.Snapshot() {
		contentType := "input_text"
		if previous.Role == "assistant" {
			contentType = "output_text"
		}
		input = append(input, map[string]any{
			"type": "message", "role": previous.Role,
			"content": []map[string]any{{"type": contentType, "text": previous.Content}},
		})
	}
	text := batch.userTranscript
	if text == "" {
		text = "這次語音尚未辨識清楚，請先詢問我這次想問什麼。"
	}
	input = append(input, map[string]any{
		"type": "message", "role": "user",
		"content": []map[string]any{{"type": "input_text", "text": text}},
	})
	return map[string]any{"type": "response.create", "response": map[string]any{
		"output_modalities": []string{"audio"}, "tools": []map[string]any{},
		"tool_choice": "none", "input": input,
		"instructions": session.instructions() + "\n" + realtimeToolGuardInstruction(batch.guardReason),
		"metadata": map[string]string{"xiaozhi_mode": "guarded_tool",
			"xiaozhi_input_generation": fmt.Sprint(batch.inputGeneration)},
	}}
}
