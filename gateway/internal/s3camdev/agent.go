package s3camdev

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"
)

const (
	maxConversationTurns            = 3
	maxConversationContentRunes     = 768
	maxConversationWindowTotalRunes = maxConversationTurns * 2 * maxConversationContentRunes
	maxToolResultRunes              = 4096
)

type ConversationTurn struct {
	Role    string
	Content string
}

type AgentTool struct {
	Name        string
	Description string
	Parameters  map[string]any
}

type AgentToolExecutor interface {
	AvailableTools() []AgentTool
	ExecuteTool(context.Context, string, json.RawMessage) (string, error)
}

type AgentPersonalizationProvider interface {
	AgentPersonalization() string
}

// MarketQuote is one validated point-in-time market observation. QuoteTime is
// RFC3339 with an explicit offset so a spoken price can never lose its date or
// market timezone. The interface is intentionally provider-neutral: the
// development Gateway can use grounded search now and replace it with a
// licensed market-data feed before sale without changing the Agent contract.
type MarketQuote struct {
	Name        string  `json:"name"`
	Exchange    string  `json:"exchange"`
	Symbol      string  `json:"symbol"`
	Currency    string  `json:"currency"`
	Price       float64 `json:"price"`
	QuoteTime   string  `json:"quote_time"`
	DelayStatus string  `json:"delay_status"`
	SourceName  string  `json:"source_name"`
	SourceURL   string  `json:"source_url"`
}

type MarketQuoteProvider interface {
	LookupMarketQuote(context.Context, string) (MarketQuote, error)
}

// LiveWebProvider keeps provider-specific browsing credentials and server-side
// search/fetch behavior inside the Gateway. Realtime models receive only a
// bounded, cited JSON result and never access the provider credential.
type LiveWebProvider interface {
	SearchWeb(context.Context, string) (string, error)
	FetchWeb(context.Context, string, string) (string, error)
}

type ToolAwareVoicePipeline interface {
	ReplyWithTools(context.Context, string, []ConversationTurn,
		AgentToolExecutor) (string, error)
}

// VoiceReplyChunk is one complete, speakable sentence emitted while the Agent
// is still generating the rest of its answer. Chunks must preserve source
// order and their concatenation is the complete reply stored in the bounded
// conversation window.
type VoiceReplyChunk struct {
	Text string
	Err  error
}

// StreamingToolAwareVoicePipeline lets the Gateway start sentence synthesis
// before the complete Agent reply exists. Implementations must keep any tool
// call on a non-spoken path until its complete JSON arguments have been
// validated and executed.
type StreamingToolAwareVoicePipeline interface {
	ReplyWithToolsStream(context.Context, string, []ConversationTurn,
		AgentToolExecutor) (<-chan VoiceReplyChunk, error)
}

// SongPerformance is a complete music performance ready for the device's
// existing ordered Opus playback path. DisplayText is stored in the bounded
// conversation window and shown on the device; Packets contain generated
// music, an authorized catalog track, or a spoken safety response.
type SongPerformance struct {
	DisplayText string
	Packets     [][]byte
	// Music selects the slower, long-form playback pacing used for generated
	// songs. A spoken safety refusal deliberately leaves this false.
	Music bool
}

// SingingVoicePipeline is intentionally separate from ordinary replies and
// Agent tools. Singing changes only media output, needs no device mutation,
// and must never be inferred from arbitrary model text or tool arguments.
type SingingVoicePipeline interface {
	Sing(context.Context, string, []ConversationTurn,
		AgentToolExecutor) (SongPerformance, error)
}

// OnlineMusicVoicePipeline searches a catalog whose API explicitly permits
// third-party streaming. It must never scrape arbitrary media pages or bypass
// a subscription service's DRM.
type OnlineMusicVoicePipeline interface {
	PlayOnlineMusic(context.Context, string) (SongPerformance, error)
}

// MediaIntent is a bounded, non-executing classification of one ASR result.
// Query contains only an optional artist, title, or genre for authorized
// catalog playback; it is never treated as a URL or instruction.
type MediaIntent struct {
	Kind  string
	Query string
}

// MediaIntentClassifier provides a semantic fallback when ASR wording does
// not match the fast deterministic routes. It classifies text only and cannot
// play media or mutate the device by itself.
type MediaIntentClassifier interface {
	ClassifyMediaIntent(context.Context, string) (MediaIntent, error)
}

type DeviceImage struct {
	Format string
	Width  int
	Height int
	Data   []byte
}

type VisionPipeline interface {
	AnalyzeImage(context.Context, string, DeviceImage) (string, error)
}

type conversationWindow struct {
	mu    sync.Mutex
	turns []ConversationTurn
}

func (window *conversationWindow) Snapshot() []ConversationTurn {
	window.mu.Lock()
	defer window.mu.Unlock()
	return append([]ConversationTurn(nil), window.turns...)
}

func (window *conversationWindow) Add(user, assistant string) {
	window.mu.Lock()
	defer window.mu.Unlock()
	window.turns = append(window.turns,
		ConversationTurn{Role: "user", Content: compactConversationContent(user)},
		ConversationTurn{Role: "assistant", Content: compactConversationContent(assistant)})
	if len(window.turns) > maxConversationTurns*2 {
		window.turns = append([]ConversationTurn(nil),
			window.turns[len(window.turns)-maxConversationTurns*2:]...)
	}
}

func (window *conversationWindow) Metrics() (turns, runes int) {
	window.mu.Lock()
	defer window.mu.Unlock()
	for _, turn := range window.turns {
		runes += utf8.RuneCountInString(turn.Content)
	}
	return len(window.turns), runes
}

func compactConversationContent(content string) string {
	content = strings.TrimSpace(content)
	runes := []rune(content)
	if len(runes) <= maxConversationContentRunes {
		return content
	}
	// Keep both the beginning and the conclusion. Follow-up questions often
	// refer to either the premise or the final recommendation of a long reply.
	headRunes := maxConversationContentRunes * 3 / 4
	tailRunes := maxConversationContentRunes - headRunes - 1
	return string(runes[:headRunes]) + "…" + string(runes[len(runes)-tailRunes:])
}

func validateToolResult(result string) (string, error) {
	result = strings.TrimSpace(result)
	if result == "" || !utf8.ValidString(result) ||
		utf8.RuneCountInString(result) > maxToolResultRunes {
		return "", fmt.Errorf("invalid tool result")
	}
	return result, nil
}
