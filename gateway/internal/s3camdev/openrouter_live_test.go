package s3camdev

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// TestOpenRouterLiveRoundTrip is opt-in because it makes three billable provider
// calls. It logs no transcript, reply, audio, credential, or provider payload.
func TestOpenRouterLiveRoundTrip(t *testing.T) {
	apiKey := os.Getenv("S3CAM_OPENROUTER_LIVE_KEY")
	if apiKey == "" {
		t.Skip("S3CAM_OPENROUTER_LIVE_KEY is not set")
	}
	config := validOpenRouterPipelineConfig()
	config.APIKey = apiKey
	pipeline, err := NewOpenRouterPipeline(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	_, err = pipeline.Reply(ctx, "請只用繁體中文回答：日本伺服器連線成功。")
	if err != nil {
		t.Fatal(err)
	}
	ttsPayload, err := json.Marshal(map[string]any{
		"model":           pipeline.ttsModel,
		"input":           "日本伺服器語音測試成功。",
		"voice":           pipeline.ttsVoice,
		"response_format": "mp3",
		"speed":           1.0,
		"provider":        map[string]string{"data_collection": "deny"},
	})
	if err != nil {
		t.Fatal(err)
	}
	audio, err := pipeline.postAudio(ctx, openRouterTTSURL, ttsPayload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pipeline.encodeTTSOpus(ctx, audio); err != nil {
		t.Fatal(err)
	}
	asrOgg, err := pipeline.runFFmpeg(ctx, audio,
		"-i", "pipe:0", "-map", "0:a:0", "-ac", "1",
		"-ar", "16000", "-c:a", "libopus", "-application", "voip",
		"-frame_duration", "60", "-vbr", "off", "-b:a", "24000",
		"-f", "opus", "pipe:1")
	if err != nil {
		t.Fatal(err)
	}
	asrPackets, err := parseOggPackets(asrOgg)
	if err != nil || len(asrPackets) < 3 {
		t.Fatalf("invalid generated ASR fixture: packets=%d err=%v",
			len(asrPackets), err)
	}
	transcript, err := pipeline.Transcribe(ctx, asrPackets[2:])
	if err != nil {
		t.Fatal(err)
	}
	if transcript == "" {
		t.Fatal("live OpenRouter ASR returned empty text")
	}
}

// TestOpenRouterLiveMarketQuote is opt-in because it makes one billable web
// search call. It logs the public quote fields but never logs the credential or
// the provider request.
func TestOpenRouterLiveMarketQuote(t *testing.T) {
	apiKey := os.Getenv("S3CAM_OPENROUTER_LIVE_KEY")
	if apiKey == "" {
		t.Skip("S3CAM_OPENROUTER_LIVE_KEY is not set")
	}
	config := validOpenRouterPipelineConfig()
	config.APIKey = apiKey
	config.WebTools = true
	if model := os.Getenv("S3CAM_OPENROUTER_LIVE_AGENT_MODEL"); model != "" {
		config.AgentModel = model
	}
	pipeline, err := NewOpenRouterPipeline(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	query := os.Getenv("S3CAM_OPENROUTER_LIVE_MARKET_QUERY")
	if query == "" {
		query = "Apple AAPL"
	}
	quote, err := pipeline.LookupMarketQuote(ctx, query)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("name=%s exchange=%s symbol=%s currency=%s price=%v quote_time=%s delay=%s source=%s source_url=%s",
		quote.Name, quote.Exchange, quote.Symbol, quote.Currency, quote.Price,
		quote.QuoteTime, quote.DelayStatus, quote.SourceName, quote.SourceURL)
}

// TestOpenRouterLiveSinging is opt-in because it makes one Agent call and one
// billable Lyria music call. It verifies that a true vocal music clip survives
// OpenRouter's audio stream and the ESP32 Opus conversion path.
func TestOpenRouterLiveSinging(t *testing.T) {
	apiKey := os.Getenv("S3CAM_OPENROUTER_LIVE_KEY")
	if apiKey == "" {
		t.Skip("S3CAM_OPENROUTER_LIVE_KEY is not set")
	}
	config := validOpenRouterPipelineConfig()
	config.APIKey = apiKey
	if model := os.Getenv("S3CAM_OPENROUTER_LIVE_AGENT_MODEL"); model != "" {
		config.AgentModel = model
	}
	pipeline, err := NewOpenRouterPipeline(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	performance, err := pipeline.Sing(ctx,
		"請唱一首關於小智機器人探索星空的開心原創短歌",
		nil, &toolExecutorStub{})
	if err != nil {
		t.Fatal(err)
	}
	if performance.DisplayText == "" || len(performance.Packets) < 10 {
		t.Fatalf("live singing performance is invalid: text=%t packets=%d",
			performance.DisplayText != "", len(performance.Packets))
	}
}
