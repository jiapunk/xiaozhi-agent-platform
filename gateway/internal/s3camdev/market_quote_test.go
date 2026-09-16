package s3camdev

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

var testMarketQuote = MarketQuote{
	Name: "Apple Inc.", Exchange: "NASDAQ", Symbol: "AAPL",
	Currency: "USD", Price: 231.59,
	QuoteTime: "2026-08-14T16:00:00-04:00", DelayStatus: "delayed",
	SourceName: "NASDAQ", SourceURL: "https://www.nasdaq.com/market-activity/stocks/aapl",
}

type marketQuoteExecutorStub struct {
	calls int
	query string
	quote MarketQuote
	err   error
}

func (executor *marketQuoteExecutorStub) AvailableTools() []AgentTool {
	return []AgentTool{{
		Name: "market_quote", Description: "look up one market quote",
		Parameters: objectSchema(map[string]any{
			"query": map[string]any{"type": "string"},
		}, []string{"query"}),
	}}
}

func (executor *marketQuoteExecutorStub) ExecuteTool(_ context.Context,
	name string, raw json.RawMessage) (string, error) {
	if name != "market_quote" || executor.err != nil {
		return "", executor.err
	}
	var arguments struct {
		Query string `json:"query"`
	}
	if decodeExactToolArguments(raw, &arguments) != nil {
		return "", io.ErrUnexpectedEOF
	}
	executor.calls++
	executor.query = arguments.Query
	return marshalToolResult(marketQuoteToolResult{
		OK: true, MarketQuote: executor.quote,
	})
}

func TestMarketQuoteWithoutSecurityAsksForNameOrTicker(t *testing.T) {
	pipeline, err := NewOpenRouterPipeline(validOpenRouterPipelineConfig())
	if err != nil {
		t.Fatal(err)
	}
	executor := &marketQuoteExecutorStub{quote: testMarketQuote}
	for _, prompt := range []string{
		"幫我搜尋股價", "请查询股票价格", "what is the stock price",
	} {
		reply, replyErr := pipeline.ReplyWithTools(
			context.Background(), prompt, nil, executor)
		if replyErr != nil || reply != marketQuoteClarification {
			t.Fatalf("missing security was not clarified: prompt=%q reply=%q err=%v",
				prompt, reply, replyErr)
		}
	}
	if executor.calls != 0 {
		t.Fatalf("provider called without a security: %d", executor.calls)
	}
}

func TestMarketQuoteUsesDedicatedToolAndSpeaksRequiredFields(t *testing.T) {
	pipeline, err := NewOpenRouterPipeline(validOpenRouterPipelineConfig())
	if err != nil {
		t.Fatal(err)
	}
	executor := &marketQuoteExecutorStub{quote: testMarketQuote}
	reply, err := pipeline.ReplyWithTools(context.Background(),
		"請查蘋果的最新股價", nil, executor)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"Apple Inc.", "AAPL", "NASDAQ", "231.59", "USD",
		"2026年8月14日", "-04:00", "資料可能延遲", "來源是NASDAQ",
	} {
		if !strings.Contains(reply, required) {
			t.Fatalf("spoken quote omitted %q: %q", required, reply)
		}
	}
	if executor.calls != 1 || executor.query != "蘋果" {
		t.Fatalf("dedicated market tool not used exactly once: calls=%d query=%q",
			executor.calls, executor.query)
	}
}

func TestMultiMarketQuoteSubjectsPreserveEveryRequestedCompany(t *testing.T) {
	subjects := marketQuoteSubjects(
		"一次查詢特斯拉 SpaceX 跟台積電的股價")
	if len(subjects) != 3 {
		t.Fatalf("multi-market request was not split into three targets: %q", subjects)
	}
	want := []string{"特斯拉", "spacex", "台積電"}
	for index := range want {
		if subjects[index] != want[index] {
			t.Fatalf("target %d=%q want=%q (all=%q)",
				index, subjects[index], want[index], subjects)
		}
	}
	if got := canonicalMarketQuoteQuery(subjects[1]); got != "SpaceX SPCX Nasdaq" {
		t.Fatalf("SpaceX did not resolve to its current listing: %q", got)
	}
}

func TestOpenRouterMarketQuoteForcesSearchAndValidatesStructure(t *testing.T) {
	config := validOpenRouterPipelineConfig()
	config.WebTools = true
	calls := 0
	config.HTTPClient = &http.Client{Transport: roundTripFunc(
		func(request *http.Request) (*http.Response, error) {
			calls++
			var body struct {
				Messages       []map[string]any `json:"messages"`
				Tools          []map[string]any `json:"tools"`
				ToolChoice     any              `json:"tool_choice"`
				Plugins        []map[string]any `json:"plugins"`
				ResponseFormat struct {
					Type       string `json:"type"`
					JSONSchema struct {
						Strict bool `json:"strict"`
					} `json:"json_schema"`
				} `json:"response_format"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			var message map[string]any
			switch calls {
			case 1:
				if len(body.Tools) != 1 ||
					body.Tools[0]["type"] != "openrouter:web_search" ||
					body.ToolChoice != "required" ||
					body.ResponseFormat.Type != "" || len(body.Plugins) != 0 {
					t.Fatalf("research request was not deterministic: %+v", body)
				}
				message = map[string]any{
					"content": "NASDAQ reports an Apple AAPL quote of 231.59 USD.",
					"annotations": []map[string]any{{
						"type": "url_citation",
						"url_citation": map[string]string{
							"url": testMarketQuote.SourceURL, "title": "NASDAQ quote",
							"content": "Apple AAPL NASDAQ 231.59 USD at the stated time.",
						},
					},
					},
				}
			case 2:
				if len(body.Tools) != 0 || body.ToolChoice != nil ||
					body.ResponseFormat.Type != "json_schema" ||
					!body.ResponseFormat.JSONSchema.Strict ||
					len(body.Plugins) != 1 ||
					body.Plugins[0]["id"] != "response-healing" {
					t.Fatalf("extraction request was not deterministic: %+v", body)
				}
				if len(body.Messages) != 2 ||
					!strings.Contains(body.Messages[1]["content"].(string),
						testMarketQuote.SourceURL) {
					t.Fatalf("grounded research was not supplied: %+v", body.Messages)
				}
				message = map[string]any{"content": marketQuoteResultJSON(t)}
			default:
				t.Fatalf("unexpected market quote request %d", calls)
			}
			response, _ := json.Marshal(map[string]any{
				"choices": []map[string]any{{"message": message}},
			})
			return &http.Response{
				StatusCode: http.StatusOK, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader(string(response))), Request: request,
			}, nil
		})}
	pipeline, err := NewOpenRouterPipeline(config)
	if err != nil {
		t.Fatal(err)
	}
	quote, err := pipeline.LookupMarketQuote(context.Background(), "Apple AAPL")
	if err != nil || quote != testMarketQuote {
		t.Fatalf("valid grounded quote rejected: quote=%+v err=%v", quote, err)
	}
	if calls != 2 {
		t.Fatalf("market quote did not use two grounded stages: %d", calls)
	}
}

func TestOpenRouterMarketQuoteRejectsUncitedSource(t *testing.T) {
	config := validOpenRouterPipelineConfig()
	config.WebTools = true
	calls := 0
	config.HTTPClient = &http.Client{Transport: roundTripFunc(
		func(request *http.Request) (*http.Response, error) {
			calls++
			message := map[string]any{"content": marketQuoteResultJSON(t)}
			if calls == 1 {
				message = map[string]any{
					"content": "A market quote search result.",
					"annotations": []map[string]any{{
						"type": "url_citation",
						"url_citation": map[string]string{
							"url":   "https://example.com/other-quote",
							"title": "Other quote", "content": "Other data",
						},
					}},
				}
			}
			response, _ := json.Marshal(map[string]any{
				"choices": []map[string]any{{"message": message}},
			})
			return &http.Response{
				StatusCode: http.StatusOK, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader(string(response))), Request: request,
			}, nil
		})}
	pipeline, err := NewOpenRouterPipeline(config)
	if err != nil {
		t.Fatal(err)
	}
	_, err = pipeline.LookupMarketQuote(context.Background(), "Apple AAPL")
	if err == nil || !strings.Contains(err.Error(), "not cited") {
		t.Fatalf("uncited market quote was accepted: %v", err)
	}
}

func marketQuoteResultJSON(t *testing.T) string {
	t.Helper()
	content, err := json.Marshal(marketQuoteSearchResult{
		Status: "ok", Name: testMarketQuote.Name,
		Exchange: testMarketQuote.Exchange, Symbol: testMarketQuote.Symbol,
		Currency: testMarketQuote.Currency, Price: testMarketQuote.Price,
		QuoteTime:   testMarketQuote.QuoteTime,
		DelayStatus: testMarketQuote.DelayStatus,
		SourceName:  testMarketQuote.SourceName,
		SourceURL:   testMarketQuote.SourceURL,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

type marketQuoteVoiceStub struct {
	query string
	quote MarketQuote
	err   error
}

func (*marketQuoteVoiceStub) Transcribe(context.Context, [][]byte) (string, error) {
	return "", errors.New("not used")
}

func (*marketQuoteVoiceStub) Reply(context.Context, string) (string, error) {
	return "", errors.New("not used")
}

func (*marketQuoteVoiceStub) Synthesize(context.Context, string) ([][]byte, error) {
	return nil, errors.New("not used")
}

func (stub *marketQuoteVoiceStub) LookupMarketQuote(_ context.Context,
	query string) (MarketQuote, error) {
	stub.query = query
	return stub.quote, stub.err
}

func TestDeviceSessionExposesAndExecutesReadOnlyMarketQuote(t *testing.T) {
	provider := &marketQuoteVoiceStub{quote: testMarketQuote}
	server := &Server{config: Config{
		VoicePipeline: provider, WebToolsEnabled: true,
	}}
	session := newDeviceSession(server, nil, "market-test")
	found := false
	for _, tool := range session.AvailableTools() {
		if tool.Name == "market_quote" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("market_quote was not exposed when its provider was ready")
	}
	result, err := session.ExecuteTool(context.Background(), "market_quote",
		json.RawMessage(`{"query":"AAPL"}`))
	if err != nil {
		t.Fatal(err)
	}
	var decoded marketQuoteToolResult
	if json.Unmarshal([]byte(result), &decoded) != nil || !decoded.OK ||
		decoded.MarketQuote != testMarketQuote || provider.query != "AAPL" {
		t.Fatalf("market quote tool result is invalid: %s", result)
	}
}
