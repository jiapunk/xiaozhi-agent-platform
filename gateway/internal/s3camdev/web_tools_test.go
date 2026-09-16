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

func TestOpenRouterLiveWebSearchRequiresGroundedServerTool(t *testing.T) {
	config := validOpenRouterPipelineConfig()
	config.WebTools = true
	config.HTTPClient = &http.Client{Transport: roundTripFunc(
		func(request *http.Request) (*http.Response, error) {
			var body struct {
				Tools      []map[string]any `json:"tools"`
				ToolChoice any              `json:"tool_choice"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if len(body.Tools) != 1 ||
				body.Tools[0]["type"] != "openrouter:web_search" ||
				body.ToolChoice != "required" {
				t.Fatalf("web search was not required: %+v", body)
			}
			response, _ := json.Marshal(map[string]any{
				"choices": []map[string]any{{"message": map[string]any{
					"content": "香港今天二十八度，有短暫陣雨。資料時間為上午十時。",
					"annotations": []map[string]any{{
						"type": "url_citation", "url_citation": map[string]string{
							"url":   "https://www.hko.gov.hk/weather",
							"title": "香港天文台",
						},
					}},
				}}},
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
	result, err := pipeline.SearchWeb(context.Background(), "香港今天天氣")
	if err != nil {
		t.Fatal(err)
	}
	var decoded liveWebToolResult
	if json.Unmarshal([]byte(result), &decoded) != nil || !decoded.OK ||
		len(decoded.Sources) != 1 || decoded.Sources[0].Name != "香港天文台" ||
		!strings.Contains(decoded.Answer, "二十八度") {
		t.Fatalf("invalid live web result: %s", result)
	}
}

type liveWebVoiceStub struct {
	searchQuery string
	fetchURL    string
	fetchQuery  string
}

func (*liveWebVoiceStub) Transcribe(context.Context, [][]byte) (string, error) {
	return "", errors.New("not used")
}

func (*liveWebVoiceStub) Reply(context.Context, string) (string, error) {
	return "", errors.New("not used")
}

func (*liveWebVoiceStub) Synthesize(context.Context, string) ([][]byte, error) {
	return nil, errors.New("not used")
}

func (stub *liveWebVoiceStub) SearchWeb(_ context.Context, query string) (string, error) {
	stub.searchQuery = query
	return `{"ok":true,"answer":"晴天"}`, nil
}

func (stub *liveWebVoiceStub) FetchWeb(_ context.Context,
	rawURL, question string) (string, error) {
	stub.fetchURL = rawURL
	stub.fetchQuery = question
	return `{"ok":true,"answer":"頁面摘要"}`, nil
}

func TestDeviceSessionExposesAndExecutesRealtimeWebTools(t *testing.T) {
	provider := &liveWebVoiceStub{}
	server := &Server{config: Config{
		VoicePipeline: provider, WebToolsEnabled: true,
	}}
	session := newDeviceSession(server, nil, "web-test")
	found := map[string]bool{}
	for _, tool := range session.AvailableTools() {
		found[tool.Name] = true
	}
	if !found["web_search"] || !found["web_fetch"] {
		t.Fatalf("Realtime web tools were not exposed: %+v", found)
	}
	if _, err := session.ExecuteTool(context.Background(), "web_search",
		json.RawMessage(`{"query":"香港今天天氣"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := session.ExecuteTool(context.Background(), "web_fetch",
		json.RawMessage(`{"url":"https://example.com/weather","question":"摘要"}`)); err != nil {
		t.Fatal(err)
	}
	if provider.searchQuery != "香港今天天氣" ||
		provider.fetchURL != "https://example.com/weather" ||
		provider.fetchQuery != "摘要" {
		t.Fatalf("web tool arguments were not preserved: %+v", provider)
	}
}

func TestOpenRouterLiveWebFetchRejectsInsecureURL(t *testing.T) {
	pipeline, err := NewOpenRouterPipeline(validOpenRouterPipelineConfig())
	if err != nil {
		t.Fatal(err)
	}
	pipeline.webTools = true
	if _, err := pipeline.FetchWeb(context.Background(),
		"http://example.com", "摘要"); err == nil {
		t.Fatal("insecure web fetch URL was accepted")
	}
}
