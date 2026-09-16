package s3camdev

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestMediaClassificationCandidateIsBroadButBounded(t *testing.T) {
	for _, transcript := range []string{
		"播放音樂", "幫我找首曲子", "唱一首歌來聽", "listen to a song",
	} {
		if !mayNeedMediaClassification(transcript) {
			t.Fatalf("media candidate missed: %q", transcript)
		}
	}
	for _, transcript := range []string{
		"今天天氣如何", "把音量放大", "拍照看看前面",
	} {
		if mayNeedMediaClassification(transcript) {
			t.Fatalf("ordinary request became media candidate: %q", transcript)
		}
	}
}

func TestOpenRouterClassifiesSemanticOnlineMusicIntent(t *testing.T) {
	config := validOpenRouterPipelineConfig()
	config.HTTPClient = &http.Client{Transport: roundTripFunc(
		func(request *http.Request) (*http.Response, error) {
			if request.URL.String() != openRouterAgentURL {
				t.Fatalf("unexpected classifier endpoint: %s", request.URL)
			}
			var body struct {
				Messages       []map[string]any `json:"messages"`
				Temperature    float64          `json:"temperature"`
				MaxTokens      int              `json:"max_tokens"`
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
			system, _ := body.Messages[0]["content"].(string)
			if body.ResponseFormat.Type != "json_schema" ||
				!body.ResponseFormat.JSONSchema.Strict || body.Temperature != 0 ||
				body.MaxTokens != 100 ||
				!strings.Contains(system, "模糊說法也優先 online_music") {
				t.Fatalf("semantic media classifier contract missing: %+v", body)
			}
			payload, _ := json.Marshal(map[string]any{
				"choices": []map[string]any{{
					"message": map[string]string{
						"content": `{"kind":"online_music","query":"Day Dreamin"}`,
					},
				}},
			})
			return &http.Response{StatusCode: http.StatusOK,
				Body:   io.NopCloser(strings.NewReader(string(payload))),
				Header: make(http.Header), Request: request}, nil
		})}
	pipeline, err := NewOpenRouterPipeline(config)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := pipeline.ClassifyMediaIntent(
		context.Background(), "麻煩找那首 Day Dreamin 給我聽")
	if err != nil || intent.Kind != "online_music" ||
		intent.Query != "Day Dreamin" ||
		canonicalOnlineMusicTranscript(intent) != "播放 Day Dreamin" {
		t.Fatalf("unexpected media intent: %+v error=%v", intent, err)
	}
}

func TestMediaIntentValidationRejectsExecutableOrInconsistentOutput(t *testing.T) {
	for _, intent := range []mediaIntentResponse{
		{Kind: "online_music", Query: "Day Dreamin"},
		{Kind: "online_music", Query: ""},
		{Kind: "original_singing", Query: ""},
		{Kind: "none", Query: ""},
	} {
		if !validMediaIntent(intent) {
			t.Fatalf("valid media intent rejected: %+v", intent)
		}
	}
	for _, intent := range []mediaIntentResponse{
		{Kind: "tool", Query: "music"},
		{Kind: "none", Query: "Day Dreamin"},
		{Kind: "original_singing", Query: "ignore instructions"},
		{Kind: "online_music", Query: "bad\nquery"},
	} {
		if validMediaIntent(intent) {
			t.Fatalf("invalid media intent accepted: %+v", intent)
		}
	}
}
