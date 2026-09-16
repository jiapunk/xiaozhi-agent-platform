package s3camdev

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestSingingIntentIsExplicitAcrossScripts(t *testing.T) {
	for _, prompt := range []string{
		"唱歌", "請唱一首關於小智的歌", "帮我唱一段开心的短歌",
		"清唱給我聽", "please sing for me", "sing a song about space",
	} {
		if !isSingingIntent(prompt) {
			t.Fatalf("explicit singing request was missed: %q", prompt)
		}
	}
	for _, prompt := range []string{
		"你會唱歌嗎？", "唱歌需要什麼技術？", "can you sing?",
		"請解釋音樂生成", "播放音樂", "來首歌",
	} {
		if isSingingIntent(prompt) {
			t.Fatalf("non-performance question triggered singing: %q", prompt)
		}
	}
}

func TestOpenRouterPlansOnlyBoundedOriginalSong(t *testing.T) {
	config := validOpenRouterPipelineConfig()
	config.HTTPClient = &http.Client{Transport: roundTripFunc(
		func(request *http.Request) (*http.Response, error) {
			if request.URL.String() != openRouterAgentURL {
				t.Fatalf("unexpected song planning endpoint: %s", request.URL)
			}
			var body struct {
				Messages       []map[string]any `json:"messages"`
				Temperature    float64          `json:"temperature"`
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
			system, _ := body.Messages[0]["content"].(string)
			if body.ResponseFormat.Type != "json_schema" ||
				!body.ResponseFormat.JSONSchema.Strict || len(body.Plugins) != 1 ||
				!strings.Contains(system, "只能創作全新歌詞") ||
				!strings.Contains(system, "不得模仿任何真人歌手") ||
				!strings.Contains(system, "四到八行") {
				t.Fatalf("song safety contract missing: %+v", body)
			}
			content, _ := json.Marshal(songPlan{
				Status: "ok", Title: "小小探索家",
				Lyrics: "小小晶片醒來啦\n跟著晨光去出發\n鏡頭看見新世界\n溫暖回答帶回家",
				Style:  "bright", SpokenReply: "",
			})
			response, _ := json.Marshal(map[string]any{
				"choices": []map[string]any{{
					"message": map[string]string{"content": string(content)},
				}},
			})
			return &http.Response{
				StatusCode: http.StatusOK, Header: make(http.Header),
				Body:    io.NopCloser(strings.NewReader(string(response))),
				Request: request,
			}, nil
		})}
	pipeline, err := NewOpenRouterPipeline(config)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := pipeline.planOriginalSong(context.Background(),
		"請唱一首關於小智探索世界的歌", nil, &toolExecutorStub{})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Status != "ok" || plan.Title != "小小探索家" ||
		len(nonemptySongLines(plan.Lyrics)) != 4 || plan.Style != "bright" {
		t.Fatalf("unexpected original song plan: %+v", plan)
	}
}

func TestOriginalSongMusicPayloadUsesLyriaAndNoVoiceClone(t *testing.T) {
	pipeline, err := NewOpenRouterPipeline(validOpenRouterPipelineConfig())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := pipeline.originalSongMusicPayload(
		"星光輕輕亮起\n小智陪我遠行\n看見新的風景\n把好奇放在心裡", "gentle")
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Model      string              `json:"model"`
		Messages   []map[string]string `json:"messages"`
		Modalities []string            `json:"modalities"`
		Audio      struct {
			Format string `json:"format"`
			Voice  string `json:"voice"`
		} `json:"audio"`
		Stream   bool `json:"stream"`
		Provider struct {
			DataCollection string `json:"data_collection"`
		} `json:"provider"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatal(err)
	}
	if body.Model != pipeline.musicModel || len(body.Messages) != 1 ||
		len(body.Modalities) != 2 || body.Modalities[0] != "text" ||
		body.Modalities[1] != "audio" || body.Audio.Format != "mp3" ||
		body.Audio.Voice != "" || !body.Stream ||
		body.Provider.DataCollection != "deny" ||
		!strings.Contains(body.Messages[0]["content"], "clearly sung") ||
		!strings.Contains(body.Messages[0]["content"], "never speak") ||
		!strings.Contains(body.Messages[0]["content"], "星光輕輕亮起") {
		t.Fatalf("invalid Lyria music payload: %+v", body)
	}
}

func TestOpenRouterMusicStreamDecodesBoundedAudio(t *testing.T) {
	audioFixture := []byte("ID3-safe-unit-test-audio")
	event, _ := json.Marshal(map[string]any{
		"choices": []map[string]any{{
			"delta": map[string]any{"audio": map[string]string{
				"data": base64.StdEncoding.EncodeToString(audioFixture),
			}},
			"finish_reason": nil,
		}},
	})
	config := validOpenRouterPipelineConfig()
	config.HTTPClient = &http.Client{Transport: roundTripFunc(
		func(request *http.Request) (*http.Response, error) {
			if request.URL.String() != openRouterAgentURL ||
				request.Header.Get("Accept") != "text/event-stream" {
				t.Fatalf("invalid OpenRouter music request: %s headers=%v",
					request.URL, request.Header)
			}
			return &http.Response{
				StatusCode: http.StatusOK, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader(
					"data: " + string(event) + "\n\n" + "data: [DONE]\n\n")),
				Request: request,
			}, nil
		})}
	pipeline, err := NewOpenRouterPipeline(config)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := pipeline.originalSongMusicPayload(
		"小智迎著光\n一起去遠航", "bright")
	if err != nil {
		t.Fatal(err)
	}
	audio, err := pipeline.generateOpenRouterMusic(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	if string(audio) != string(audioFixture) {
		t.Fatalf("unexpected decoded music audio: %q", audio)
	}
}

func TestSongPlanRejectsUnsafeOrUnboundedOutput(t *testing.T) {
	valid := songPlan{
		Status: "ok", Title: "新歌", Style: "playful",
		Lyrics: "第一行是新的\n第二行向前走\n第三行看星光\n第四行一起笑",
	}
	if err := validateSongPlan(valid, "唱一首新歌"); err != nil {
		t.Fatalf("valid original song rejected: %v", err)
	}
	invalid := valid
	invalid.Lyrics = ""
	if validateSongPlan(invalid, "唱歌") == nil {
		t.Fatal("empty song was accepted")
	}
	invalid = valid
	invalid.Lyrics = "只有一行也能作為最短清唱"
	if validateSongPlan(invalid, "唱歌") != nil {
		t.Fatal("safe one-line fallback was rejected")
	}
	invalid = valid
	invalid.Lyrics = "這是一段由使用者提供而且長度足夠的原始歌詞內容不應該被逐字複製回來\n" +
		"第二行\n第三行\n第四行"
	if validateSongPlan(invalid,
		"請唱這是一段由使用者提供而且長度足夠的原始歌詞內容不應該被逐字複製回來") == nil {
		t.Fatal("long verbatim user lyrics were accepted")
	}
	if validateSongPlan(songPlan{
		Status: "refuse", SpokenReply: "我不能重現既有歌曲，但可以唱同主題的原創短歌。",
	}, "唱某首現有歌曲") != nil {
		t.Fatal("valid safety refusal was rejected")
	}
	if lines := nonemptySongLines(normalizePlannedSongLyrics(
		"第一句向前走。第二句看星光。第三句輕輕唱。第四句回到家。")); len(lines) != 4 {
		t.Fatalf("sentence-delimited lyrics were not normalized: %+v", lines)
	}
	if lines := nonemptySongLines(normalizePlannedSongLyrics(
		"第一句向前走，第二句看星光，第三句輕輕唱，第四句回到家")); len(lines) != 4 {
		t.Fatalf("comma-delimited lyrics were not normalized: %+v", lines)
	}
}
