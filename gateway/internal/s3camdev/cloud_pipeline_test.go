package s3camdev

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

const (
	testDashScopeKey = "sk-dashscope-0123456789abcdef"
	testDeepSeekKey  = "sk-deepseek-0123456789abcdef"
)

func validCloudPipelineConfig() CloudPipelineConfig {
	return CloudPipelineConfig{
		ASRURL:    "https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions",
		ASRAPIKey: testDashScopeKey, ASRModel: "qwen3-asr-flash",
		AgentURL:    "https://api.deepseek.com/chat/completions",
		AgentAPIKey: testDeepSeekKey, AgentModel: "deepseek-v4-flash",
		TTSURL:    "https://dashscope-intl.aliyuncs.com/api/v1/services/aigc/multimodal-generation/generation",
		TTSAPIKey: testDashScopeKey, TTSModel: "qwen3-tts-flash",
		TTSVoice: "Cherry", FFmpegPath: "ffmpeg",
	}
}

func TestCloudPipelineAcceptsOnlyPinnedProviderEndpoints(t *testing.T) {
	if _, err := NewCloudPipeline(validCloudPipelineConfig()); err != nil {
		t.Fatalf("official cloud provider configuration was rejected: %v", err)
	}
	workspaceConfig := validCloudPipelineConfig()
	workspaceConfig.ASRURL = "https://ws-123.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1/chat/completions"
	workspaceConfig.TTSURL = "https://ws-123.ap-southeast-1.maas.aliyuncs.com/api/v1/services/aigc/multimodal-generation/generation"
	if _, err := NewCloudPipeline(workspaceConfig); err != nil {
		t.Fatalf("workspace-specific Singapore endpoints were rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*CloudPipelineConfig)
	}{
		{"HTTP ASR", func(config *CloudPipelineConfig) {
			config.ASRURL = "http://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions"
		}},
		{"attacker ASR", func(config *CloudPipelineConfig) {
			config.ASRURL = "https://dashscope-intl.aliyuncs.com.evil.example/compatible-mode/v1/chat/completions"
		}},
		{"nested fake workspace", func(config *CloudPipelineConfig) {
			config.ASRURL = "https://fake.ws-123.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1/chat/completions"
		}},
		{"DeepSeek query", func(config *CloudPipelineConfig) {
			config.AgentURL = "https://api.deepseek.com/chat/completions?key=leak"
		}},
		{"wrong TTS path", func(config *CloudPipelineConfig) {
			config.TTSURL = "https://dashscope-intl.aliyuncs.com/other"
		}},
		{"whitespace key", func(config *CloudPipelineConfig) {
			config.AgentAPIKey = "sk-invalid key"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validCloudPipelineConfig()
			test.mutate(&config)
			if _, err := NewCloudPipeline(config); err == nil {
				t.Fatal("unsafe cloud provider configuration was accepted")
			}
		})
	}
}

func TestCloudAgentUsesBearerAndNormalizesSpokenReply(t *testing.T) {
	config := validCloudPipelineConfig()
	config.HTTPClient = &http.Client{Transport: roundTripFunc(
		func(request *http.Request) (*http.Response, error) {
			if request.URL.String() != config.AgentURL ||
				request.Header.Get("Authorization") != "Bearer "+testDeepSeekKey ||
				request.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("invalid DeepSeek request: url=%s headers=%v",
					request.URL, request.Header)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Body: io.NopCloser(strings.NewReader(
					`{"choices":[{"message":{"content":"**東京 Gateway 正常。**"}}]}`)),
				Request: request,
			}, nil
		})}
	pipeline, err := NewCloudPipeline(config)
	if err != nil {
		t.Fatal(err)
	}
	reply, err := pipeline.Reply(context.Background(), "請回覆測試")
	if err != nil {
		t.Fatal(err)
	}
	if reply != "東京 Gateway 正常。" {
		t.Fatalf("unexpected spoken reply: %q", reply)
	}
}

func TestSignedAudioURLIsUpgradedAndRestricted(t *testing.T) {
	trusted, err := validateSignedAudioURL(
		"http://dashscope-result-sg.oss-ap-southeast-1.aliyuncs.com/audio.wav?Expires=1")
	if err != nil || trusted.Scheme != "https" ||
		trusted.RawQuery != "Expires=1" {
		t.Fatalf("trusted signed URL was not safely upgraded: url=%v err=%v",
			trusted, err)
	}
	for _, raw := range []string{
		"https://evil.example/audio.wav",
		"https://aliyuncs.com/audio.wav",
		"https://trusted.aliyuncs.com.evil.example/audio.wav",
		"https://user:pass@trusted.aliyuncs.com/audio.wav",
		"https://trusted.aliyuncs.com:8443/audio.wav",
	} {
		if _, err := validateSignedAudioURL(raw); err == nil {
			t.Fatalf("untrusted signed audio URL was accepted: %s", raw)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
