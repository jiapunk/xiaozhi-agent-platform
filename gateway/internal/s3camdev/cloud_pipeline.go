package s3camdev

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"xiaozhi-agent-platform/gateway/internal/opuspacket"
)

const (
	maxCloudASRResponseBytes   = 256 * 1024
	maxCloudAgentResponseBytes = 512 * 1024
	maxCloudTTSResponseBytes   = 256 * 1024
	maxCloudTTSDownloadBytes   = 16 * 1024 * 1024
	maxCloudRedirects          = 3
)

type CloudPipelineConfig struct {
	ASRURL      string
	ASRAPIKey   string
	ASRModel    string
	AgentURL    string
	AgentAPIKey string
	AgentModel  string
	TTSURL      string
	TTSAPIKey   string
	TTSModel    string
	TTSVoice    string
	FFmpegPath  string
	HTTPClient  *http.Client
}

// CloudPipeline keeps all provider credentials in the product-owned Gateway.
// The ESP32 only talks to this Gateway and never receives provider API keys.
type CloudPipeline struct {
	asrURL      string
	asrAPIKey   string
	asrModel    string
	agentURL    string
	agentAPIKey string
	agentModel  string
	ttsURL      string
	ttsAPIKey   string
	ttsModel    string
	ttsVoice    string
	ffmpegPath  string
	httpClient  *http.Client
}

func NewCloudPipeline(config CloudPipelineConfig) (*CloudPipeline, error) {
	if err := validateDashScopeHTTPSURL(config.ASRURL,
		"/compatible-mode/v1/chat/completions"); err != nil {
		return nil, fmt.Errorf("ASR endpoint: %w", err)
	}
	if err := validateDeepSeekURL(config.AgentURL); err != nil {
		return nil, fmt.Errorf("Agent endpoint: %w", err)
	}
	if err := validateDashScopeHTTPSURL(config.TTSURL,
		"/api/v1/services/aigc/multimodal-generation/generation"); err != nil {
		return nil, fmt.Errorf("TTS endpoint: %w", err)
	}
	for name, secret := range map[string]string{
		"ASR API key": config.ASRAPIKey, "Agent API key": config.AgentAPIKey,
		"TTS API key": config.TTSAPIKey,
	} {
		if err := validateSecret(secret); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	for name, value := range map[string]string{
		"ASR model": config.ASRModel, "Agent model": config.AgentModel,
		"TTS model": config.TTSModel, "TTS voice": config.TTSVoice,
		"FFmpeg path": config.FFmpegPath,
	} {
		if strings.TrimSpace(value) == "" || strings.TrimSpace(value) != value ||
			strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return nil, fmt.Errorf("%s is invalid", name)
		}
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	clientCopy := *client
	if clientCopy.Timeout == 0 {
		clientCopy.Timeout = 5 * time.Minute
	}
	// Provider authorization must never follow a redirect to another origin.
	// Signed TTS audio redirects are handled explicitly and revalidated below.
	clientCopy.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &CloudPipeline{
		asrURL: config.ASRURL, asrAPIKey: config.ASRAPIKey,
		asrModel: config.ASRModel, agentURL: config.AgentURL,
		agentAPIKey: config.AgentAPIKey, agentModel: config.AgentModel,
		ttsURL: config.TTSURL, ttsAPIKey: config.TTSAPIKey,
		ttsModel: config.TTSModel, ttsVoice: config.TTSVoice,
		ffmpegPath: config.FFmpegPath, httpClient: &clientCopy,
	}, nil
}

func validateDashScopeHTTPSURL(raw, expectedPath string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed == nil {
		return fmt.Errorf("must be the exact trusted HTTPS provider URL")
	}
	host := strings.ToLower(parsed.Hostname())
	workspaceSuffix := ".ap-southeast-1.maas.aliyuncs.com"
	workspacePrefix := strings.TrimSuffix(host, workspaceSuffix)
	trustedHost := host == "dashscope-intl.aliyuncs.com" ||
		(strings.HasSuffix(host, workspaceSuffix) && workspacePrefix != host &&
			workspacePrefix != "" && !strings.Contains(workspacePrefix, "."))
	if parsed.Scheme != "https" || !trustedHost ||
		parsed.Port() != "" || parsed.Path != expectedPath || parsed.RawPath != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return fmt.Errorf("must be the exact trusted HTTPS provider URL")
	}
	return nil
}

func validateDeepSeekURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" ||
		parsed.Hostname() != "api.deepseek.com" || parsed.Port() != "" ||
		(parsed.Path != "/chat/completions" && parsed.Path != "/v1/chat/completions") ||
		parsed.RawPath != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.User != nil {
		return fmt.Errorf("must be an exact trusted DeepSeek HTTPS URL")
	}
	return nil
}

func validateSecret(secret string) error {
	if len(secret) < 8 || len(secret) > 4096 || strings.TrimSpace(secret) != secret ||
		strings.IndexFunc(secret, func(character rune) bool {
			return unicode.IsSpace(character) || unicode.IsControl(character)
		}) >= 0 {
		return fmt.Errorf("secret is missing or malformed")
	}
	return nil
}

func (pipeline *CloudPipeline) Transcribe(ctx context.Context,
	packets [][]byte) (string, error) {
	if pipeline == nil || len(packets) == 0 {
		return "", fmt.Errorf("no audio packets")
	}
	ogg, err := encodeOggOpus(packets, 16000)
	if err != nil {
		return "", err
	}
	pcm, err := pipeline.runFFmpeg(ctx, ogg,
		"-f", "ogg", "-i", "pipe:0", "-map", "0:a:0", "-ac", "1",
		"-ar", "16000", "-c:a", "pcm_s16le", "-f", "s16le", "pipe:1")
	if err != nil {
		return "", fmt.Errorf("decode microphone Opus: %w", err)
	}
	wav, err := encodePCM16WAV(pcm, 16000, 1)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(map[string]any{
		"model": pipeline.asrModel,
		"messages": []map[string]any{{
			"role": "user",
			"content": []map[string]any{{
				"type": "input_audio",
				"input_audio": map[string]string{
					"data": "data:audio/wav;base64," +
						base64.StdEncoding.EncodeToString(wav),
				},
			}},
		}},
		"stream":      false,
		"asr_options": map[string]bool{"enable_itn": true},
	})
	if err != nil {
		return "", err
	}
	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := pipeline.postJSON(ctx, pipeline.asrURL, pipeline.asrAPIKey,
		payload, maxCloudASRResponseBytes, &result); err != nil {
		return "", fmt.Errorf("call cloud ASR: %w", err)
	}
	if len(result.Choices) != 1 {
		return "", fmt.Errorf("cloud ASR returned an invalid choice count")
	}
	transcript := strings.TrimSpace(result.Choices[0].Message.Content)
	if transcript == "" || !utf8.ValidString(transcript) ||
		utf8.RuneCountInString(transcript) > 512 {
		return "", fmt.Errorf("cloud ASR returned invalid text")
	}
	return transcript, nil
}

func (pipeline *CloudPipeline) Reply(ctx context.Context,
	transcript string) (string, error) {
	transcript = strings.TrimSpace(transcript)
	if pipeline == nil || transcript == "" || !utf8.ValidString(transcript) ||
		utf8.RuneCountInString(transcript) > 512 {
		return "", fmt.Errorf("invalid cloud Agent input")
	}
	payload, err := json.Marshal(map[string]any{
		"model": pipeline.agentModel,
		"messages": []map[string]string{
			{"role": "system", "content": "你是 ESP32 產品中的語音智慧代理。使用自然的繁體中文完整回答，確保句子自然結束，不要使用 Markdown，也不要描述內部推理。內容應適合語音聆聽，但不得因篇幅而省略結尾。"},
			{"role": "user", "content": transcript},
		},
		"temperature": 0.4,
		"stream":      false,
		"thinking":    map[string]string{"type": "disabled"},
	})
	if err != nil {
		return "", err
	}
	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := pipeline.postJSON(ctx, pipeline.agentURL, pipeline.agentAPIKey,
		payload, maxCloudAgentResponseBytes, &result); err != nil {
		return "", fmt.Errorf("call DeepSeek Agent: %w", err)
	}
	if len(result.Choices) != 1 {
		return "", fmt.Errorf("DeepSeek Agent returned an invalid choice count")
	}
	reply := normalizeSpokenReply(result.Choices[0].Message.Content)
	if reply == "" {
		return "", fmt.Errorf("DeepSeek Agent returned no spoken reply")
	}
	return reply, nil
}

func (pipeline *CloudPipeline) Synthesize(ctx context.Context,
	reply string) ([][]byte, error) {
	reply = strings.TrimSpace(reply)
	if pipeline == nil || reply == "" || !utf8.ValidString(reply) ||
		utf8.RuneCountInString(reply) > maxSpokenReplyRunes {
		return nil, fmt.Errorf("invalid cloud TTS input")
	}
	payload, err := json.Marshal(map[string]any{
		"model": pipeline.ttsModel,
		"input": map[string]string{
			"text": reply, "voice": pipeline.ttsVoice,
			"language_type": "Chinese",
		},
	})
	if err != nil {
		return nil, err
	}
	var result struct {
		Output struct {
			Audio struct {
				URL string `json:"url"`
			} `json:"audio"`
		} `json:"output"`
	}
	if err := pipeline.postJSON(ctx, pipeline.ttsURL, pipeline.ttsAPIKey,
		payload, maxCloudTTSResponseBytes, &result); err != nil {
		return nil, fmt.Errorf("call cloud TTS: %w", err)
	}
	audioURL, err := validateSignedAudioURL(result.Output.Audio.URL)
	if err != nil {
		return nil, fmt.Errorf("cloud TTS audio URL: %w", err)
	}
	audio, err := pipeline.downloadSignedAudio(ctx, audioURL)
	if err != nil {
		return nil, fmt.Errorf("download cloud TTS audio: %w", err)
	}
	ogg, err := pipeline.runFFmpeg(ctx, audio,
		"-i", "pipe:0", "-map", "0:a:0", "-ac", "1", "-ar", "24000",
		"-af", "loudnorm=I=-14:LRA=6:TP=-1.0",
		"-c:a", "libopus", "-application", "voip", "-frame_duration", "60",
		"-vbr", "off", "-b:a", "24000", "-f", "opus", "pipe:1")
	if err != nil {
		return nil, fmt.Errorf("encode cloud TTS Opus: %w", err)
	}
	packets, err := parseOggPackets(ogg)
	if err != nil || len(packets) < 3 || len(packets[0]) < 8 ||
		len(packets[1]) < 8 || string(packets[0][:8]) != "OpusHead" ||
		string(packets[1][:8]) != "OpusTags" {
		return nil, fmt.Errorf("cloud TTS returned invalid Ogg Opus")
	}
	packets = packets[2:]
	if len(packets) == 0 || len(packets) > maxSpokenReplyOpusPackets {
		return nil, fmt.Errorf("cloud TTS duration is out of range")
	}
	for _, packet := range packets {
		if err := opuspacket.ValidateMonoDuration(packet, opusFrameDurationMS); err != nil {
			return nil, fmt.Errorf("cloud TTS Opus frame rejected: %w", err)
		}
	}
	return packets, nil
}

func (pipeline *CloudPipeline) postJSON(ctx context.Context, endpoint, key string,
	payload []byte, maximum int64, output any) error {
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+key)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := pipeline.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("provider status %d", response.StatusCode)
	}
	return decodeLimitedJSON(response.Body, maximum, output)
}

func validateSignedAudioURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" || parsed.User != nil ||
		parsed.Fragment != "" || parsed.Port() != "" ||
		(parsed.Scheme != "https" && parsed.Scheme != "http") ||
		!isTrustedAlibabaAudioHost(parsed.Hostname()) {
		return nil, fmt.Errorf("untrusted signed audio URL")
	}
	// Some Model Studio responses document an HTTP signed URL. Upgrade it so
	// audio never crosses the network without TLS.
	parsed.Scheme = "https"
	return parsed, nil
}

func isTrustedAlibabaAudioHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return strings.HasSuffix(host, ".aliyuncs.com") ||
		strings.HasSuffix(host, ".aliyuncs.com.cn")
}

func (pipeline *CloudPipeline) downloadSignedAudio(ctx context.Context,
	initial *url.URL) ([]byte, error) {
	current := initial
	for redirects := 0; redirects <= maxCloudRedirects; redirects++ {
		request, err := http.NewRequestWithContext(
			ctx, http.MethodGet, current.String(), nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Accept", "audio/*,application/octet-stream")
		response, err := pipeline.httpClient.Do(request)
		if err != nil {
			return nil, err
		}
		if response.StatusCode >= 300 && response.StatusCode <= 399 {
			location := response.Header.Get("Location")
			_ = response.Body.Close()
			if redirects == maxCloudRedirects || location == "" {
				return nil, fmt.Errorf("too many or invalid redirects")
			}
			next, err := current.Parse(location)
			if err != nil {
				return nil, fmt.Errorf("invalid redirect URL")
			}
			current, err = validateSignedAudioURL(next.String())
			if err != nil {
				return nil, err
			}
			continue
		}
		if response.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
			_ = response.Body.Close()
			return nil, fmt.Errorf("audio status %d", response.StatusCode)
		}
		audio, readErr := io.ReadAll(io.LimitReader(
			response.Body, maxCloudTTSDownloadBytes+1))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(audio) == 0 ||
			len(audio) > maxCloudTTSDownloadBytes {
			return nil, fmt.Errorf("invalid audio response")
		}
		return audio, nil
	}
	return nil, fmt.Errorf("signed audio redirect limit reached")
}

func (pipeline *CloudPipeline) runFFmpeg(ctx context.Context, input []byte,
	arguments ...string) ([]byte, error) {
	commandArguments := append([]string{
		"-nostdin", "-hide_banner", "-loglevel", "error",
	}, arguments...)
	command := exec.CommandContext(ctx, pipeline.ffmpegPath, commandArguments...)
	command.Stdin = bytes.NewReader(input)
	var output bytes.Buffer
	var diagnostic bytes.Buffer
	command.Stdout = &output
	command.Stderr = &diagnostic
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("FFmpeg failed: %s", strings.TrimSpace(diagnostic.String()))
	}
	return output.Bytes(), nil
}
