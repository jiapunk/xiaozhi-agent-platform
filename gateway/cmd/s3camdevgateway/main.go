package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"xiaozhi-agent-platform/gateway/internal/s3camdev"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	address := envOr("S3CAM_GATEWAY_ADDRESS", ":8766")
	publicWebSocketURL := envOr("S3CAM_GATEWAY_PUBLIC_WS_URL", "ws://127.0.0.1:8766/v1/device")
	expectedDeviceID := os.Getenv("S3CAM_GATEWAY_EXPECTED_DEVICE_ID")
	allowedDeviceIDs := optionalCommaList(
		os.Getenv("S3CAM_GATEWAY_ALLOWED_DEVICE_IDS"))
	deviceBootstrapTokens, err := loadDeviceBootstrapTokens(
		os.Getenv("S3CAM_GATEWAY_DEVICE_BOOTSTRAP_TOKENS_FILE"))
	if err != nil {
		logger.Error("device bootstrap token file rejected", "error", err)
		os.Exit(2)
	}
	bootstrapToken, err := loadSecret(
		"S3CAM_GATEWAY_BOOTSTRAP_TOKEN", "S3CAM_GATEWAY_BOOTSTRAP_TOKEN_FILE")
	if err != nil {
		logger.Error("Gateway bootstrap secret rejected", "error", err)
		os.Exit(2)
	}
	sessionToken, err := loadSecret(
		"S3CAM_GATEWAY_SESSION_TOKEN", "S3CAM_GATEWAY_SESSION_TOKEN_FILE")
	if err != nil {
		logger.Error("Gateway session secret rejected", "error", err)
		os.Exit(2)
	}
	memoryKey, err := loadSecret(
		"S3CAM_AGENT_MEMORY_KEY", "S3CAM_AGENT_MEMORY_KEY_FILE")
	if err != nil {
		logger.Error("Agent memory secret rejected", "error", err)
		os.Exit(2)
	}
	agentMemory, err := s3camdev.NewAgentMemory(
		os.Getenv("S3CAM_AGENT_MEMORY_FILE"), memoryKey)
	if err != nil {
		logger.Error("Agent memory configuration rejected", "error", err)
		os.Exit(2)
	}
	speakerIdentityEnabled := os.Getenv("S3CAM_SPEAKER_ID_ENABLED") == "1"
	var speakerIdentity *s3camdev.SpeakerIdentityService
	if speakerIdentityEnabled {
		speakerKey, secretErr := loadSecret(
			"S3CAM_SPEAKER_ID_KEY", "S3CAM_SPEAKER_ID_KEY_FILE")
		if secretErr != nil {
			logger.Error("speaker identity secret rejected", "error", secretErr)
			os.Exit(2)
		}
		threshold, parseErr := strconv.ParseFloat(
			envOr("S3CAM_SPEAKER_ID_THRESHOLD", "0.60"), 64)
		if parseErr != nil {
			logger.Error("speaker identity threshold rejected", "error", parseErr)
			os.Exit(2)
		}
		speakerIdentity, err = s3camdev.NewSpeakerIdentityService(
			s3camdev.SpeakerIdentityConfig{
				EmbeddingURL: envOr("S3CAM_SPEAKER_EMBEDDING_URL",
					"http://127.0.0.1:8767/v1/embedding"),
				StorePath:  os.Getenv("S3CAM_SPEAKER_ID_FILE"),
				EncodedKey: speakerKey, Threshold: threshold,
			})
		if err != nil {
			logger.Error("speaker identity configuration rejected", "error", err)
			os.Exit(2)
		}
	}
	localEnabled := os.Getenv("S3CAM_LOCAL_AI_ENABLED") == "1"
	cloudEnabled := os.Getenv("S3CAM_CLOUD_AI_ENABLED") == "1"
	openRouterEnabled := os.Getenv("S3CAM_OPENROUTER_ENABLED") == "1"
	realtimeEnabled := os.Getenv("S3CAM_OPENAI_REALTIME_ENABLED") == "1"
	webToolsEnabled := os.Getenv("S3CAM_OPENROUTER_WEB_TOOLS_ENABLED") == "1"
	deviceTimezoneOffset, err := strconv.Atoi(
		envOr("S3CAM_DEVICE_TIMEZONE_OFFSET_MINUTES", "480"))
	if err != nil || deviceTimezoneOffset < -720 || deviceTimezoneOffset > 840 {
		logger.Error("device timezone offset rejected")
		os.Exit(2)
	}
	voiceCloneEnabled := os.Getenv("S3CAM_VOICE_CLONE_ENABLED") == "1"
	profilesEnabled := 0
	for _, enabled := range []bool{localEnabled, cloudEnabled, openRouterEnabled} {
		if enabled {
			profilesEnabled++
		}
	}
	if profilesEnabled > 1 {
		logger.Error("local, direct cloud, and OpenRouter profiles are mutually exclusive")
		os.Exit(2)
	}
	if (cloudEnabled || openRouterEnabled) && bootstrapToken == "" {
		logger.Error("remote AI profile requires a bootstrap token")
		os.Exit(2)
	}
	if webToolsEnabled && !openRouterEnabled {
		logger.Error("OpenRouter web tools require the OpenRouter profile")
		os.Exit(2)
	}
	if voiceCloneEnabled && !strings.HasPrefix(publicWebSocketURL, "wss://") {
		logger.Error("voice cloning requires a public WSS/HTTPS Gateway")
		os.Exit(2)
	}
	var realtime *s3camdev.OpenAIRealtimeGateway
	if realtimeEnabled {
		openAIAPIKey, secretErr := loadSecret(
			"S3CAM_OPENAI_API_KEY", "S3CAM_OPENAI_API_KEY_FILE")
		if secretErr != nil {
			logger.Error("OpenAI Realtime secret rejected", "error", secretErr)
			os.Exit(2)
		}
		realtime, err = s3camdev.NewOpenAIRealtimeGateway(
			s3camdev.OpenAIRealtimeConfig{
				APIKey: openAIAPIKey,
				URL: envOr("S3CAM_OPENAI_REALTIME_URL",
					"wss://api.openai.com/v1/realtime"),
				Model: envOr("S3CAM_OPENAI_REALTIME_MODEL",
					"gpt-realtime-2.1-mini"),
				SmartModel: envOr("S3CAM_OPENAI_REALTIME_SMART_MODEL",
					"gpt-realtime-2.1"),
				AdaptiveRouting: envOr(
					"S3CAM_OPENAI_REALTIME_ADAPTIVE_ROUTING", "1") == "1",
				FastReasoning: envOr(
					"S3CAM_OPENAI_REALTIME_FAST_REASONING", "minimal"),
				SmartReasoning: envOr(
					"S3CAM_OPENAI_REALTIME_SMART_REASONING", "low"),
				Voice: envOr("S3CAM_OPENAI_REALTIME_VOICE", "marin"),
				VoiceID: strings.TrimSpace(os.Getenv(
					"S3CAM_OPENAI_REALTIME_VOICE_ID")),
				TranscriptionModel: envOr(
					"S3CAM_OPENAI_TRANSCRIPTION_MODEL", "gpt-transcribe"),
				TranscriptFirst: envOr(
					"S3CAM_OPENAI_TRANSCRIPT_FIRST", "1") == "1",
				// Current watches stream silence as real PCM. Only legacy VAD-
				// gated clients need synthetic trailing silence; never infer this
				// transport property from the transcription/response policy.
				LegacyGatedInput: os.Getenv("S3CAM_OPENAI_LEGACY_GATED_INPUT") == "1",
				SemanticEagerness: envOr(
					"S3CAM_OPENAI_SEMANTIC_EAGERNESS", "medium"),
				FFmpegPath: envOr("S3CAM_FFMPEG_PATH", "ffmpeg"),
				Logger:     logger,
			})
		if err != nil {
			logger.Error("OpenAI Realtime configuration rejected", "error", err)
			os.Exit(2)
		}
	}
	var voiceClone *s3camdev.VoiceCloneService
	if voiceCloneEnabled {
		voiceAPIKey, secretErr := loadSecret(
			"S3CAM_DASHSCOPE_VOICE_API_KEY",
			"S3CAM_DASHSCOPE_VOICE_API_KEY_FILE")
		if secretErr != nil {
			logger.Error("voice-cloning secret rejected", "error", secretErr)
			os.Exit(2)
		}
		voiceClone, err = s3camdev.NewVoiceCloneService(s3camdev.VoiceCloneConfig{
			APIKey: voiceAPIKey,
			ManagementURL: envOr("S3CAM_VOICE_MANAGEMENT_URL",
				"https://dashscope-intl.aliyuncs.com/api/v1/services/audio/tts/customization"),
			TTSURL: envOr("S3CAM_VOICE_TTS_URL",
				"https://dashscope-intl.aliyuncs.com/api/v1/services/aigc/multimodal-generation/generation"),
			TargetModel: envOr("S3CAM_VOICE_TARGET_MODEL",
				"qwen-audio-3.0-tts-flash"),
			VoicePrefix:    envOr("S3CAM_VOICE_PREFIX", "myvoice"),
			PublicHTTPSURL: "https://" + publicWebSocketHost(publicWebSocketURL),
			FFmpegPath:     envOr("S3CAM_FFMPEG_PATH", "ffmpeg"),
			ProfileFile: envOr("S3CAM_VOICE_PROFILE_FILE",
				"/var/lib/xiaozhi-gateway/voice-profile.enc"),
			ProfileKey: memoryKey,
		})
		if err != nil {
			logger.Error("voice-cloning configuration rejected", "error", err)
			os.Exit(2)
		}
	}
	var voicePipeline s3camdev.VoicePipeline
	if localEnabled {
		localPipeline, err := s3camdev.NewLocalPipeline(s3camdev.LocalPipelineConfig{
			ASRURL:       envOr("S3CAM_LOCAL_ASR_URL", "http://127.0.0.1:12393/asr"),
			AgentURL:     envOr("S3CAM_LOCAL_AGENT_URL", "http://127.0.0.1:8317/v1/chat/completions"),
			AgentModel:   envOr("S3CAM_LOCAL_AGENT_MODEL", "xiaozhi-local-agent"),
			TTSURL:       envOr("S3CAM_LOCAL_TTS_URL", "http://127.0.0.1:9880/tts"),
			FFmpegPath:   envOr("S3CAM_FFMPEG_PATH", "ffmpeg"),
			RefAudioPath: os.Getenv("S3CAM_LOCAL_TTS_REF_AUDIO_PATH"),
			PromptText:   os.Getenv("S3CAM_LOCAL_TTS_PROMPT_TEXT"),
		})
		if err != nil {
			logger.Error("local AI pipeline configuration rejected", "error", err)
			os.Exit(2)
		}
		voicePipeline = localPipeline
	}
	if cloudEnabled {
		dashScopeAPIKey, secretErr := loadSecret(
			"S3CAM_DASHSCOPE_API_KEY", "S3CAM_DASHSCOPE_API_KEY_FILE")
		if secretErr != nil {
			logger.Error("DashScope secret rejected", "error", secretErr)
			os.Exit(2)
		}
		deepSeekAPIKey, secretErr := loadSecret(
			"S3CAM_DEEPSEEK_API_KEY", "S3CAM_DEEPSEEK_API_KEY_FILE")
		if secretErr != nil {
			logger.Error("DeepSeek secret rejected", "error", secretErr)
			os.Exit(2)
		}
		cloudPipeline, pipelineErr := s3camdev.NewCloudPipeline(
			s3camdev.CloudPipelineConfig{
				ASRURL: envOr("S3CAM_CLOUD_ASR_URL",
					"https://dashscope-intl.aliyuncs.com/compatible-mode/v1/chat/completions"),
				ASRAPIKey: dashScopeAPIKey,
				ASRModel:  envOr("S3CAM_CLOUD_ASR_MODEL", "qwen3-asr-flash"),
				AgentURL: envOr("S3CAM_CLOUD_AGENT_URL",
					"https://api.deepseek.com/chat/completions"),
				AgentAPIKey: deepSeekAPIKey,
				AgentModel:  envOr("S3CAM_CLOUD_AGENT_MODEL", "deepseek-v4-flash"),
				TTSURL: envOr("S3CAM_CLOUD_TTS_URL",
					"https://dashscope-intl.aliyuncs.com/api/v1/services/aigc/multimodal-generation/generation"),
				TTSAPIKey:  dashScopeAPIKey,
				TTSModel:   envOr("S3CAM_CLOUD_TTS_MODEL", "qwen3-tts-flash"),
				TTSVoice:   envOr("S3CAM_CLOUD_TTS_VOICE", "Cherry"),
				FFmpegPath: envOr("S3CAM_FFMPEG_PATH", "ffmpeg"),
			})
		if pipelineErr != nil {
			logger.Error("cloud AI pipeline configuration rejected",
				"error", pipelineErr)
			os.Exit(2)
		}
		voicePipeline = cloudPipeline
	}
	if openRouterEnabled {
		openRouterAPIKey, secretErr := loadSecret(
			"S3CAM_OPENROUTER_API_KEY", "S3CAM_OPENROUTER_API_KEY_FILE")
		if secretErr != nil {
			logger.Error("OpenRouter secret rejected", "error", secretErr)
			os.Exit(2)
		}
		openRouterPipeline, pipelineErr := s3camdev.NewOpenRouterPipeline(
			s3camdev.OpenRouterPipelineConfig{
				APIKey: openRouterAPIKey,
				ASRModel: envOr("S3CAM_OPENROUTER_ASR_MODEL",
					"qwen/qwen3-asr-flash-2026-02-10"),
				AgentModel: envOr("S3CAM_OPENROUTER_AGENT_MODEL",
					"deepseek/deepseek-v4-flash"),
				AgentFallbackModels: optionalCommaList(
					os.Getenv("S3CAM_OPENROUTER_AGENT_FALLBACK_MODELS")),
				VisionModel: envOr("S3CAM_OPENROUTER_VISION_MODEL",
					"google/gemini-3.1-flash-lite"),
				TTSModel: envOr("S3CAM_OPENROUTER_TTS_MODEL",
					"qwen/qwen-audio-3.0-tts-flash"),
				TTSVoice: envOr("S3CAM_OPENROUTER_TTS_VOICE", "longanlingxi"),
				MusicModel: envOr("S3CAM_OPENROUTER_MUSIC_MODEL",
					"google/lyria-3-clip-preview"),
				FFmpegPath: envOr("S3CAM_FFMPEG_PATH", "ffmpeg"),
				WebTools:   webToolsEnabled,
				VoiceClone: voiceClone,
			})
		if pipelineErr != nil {
			logger.Error("OpenRouter pipeline configuration rejected",
				"error", pipelineErr)
			os.Exit(2)
		}
		voicePipeline = openRouterPipeline
	}
	gateway, err := s3camdev.New(s3camdev.Config{
		PublicWebSocketURL:          publicWebSocketURL,
		TextLocale:                  envOr("S3CAM_TEXT_LOCALE", "zh-TW"),
		GlyphProviderURL:            os.Getenv("S3CAM_GLYPH_PROVIDER_URL"),
		ExpectedDeviceID:            expectedDeviceID,
		AllowedDeviceIDs:            allowedDeviceIDs,
		DeviceBootstrapTokens:       deviceBootstrapTokens,
		BootstrapToken:              bootstrapToken,
		Token:                       sessionToken,
		RequireTLS:                  cloudEnabled || openRouterEnabled || realtimeEnabled,
		VoicePipeline:               voicePipeline,
		Realtime:                    realtime,
		Memory:                      agentMemory,
		SpeakerIdentity:             speakerIdentity,
		VoiceClone:                  voiceClone,
		WebToolsEnabled:             webToolsEnabled,
		DeviceTimezoneOffsetMinutes: deviceTimezoneOffset,
		Logger:                      logger,
	})
	if err != nil {
		logger.Error("development Gateway configuration rejected", "error", err)
		os.Exit(2)
	}
	server := &http.Server{
		Addr: address, Handler: gateway.Handler(), ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout: 75 * time.Second, MaxHeaderBytes: 16 * 1024,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errChannel := make(chan error, 1)
	go func() {
		logger.Info("S3CAM Gateway starting",
			"address", address, "dashboard", "http://"+publicWebSocketHost(publicWebSocketURL)+"/",
			"local_ai", localEnabled, "cloud_ai", cloudEnabled,
			"openrouter_ai", openRouterEnabled,
			"openai_realtime", realtimeEnabled,
			"web_tools", webToolsEnabled,
			"speaker_identity", speakerIdentityEnabled,
			"voice_clone", voiceCloneEnabled,
			"text_locale", envOr("S3CAM_TEXT_LOCALE", "zh-TW"),
			"glyph_provider", os.Getenv("S3CAM_GLYPH_PROVIDER_URL") != "",
			"bootstrap_auth", bootstrapToken != "")
		errChannel <- server.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			logger.Error("development Gateway shutdown failed", "error", err)
			os.Exit(1)
		}
	case err := <-errChannel:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("development Gateway stopped", "error", err)
			os.Exit(1)
		}
	}
}

func loadSecret(environmentName, fileEnvironmentName string) (string, error) {
	direct := os.Getenv(environmentName)
	path := os.Getenv(fileEnvironmentName)
	if direct != "" && path != "" {
		return "", fmt.Errorf("set only one of %s and %s",
			environmentName, fileEnvironmentName)
	}
	if path == "" {
		return direct, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open secret file: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return "", fmt.Errorf("read secret file: %w", err)
	}
	if len(data) > 4096 {
		return "", fmt.Errorf("secret file exceeds 4096 bytes")
	}
	value := string(data)
	value = strings.TrimSuffix(value, "\n")
	value = strings.TrimSuffix(value, "\r")
	return value, nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func optionalCommaList(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}

func loadDeviceBootstrapTokens(path string) (map[string]string, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 16*1024))
	var tokens map[string]string
	if err := decoder.Decode(&tokens); err != nil {
		return nil, err
	}
	if len(tokens) == 0 {
		return nil, fmt.Errorf("device bootstrap token map is empty")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, fmt.Errorf("device bootstrap token file has trailing data")
	}
	return tokens, nil
}

func publicWebSocketHost(raw string) string {
	const wsPrefix = "ws://"
	const wssPrefix = "wss://"
	if len(raw) > len(wsPrefix) && raw[:len(wsPrefix)] == wsPrefix {
		raw = raw[len(wsPrefix):]
	} else if len(raw) > len(wssPrefix) && raw[:len(wssPrefix)] == wssPrefix {
		raw = raw[len(wssPrefix):]
	}
	for index, character := range raw {
		if character == '/' {
			return raw[:index]
		}
	}
	return raw
}
