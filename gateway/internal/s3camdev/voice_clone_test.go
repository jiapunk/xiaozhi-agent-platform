package s3camdev

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func validVoiceCloneConfig(t *testing.T) VoiceCloneConfig {
	t.Helper()
	return VoiceCloneConfig{
		APIKey:        "sk-voice-unit-test-not-real",
		ManagementURL: "https://workspace1.ap-southeast-1.maas.aliyuncs.com/api/v1/services/audio/tts/customization",
		TTSURL:        "https://workspace1.ap-southeast-1.maas.aliyuncs.com/api/v1/services/aigc/multimodal-generation/generation",
		TargetModel:   "qwen-audio-3.0-tts-flash", VoicePrefix: "myvoice",
		PublicHTTPSURL: "https://voice.example.com:8443", FFmpegPath: "ffmpeg",
		ProfileFile: filepath.Join(t.TempDir(), "voice-profile.enc"),
		ProfileKey: base64.RawStdEncoding.EncodeToString(
			[]byte("0123456789abcdef0123456789abcdef")),
	}
}

func TestVoiceEnrollmentRequiresPhysicalCodeAndIsOneUse(t *testing.T) {
	service, err := NewVoiceCloneService(validVoiceCloneConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	code, err := service.BeginEnrollment()
	if err != nil || len(code) != 6 {
		t.Fatalf("invalid enrollment code: %q err=%v", code, err)
	}
	authorize := func(code string, consent bool) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"code": code, "consent": consent})
		request := httptest.NewRequest(http.MethodPost,
			"/v1/voice/enrollment/authorize", bytes.NewReader(body))
		response := httptest.NewRecorder()
		service.authorizeEnrollment(response, request)
		return response
	}
	if response := authorize(code, false); response.Code != http.StatusBadRequest {
		t.Fatalf("enrollment without consent returned %d", response.Code)
	}
	response := authorize(code, true)
	if response.Code != http.StatusOK {
		t.Fatalf("valid enrollment rejected: %d %s", response.Code, response.Body.String())
	}
	if replay := authorize(code, true); replay.Code != http.StatusUnauthorized {
		t.Fatalf("enrollment code replay returned %d", replay.Code)
	}
}

func TestVoiceCloneRejectsUntrustedProviderAndPublicOrigins(t *testing.T) {
	for _, mutate := range []func(*VoiceCloneConfig){
		func(config *VoiceCloneConfig) {
			config.ManagementURL = "https://evil.example/api/v1/services/audio/tts/customization"
		},
		func(config *VoiceCloneConfig) { config.PublicHTTPSURL = "http://voice.example.com" },
		func(config *VoiceCloneConfig) { config.ProfileKey = "too-short" },
	} {
		config := validVoiceCloneConfig(t)
		mutate(&config)
		if _, err := NewVoiceCloneService(config); err == nil {
			t.Fatal("unsafe voice clone configuration was accepted")
		}
	}
}
