package tts

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"xiaozhi-agent-platform/gateway/internal/opuspacket"
	"xiaozhi-agent-platform/gateway/internal/speechcontract"
)

const (
	framedContentType = "application/x-opus-frames"
	maxFrameBytes     = 4096
	maxTotalBytes     = 4 * 1024 * 1024
)

type FramedHTTPConfig struct {
	Endpoint         string
	HealthURL        string
	BearerToken      string
	Client           *http.Client
	AllowInsecure    bool
	SampleRate       int
	FrameDuration    int
	MaxOutputAudioMS int64
}

type FramedHTTP struct {
	endpoint      string
	healthURL     string
	bearerToken   string
	client        *http.Client
	sampleRate    int
	frameDuration int
	maxFrames     int64
}

type synthesisRequest struct {
	Contract        string `json:"contract"`
	DeviceID        string `json:"device_id"`
	SessionID       string `json:"session_id"`
	RequestID       uint32 `json:"request_id"`
	Text            string `json:"text"`
	Format          string `json:"format"`
	SampleRate      int    `json:"sample_rate"`
	FrameDurationMS int    `json:"frame_duration_ms"`
}

func NewFramedHTTP(config FramedHTTPConfig) (*FramedHTTP, error) {
	if err := validateURL(config.Endpoint, config.AllowInsecure); err != nil {
		return nil, fmt.Errorf("TTS endpoint: %w", err)
	}
	if config.HealthURL != "" {
		if err := validateURL(config.HealthURL, config.AllowInsecure); err != nil {
			return nil, fmt.Errorf("TTS health URL: %w", err)
		}
	}
	if strings.TrimSpace(config.BearerToken) == "" {
		return nil, fmt.Errorf("TTS bearer token is required")
	}
	if config.SampleRate <= 0 || config.SampleRate > 48000 ||
		config.FrameDuration <= 0 || config.FrameDuration > 120 {
		return nil, fmt.Errorf("invalid TTS audio parameters")
	}
	if config.MaxOutputAudioMS == 0 {
		config.MaxOutputAudioMS = 120_000
	}
	if config.MaxOutputAudioMS < int64(config.FrameDuration) ||
		config.MaxOutputAudioMS > 600_000 {
		return nil, fmt.Errorf("invalid TTS maximum output duration")
	}
	client := config.Client
	if client == nil {
		client = &http.Client{Timeout: 35 * time.Second}
	}
	return &FramedHTTP{
		endpoint: config.Endpoint, healthURL: config.HealthURL,
		bearerToken: config.BearerToken, client: client,
		sampleRate: config.SampleRate, frameDuration: config.FrameDuration,
		maxFrames: config.MaxOutputAudioMS / int64(config.FrameDuration),
	}, nil
}

func (client *FramedHTTP) Stream(ctx context.Context, synthesis Request, emit EmitFrame) error {
	if client == nil || synthesis.DeviceID == "" || synthesis.SessionID == "" ||
		synthesis.RequestID == 0 || strings.TrimSpace(synthesis.Text) == "" || emit == nil {
		return fmt.Errorf("invalid synthesis request")
	}
	payload, err := json.Marshal(synthesisRequest{
		Contract: speechcontract.TTSVersion,
		DeviceID: synthesis.DeviceID, SessionID: synthesis.SessionID,
		RequestID: synthesis.RequestID, Text: synthesis.Text,
		Format: "opus", SampleRate: client.sampleRate,
		FrameDurationMS: client.frameDuration,
	})
	if err != nil {
		return fmt.Errorf("encode synthesis request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create synthesis request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+client.bearerToken)
	request.Header.Set("Idempotency-Key", fmt.Sprintf("%s:%d", synthesis.SessionID, synthesis.RequestID))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", framedContentType)
	request.Header.Set(speechcontract.Header, speechcontract.TTSVersion)

	response, err := client.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("call TTS upstream: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("TTS upstream status %d", response.StatusCode)
	}
	if response.Header.Get(speechcontract.Header) != speechcontract.TTSVersion {
		return fmt.Errorf("TTS upstream contract mismatch")
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != framedContentType {
		return fmt.Errorf("unexpected TTS content type")
	}

	var total int
	var frames int
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var header [4]byte
		_, err := io.ReadFull(response.Body, header[:])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("read TTS frame header: %w", err)
		}
		length := int(binary.BigEndian.Uint32(header[:]))
		if length <= 0 || length > maxFrameBytes || total+length > maxTotalBytes {
			return fmt.Errorf("invalid TTS frame length")
		}
		frame := make([]byte, length)
		if _, err := io.ReadFull(response.Body, frame); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("read TTS frame: %w", err)
		}
		if err := opuspacket.ValidateMonoDuration(frame, client.frameDuration); err != nil {
			return fmt.Errorf("invalid TTS Opus packet: %w", err)
		}
		if int64(frames) >= client.maxFrames {
			return fmt.Errorf("TTS upstream exceeded maximum output duration")
		}
		if err := emit(frame); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		total += length
		frames++
	}
	if frames == 0 {
		return fmt.Errorf("TTS upstream returned no audio frames")
	}
	return nil
}

func (client *FramedHTTP) Ready(ctx context.Context) error {
	if client == nil {
		return fmt.Errorf("TTS client is nil")
	}
	if client.healthURL == "" {
		return nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.healthURL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+client.bearerToken)
	request.Header.Set(speechcontract.Header, speechcontract.TTSVersion)
	response, err := client.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("TTS health status %d", response.StatusCode)
	}
	if response.Header.Get(speechcontract.Header) != speechcontract.TTSVersion {
		return fmt.Errorf("TTS health contract mismatch")
	}
	return nil
}

func validateURL(raw string, allowInsecure bool) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("invalid URL")
	}
	if parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" {
		return fmt.Errorf("userinfo, query strings, and fragments are not allowed")
	}
	if parsed.Scheme != "https" && !(allowInsecure && parsed.Scheme == "http") {
		return fmt.Errorf("HTTPS is required")
	}
	return nil
}
