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
	"strings"
	"time"
	"unicode/utf8"
)

const (
	maxGlyphPushResponseBytes = 96 * 1024
	maxGlyphPushGlyphs        = 64
	maxGlyphPushBitmapBytes   = 64 * 1024
)

type TextFontCapability struct {
	GlyphPush bool   `json:"-"`
	Bundle    string `json:"bundle"`
	Charset   string `json:"charset"`
	Size      int    `json:"size"`
	BPP       int    `json:"bpp"`
}

func (capability TextFontCapability) Valid() bool {
	return capability.GlyphPush && capability.Bundle != "" &&
		len(capability.Bundle) <= 64 &&
		(capability.Charset == "basic" || capability.Charset == "common") &&
		capability.Size > 0 && capability.Size <= 128 &&
		(capability.BPP == 1 || capability.BPP == 4)
}

type TextGlyph struct {
	Codepoint int    `json:"codepoint"`
	Advance   uint32 `json:"adv_w"`
	BoxWidth  uint16 `json:"box_w"`
	BoxHeight uint16 `json:"box_h"`
	OffsetX   int16  `json:"ofs_x"`
	OffsetY   int16  `json:"ofs_y"`
	Bitmap    string `json:"bitmap"`
}

type GlyphPushPayload struct {
	Version int         `json:"v"`
	Bundle  string      `json:"bundle"`
	Size    int         `json:"size"`
	BPP     int         `json:"bpp"`
	Glyphs  []TextGlyph `json:"glyphs"`
}

type GlyphProvider struct {
	endpoint string
	client   *http.Client
}

func NewGlyphProvider(endpoint string) (*GlyphProvider, error) {
	if strings.TrimSpace(endpoint) != endpoint || endpoint == "" {
		return nil, fmt.Errorf("glyph provider URL is invalid")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") ||
		parsed.Host == "" || parsed.Path != "/glyph-push" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("glyph provider URL must be an exact HTTP(S) /glyph-push URL")
	}
	return &GlyphProvider{
		endpoint: endpoint,
		client:   &http.Client{Timeout: 1500 * time.Millisecond},
	}, nil
}

func (provider *GlyphProvider) Payload(ctx context.Context,
	capability TextFontCapability, text string) (*GlyphPushPayload, error) {
	if provider == nil || !capability.Valid() || text == "" || !utf8.ValidString(text) {
		return nil, nil
	}
	requestBody, err := json.Marshal(map[string]any{
		"device": map[string]any{
			"features":  map[string]bool{"glyph_push": true},
			"text_font": capability,
		},
		"text": text,
	})
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		provider.endpoint, bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := provider.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("request glyph provider: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("glyph provider returned status %d", response.StatusCode)
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body,
		maxGlyphPushResponseBytes+1))
	decoder.DisallowUnknownFields()
	var envelope struct {
		GlyphPush *GlyphPushPayload `json:"glyph_push"`
	}
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fmt.Errorf("decode glyph provider response: %w", err)
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, fmt.Errorf("glyph provider response has trailing data")
	}
	if envelope.GlyphPush == nil {
		return nil, nil
	}
	if err := validateGlyphPush(capability, envelope.GlyphPush); err != nil {
		return nil, err
	}
	return envelope.GlyphPush, nil
}

func validateGlyphPush(capability TextFontCapability,
	payload *GlyphPushPayload) error {
	if payload.Version != 1 || payload.Bundle != capability.Bundle ||
		payload.Size != capability.Size || payload.BPP != capability.BPP ||
		len(payload.Glyphs) == 0 || len(payload.Glyphs) > maxGlyphPushGlyphs {
		return fmt.Errorf("glyph provider returned incompatible metadata")
	}
	totalBitmapBytes := 0
	seen := make(map[int]struct{}, len(payload.Glyphs))
	for _, glyph := range payload.Glyphs {
		if glyph.Codepoint < 0x20 || glyph.Codepoint > utf8.MaxRune ||
			glyph.BoxWidth > 128 || glyph.BoxHeight > 128 {
			return fmt.Errorf("glyph provider returned invalid glyph metrics")
		}
		if _, duplicate := seen[glyph.Codepoint]; duplicate {
			return fmt.Errorf("glyph provider returned a duplicate glyph")
		}
		seen[glyph.Codepoint] = struct{}{}
		bitmap, err := base64.StdEncoding.DecodeString(glyph.Bitmap)
		expectedBytes := (int(glyph.BoxWidth)*int(glyph.BoxHeight)*payload.BPP + 7) / 8
		if err != nil || len(bitmap) != expectedBytes {
			return fmt.Errorf("glyph provider returned an invalid bitmap")
		}
		totalBitmapBytes += len(bitmap)
		if totalBitmapBytes > maxGlyphPushBitmapBytes {
			return fmt.Errorf("glyph provider bitmap budget exceeded")
		}
	}
	return nil
}
