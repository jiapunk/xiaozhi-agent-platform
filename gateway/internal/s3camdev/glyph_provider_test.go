package s3camdev

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGlyphProviderValidatesAndReturnsPayload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter,
		request *http.Request) {
		if request.URL.Path != "/glyph-push" {
			t.Fatalf("unexpected path: %s", request.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"glyph_push": map[string]any{
				"v": 1, "bundle": "noto-tc-v1", "size": 30, "bpp": 4,
				"glyphs": []map[string]any{{
					"codepoint": int('龘'), "adv_w": 480, "box_w": 2,
					"box_h": 2, "ofs_x": 0, "ofs_y": 0,
					"bitmap": base64.StdEncoding.EncodeToString([]byte{0x12, 0x34}),
				}},
			},
		})
	}))
	defer server.Close()
	provider, err := NewGlyphProvider(server.URL + "/glyph-push")
	if err != nil {
		t.Fatal(err)
	}
	capability := TextFontCapability{
		GlyphPush: true, Bundle: "noto-tc-v1", Charset: "common", Size: 30, BPP: 4,
	}
	payload, err := provider.Payload(context.Background(), capability, "龘")
	if err != nil {
		t.Fatal(err)
	}
	if payload == nil || len(payload.Glyphs) != 1 || payload.Glyphs[0].Codepoint != int('龘') {
		t.Fatalf("unexpected glyph payload: %+v", payload)
	}
}

func TestGlyphProviderRejectsMismatchedBundle(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter,
		request *http.Request) {
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"glyph_push": map[string]any{
				"v": 1, "bundle": "wrong", "size": 30, "bpp": 4,
				"glyphs": []map[string]any{{
					"codepoint": int('龘'), "adv_w": 480, "box_w": 0,
					"box_h": 0, "ofs_x": 0, "ofs_y": 0, "bitmap": "",
				}},
			},
		})
	}))
	defer server.Close()
	provider, err := NewGlyphProvider(server.URL + "/glyph-push")
	if err != nil {
		t.Fatal(err)
	}
	_, err = provider.Payload(context.Background(), TextFontCapability{
		GlyphPush: true, Bundle: "noto-tc-v1", Charset: "common", Size: 30, BPP: 4,
	}, "龘")
	if err == nil {
		t.Fatal("expected mismatched bundle to be rejected")
	}
}
