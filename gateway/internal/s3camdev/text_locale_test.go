package s3camdev

import (
	"context"
	"testing"
)

func TestTextLocalizerRegionalModes(t *testing.T) {
	tests := []struct {
		locale string
		input  string
		want   string
	}{
		{"zh-TW", "鼠标和数据库里的软件", "滑鼠和資料庫裡的軟體"},
		{"zh-HK", "汉字和里程", "漢字和里程"},
		{"zh-CN", "滑鼠和資料庫裡的軟體", "鼠标和数据库里的软件"},
	}
	for _, test := range tests {
		localizer, err := NewTextLocalizer(test.locale)
		if err != nil {
			t.Fatalf("NewTextLocalizer(%q): %v", test.locale, err)
		}
		if got := localizer.Normalize(test.input); got != test.want {
			t.Errorf("Normalize(%q, %q) = %q, want %q",
				test.locale, test.input, got, test.want)
		}
	}
}

func TestTextLocalizerRejectsUnknownLocale(t *testing.T) {
	if _, err := NewTextLocalizer("zh-SG"); err == nil {
		t.Fatal("expected unsupported locale to be rejected")
	}
}

func TestLocalizedReplyStreamNormalizesBeforeSynthesis(t *testing.T) {
	localizer, err := NewTextLocalizer("zh-TW")
	if err != nil {
		t.Fatal(err)
	}
	input := make(chan VoiceReplyChunk, 1)
	input <- VoiceReplyChunk{Text: "数据库连接正常。"}
	close(input)
	chunk := <-localizedReplyStream(context.Background(), localizer, input)
	if chunk.Text != "資料庫連線正常。" {
		t.Fatalf("unexpected localized chunk: %q", chunk.Text)
	}
}
