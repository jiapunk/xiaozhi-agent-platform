package s3camdev

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

const testUplinkOpusBase64 = "W0Eq5m/L6fEF2RCrGyG5RwPjcoYZy8DxgXZTmMvaSw8sQZlSFAjLzT4NDWkwz/cMlh//3K8oF6ThU6NCt4eJujv5fnXez4Ftl14ecg8BoDyQQl7HYsaOZ5F3CZNaSDfenBnNCcf4euaGNr1ixYVgwqVGahrDsxIZKBsiKfSf2a7/XOK9BVAdhPmsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestOggOpusRoundTrip(t *testing.T) {
	packet, err := base64.StdEncoding.DecodeString(testUplinkOpusBase64)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := encodeOggOpus([][]byte{packet, packet}, 16000)
	if err != nil {
		t.Fatal(err)
	}
	packets, err := parseOggPackets(stream)
	if err != nil {
		t.Fatal(err)
	}
	if len(packets) != 4 || string(packets[0][:8]) != "OpusHead" ||
		string(packets[1][:8]) != "OpusTags" ||
		string(packets[2]) != string(packet) || string(packets[3]) != string(packet) {
		t.Fatalf("unexpected Ogg packet round trip: packets=%d", len(packets))
	}
}

func TestPCM16WAVAndReplyNormalization(t *testing.T) {
	pcm := []byte{0x01, 0x00, 0xff, 0xff}
	wav, err := encodePCM16WAV(pcm, 16000, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(wav) != 48 || string(wav[:4]) != "RIFF" ||
		string(wav[8:12]) != "WAVE" || string(wav[36:40]) != "data" ||
		binary.LittleEndian.Uint32(wav[40:44]) != uint32(len(pcm)) ||
		string(wav[44:]) != string(pcm) {
		t.Fatalf("invalid WAV encoding: bytes=%d", len(wav))
	}
	if got := normalizeSpokenReply("**本機 Agent 正常。**"); got != "本機 Agent 正常。" {
		t.Fatalf("unexpected reply cleanup: %q", got)
	}
	if got := normalizeSpokenReply("資料來自 [中央氣象署](https://www.cwa.gov.tw/)。"); got != "資料來自 中央氣象署。" {
		t.Fatalf("web citation was not made speech-safe: %q", got)
	}
	completeReply := strings.Repeat("這是一段必須完整保留且不能從中間切斷的回答。", 80)
	if got := normalizeSpokenReply(completeReply); got != completeReply {
		t.Fatalf("a complete spoken reply was cut: %d",
			len([]rune(got)))
	}
}

func TestLocalPipelineRejectsNonLoopbackServices(t *testing.T) {
	_, err := NewLocalPipeline(LocalPipelineConfig{
		ASRURL: "https://example.com/asr", AgentURL: "http://127.0.0.1:8317/v1/chat/completions",
		AgentModel: "local", TTSURL: "http://127.0.0.1:9880/tts",
		FFmpegPath: "ffmpeg", RefAudioPath: "/tmp/reference.wav", PromptText: "prompt",
	})
	if err == nil {
		t.Fatal("non-loopback ASR endpoint was accepted")
	}
}
