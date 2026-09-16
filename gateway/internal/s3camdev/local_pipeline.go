package s3camdev

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"xiaozhi-agent-platform/gateway/internal/opuspacket"
)

const (
	maxLocalASRResponseBytes = 64 * 1024
	maxLocalLLMResponseBytes = 512 * 1024
	maxLocalTTSBytes         = 16 * 1024 * 1024
	// This is a defensive provider-input ceiling, not a presentation limit.
	// Replies below it must never be sliced or rewritten merely for length.
	maxSpokenReplyRunes       = 4096
	maxSpokenReplyOpusPackets = 6000
	opusClockRate             = 48000
	opusFrameDurationMS       = 60
)

type LocalPipelineConfig struct {
	ASRURL       string
	AgentURL     string
	AgentModel   string
	TTSURL       string
	FFmpegPath   string
	RefAudioPath string
	PromptText   string
	HTTPClient   *http.Client
}

type LocalPipeline struct {
	asrURL       string
	agentURL     string
	agentModel   string
	ttsURL       string
	ffmpegPath   string
	refAudioPath string
	promptText   string
	httpClient   *http.Client
}

func NewLocalPipeline(config LocalPipelineConfig) (*LocalPipeline, error) {
	for name, endpoint := range map[string][2]string{
		"ASR":   {config.ASRURL, "/asr"},
		"Agent": {config.AgentURL, "/v1/chat/completions"},
		"TTS":   {config.TTSURL, "/tts"},
	} {
		if err := validateLoopbackEndpoint(endpoint[0], endpoint[1]); err != nil {
			return nil, fmt.Errorf("%s endpoint: %w", name, err)
		}
	}
	if strings.TrimSpace(config.AgentModel) == "" ||
		strings.TrimSpace(config.FFmpegPath) == "" ||
		strings.TrimSpace(config.RefAudioPath) == "" ||
		strings.TrimSpace(config.PromptText) == "" {
		return nil, fmt.Errorf("local voice pipeline configuration is incomplete")
	}
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	return &LocalPipeline{
		asrURL: config.ASRURL, agentURL: config.AgentURL,
		agentModel: config.AgentModel, ttsURL: config.TTSURL,
		ffmpegPath: config.FFmpegPath, refAudioPath: config.RefAudioPath,
		promptText: config.PromptText, httpClient: client,
	}, nil
}

func validateLoopbackEndpoint(raw, expectedPath string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" ||
		parsed.Path != expectedPath || parsed.RawQuery != "" ||
		parsed.Fragment != "" || parsed.User != nil {
		return fmt.Errorf("must be an exact loopback HTTP %s URL", expectedPath)
	}
	host := parsed.Hostname()
	address := net.ParseIP(host)
	if host != "localhost" && (address == nil || !address.IsLoopback()) {
		return fmt.Errorf("must remain on the local machine")
	}
	return nil
}

func (pipeline *LocalPipeline) Transcribe(ctx context.Context,
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

	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	part, err := form.CreateFormFile("file", "capture.wav")
	if err != nil {
		return "", err
	}
	if _, err := part.Write(wav); err != nil {
		return "", err
	}
	if err := form.Close(); err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, pipeline.asrURL, &body)
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", form.FormDataContentType())
	response, err := pipeline.httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("call local ASR: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return "", fmt.Errorf("local ASR status %d", response.StatusCode)
	}
	var result struct {
		Text string `json:"text"`
	}
	if err := decodeLimitedJSON(response.Body, maxLocalASRResponseBytes, &result); err != nil {
		return "", fmt.Errorf("decode local ASR response: %w", err)
	}
	result.Text = strings.TrimSpace(result.Text)
	if result.Text == "" || !utf8.ValidString(result.Text) ||
		utf8.RuneCountInString(result.Text) > 512 {
		return "", fmt.Errorf("local ASR returned invalid text")
	}
	return result.Text, nil
}

func (pipeline *LocalPipeline) Reply(ctx context.Context,
	transcript string) (string, error) {
	transcript = strings.TrimSpace(transcript)
	if pipeline == nil || transcript == "" || !utf8.ValidString(transcript) {
		return "", fmt.Errorf("invalid local Agent input")
	}
	payload, err := json.Marshal(map[string]any{
		"model": pipeline.agentModel,
		"messages": []map[string]string{
			{"role": "system", "content": "你是 ESP32 產品中的本機智慧代理。使用自然的繁體中文完整回答，確保句子自然結束，不要使用 Markdown，也不要描述內部推理。內容應適合語音聆聽，但不得因篇幅而省略結尾。"},
			{"role": "user", "content": transcript},
		},
		"temperature": 0.4,
	})
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, pipeline.agentURL, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := pipeline.httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("call local Agent: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return "", fmt.Errorf("local Agent status %d", response.StatusCode)
	}
	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := decodeLimitedJSON(response.Body, maxLocalLLMResponseBytes, &result); err != nil {
		return "", fmt.Errorf("decode local Agent response: %w", err)
	}
	if len(result.Choices) != 1 {
		return "", fmt.Errorf("local Agent returned an invalid choice count")
	}
	reply := normalizeSpokenReply(result.Choices[0].Message.Content)
	if reply == "" {
		return "", fmt.Errorf("local Agent returned no spoken reply")
	}
	return reply, nil
}

var (
	spokenMarkdownLink = regexp.MustCompile(`\[([^\]\n]{1,160})\]\(https?://[^)\s]+\)`)
	spokenBareURL      = regexp.MustCompile(`https?://[^\s]+`)
)

func normalizeSpokenReply(input string) string {
	input = strings.TrimSpace(input)
	// Web tools may return Markdown citations. Keep the human-readable source
	// name for speech, while avoiding a long character-by-character URL readout.
	input = spokenMarkdownLink.ReplaceAllString(input, "$1")
	input = spokenBareURL.ReplaceAllString(input, "")
	input = strings.NewReplacer("`", "", "#", "", "*", "").Replace(input)
	input = strings.TrimSpace(input)
	if !utf8.ValidString(input) {
		return ""
	}
	return input
}

func (pipeline *LocalPipeline) Synthesize(ctx context.Context,
	reply string) ([][]byte, error) {
	if pipeline == nil || strings.TrimSpace(reply) == "" {
		return nil, fmt.Errorf("invalid local TTS input")
	}
	payload, err := json.Marshal(map[string]any{
		"text": reply, "text_lang": "zh",
		"ref_audio_path": pipeline.refAudioPath,
		"prompt_lang":    "zh", "prompt_text": pipeline.promptText,
		"text_split_method": "cut5", "batch_size": 1,
		"media_type": "wav", "streaming_mode": false,
	})
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, pipeline.ttsURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := pipeline.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("call local TTS: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return nil, fmt.Errorf("local TTS status %d", response.StatusCode)
	}
	wav, err := io.ReadAll(io.LimitReader(response.Body, maxLocalTTSBytes+1))
	if err != nil || len(wav) == 0 || len(wav) > maxLocalTTSBytes {
		return nil, fmt.Errorf("local TTS returned invalid audio")
	}
	ogg, err := pipeline.runFFmpeg(ctx, wav,
		"-i", "pipe:0", "-map", "0:a:0", "-ac", "1", "-ar", "24000",
		"-af", "loudnorm=I=-14:LRA=6:TP=-1.0",
		"-c:a", "libopus", "-application", "voip", "-frame_duration", "60",
		"-vbr", "off", "-b:a", "24000", "-f", "opus", "pipe:1")
	if err != nil {
		return nil, fmt.Errorf("encode local TTS Opus: %w", err)
	}
	packets, err := parseOggPackets(ogg)
	if err != nil || len(packets) < 3 || len(packets[0]) < 8 ||
		len(packets[1]) < 8 || string(packets[0][:8]) != "OpusHead" ||
		string(packets[1][:8]) != "OpusTags" {
		return nil, fmt.Errorf("local TTS returned invalid Ogg Opus")
	}
	packets = packets[2:]
	if len(packets) == 0 || len(packets) > maxSpokenReplyOpusPackets {
		return nil, fmt.Errorf("local TTS duration is out of range")
	}
	for _, packet := range packets {
		if err := opuspacket.ValidateMonoDuration(packet, opusFrameDurationMS); err != nil {
			return nil, fmt.Errorf("local TTS Opus frame rejected: %w", err)
		}
	}
	return packets, nil
}

func (pipeline *LocalPipeline) runFFmpeg(ctx context.Context, input []byte,
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

func decodeLimitedJSON(reader io.Reader, maximum int64, output any) error {
	limited := io.LimitReader(reader, maximum+1)
	data, err := io.ReadAll(limited)
	if err != nil || int64(len(data)) > maximum {
		return fmt.Errorf("response exceeds limit")
	}
	if err := json.Unmarshal(data, output); err != nil {
		return err
	}
	return nil
}

func encodePCM16WAV(pcm []byte, sampleRate, channels int) ([]byte, error) {
	if len(pcm) == 0 || len(pcm)%2 != 0 || sampleRate <= 0 || channels != 1 ||
		len(pcm) > int(^uint32(0))-44 {
		return nil, fmt.Errorf("invalid PCM for WAV")
	}
	output := make([]byte, 44+len(pcm))
	copy(output[0:4], "RIFF")
	binary.LittleEndian.PutUint32(output[4:8], uint32(len(output)-8))
	copy(output[8:12], "WAVE")
	copy(output[12:16], "fmt ")
	binary.LittleEndian.PutUint32(output[16:20], 16)
	binary.LittleEndian.PutUint16(output[20:22], 1)
	binary.LittleEndian.PutUint16(output[22:24], uint16(channels))
	binary.LittleEndian.PutUint32(output[24:28], uint32(sampleRate))
	binary.LittleEndian.PutUint32(output[28:32], uint32(sampleRate*channels*2))
	binary.LittleEndian.PutUint16(output[32:34], uint16(channels*2))
	binary.LittleEndian.PutUint16(output[34:36], 16)
	copy(output[36:40], "data")
	binary.LittleEndian.PutUint32(output[40:44], uint32(len(pcm)))
	copy(output[44:], pcm)
	return output, nil
}

func encodeOggOpus(packets [][]byte, inputSampleRate int) ([]byte, error) {
	if len(packets) == 0 || inputSampleRate != 16000 {
		return nil, fmt.Errorf("invalid microphone Opus stream")
	}
	const serial = uint32(0x53334341)
	opusHead := append([]byte("OpusHead"), 1, 1)
	headerTail := make([]byte, 9)
	binary.LittleEndian.PutUint16(headerTail[0:2], 312)
	binary.LittleEndian.PutUint32(headerTail[2:6], uint32(inputSampleRate))
	opusHead = append(opusHead, headerTail...)
	vendor := []byte("xiaozhi-s3cam-local-gateway")
	opusTags := append([]byte("OpusTags"), make([]byte, 4)...)
	binary.LittleEndian.PutUint32(opusTags[8:12], uint32(len(vendor)))
	opusTags = append(opusTags, vendor...)
	opusTags = append(opusTags, 0, 0, 0, 0)

	var stream bytes.Buffer
	stream.Write(makeOggPage(opusHead, 0x02, 0, serial, 0))
	stream.Write(makeOggPage(opusTags, 0x00, 0, serial, 1))
	granule := uint64(312)
	for index, packet := range packets {
		if err := opuspacket.ValidateMonoDuration(packet, opusFrameDurationMS); err != nil {
			return nil, fmt.Errorf("invalid microphone Opus frame: %w", err)
		}
		granule += opusClockRate * opusFrameDurationMS / 1000
		headerType := byte(0)
		if index == len(packets)-1 {
			headerType = 0x04
		}
		stream.Write(makeOggPage(
			packet, headerType, granule, serial, uint32(index+2)))
	}
	return stream.Bytes(), nil
}

func makeOggPage(packet []byte, headerType byte, granule uint64,
	serial, sequence uint32) []byte {
	segments := make([]byte, 0, len(packet)/255+1)
	remaining := len(packet)
	for remaining >= 255 {
		segments = append(segments, 255)
		remaining -= 255
	}
	segments = append(segments, byte(remaining))
	header := make([]byte, 27+len(segments))
	copy(header[0:4], "OggS")
	header[4] = 0
	header[5] = headerType
	binary.LittleEndian.PutUint64(header[6:14], granule)
	binary.LittleEndian.PutUint32(header[14:18], serial)
	binary.LittleEndian.PutUint32(header[18:22], sequence)
	header[26] = byte(len(segments))
	copy(header[27:], segments)
	page := append(header, packet...)
	binary.LittleEndian.PutUint32(page[22:26], oggCRC(page))
	return page
}

func parseOggPackets(stream []byte) ([][]byte, error) {
	var packets [][]byte
	var current []byte
	for offset := 0; offset < len(stream); {
		if offset+27 > len(stream) || string(stream[offset:offset+4]) != "OggS" {
			return nil, fmt.Errorf("invalid Ogg page")
		}
		segmentCount := int(stream[offset+26])
		headerEnd := offset + 27 + segmentCount
		if headerEnd > len(stream) {
			return nil, fmt.Errorf("truncated Ogg lacing")
		}
		payloadLength := 0
		for _, length := range stream[offset+27 : headerEnd] {
			payloadLength += int(length)
		}
		pageEnd := headerEnd + payloadLength
		if pageEnd > len(stream) {
			return nil, fmt.Errorf("truncated Ogg payload")
		}
		pageCopy := append([]byte(nil), stream[offset:pageEnd]...)
		expectedCRC := binary.LittleEndian.Uint32(pageCopy[22:26])
		clear(pageCopy[22:26])
		if oggCRC(pageCopy) != expectedCRC {
			return nil, fmt.Errorf("invalid Ogg checksum")
		}
		payloadOffset := headerEnd
		for _, lengthByte := range stream[offset+27 : headerEnd] {
			length := int(lengthByte)
			current = append(current, stream[payloadOffset:payloadOffset+length]...)
			payloadOffset += length
			if length < 255 {
				packets = append(packets, append([]byte(nil), current...))
				current = current[:0]
			}
		}
		offset = pageEnd
	}
	if len(current) != 0 {
		return nil, fmt.Errorf("unterminated Ogg packet")
	}
	return packets, nil
}

func oggCRC(data []byte) uint32 {
	var checksum uint32
	for _, value := range data {
		checksum ^= uint32(value) << 24
		for range 8 {
			if checksum&0x80000000 != 0 {
				checksum = checksum<<1 ^ 0x04c11db7
			} else {
				checksum <<= 1
			}
		}
	}
	return checksum
}
