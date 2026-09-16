package speechqualification

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"xiaozhi-agent-platform/gateway/internal/opuspacket"
)

const (
	codecFixtureSchema = "xiaozhi-opus-codec-fixtures-v1"
	oggSerial          = uint32(0x5849414f)
)

type DecodeResult struct {
	Samples   int
	PCMHash   string
	NonSilent bool
}

type DecoderIdentity struct {
	FixtureManifestSHA256 string `json:"fixture_manifest_sha256"`
	FFmpegSHA256          string `json:"ffmpeg_sha256"`
	FFmpegVersion         string `json:"ffmpeg_version"`
}

type PacketDecoder interface {
	Identity() DecoderIdentity
	Decode(ctx context.Context, packet []byte, sampleRate int) (DecodeResult, error)
}

type ReferenceDecoder struct {
	ffmpeg   string
	identity DecoderIdentity
}

type codecFixtureManifest struct {
	Boundary           string `json:"boundary"`
	Schema             string `json:"schema"`
	QualificationOnly  bool   `json:"qualification_only"`
	ReferenceToolchain struct {
		DecoderBackend  string `json:"decoder_backend"`
		EncoderBackend  string `json:"encoder_backend"`
		FFmpegSHA256    string `json:"ffmpeg_sha256"`
		FFmpegVersion   string `json:"ffmpeg_version"`
		LicenseBoundary string `json:"license_boundary"`
	} `json:"reference_toolchain"`
	Fixtures []struct {
		Channels       int    `json:"channels"`
		DecodedPCMHash string `json:"decoded_pcm_s16le_sha256"`
		Samples        int    `json:"decoded_sample_count"`
		Direction      string `json:"direction"`
		DurationMS     int    `json:"duration_ms"`
		Encoder        struct {
			Application     string `json:"application"`
			BitRate         int    `json:"bit_rate"`
			Codec           string `json:"codec"`
			FrameDurationMS int    `json:"frame_duration_ms"`
			VBR             string `json:"vbr"`
		} `json:"encoder"`
		Name         string `json:"name"`
		Packet       string `json:"packet_base64"`
		PacketBytes  int    `json:"packet_bytes"`
		PacketSHA256 string `json:"packet_sha256"`
		SampleRate   int    `json:"sample_rate_hz"`
		Source       struct {
			FrequencyHz             int    `json:"frequency_hz"`
			Kind                    string `json:"kind"`
			SelectedDataPacketIndex int    `json:"selected_data_packet_index"`
			SourceDurationMS        int    `json:"source_duration_ms"`
		} `json:"source"`
	} `json:"fixtures"`
}

func NewReferenceDecoder(ffmpegName, fixtureManifestName string) (*ReferenceDecoder, error) {
	manifestData, err := readRegular(fixtureManifestName, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("codec fixture manifest: %w", err)
	}
	var manifest codecFixtureManifest
	decoder := json.NewDecoder(bytes.NewReader(manifestData))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("codec fixture manifest JSON: %w", err)
	}
	if decoder.Decode(&struct{}{}) == nil {
		return nil, fmt.Errorf("codec fixture manifest has trailing JSON")
	}
	if manifest.Schema != codecFixtureSchema || !manifest.QualificationOnly ||
		manifest.ReferenceToolchain.EncoderBackend != "libopus" ||
		manifest.ReferenceToolchain.DecoderBackend != "ffmpeg-native-opus" ||
		len(manifest.Fixtures) != 2 {
		return nil, fmt.Errorf("codec fixture manifest violates M27 policy")
	}
	ffmpegPath := filepath.Clean(ffmpegName)
	info, err := os.Lstat(ffmpegPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o111 == 0 {
		return nil, fmt.Errorf("reviewed FFmpeg must be an executable regular file")
	}
	ffmpegHash, err := hashFile(ffmpegPath)
	if err != nil || ffmpegHash != manifest.ReferenceToolchain.FFmpegSHA256 {
		return nil, fmt.Errorf("reviewed FFmpeg binary hash mismatch")
	}
	versionContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	versionOutput, err := exec.CommandContext(versionContext, ffmpegPath, "-version").Output()
	if err != nil {
		return nil, fmt.Errorf("cannot identify reviewed FFmpeg")
	}
	version := strings.SplitN(string(versionOutput), "\n", 2)[0]
	if version != manifest.ReferenceToolchain.FFmpegVersion {
		return nil, fmt.Errorf("reviewed FFmpeg version mismatch")
	}
	reference := &ReferenceDecoder{
		ffmpeg: ffmpegPath,
		identity: DecoderIdentity{
			FixtureManifestSHA256: hashBytes(manifestData),
			FFmpegSHA256:          ffmpegHash,
			FFmpegVersion:         version,
		},
	}
	seen := map[string]bool{}
	for _, fixture := range manifest.Fixtures {
		profileOK := fixture.Name == "stt-16k-mono-60ms" &&
			fixture.Direction == "stt_uplink" && fixture.SampleRate == 16000 && fixture.Samples == 960
		profileOK = profileOK || fixture.Name == "tts-24k-mono-60ms" &&
			fixture.Direction == "tts_downlink" && fixture.SampleRate == 24000 && fixture.Samples == 1440
		if seen[fixture.Name] || fixture.Channels != 1 || fixture.DurationMS != 60 ||
			(fixture.SampleRate != 16000 && fixture.SampleRate != 24000) ||
			fixture.Samples != fixture.SampleRate*60/1000 || fixture.PacketBytes < 2 ||
			fixture.Encoder.Codec != "libopus" || fixture.Encoder.FrameDurationMS != 60 ||
			fixture.Encoder.Application != "voip" || fixture.Encoder.BitRate != 24000 ||
			fixture.Encoder.VBR != "off" || !profileOK {
			return nil, fmt.Errorf("codec fixture profile is invalid")
		}
		seen[fixture.Name] = true
		packet, err := base64.StdEncoding.Strict().DecodeString(fixture.Packet)
		if err != nil || len(packet) != fixture.PacketBytes ||
			base64.StdEncoding.EncodeToString(packet) != fixture.Packet ||
			hashBytes(packet) != fixture.PacketSHA256 ||
			opuspacket.ValidateMonoDuration(packet, 60) != nil {
			return nil, fmt.Errorf("codec fixture packet is invalid")
		}
		result, err := reference.Decode(context.Background(), packet, fixture.SampleRate)
		if err != nil || result.Samples != fixture.Samples || !result.NonSilent ||
			result.PCMHash != fixture.DecodedPCMHash {
			return nil, fmt.Errorf("codec fixture reference decode mismatch")
		}
	}
	if !seen["stt-16k-mono-60ms"] || !seen["tts-24k-mono-60ms"] {
		return nil, fmt.Errorf("codec fixture profiles are incomplete")
	}
	return reference, nil
}

func (decoder *ReferenceDecoder) Identity() DecoderIdentity {
	return decoder.identity
}

func (decoder *ReferenceDecoder) Decode(ctx context.Context, packet []byte, sampleRate int) (DecodeResult, error) {
	if decoder == nil || (sampleRate != 16000 && sampleRate != 24000) {
		return DecodeResult{}, fmt.Errorf("invalid reference decode request")
	}
	if err := opuspacket.ValidateMonoDuration(packet, 60); err != nil {
		return DecodeResult{}, err
	}
	ogg, err := wrapRawOpus(packet, sampleRate)
	if err != nil {
		return DecodeResult{}, err
	}
	decodeContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(
		decodeContext, decoder.ffmpeg, "-nostdin", "-hide_banner", "-loglevel", "error",
		"-threads", "1", "-c:a", "opus", "-f", "ogg", "-i", "pipe:0",
		"-map", "0:a:0", "-ac", "1", "-ar", fmt.Sprint(sampleRate),
		"-c:a", "pcm_s16le", "-f", "s16le", "pipe:1",
	)
	command.Stdin = bytes.NewReader(ogg)
	pcm, err := command.Output()
	if err != nil {
		return DecodeResult{}, fmt.Errorf("reference decoder rejected packet")
	}
	expectedBytes := sampleRate * 60 / 1000 * 2
	if len(pcm) != expectedBytes {
		return DecodeResult{}, fmt.Errorf("reference decoder emitted %d bytes; expected %d", len(pcm), expectedBytes)
	}
	nonSilent := false
	for _, value := range pcm {
		if value != 0 {
			nonSilent = true
			break
		}
	}
	return DecodeResult{
		Samples: len(pcm) / 2, PCMHash: hashBytes(pcm), NonSilent: nonSilent,
	}, nil
}

func wrapRawOpus(packet []byte, sampleRate int) ([]byte, error) {
	if len(packet) < 2 || len(packet) > 4096 || (sampleRate != 16000 && sampleRate != 24000) {
		return nil, fmt.Errorf("invalid raw Opus packet")
	}
	head := append([]byte("OpusHead\x01\x01\x00\x00"), byte(sampleRate), byte(sampleRate>>8), byte(sampleRate>>16), byte(sampleRate>>24), 0, 0, 0)
	vendor := []byte("xiaozhi-agent-platform M28")
	tags := append([]byte("OpusTags"), uint32LE(uint32(len(vendor)))...)
	tags = append(tags, vendor...)
	tags = append(tags, 0, 0, 0, 0)
	output := make([]byte, 0, len(packet)+160)
	output = append(output, oggPage(head, 0x02, 0, 0)...)
	output = append(output, oggPage(tags, 0, 0, 1)...)
	output = append(output, oggPage(packet, 0x04, 2880, 2)...)
	return output, nil
}

func oggPage(packet []byte, headerType byte, granule uint64, sequence uint32) []byte {
	segments := make([]byte, 0, len(packet)/255+1)
	remaining := len(packet)
	for remaining >= 255 {
		segments = append(segments, 255)
		remaining -= 255
	}
	segments = append(segments, byte(remaining))
	page := make([]byte, 27+len(segments)+len(packet))
	copy(page, "OggS")
	page[5] = headerType
	binary.LittleEndian.PutUint64(page[6:14], granule)
	binary.LittleEndian.PutUint32(page[14:18], oggSerial)
	binary.LittleEndian.PutUint32(page[18:22], sequence)
	page[26] = byte(len(segments))
	copy(page[27:], segments)
	copy(page[27+len(segments):], packet)
	binary.LittleEndian.PutUint32(page[22:26], oggCRC(page))
	return page
}

func oggCRC(data []byte) uint32 {
	var crc uint32
	for _, value := range data {
		crc ^= uint32(value) << 24
		for range 8 {
			if crc&0x80000000 != 0 {
				crc = crc<<1 ^ 0x04c11db7
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

func uint32LE(value uint32) []byte {
	result := make([]byte, 4)
	binary.LittleEndian.PutUint32(result, value)
	return result
}

func hashBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func hashFile(name string) (string, error) {
	file, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
