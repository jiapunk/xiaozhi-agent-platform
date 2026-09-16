// Package speechqualification runs signed, transcript-free qualification of
// private speech adapters without treating protocol evidence as market release.
package speechqualification

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"xiaozhi-agent-platform/gateway/internal/opuspacket"
)

const (
	CorpusSchema    = "xiaozhi-speech-qualification-corpus-v1"
	maximumCorpus   = 2 << 20
	maximumCases    = 8
	maximumPackets  = 256
	maximumTextSize = 1024
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$`)

type Corpus struct {
	Schema       string    `json:"schema"`
	CorpusID     string    `json:"corpus_id"`
	ConsentClass string    `json:"consent_class"`
	STT          STTCase   `json:"stt_case"`
	TTS          []TTSCase `json:"tts_cases"`
	Cancel       TTSCase   `json:"tts_cancel_case"`
}

type STTCase struct {
	CaseID       string   `json:"case_id"`
	SampleRate   int      `json:"sample_rate_hz"`
	Channels     int      `json:"channels"`
	DurationMS   int      `json:"packet_duration_ms"`
	Packets      []string `json:"packets_base64"`
	ExpectedText string   `json:"expected_text"`
}

type TTSCase struct {
	CaseID string `json:"case_id"`
	Text   string `json:"text"`
}

type LoadedCorpus struct {
	Corpus Corpus
	SHA256 string
	STT    [][]byte
}

func LoadCorpus(name string) (LoadedCorpus, error) {
	data, err := readRegular(name, maximumCorpus)
	if err != nil {
		return LoadedCorpus{}, fmt.Errorf("qualification corpus: %w", err)
	}
	var corpus Corpus
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&corpus); err != nil {
		return LoadedCorpus{}, fmt.Errorf("qualification corpus JSON: %w", err)
	}
	if decoder.Decode(&struct{}{}) == nil {
		return LoadedCorpus{}, fmt.Errorf("qualification corpus has trailing JSON")
	}
	canonical, err := prettyJSON(corpus)
	if err != nil || !bytes.Equal(canonical, data) {
		return LoadedCorpus{}, fmt.Errorf("qualification corpus is not canonical JSON")
	}
	packets, err := validateCorpus(corpus)
	if err != nil {
		return LoadedCorpus{}, err
	}
	return LoadedCorpus{Corpus: corpus, SHA256: hashBytes(data), STT: packets}, nil
}

func validateCorpus(corpus Corpus) ([][]byte, error) {
	if corpus.Schema != CorpusSchema || !validIdentifier(corpus.CorpusID) {
		return nil, fmt.Errorf("qualification corpus identity is invalid")
	}
	switch corpus.ConsentClass {
	case "synthetic", "approved_nonprivate", "approved_private":
	default:
		return nil, fmt.Errorf("qualification corpus consent_class is invalid")
	}
	if !validIdentifier(corpus.STT.CaseID) || corpus.STT.SampleRate != 16000 ||
		corpus.STT.Channels != 1 || corpus.STT.DurationMS != 60 ||
		len(corpus.STT.Packets) < 1 || len(corpus.STT.Packets) > maximumPackets ||
		!validText(corpus.STT.ExpectedText) {
		return nil, fmt.Errorf("qualification STT case violates product policy")
	}
	packets := make([][]byte, 0, len(corpus.STT.Packets))
	for _, encoded := range corpus.STT.Packets {
		packet, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || base64.StdEncoding.EncodeToString(packet) != encoded ||
			len(packet) > 4096 {
			return nil, fmt.Errorf("qualification STT packet is not canonical base64")
		}
		if err := opuspacket.ValidateMonoDuration(packet, 60); err != nil {
			return nil, fmt.Errorf("qualification STT packet: %w", err)
		}
		packets = append(packets, packet)
	}
	if len(corpus.TTS) < 2 || len(corpus.TTS) > maximumCases ||
		!validIdentifier(corpus.Cancel.CaseID) || !validText(corpus.Cancel.Text) {
		return nil, fmt.Errorf("qualification TTS cases violate policy")
	}
	seen := map[string]bool{corpus.STT.CaseID: true}
	previous := ""
	for _, test := range corpus.TTS {
		if !validIdentifier(test.CaseID) || !validText(test.Text) || seen[test.CaseID] ||
			(previous != "" && test.CaseID <= previous) {
			return nil, fmt.Errorf("qualification TTS cases are duplicated or noncanonical")
		}
		seen[test.CaseID] = true
		previous = test.CaseID
	}
	if seen[corpus.Cancel.CaseID] {
		return nil, fmt.Errorf("qualification cancel case is duplicated")
	}
	return packets, nil
}

func validIdentifier(value string) bool {
	return identifierPattern.MatchString(value)
}

func validText(value string) bool {
	return utf8.ValidString(value) && value == strings.TrimSpace(value) &&
		len(value) > 0 && len([]byte(value)) <= maximumTextSize &&
		!strings.ContainsAny(value, "\x00\r\n")
}

func prettyJSON(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func readRegular(name string, maximum int64) ([]byte, error) {
	clean := filepath.Clean(name)
	info, err := os.Lstat(clean)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() < 1 || info.Size() > maximum {
		return nil, fmt.Errorf("file is missing, non-regular, empty, or oversized")
	}
	data, err := os.ReadFile(clean)
	if err != nil || int64(len(data)) != info.Size() {
		return nil, fmt.Errorf("file could not be read atomically")
	}
	return data, nil
}

func sortedStrings(values []string) bool {
	return sort.StringsAreSorted(values)
}
