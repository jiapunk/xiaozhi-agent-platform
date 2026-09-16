package s3camdev

import (
	"bufio"
	"context"
	"embed"
	"fmt"
	"io"
	"strings"
	"sync"
)

const defaultTextLocale = "zh-TW"

// TextLocalizer normalizes provider text before it is displayed, spoken,
// routed to tools, or stored in a bounded conversation window. This keeps ASR
// subtitles and TTS speech in the same regional Chinese convention.
type TextLocalizer struct {
	locale string
	stages []localeDictionary
}

type localeDictionary struct {
	entries   map[string]string
	maxKeyLen int
}

// The dictionaries are the unmodified OpenCC text dictionaries at pinned
// commit 4f90418b9ed73a91023897095c762e5fdaadc016. OpenCC and its dictionaries
// are Apache-2.0; keeping the conversion engine here avoids linking an
// unrelated GPL trie dependency used by an unofficial Go port.
//
//go:embed textlocale_data/*.txt
var textLocaleData embed.FS

var (
	textLocaleOnce   sync.Once
	textLocaleStages map[string][]localeDictionary
	textLocaleError  error
)

func NewTextLocalizer(locale string) (*TextLocalizer, error) {
	locale = strings.TrimSpace(locale)
	if locale == "" {
		locale = defaultTextLocale
	}
	switch strings.ToLower(locale) {
	case "zh-tw", "zh-hant-tw":
		locale = "zh-TW"
	case "zh-hk", "zh-hant-hk":
		locale = "zh-HK"
	case "zh-cn", "zh-hans-cn":
		locale = "zh-CN"
	default:
		return nil, fmt.Errorf("text locale must be zh-TW, zh-HK, or zh-CN")
	}
	textLocaleOnce.Do(loadTextLocaleStages)
	if textLocaleError != nil {
		return nil, fmt.Errorf("initialize %s text conversion: %w",
			locale, textLocaleError)
	}
	return &TextLocalizer{locale: locale, stages: textLocaleStages[locale]}, nil
}

func (localizer *TextLocalizer) Locale() string {
	if localizer == nil || localizer.locale == "" {
		return defaultTextLocale
	}
	return localizer.locale
}

func (localizer *TextLocalizer) Normalize(text string) string {
	if localizer == nil || text == "" {
		return text
	}
	for _, stage := range localizer.stages {
		text = stage.convert(text)
	}
	return text
}

func loadTextLocaleStages() {
	stage := func(names ...string) localeDictionary {
		dictionary, err := loadLocaleDictionary(names...)
		if err != nil && textLocaleError == nil {
			textLocaleError = err
		}
		return dictionary
	}
	textLocaleStages = map[string][]localeDictionary{
		"zh-TW": {
			stage("STPhrases", "STCharacters"),
			stage("TWPhrases", "TWVariantsPhrases", "TWVariants"),
		},
		"zh-HK": {
			stage("STPhrases", "STCharacters"),
			stage("HKVariantsPhrases", "HKVariants"),
		},
		"zh-CN": {
			stage("TWPhrasesRev", "TWVariantsRevPhrases"),
			stage("TSPhrases", "TSCharacters"),
		},
	}
}

func loadLocaleDictionary(names ...string) (localeDictionary, error) {
	dictionary := localeDictionary{entries: make(map[string]string)}
	for _, name := range names {
		file, err := textLocaleData.Open("textlocale_data/" + name + ".txt")
		if err != nil {
			return localeDictionary{}, err
		}
		if err := appendLocaleDictionary(&dictionary, file); err != nil {
			file.Close()
			return localeDictionary{}, fmt.Errorf("parse %s: %w", name, err)
		}
		if err := file.Close(); err != nil {
			return localeDictionary{}, err
		}
	}
	return dictionary, nil
}

func appendLocaleDictionary(dictionary *localeDictionary, reader io.Reader) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		columns := strings.SplitN(line, "\t", 2)
		if len(columns) != 2 || columns[0] == "" {
			return fmt.Errorf("invalid dictionary row")
		}
		values := strings.Fields(columns[1])
		if len(values) == 0 {
			return fmt.Errorf("dictionary row has no output")
		}
		// Earlier dictionaries in a short-circuit group have priority.
		if _, exists := dictionary.entries[columns[0]]; exists {
			continue
		}
		dictionary.entries[columns[0]] = values[0]
		if length := len([]rune(columns[0])); length > dictionary.maxKeyLen {
			dictionary.maxKeyLen = length
		}
	}
	return scanner.Err()
}

func (dictionary localeDictionary) convert(text string) string {
	input := []rune(text)
	var output strings.Builder
	output.Grow(len(text))
	for position := 0; position < len(input); {
		maximum := dictionary.maxKeyLen
		if remaining := len(input) - position; maximum > remaining {
			maximum = remaining
		}
		matched := false
		for length := maximum; length > 0; length-- {
			if value, ok := dictionary.entries[string(input[position:position+length])]; ok {
				output.WriteString(value)
				position += length
				matched = true
				break
			}
		}
		if !matched {
			output.WriteRune(input[position])
			position++
		}
	}
	return output.String()
}

// localizedReplyStream performs conversion before synthesis so the subtitle,
// spoken audio, and conversation history all contain exactly the same text.
func localizedReplyStream(ctx context.Context, localizer *TextLocalizer,
	input <-chan VoiceReplyChunk) <-chan VoiceReplyChunk {
	output := make(chan VoiceReplyChunk, 2)
	go func() {
		defer close(output)
		for chunk := range input {
			if chunk.Err == nil {
				chunk.Text = localizer.Normalize(chunk.Text)
			}
			select {
			case <-ctx.Done():
				return
			case output <- chunk:
			}
		}
	}()
	return output
}
