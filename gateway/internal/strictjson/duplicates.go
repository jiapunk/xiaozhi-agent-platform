// Package strictjson contains narrow structural checks used before decoding
// security-sensitive JSON documents.
package strictjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// RejectDuplicateFields parses one JSON value and rejects duplicate object
// member names at every nesting level. encoding/json otherwise silently keeps
// the last value, which is unsafe for human-reviewed credential documents.
func RejectDuplicateFields(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if err := parseValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("strict JSON contains trailing data")
	}
	return nil
}

func parseValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("strict JSON token: %w", err)
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return fmt.Errorf("strict JSON object key is invalid")
			}
			if _, found := seen[key]; found {
				return fmt.Errorf("strict JSON contains a duplicate field")
			}
			seen[key] = struct{}{}
			if err := parseValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return fmt.Errorf("strict JSON object is incomplete")
		}
	case '[':
		for decoder.More() {
			if err := parseValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return fmt.Errorf("strict JSON array is incomplete")
		}
	default:
		return fmt.Errorf("strict JSON delimiter is invalid")
	}
	return nil
}
