package accountauth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"xiaozhi-agent-platform/gateway/internal/strictjson"
)

const maximumPushTokenKeyringBytes = 16 * 1024

type pushTokenKeyringDocument struct {
	Version      uint32                        `json:"version"`
	CurrentKeyID string                        `json:"current_key_id"`
	Keys         []pushTokenKeyringDocumentKey `json:"keys"`
}

type pushTokenKeyringDocumentKey struct {
	KeyID         string `json:"key_id"`
	EncryptionKey string `json:"encryption_key_base64url"`
	LookupKey     string `json:"lookup_key_base64url"`
}

// LoadPushTokenProtector reads a bounded, versioned keyring from the workload
// secret mount. Raw device tokens remain encrypted at rest and old key IDs may
// remain readable during a controlled rotation.
func LoadPushTokenProtector(path string) (*AESGCMPushTokenProtector, error) {
	payload, err := readBoundedRegularFile(path, maximumPushTokenKeyringBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid push token keyring file")
	}
	defer clearBytes(payload)
	if err := strictjson.RejectDuplicateFields(payload); err != nil {
		return nil, fmt.Errorf("invalid push token keyring document")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var document pushTokenKeyringDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("invalid push token keyring document")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF || document.Version != 1 ||
		len(document.Keys) < 1 || len(document.Keys) > 8 {
		return nil, fmt.Errorf("invalid push token keyring document")
	}
	materials := make(map[string]PushTokenKeyMaterial, len(document.Keys))
	seenMaterial := make(map[string]bool, len(document.Keys)*2)
	for _, item := range document.Keys {
		encryption, decodeErr := decodeCanonicalPushKey(item.EncryptionKey)
		if decodeErr != nil {
			return nil, fmt.Errorf("invalid push token keyring material")
		}
		lookup, decodeErr := decodeCanonicalPushKey(item.LookupKey)
		if decodeErr != nil || seenMaterial[string(encryption)] ||
			seenMaterial[string(lookup)] || bytes.Equal(encryption, lookup) {
			clearBytes(encryption)
			clearBytes(lookup)
			return nil, fmt.Errorf("invalid push token keyring material")
		}
		if _, exists := materials[item.KeyID]; exists {
			clearBytes(encryption)
			clearBytes(lookup)
			return nil, fmt.Errorf("duplicate push token key ID")
		}
		seenMaterial[string(encryption)] = true
		seenMaterial[string(lookup)] = true
		materials[item.KeyID] = PushTokenKeyMaterial{
			EncryptionKey: encryption, LookupKey: lookup}
	}
	protector, err := NewAESGCMPushTokenProtector(
		document.CurrentKeyID, materials)
	for _, material := range materials {
		clearBytes(material.EncryptionKey)
		clearBytes(material.LookupKey)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid push token keyring")
	}
	return protector, nil
}

func decodeCanonicalPushKey(encoded string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != 32 ||
		base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		clearBytes(decoded)
		return nil, ErrInvalid
	}
	return decoded, nil
}

func readBoundedRegularFile(path string, maximum int64) ([]byte, error) {
	if path == "" || maximum <= 0 {
		return nil, ErrInvalid
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	status, err := file.Stat()
	if err != nil || !status.Mode().IsRegular() || status.Size() <= 0 ||
		status.Size() > maximum {
		return nil, ErrInvalid
	}
	payload, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(payload) == 0 || int64(len(payload)) > maximum {
		return nil, ErrInvalid
	}
	return payload, nil
}

func clearBytes(payload []byte) {
	for index := range payload {
		payload[index] = 0
	}
}
