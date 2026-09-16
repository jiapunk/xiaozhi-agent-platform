package accountauth

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPushTokenProtectorUsesVersionedRotationKeyring(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "push-keyring.json")
	key := func(character byte) string {
		return base64.RawURLEncoding.EncodeToString(
			[]byte(strings.Repeat(string(character), 32)))
	}
	payload := `{"version":1,"current_key_id":"push-2","keys":[` +
		`{"key_id":"push-1","encryption_key_base64url":"` + key('a') +
		`","lookup_key_base64url":"` + key('b') + `"},` +
		`{"key_id":"push-2","encryption_key_base64url":"` + key('c') +
		`","lookup_key_base64url":"` + key('d') + `"}]}`
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	protector, err := LoadPushTokenProtector(path)
	if err != nil {
		t.Fatal(err)
	}
	if protector.currentKeyID != "push-2" || len(protector.keys) != 2 {
		t.Fatalf("unexpected keyring: %#v", protector)
	}

	if err := os.WriteFile(path, []byte(strings.Replace(payload,
		key('d'), key('c'), 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPushTokenProtector(path); err == nil {
		t.Fatal("duplicate key material accepted")
	}

	duplicateField := strings.Replace(payload, `{"version":1,`,
		`{"version":1,"version":1,`, 1)
	if err := os.WriteFile(path, []byte(duplicateField), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPushTokenProtector(path); err == nil {
		t.Fatal("duplicate keyring JSON field accepted")
	}
}
