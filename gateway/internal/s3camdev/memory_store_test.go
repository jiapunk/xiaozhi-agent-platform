package s3camdev

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestAgentMemoryEncryptsPersistsAndRejectsTampering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-memory.enc")
	key := base64.RawStdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	memory, err := NewAgentMemory(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := memory.Put("preference", "language", "繁體中文"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || bytes.Contains(raw, []byte("繁體中文")) {
		t.Fatal("memory was not encrypted")
	}
	reloaded, err := NewAgentMemory(path, key)
	if err != nil {
		t.Fatal(err)
	}
	entry, found := reloaded.Get("language")
	if !found || entry.Value != "繁體中文" {
		t.Fatalf("memory did not persist: %+v found=%v", entry, found)
	}
	raw[len(raw)-1] ^= 0xff
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewAgentMemory(path, key); err == nil {
		t.Fatal("tampered encrypted memory was accepted")
	}
}

func TestAgentMemoryIsBoundedAndKeyValidated(t *testing.T) {
	memory, err := NewAgentMemory("", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := memory.Put("preference", "Invalid Key", "value"); err == nil {
		t.Fatal("invalid memory key was accepted")
	}
	for index := 0; index < maximumMemoryEntriesPerOwner; index++ {
		key := "key_" + string(rune('a'+index))
		if err := memory.Put("profile", key, "value"); err != nil {
			t.Fatal(err)
		}
	}
	if err := memory.Put("profile", "overflow", "value"); err == nil {
		t.Fatal("unbounded memory entry was accepted")
	}
}

func TestAgentMemorySeparatesSpeakerOwners(t *testing.T) {
	memory, err := NewAgentMemory("", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := memory.PutFor("spk-alice", "profile", "name", "Alice"); err != nil {
		t.Fatal(err)
	}
	if err := memory.PutFor("spk-bob", "profile", "name", "Bob"); err != nil {
		t.Fatal(err)
	}
	alice, found := memory.GetFor("spk-alice", "name")
	if !found || alice.Value != "Alice" {
		t.Fatalf("unexpected Alice memory: %+v found=%v", alice, found)
	}
	if _, found := memory.GetFor("spk-alice", "missing"); found {
		t.Fatal("unexpected cross-owner memory")
	}
	list := memory.SnapshotFor("spk-bob")
	if len(list) != 1 || list[0].Value != "Bob" {
		t.Fatalf("unexpected Bob memory: %+v", list)
	}
}
