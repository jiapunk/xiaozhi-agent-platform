package s3camdev

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

const (
	maximumMemoryEntriesPerOwner = 16
	maximumMemoryEntriesTotal    = 128
	memoryFileHeader             = "XZMEM1"
)

type MemoryEntry struct {
	Owner    string `json:"owner,omitempty"`
	Category string `json:"category"`
	Key      string `json:"key"`
	Value    string `json:"value"`
}

type AgentMemory struct {
	mu      sync.Mutex
	path    string
	aead    cipher.AEAD
	entries map[string]MemoryEntry
}

func NewAgentMemory(path, encodedKey string) (*AgentMemory, error) {
	memory := &AgentMemory{path: path, entries: make(map[string]MemoryEntry)}
	if path == "" {
		if encodedKey != "" {
			return nil, fmt.Errorf("memory key requires a memory file")
		}
		return memory, nil
	}
	key, err := decodeMemoryKey(encodedKey)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize memory encryption: %w", err)
	}
	memory.aead, err = cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize memory authentication: %w", err)
	}
	if err := memory.load(); err != nil {
		return nil, err
	}
	return memory, nil
}

func decodeMemoryKey(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	decoders := []func(string) ([]byte, error){
		hex.DecodeString, base64.RawStdEncoding.DecodeString,
		base64.StdEncoding.DecodeString, base64.RawURLEncoding.DecodeString,
	}
	for _, decode := range decoders {
		if decoded, err := decode(value); err == nil && len(decoded) == 32 {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("memory encryption key must encode exactly 32 bytes")
}

func (memory *AgentMemory) List() []MemoryEntry {
	return memory.ListFor("")
}

func (memory *AgentMemory) ListFor(owner string) []MemoryEntry {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	entries := make([]MemoryEntry, 0, maximumMemoryEntriesPerOwner)
	for _, entry := range memory.entries {
		if entry.Owner != owner {
			continue
		}
		entry.Value = ""
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })
	return entries
}

func (memory *AgentMemory) Get(key string) (MemoryEntry, bool) {
	return memory.GetFor("", key)
}

func (memory *AgentMemory) GetFor(owner, key string) (MemoryEntry, bool) {
	memory.mu.Lock()
	defer memory.mu.Unlock()
	entry, ok := memory.entries[memoryMapKey(owner, key)]
	return entry, ok
}

func (memory *AgentMemory) Put(category, key, value string) error {
	return memory.PutFor("", category, key, value)
}

func (memory *AgentMemory) PutFor(owner, category, key, value string) error {
	if category != "profile" && category != "preference" {
		return fmt.Errorf("invalid memory category")
	}
	if !validMemoryOwner(owner) || !validMemoryKey(key) || value == "" ||
		!utf8.ValidString(value) ||
		utf8.RuneCountInString(value) > 160 {
		return fmt.Errorf("invalid memory entry")
	}
	memory.mu.Lock()
	defer memory.mu.Unlock()
	mapKey := memoryMapKey(owner, key)
	if _, exists := memory.entries[mapKey]; !exists {
		if len(memory.entries) >= maximumMemoryEntriesTotal ||
			memory.ownerEntryCountLocked(owner) >= maximumMemoryEntriesPerOwner {
			return fmt.Errorf("memory is full")
		}
	}
	previous, existed := memory.entries[mapKey]
	memory.entries[mapKey] = MemoryEntry{
		Owner: owner, Category: category, Key: key, Value: value,
	}
	if err := memory.persistLocked(); err != nil {
		if existed {
			memory.entries[mapKey] = previous
		} else {
			delete(memory.entries, mapKey)
		}
		return err
	}
	return nil
}

func (memory *AgentMemory) Forget(key string) (bool, error) {
	return memory.ForgetFor("", key)
}

func (memory *AgentMemory) ForgetFor(owner, key string) (bool, error) {
	if !validMemoryOwner(owner) || !validMemoryKey(key) {
		return false, fmt.Errorf("invalid memory key")
	}
	memory.mu.Lock()
	defer memory.mu.Unlock()
	mapKey := memoryMapKey(owner, key)
	previous, existed := memory.entries[mapKey]
	if !existed {
		return false, nil
	}
	delete(memory.entries, mapKey)
	if err := memory.persistLocked(); err != nil {
		memory.entries[mapKey] = previous
		return false, err
	}
	return true, nil
}

func (memory *AgentMemory) ForgetOwner(owner string) error {
	if owner == "" || !validMemoryOwner(owner) {
		return fmt.Errorf("invalid memory owner")
	}
	memory.mu.Lock()
	defer memory.mu.Unlock()
	removed := make(map[string]MemoryEntry)
	for mapKey, entry := range memory.entries {
		if entry.Owner == owner {
			removed[mapKey] = entry
			delete(memory.entries, mapKey)
		}
	}
	if len(removed) == 0 {
		return nil
	}
	if err := memory.persistLocked(); err != nil {
		for mapKey, entry := range removed {
			memory.entries[mapKey] = entry
		}
		return err
	}
	return nil
}

func (memory *AgentMemory) SnapshotFor(owner string) []MemoryEntry {
	if !validMemoryOwner(owner) {
		return nil
	}
	memory.mu.Lock()
	defer memory.mu.Unlock()
	entries := make([]MemoryEntry, 0, maximumMemoryEntriesPerOwner)
	for _, entry := range memory.entries {
		if entry.Owner == owner {
			entries = append(entries, entry)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })
	return entries
}

func (memory *AgentMemory) ownerEntryCountLocked(owner string) int {
	count := 0
	for _, entry := range memory.entries {
		if entry.Owner == owner {
			count++
		}
	}
	return count
}

func memoryMapKey(owner, key string) string {
	return owner + "\x00" + key
}

func validMemoryOwner(owner string) bool {
	if owner == "" {
		return true
	}
	if len(owner) > 32 {
		return false
	}
	for _, character := range owner {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func validMemoryKey(key string) bool {
	if len(key) == 0 || len(key) > 32 {
		return false
	}
	for _, character := range key {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') &&
			character != '_' && character != '-' && character != '.' {
			return false
		}
	}
	return true
}

// safeLongTermMemory is the hard safety boundary behind the model's softer
// relevance decision. It runs before a candidate is spoken or displayed, so a
// model mistake cannot turn a secret or sensitive trait into a consent prompt.
func safeLongTermMemory(key, value string) bool {
	if !validMemoryKey(key) || value == "" || value != strings.TrimSpace(value) ||
		!utf8.ValidString(value) || utf8.RuneCountInString(value) > 160 ||
		strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return false
	}
	for _, sensitiveKeyPart := range []string{
		"password", "passcode", "secret", "token", "api_key", "private_key",
		"pin", "credit", "bank", "account", "passport", "identity_card",
		"phone", "email", "address", "health", "medical", "allergy",
		"religion", "politic", "sexual", "biometric", "fingerprint",
		"faceprint", "voiceprint",
	} {
		if strings.Contains(key, sensitiveKeyPart) {
			return false
		}
	}
	return !containsSensitiveMemoryCue(key + " " + value)
}

func (memory *AgentMemory) load() error {
	data, err := os.ReadFile(memory.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read encrypted Agent memory: %w", err)
	}
	if len(data) < len(memoryFileHeader)+memory.aead.NonceSize() ||
		string(data[:len(memoryFileHeader)]) != memoryFileHeader {
		return fmt.Errorf("encrypted Agent memory has an invalid format")
	}
	nonceStart := len(memoryFileHeader)
	nonceEnd := nonceStart + memory.aead.NonceSize()
	plain, err := memory.aead.Open(nil, data[nonceStart:nonceEnd],
		data[nonceEnd:], []byte(memoryFileHeader))
	if err != nil {
		return fmt.Errorf("authenticate encrypted Agent memory: %w", err)
	}
	var entries []MemoryEntry
	if err := json.Unmarshal(plain, &entries); err != nil ||
		len(entries) > maximumMemoryEntriesTotal {
		return fmt.Errorf("encrypted Agent memory content is invalid")
	}
	for _, entry := range entries {
		if entry.Category != "profile" && entry.Category != "preference" ||
			!validMemoryOwner(entry.Owner) || !validMemoryKey(entry.Key) ||
			entry.Value == "" ||
			!utf8.ValidString(entry.Value) ||
			utf8.RuneCountInString(entry.Value) > 160 {
			return fmt.Errorf("encrypted Agent memory entry is invalid")
		}
		mapKey := memoryMapKey(entry.Owner, entry.Key)
		if _, duplicate := memory.entries[mapKey]; duplicate {
			return fmt.Errorf("encrypted Agent memory contains a duplicate key")
		}
		if memory.ownerEntryCountLocked(entry.Owner) >= maximumMemoryEntriesPerOwner {
			return fmt.Errorf("encrypted Agent memory owner is full")
		}
		memory.entries[mapKey] = entry
	}
	return nil
}

func (memory *AgentMemory) persistLocked() error {
	if memory.path == "" {
		return nil
	}
	entries := make([]MemoryEntry, 0, len(memory.entries))
	for _, entry := range memory.entries {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })
	plain, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	nonce := make([]byte, memory.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("generate memory nonce: %w", err)
	}
	data := append([]byte(memoryFileHeader), nonce...)
	data = memory.aead.Seal(data, nonce, plain, []byte(memoryFileHeader))
	directory := filepath.Dir(memory.path)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return fmt.Errorf("create memory directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".agent-memory-*")
	if err != nil {
		return fmt.Errorf("create memory snapshot: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err == nil {
		_, err = temporary.Write(data)
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("write encrypted Agent memory: %w", err)
	}
	if err := os.Rename(temporaryPath, memory.path); err != nil {
		return fmt.Errorf("commit encrypted Agent memory: %w", err)
	}
	return nil
}
