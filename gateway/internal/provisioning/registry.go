package provisioning

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

const (
	maximumRegistryBytes = 8 * 1024 * 1024
	maximumDevices       = 100_000
	maximumDeviceSecret  = 128
)

type registryEntry struct {
	DeviceID   string `json:"device_id"`
	SecretB64  string `json:"secret_b64"`
	Board      string `json:"board,omitempty"`
	OTAChannel string `json:"ota_channel,omitempty"`
	Disabled   bool   `json:"disabled,omitempty"`
}

type registryDocument struct {
	Version int             `json:"version"`
	Devices []registryEntry `json:"devices"`
}

type deviceRecord struct {
	secret     []byte
	board      string
	otaChannel string
	disabled   bool
}

type registryState struct {
	devices    map[string]deviceRecord
	purpose    string
	revision   uint64
	issuedAt   time.Time
	validUntil time.Time
	digest     [32]byte
	signingKey string
}

type Registry struct {
	mu    sync.RWMutex
	state *registryState
	now   func() time.Time
}

func LoadRegistry(path string) (*Registry, error) {
	if path == "" {
		return nil, fmt.Errorf("device provisioning registry path is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open device provisioning registry: %w", err)
	}
	defer file.Close()
	return ParseRegistry(file)
}

func ParseRegistry(reader io.Reader) (*Registry, error) {
	if reader == nil {
		return nil, fmt.Errorf("device provisioning registry is required")
	}
	payload, err := io.ReadAll(io.LimitReader(reader, maximumRegistryBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read device provisioning registry: %w", err)
	}
	if len(payload) == 0 || len(payload) > maximumRegistryBytes {
		return nil, fmt.Errorf("device provisioning registry has invalid size")
	}
	var document registryDocument
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode device provisioning registry: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("device provisioning registry has trailing data")
	}
	if document.Version != 1 || len(document.Devices) == 0 ||
		len(document.Devices) > maximumDevices {
		return nil, fmt.Errorf("device provisioning registry version/count is invalid")
	}

	state, err := buildRegistryState(document.Devices, true)
	if err != nil {
		return nil, err
	}
	return &Registry{state: state, now: time.Now}, nil
}

func buildRegistryState(entries []registryEntry, requireSecrets bool) (*registryState, error) {
	state := &registryState{devices: make(map[string]deviceRecord, len(entries))}
	for _, entry := range entries {
		if !auth.ValidIdentifier(entry.DeviceID, 64) {
			return nil, fmt.Errorf("device provisioning registry contains invalid device id")
		}
		if _, exists := state.devices[entry.DeviceID]; exists {
			return nil, fmt.Errorf("device provisioning registry contains duplicate device id")
		}
		var secret []byte
		var err error
		if entry.SecretB64 != "" {
			secret, err = decodeSecret(entry.SecretB64)
		}
		if (requireSecrets && entry.SecretB64 == "") ||
			(entry.SecretB64 != "" &&
				(err != nil || len(secret) < 32 || len(secret) > maximumDeviceSecret)) {
			return nil, fmt.Errorf("device provisioning secret must encode 32 through 128 bytes")
		}
		if (entry.Board == "") != (entry.OTAChannel == "") ||
			(entry.Board != "" && (!auth.ValidIdentifier(entry.Board, 32) ||
				!auth.ValidIdentifier(entry.OTAChannel, 32))) {
			return nil, fmt.Errorf("device OTA board/channel profile is invalid")
		}
		state.devices[entry.DeviceID] = deviceRecord{
			secret: append([]byte(nil), secret...), board: entry.Board,
			otaChannel: entry.OTAChannel, disabled: entry.Disabled,
		}
	}
	return state, nil
}

type OTAProfile struct {
	Board   string
	Channel string
}

func (registry *Registry) OTAProfile(deviceID string) (OTAProfile, bool) {
	record, found := registry.lookup(deviceID)
	if !found || record.disabled || record.board == "" || record.otaChannel == "" {
		return OTAProfile{}, false
	}
	return OTAProfile{Board: record.board, Channel: record.otaChannel}, true
}

func (registry *Registry) DeviceAllowed(deviceID string) bool {
	record, found := registry.lookup(deviceID)
	return found && !record.disabled
}

func decodeSecret(value string) ([]byte, error) {
	for _, encoding := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.StdEncoding,
	} {
		if decoded, err := encoding.DecodeString(value); err == nil {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("invalid base64")
}

func (registry *Registry) lookup(deviceID string) (deviceRecord, bool) {
	record, found, _ := registry.lookupVersioned(deviceID)
	return record, found
}

func (registry *Registry) lookupVersioned(deviceID string) (deviceRecord, bool, uint64) {
	if registry == nil {
		return deviceRecord{}, false, 0
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	if !registry.readyLocked() {
		return deviceRecord{}, false, 0
	}
	record, found := registry.state.devices[deviceID]
	return record, found, registry.state.revision
}

func (registry *Registry) stillAllowedAtRevision(deviceID string,
	revision uint64) bool {
	if registry == nil {
		return false
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	if !registry.readyLocked() || registry.state.revision != revision {
		return false
	}
	record, found := registry.state.devices[deviceID]
	return found && !record.disabled
}

func (registry *Registry) withDeviceAllowed(deviceID string,
	action func() error) error {
	if registry == nil || action == nil {
		return ErrUnauthorized
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	if !registry.readyLocked() {
		return ErrUnauthorized
	}
	record, found := registry.state.devices[deviceID]
	if !found || record.disabled {
		return ErrUnauthorized
	}
	return action()
}

func (registry *Registry) Ready() bool {
	if registry == nil {
		return false
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	return registry.readyLocked()
}

func (registry *Registry) ProofReady() bool {
	if registry == nil {
		return false
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	if !registry.readyLocked() {
		return false
	}
	if registry.state.revision > 0 && registry.state.purpose != ProofSnapshotPurpose {
		return false
	}
	for _, record := range registry.state.devices {
		if !record.disabled && len(record.secret) < 32 {
			return false
		}
	}
	return true
}

func (registry *Registry) readyLocked() bool {
	if registry.state == nil {
		return false
	}
	if registry.state.validUntil.IsZero() {
		return true
	}
	now := time.Now
	if registry.now != nil {
		now = registry.now
	}
	return now().UTC().Before(registry.state.validUntil)
}
