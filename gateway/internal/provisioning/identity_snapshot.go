package provisioning

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

const (
	RegistrySignatureDomain = "xiaozhi-device-identity-snapshot-v1\n"
	AccessSnapshotPurpose   = "access"
	ProofSnapshotPurpose    = "proof"
	minimumSnapshotValidity = 5 * time.Minute
	maximumSnapshotValidity = 24 * time.Hour
	maximumSnapshotFuture   = 5 * time.Minute
)

var (
	ErrSnapshotRollback     = errors.New("device identity snapshot rollback")
	ErrSnapshotEquivocation = errors.New("device identity snapshot revision equivocation")
)

type unsignedSnapshotDocument struct {
	Version    int             `json:"version"`
	Revision   uint64          `json:"revision"`
	Purpose    string          `json:"purpose"`
	IssuedAt   string          `json:"issued_at"`
	ValidUntil string          `json:"valid_until"`
	Devices    []registryEntry `json:"devices"`
}

type signedSnapshotDocument struct {
	Version      int             `json:"version"`
	Revision     uint64          `json:"revision"`
	Purpose      string          `json:"purpose"`
	IssuedAt     string          `json:"issued_at"`
	ValidUntil   string          `json:"valid_until"`
	Devices      []registryEntry `json:"devices"`
	SigningKeyID string          `json:"signing_key_id"`
	Signature    string          `json:"signature"`
}

type signedSnapshotPayload struct {
	Version      int             `json:"version"`
	Revision     uint64          `json:"revision"`
	Purpose      string          `json:"purpose"`
	IssuedAt     string          `json:"issued_at"`
	ValidUntil   string          `json:"valid_until"`
	Devices      []registryEntry `json:"devices"`
	SigningKeyID string          `json:"signing_key_id"`
}

type Snapshot struct {
	state    *registryState
	revision uint64
	digest   [32]byte
}

type SnapshotStatus struct {
	Revision     uint64
	Purpose      string
	IssuedAt     time.Time
	ValidUntil   time.Time
	DigestSHA256 string
	SigningKeyID string
	Ready        bool
}

type ReloadEvent struct {
	Changed bool
	Status  SnapshotStatus
	Err     error
}

type RegistryReloader struct {
	path         string
	publicKey    ed25519.PublicKey
	signingKeyID string
	purpose      string
	registry     *Registry
	now          func() time.Time
}

func SignRegistrySnapshot(reader io.Reader, signingKeyID string,
	privateKey ed25519.PrivateKey, now time.Time) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize ||
		!auth.ValidIdentifier(signingKeyID, 64) {
		return nil, fmt.Errorf("invalid device identity signing configuration")
	}
	var unsigned unsignedSnapshotDocument
	if err := decodeStrictDocument(reader, &unsigned); err != nil {
		return nil, fmt.Errorf("decode unsigned device identity snapshot: %w", err)
	}
	payload := signedSnapshotPayload{
		Version: unsigned.Version, Revision: unsigned.Revision,
		Purpose:  unsigned.Purpose,
		IssuedAt: unsigned.IssuedAt, ValidUntil: unsigned.ValidUntil,
		Devices: unsigned.Devices, SigningKeyID: signingKeyID,
	}
	if _, _, err := validateSnapshotPayload(payload, now); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode device identity snapshot: %w", err)
	}
	signature := ed25519.Sign(privateKey,
		append([]byte(RegistrySignatureDomain), canonical...))
	document := signedSnapshotDocument{
		Version: payload.Version, Revision: payload.Revision,
		Purpose:  payload.Purpose,
		IssuedAt: payload.IssuedAt, ValidUntil: payload.ValidUntil,
		Devices: payload.Devices, SigningKeyID: payload.SigningKeyID,
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}
	output, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode signed device identity snapshot: %w", err)
	}
	return append(output, '\n'), nil
}

func ParseSignedRegistrySnapshot(reader io.Reader, publicKey ed25519.PublicKey,
	expectedSigningKeyID string, now time.Time) (*Snapshot, error) {
	if len(publicKey) != ed25519.PublicKeySize ||
		!auth.ValidIdentifier(expectedSigningKeyID, 64) {
		return nil, fmt.Errorf("invalid device identity verification configuration")
	}
	var document signedSnapshotDocument
	if err := decodeStrictDocument(reader, &document); err != nil {
		return nil, fmt.Errorf("decode signed device identity snapshot: %w", err)
	}
	if document.SigningKeyID != expectedSigningKeyID {
		return nil, fmt.Errorf("device identity signing key id mismatch")
	}
	payload := signedSnapshotPayload{
		Version: document.Version, Revision: document.Revision,
		Purpose:  document.Purpose,
		IssuedAt: document.IssuedAt, ValidUntil: document.ValidUntil,
		Devices: document.Devices, SigningKeyID: document.SigningKeyID,
	}
	issuedAt, validUntil, err := validateSnapshotPayload(payload, now)
	if err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode device identity snapshot: %w", err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(document.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != document.Signature ||
		!ed25519.Verify(publicKey,
			append([]byte(RegistrySignatureDomain), canonical...), signature) {
		return nil, fmt.Errorf("device identity snapshot signature is invalid")
	}
	state, err := buildRegistryState(payload.Devices, false)
	if err != nil {
		return nil, err
	}
	fullCanonical, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("encode signed device identity snapshot: %w", err)
	}
	digest := sha256.Sum256(fullCanonical)
	state.revision = payload.Revision
	state.purpose = payload.Purpose
	state.issuedAt = issuedAt
	state.validUntil = validUntil
	state.digest = digest
	state.signingKey = payload.SigningKeyID
	return &Snapshot{
		state: state, revision: payload.Revision, digest: digest,
	}, nil
}

func LoadSignedRegistrySnapshot(path string, publicKey ed25519.PublicKey,
	expectedSigningKeyID string, now time.Time) (*Snapshot, error) {
	file, err := openConfidentialRegularFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return ParseSignedRegistrySnapshot(file, publicKey,
		expectedSigningKeyID, now)
}

func LoadReloadableRegistry(path, publicKeyPath, signingKeyID,
	expectedPurpose string, minimumRevision uint64,
	now func() time.Time) (*Registry, *RegistryReloader, error) {
	if minimumRevision == 0 {
		return nil, nil, fmt.Errorf("device identity minimum revision is required")
	}
	if now == nil {
		now = time.Now
	}
	publicKey, err := LoadEd25519PublicKey(publicKeyPath)
	if err != nil {
		return nil, nil, err
	}
	snapshot, err := LoadSignedRegistrySnapshot(path, publicKey,
		signingKeyID, now().UTC())
	if err != nil {
		return nil, nil, err
	}
	if snapshot.revision < minimumRevision {
		return nil, nil, fmt.Errorf("device identity snapshot is below the configured revision floor")
	}
	if snapshot.state.purpose != expectedPurpose {
		return nil, nil, fmt.Errorf("device identity snapshot purpose mismatch")
	}
	registry, err := NewRegistryFromSnapshot(snapshot, now)
	if err != nil {
		return nil, nil, err
	}
	reloader, err := NewRegistryReloader(path, publicKey, signingKeyID,
		expectedPurpose, registry, now)
	if err != nil {
		return nil, nil, err
	}
	return registry, reloader, nil
}

func NewRegistryFromSnapshot(snapshot *Snapshot,
	now func() time.Time) (*Registry, error) {
	if snapshot == nil || snapshot.state == nil {
		return nil, fmt.Errorf("device identity snapshot is required")
	}
	if now == nil {
		now = time.Now
	}
	return &Registry{state: copyRegistryState(snapshot.state), now: now}, nil
}

func (registry *Registry) ApplySnapshot(snapshot *Snapshot) (bool, error) {
	if registry == nil || snapshot == nil || snapshot.state == nil {
		return false, fmt.Errorf("device identity registry and snapshot are required")
	}
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.state != nil {
		if snapshot.revision < registry.state.revision {
			return false, ErrSnapshotRollback
		}
		if snapshot.revision == registry.state.revision {
			if snapshot.digest != registry.state.digest {
				return false, ErrSnapshotEquivocation
			}
			return false, nil
		}
	}
	registry.state = copyRegistryState(snapshot.state)
	return true, nil
}

func (registry *Registry) Status() SnapshotStatus {
	if registry == nil {
		return SnapshotStatus{}
	}
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	if registry.state == nil {
		return SnapshotStatus{}
	}
	status := SnapshotStatus{
		Revision:     registry.state.revision,
		Purpose:      registry.state.purpose,
		IssuedAt:     registry.state.issuedAt,
		ValidUntil:   registry.state.validUntil,
		DigestSHA256: fmt.Sprintf("%x", registry.state.digest),
		SigningKeyID: registry.state.signingKey,
		Ready:        registry.readyLocked(),
	}
	return status
}

func NewRegistryReloader(path string, publicKey ed25519.PublicKey,
	signingKeyID, expectedPurpose string, registry *Registry,
	now func() time.Time) (*RegistryReloader, error) {
	if path == "" || len(publicKey) != ed25519.PublicKeySize ||
		!auth.ValidIdentifier(signingKeyID, 64) || registry == nil ||
		(expectedPurpose != AccessSnapshotPurpose &&
			expectedPurpose != ProofSnapshotPurpose) {
		return nil, fmt.Errorf("invalid device identity reloader configuration")
	}
	if now == nil {
		now = time.Now
	}
	return &RegistryReloader{
		path: path, publicKey: append(ed25519.PublicKey(nil), publicKey...),
		signingKeyID: signingKeyID, purpose: expectedPurpose,
		registry: registry, now: now,
	}, nil
}

func (reloader *RegistryReloader) Reload() (bool, SnapshotStatus, error) {
	if reloader == nil {
		return false, SnapshotStatus{}, fmt.Errorf("device identity reloader is required")
	}
	snapshot, err := LoadSignedRegistrySnapshot(reloader.path,
		reloader.publicKey, reloader.signingKeyID, reloader.now().UTC())
	if err != nil {
		return false, reloader.registry.Status(), err
	}
	if snapshot.state.purpose != reloader.purpose {
		return false, reloader.registry.Status(),
			fmt.Errorf("device identity snapshot purpose mismatch")
	}
	changed, err := reloader.registry.ApplySnapshot(snapshot)
	return changed, reloader.registry.Status(), err
}

func (reloader *RegistryReloader) Run(ctx context.Context,
	interval time.Duration, notify func(ReloadEvent)) {
	if reloader == nil || ctx == nil || interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			changed, status, err := reloader.Reload()
			if notify != nil {
				notify(ReloadEvent{Changed: changed, Status: status, Err: err})
			}
		}
	}
}

func LoadEd25519PublicKey(path string) (ed25519.PublicKey, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 64*1024 {
		return nil, fmt.Errorf("device identity public key file is invalid")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read device identity public key: %w", err)
	}
	if block, _ := pem.Decode(payload); block != nil {
		parsed, parseErr := x509.ParsePKIXPublicKey(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("parse device identity public key: %w", parseErr)
		}
		key, ok := parsed.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("device identity public key is not Ed25519")
		}
		return append(ed25519.PublicKey(nil), key...), nil
	}
	decoded, err := decodeCanonicalBase64(strings.TrimSpace(string(payload)))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("device identity public key must be Ed25519 PEM or base64url")
	}
	return ed25519.PublicKey(decoded), nil
}

func LoadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	file, err := openConfidentialRegularFile(path)
	if err != nil {
		return nil, err
	}
	payload, err := io.ReadAll(io.LimitReader(file, 64*1024+1))
	_ = file.Close()
	if err != nil {
		return nil, fmt.Errorf("read device identity private key: %w", err)
	}
	if len(payload) > 64*1024 {
		return nil, fmt.Errorf("device identity private key file is too large")
	}
	if block, _ := pem.Decode(payload); block != nil {
		parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("parse device identity private key: %w", parseErr)
		}
		key, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("device identity private key is not Ed25519")
		}
		return append(ed25519.PrivateKey(nil), key...), nil
	}
	decoded, err := decodeCanonicalBase64(strings.TrimSpace(string(payload)))
	if err != nil {
		return nil, fmt.Errorf("device identity private key is invalid")
	}
	if len(decoded) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(decoded), nil
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("device identity private key must be PKCS8 PEM or base64url")
	}
	return ed25519.PrivateKey(decoded), nil
}

func validateSnapshotPayload(payload signedSnapshotPayload,
	now time.Time) (time.Time, time.Time, error) {
	if payload.Version != 2 || payload.Revision == 0 ||
		len(payload.Devices) == 0 || len(payload.Devices) > maximumDevices ||
		!auth.ValidIdentifier(payload.SigningKeyID, 64) ||
		(payload.Purpose != AccessSnapshotPurpose &&
			payload.Purpose != ProofSnapshotPurpose) {
		return time.Time{}, time.Time{}, fmt.Errorf("device identity snapshot version/revision/count is invalid")
	}
	issuedAt, err := time.Parse(time.RFC3339, payload.IssuedAt)
	if err != nil || issuedAt.Format(time.RFC3339) != payload.IssuedAt ||
		issuedAt.Location() != time.UTC {
		return time.Time{}, time.Time{}, fmt.Errorf("device identity issued_at must be canonical UTC RFC3339")
	}
	validUntil, err := time.Parse(time.RFC3339, payload.ValidUntil)
	if err != nil || validUntil.Format(time.RFC3339) != payload.ValidUntil ||
		validUntil.Location() != time.UTC {
		return time.Time{}, time.Time{}, fmt.Errorf("device identity valid_until must be canonical UTC RFC3339")
	}
	duration := validUntil.Sub(issuedAt)
	now = now.UTC()
	if duration < minimumSnapshotValidity || duration > maximumSnapshotValidity ||
		issuedAt.After(now.Add(maximumSnapshotFuture)) || !validUntil.After(now) {
		return time.Time{}, time.Time{}, fmt.Errorf("device identity snapshot validity window is invalid")
	}
	previous := ""
	for index, entry := range payload.Devices {
		if index > 0 && entry.DeviceID <= previous {
			return time.Time{}, time.Time{}, fmt.Errorf("device identity devices must be strictly sorted")
		}
		if entry.SecretB64 != "" {
			secret, decodeErr := base64.RawURLEncoding.DecodeString(entry.SecretB64)
			if decodeErr != nil || len(secret) < 32 || len(secret) > maximumDeviceSecret ||
				base64.RawURLEncoding.EncodeToString(secret) != entry.SecretB64 {
				return time.Time{}, time.Time{}, fmt.Errorf("device identity secret must use canonical base64url")
			}
		}
		if payload.Purpose == AccessSnapshotPurpose && entry.SecretB64 != "" {
			return time.Time{}, time.Time{}, fmt.Errorf("access identity snapshot must not contain proof secrets")
		}
		if payload.Purpose == ProofSnapshotPurpose && !entry.Disabled &&
			entry.SecretB64 == "" {
			return time.Time{}, time.Time{}, fmt.Errorf("enabled proof identity is missing secret material")
		}
		previous = entry.DeviceID
	}
	if _, err := buildRegistryState(payload.Devices, false); err != nil {
		return time.Time{}, time.Time{}, err
	}
	return issuedAt, validUntil, nil
}

func copyRegistryState(source *registryState) *registryState {
	if source == nil {
		return nil
	}
	copyState := &registryState{
		devices:  make(map[string]deviceRecord, len(source.devices)),
		purpose:  source.purpose,
		revision: source.revision, issuedAt: source.issuedAt,
		validUntil: source.validUntil, digest: source.digest,
		signingKey: source.signingKey,
	}
	for deviceID, record := range source.devices {
		record.secret = append([]byte(nil), record.secret...)
		copyState.devices[deviceID] = record
	}
	return copyState
}

func decodeStrictDocument(reader io.Reader, destination any) error {
	if reader == nil {
		return fmt.Errorf("document is required")
	}
	payload, err := io.ReadAll(io.LimitReader(reader, maximumRegistryBytes+1))
	if err != nil || len(payload) == 0 || len(payload) > maximumRegistryBytes {
		return fmt.Errorf("document has invalid size")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("document has trailing data")
	}
	return nil
}

func decodeCanonicalBase64(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("invalid canonical base64url")
	}
	return decoded, nil
}

func openConfidentialRegularFile(path string) (*os.File, error) {
	if path == "" {
		return nil, fmt.Errorf("confidential file path is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat confidential file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("confidential file must be regular and mode 0600 or stricter")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open confidential file: %w", err)
	}
	return file, nil
}
