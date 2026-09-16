package deviceclaim

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

const (
	claimBytes   = 32
	requestBytes = 16
	nonceBytes   = 16
	bindingBytes = 16
)

var (
	ErrInvalid      = errors.New("invalid device claim")
	ErrReplay       = errors.New("replayed app claim request")
	ErrCapacity     = errors.New("device claim capacity reached")
	ErrConflict     = errors.New("device claim conflict")
	ErrNotFound     = errors.New("device claim not found")
	ErrExpired      = errors.New("device claim expired")
	ErrUnauthorized = errors.New("device claim unauthorized")
	ErrUnavailable  = errors.New("device ownership store unavailable")
)

type Status string

const (
	StatusPending Status = "pending"
	StatusBound   Status = "bound"
	StatusExpired Status = "expired"
)

type Record struct {
	RequestID string
	DeviceID  string
	Status    Status
	ExpiresAt time.Time
}

type Ownership struct {
	OwnerID         string
	TenantID        string
	BindingID       string
	BindingRevision uint64
}

func (ownership Ownership) Matches(ownerID, tenantID, bindingID string,
	bindingRevision uint64) bool {
	return ownership.OwnerID == ownerID && ownership.TenantID == tenantID &&
		ownership.BindingID == bindingID &&
		ownership.BindingRevision == bindingRevision &&
		ValidBindingID(bindingID) && auth.ValidBindingRevision(bindingRevision)
}

type OwnershipResolver interface {
	Owner(deviceID string) (Ownership, bool, error)
}

// BatchOwnershipResolver prevents periodic revocation reconciliation from
// amplifying one database lookup into one lookup per active device.
type BatchOwnershipResolver interface {
	OwnershipResolver
	Owners(deviceIDs []string) (map[string]Ownership, error)
}

type ReadyOwnershipResolver interface {
	OwnershipResolver
	VerifySchema() error
}

// OwnershipStore is the atomic persistence boundary. Production adapters must
// implement these operations with one durable serializable transaction domain
// across all replicas; Store below is only the single-process reference.
type OwnershipStore interface {
	OwnershipResolver
	Begin(userID, tenantID, deviceID, code, appNonce string,
		now time.Time) (Record, error)
	Confirm(deviceID, code string, now time.Time) (Record, error)
	Lookup(userID, tenantID, requestID string, now time.Time) (Record, error)
	Release(userID, tenantID, deviceID string, now time.Time) (Ownership, error)
}

var _ OwnershipStore = (*Store)(nil)

type storedRecord struct {
	requestID string
	userID    string
	tenantID  string
	deviceID  string
	digest    [sha256.Size]byte
	status    Status
	expiresAt time.Time
}

type ownershipEntry struct {
	Ownership
	active bool
}

// Store is an intentionally single-process reference. It proves atomic pairing
// semantics; a market deployment must supply the same operations from a
// transactional, durable, multi-replica ownership store.
type Store struct {
	mu         sync.Mutex
	ttl        time.Duration
	maxRecords int
	random     io.Reader
	records    map[string]*storedRecord
	byDigest   map[[sha256.Size]byte]string
	owners     map[string]ownershipEntry
	appNonces  map[string]time.Time
}

func NewStore(ttl time.Duration, maxRecords int) (*Store, error) {
	return newStore(ttl, maxRecords, rand.Reader)
}

func newStore(ttl time.Duration, maxRecords int, random io.Reader) (*Store, error) {
	if ttl < time.Minute || ttl > 10*time.Minute || maxRecords < 1 ||
		maxRecords > 100000 || random == nil {
		return nil, fmt.Errorf("invalid device claim store configuration")
	}
	return &Store{
		ttl: ttl, maxRecords: maxRecords, random: random,
		records:   make(map[string]*storedRecord),
		byDigest:  make(map[[sha256.Size]byte]string),
		owners:    make(map[string]ownershipEntry),
		appNonces: make(map[string]time.Time),
	}, nil
}

func ValidClaimCode(value string) bool {
	return canonicalBytes(value, claimBytes)
}

func ValidAppNonce(value string) bool {
	return canonicalBytes(value, nonceBytes)
}

func ValidRequestID(value string) bool {
	return canonicalBytes(value, requestBytes)
}

func ValidBindingID(value string) bool {
	return canonicalBytes(value, bindingBytes)
}

func canonicalBytes(value string, size int) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == size &&
		base64.RawURLEncoding.EncodeToString(decoded) == value
}

func claimDigest(code string) [sha256.Size]byte {
	return sha256.Sum256([]byte("xiaozhi-device-claim-code-v1\n" + code))
}

func (store *Store) Begin(userID, tenantID, deviceID, code, appNonce string,
	now time.Time) (Record, error) {
	if store == nil || !auth.ValidIdentifier(userID, 128) ||
		!auth.ValidIdentifier(tenantID, 128) ||
		!auth.ValidIdentifier(deviceID, 64) || !ValidClaimCode(code) ||
		!ValidAppNonce(appNonce) || now.IsZero() {
		return Record{}, ErrInvalid
	}
	now = now.UTC()
	digest := claimDigest(code)
	nonceKey := tenantID + "\x00" + userID + "\x00" + appNonce

	store.mu.Lock()
	defer store.mu.Unlock()
	store.cleanup(now)
	if expires, exists := store.appNonces[nonceKey]; exists && expires.After(now) {
		return Record{}, ErrReplay
	}
	if len(store.appNonces) >= store.maxRecords*4 {
		return Record{}, ErrCapacity
	}
	store.appNonces[nonceKey] = now.Add(store.ttl)

	if requestID, exists := store.byDigest[digest]; exists {
		existing := store.records[requestID]
		if existing == nil || existing.userID != userID ||
			existing.tenantID != tenantID ||
			existing.deviceID != deviceID || !existing.expiresAt.After(now) {
			return Record{}, ErrConflict
		}
		return publicRecord(existing, now), nil
	}
	if owner, exists := store.owners[deviceID]; exists && owner.active &&
		(owner.OwnerID != userID || owner.TenantID != tenantID) {
		return Record{}, ErrConflict
	}
	if store.activeRecords(now) >= store.maxRecords {
		return Record{}, ErrCapacity
	}
	requestID, err := store.newRequestID()
	if err != nil {
		return Record{}, fmt.Errorf("generate claim request id: %w", err)
	}
	record := &storedRecord{
		requestID: requestID, userID: userID, tenantID: tenantID,
		deviceID: deviceID,
		digest:   digest, status: StatusPending, expiresAt: now.Add(store.ttl),
	}
	store.records[requestID] = record
	store.byDigest[digest] = requestID
	return publicRecord(record, now), nil
}

func (store *Store) Confirm(deviceID, code string, now time.Time) (Record, error) {
	if store == nil || !auth.ValidIdentifier(deviceID, 64) ||
		!ValidClaimCode(code) || now.IsZero() {
		return Record{}, ErrInvalid
	}
	now = now.UTC()
	digest := claimDigest(code)
	store.mu.Lock()
	defer store.mu.Unlock()
	store.cleanup(now)
	requestID, exists := store.byDigest[digest]
	if !exists {
		return Record{}, ErrNotFound
	}
	record := store.records[requestID]
	if record == nil || record.deviceID != deviceID {
		return Record{}, ErrConflict
	}
	if !record.expiresAt.After(now) {
		return Record{}, ErrExpired
	}
	if owner, owned := store.owners[deviceID]; owned && owner.active &&
		(owner.OwnerID != record.userID ||
			owner.TenantID != record.tenantID) {
		return Record{}, ErrConflict
	}
	owner, exists := store.owners[deviceID]
	if !exists || !owner.active {
		bindingID, err := store.newCanonicalID(bindingBytes, func(candidate string) bool {
			for _, owner := range store.owners {
				if owner.BindingID == candidate {
					return true
				}
			}
			return false
		})
		if err != nil {
			return Record{}, fmt.Errorf("generate binding id: %w", err)
		}
		revision := uint64(1)
		if exists {
			if owner.BindingRevision >= auth.MaximumBindingRevision {
				return Record{}, ErrConflict
			}
			revision = owner.BindingRevision + 1
		}
		store.owners[deviceID] = ownershipEntry{
			Ownership: Ownership{
				OwnerID: record.userID, TenantID: record.tenantID,
				BindingID: bindingID, BindingRevision: revision,
			},
			active: true,
		}
	}
	record.status = StatusBound
	return publicRecord(record, now), nil
}

func (store *Store) Lookup(userID, tenantID, requestID string,
	now time.Time) (Record, error) {
	if store == nil || !auth.ValidIdentifier(userID, 128) ||
		!auth.ValidIdentifier(tenantID, 128) ||
		!ValidRequestID(requestID) || now.IsZero() {
		return Record{}, ErrInvalid
	}
	now = now.UTC()
	store.mu.Lock()
	defer store.mu.Unlock()
	store.cleanup(now)
	record := store.records[requestID]
	if record == nil {
		return Record{}, ErrNotFound
	}
	if record.userID != userID || record.tenantID != tenantID {
		return Record{}, ErrUnauthorized
	}
	return publicRecord(record, now), nil
}

func (store *Store) Owner(deviceID string) (Ownership, bool, error) {
	if store == nil || !auth.ValidIdentifier(deviceID, 64) {
		return Ownership{}, false, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	owner, exists := store.owners[deviceID]
	if !exists || !owner.active {
		return Ownership{}, false, nil
	}
	return owner.Ownership, true, nil
}

func (store *Store) Owners(deviceIDs []string) (map[string]Ownership, error) {
	if store == nil || len(deviceIDs) > 1000 {
		return nil, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	owners := make(map[string]Ownership, len(deviceIDs))
	seen := make(map[string]struct{}, len(deviceIDs))
	for _, deviceID := range deviceIDs {
		if !auth.ValidIdentifier(deviceID, 64) {
			return nil, ErrInvalid
		}
		if _, exists := seen[deviceID]; exists {
			return nil, ErrInvalid
		}
		seen[deviceID] = struct{}{}
		entry, exists := store.owners[deviceID]
		if exists && entry.active {
			owners[deviceID] = entry.Ownership
		}
	}
	return owners, nil
}

func (store *Store) Release(userID, tenantID, deviceID string,
	now time.Time) (Ownership, error) {
	if store == nil || !auth.ValidIdentifier(userID, 128) ||
		!auth.ValidIdentifier(tenantID, 128) ||
		!auth.ValidIdentifier(deviceID, 64) || now.IsZero() {
		return Ownership{}, ErrInvalid
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	entry, exists := store.owners[deviceID]
	if !exists {
		return Ownership{}, ErrNotFound
	}
	if entry.OwnerID != userID || entry.TenantID != tenantID {
		return Ownership{}, ErrUnauthorized
	}
	if !entry.active {
		return entry.Ownership, nil
	}
	if entry.BindingRevision >= auth.MaximumBindingRevision {
		return Ownership{}, ErrConflict
	}
	entry.BindingRevision++
	entry.active = false
	store.owners[deviceID] = entry
	return entry.Ownership, nil
}

func (store *Store) newRequestID() (string, error) {
	return store.newCanonicalID(requestBytes, func(candidate string) bool {
		_, exists := store.records[candidate]
		return exists
	})
}

func (store *Store) newCanonicalID(size int, exists func(string) bool) (string, error) {
	for attempt := 0; attempt < 4; attempt++ {
		raw := make([]byte, size)
		if _, err := io.ReadFull(store.random, raw); err != nil {
			return "", err
		}
		encoded := base64.RawURLEncoding.EncodeToString(raw)
		if !exists(encoded) {
			return encoded, nil
		}
	}
	return "", ErrCapacity
}

func (store *Store) activeRecords(now time.Time) int {
	count := 0
	for _, record := range store.records {
		if record.expiresAt.After(now) {
			count++
		}
	}
	return count
}

func (store *Store) cleanup(now time.Time) {
	for nonce, expires := range store.appNonces {
		if !expires.After(now) {
			delete(store.appNonces, nonce)
		}
	}
	for requestID, record := range store.records {
		if !record.expiresAt.After(now) {
			if current, exists := store.byDigest[record.digest]; exists && current == requestID {
				delete(store.byDigest, record.digest)
			}
			record.status = StatusExpired
		}
		if !record.expiresAt.Add(store.ttl).After(now) {
			delete(store.records, requestID)
		}
	}
}

func publicRecord(record *storedRecord, now time.Time) Record {
	status := record.status
	if !record.expiresAt.After(now) {
		status = StatusExpired
	}
	return Record{
		RequestID: record.requestID, DeviceID: record.deviceID,
		Status: status, ExpiresAt: record.expiresAt,
	}
}
