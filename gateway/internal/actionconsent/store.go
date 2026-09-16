// Package actionconsent defines the atomic persistence boundary for one exact
// Agent action consent. It deliberately stores typed action arguments rather
// than prompt or model text.
package actionconsent

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

const (
	Contract        = "xz-action-consent-v1"
	Capability      = "device.set_indicator"
	MaximumLifetime = 30 * time.Second
	challengeBytes  = 16
)

var (
	ErrInvalid     = errors.New("invalid action consent")
	ErrReplay      = errors.New("action consent already decided")
	ErrCapacity    = errors.New("action consent capacity reached")
	ErrConflict    = errors.New("action consent mismatch")
	ErrNotFound    = errors.New("action consent not found")
	ErrExpired     = errors.New("action consent expired")
	ErrPending     = errors.New("action consent decision pending")
	ErrUnavailable = errors.New("action consent store unavailable")
)

type Decision string

const (
	DecisionApprove Decision = "approve"
	DecisionDeny    Decision = "deny"
)

type Action struct {
	IndicatorOn bool
}

// Challenge is registered only by a trusted, authenticated device bridge.
// The bridge must not accept this record from the Companion App.
type Challenge struct {
	ChallengeID   string
	DeviceID      string
	OwnerID       string
	TenantID      string
	OwnerRevision uint64
	SessionID     string
	RequestID     uint32
	Action        Action
	ExpiresAt     time.Time
}

// Request repeats every security-relevant field. The App may choose only the
// decision; it cannot rewrite the action or its arguments.
type Request struct {
	ChallengeID   string
	DeviceID      string
	OwnerRevision uint64
	SessionID     string
	RequestID     uint32
	Action        Action
	Decision      Decision
}

// DeviceRequest is the exact binding presented by the authenticated device
// when it consumes the App decision. It intentionally has no Decision field:
// only the stored App decision may choose approve or deny.
type DeviceRequest struct {
	ChallengeID   string
	DeviceID      string
	OwnerRevision uint64
	SessionID     string
	RequestID     uint32
	Action        Action
}

// Actor is derived from the authenticated Companion token and the current
// ownership record, never from the JSON body.
type Actor struct {
	OwnerID       string
	TenantID      string
	DeviceID      string
	OwnerRevision uint64
}

type Record struct {
	Challenge  Challenge
	Decision   Decision
	DecidedAt  time.Time
	ConsumedAt time.Time
}

// DecisionStore is the multi-replica atomic persistence boundary. A market
// implementation must serialize Register and Decide across all serving
// replicas and re-read the current ownership row inside the same serializable
// Decide transaction. The Actor populated by HTTP is defense in depth, not a
// substitute for that database ownership check.
type DecisionStore interface {
	Register(challenge Challenge, now time.Time) error
	Pending(actor Actor, now time.Time) (Record, bool, error)
	Decide(actor Actor, request Request, now time.Time) (Record, error)
	Consume(request DeviceRequest, now time.Time) (Record, error)
}

// ReadyDecisionStore is implemented by durable adapters that can prove their
// schema and backing service are ready before this process accepts traffic.
type ReadyDecisionStore interface {
	DecisionStore
	VerifySchema() error
}

type storedRecord struct {
	challenge  Challenge
	decision   Decision
	decidedAt  time.Time
	consumedAt time.Time
}

type storedWake struct {
	wake        Wake
	availableAt time.Time
	claimedBy   string
	leaseUntil  time.Time
}

// Store is a single-process reference implementation for development and
// contract tests. It is intentionally not a production persistence adapter.
type Store struct {
	mu         sync.Mutex
	maxRecords int
	records    map[string]*storedRecord
	wakes      map[string]*storedWake
}

var _ DecisionStore = (*Store)(nil)
var _ WakeOutbox = (*Store)(nil)

func NewStore(maxRecords int) (*Store, error) {
	if maxRecords < 1 || maxRecords > 100000 {
		return nil, fmt.Errorf("invalid action consent store configuration")
	}
	return &Store{
		maxRecords: maxRecords,
		records:    make(map[string]*storedRecord),
		wakes:      make(map[string]*storedWake),
	}, nil
}

func NewChallengeID() (string, error) {
	value := make([]byte, challengeBytes)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate action consent challenge id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func ValidChallengeID(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == challengeBytes &&
		base64.RawURLEncoding.EncodeToString(decoded) == value
}

func ValidChallenge(challenge Challenge, now time.Time) bool {
	if now.IsZero() || !ValidChallengeID(challenge.ChallengeID) ||
		!auth.ValidIdentifier(challenge.DeviceID, 64) ||
		!auth.ValidIdentifier(challenge.OwnerID, 128) ||
		!auth.ValidIdentifier(challenge.TenantID, 128) ||
		!auth.ValidBindingRevision(challenge.OwnerRevision) ||
		!auth.ValidIdentifier(challenge.SessionID, 64) ||
		challenge.RequestID == 0 || challenge.ExpiresAt.IsZero() {
		return false
	}
	lifetime := challenge.ExpiresAt.UTC().Sub(now.UTC())
	return lifetime > 0 && lifetime <= MaximumLifetime
}

func validDecision(decision Decision) bool {
	return decision == DecisionApprove || decision == DecisionDeny
}

func (store *Store) Register(challenge Challenge, now time.Time) error {
	if store == nil || !ValidChallenge(challenge, now) {
		return ErrInvalid
	}
	challenge.ExpiresAt = challenge.ExpiresAt.UTC()
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, exists := store.records[challenge.ChallengeID]; exists {
		return ErrConflict
	}
	for _, existing := range store.records {
		if existing.challenge.DeviceID == challenge.DeviceID &&
			existing.challenge.SessionID == challenge.SessionID &&
			existing.challenge.RequestID == challenge.RequestID {
			return ErrConflict
		}
	}
	if len(store.records) >= store.maxRecords {
		return ErrCapacity
	}
	store.records[challenge.ChallengeID] = &storedRecord{challenge: challenge}
	store.wakes[challenge.ChallengeID] = &storedWake{
		wake: wakeFromChallenge(challenge), availableAt: now.UTC(),
	}
	return nil
}

func (store *Store) ClaimWake(workerID string, now time.Time,
	lease time.Duration) (Wake, bool, error) {
	if store == nil || now.IsZero() || !validWakeWorker(workerID) ||
		!validWakeLease(lease) {
		return Wake{}, false, ErrInvalid
	}
	now = now.UTC()
	store.mu.Lock()
	defer store.mu.Unlock()
	var selected *storedWake
	for wakeID, candidate := range store.wakes {
		record := store.records[wakeID]
		if record == nil || record.decision != "" ||
			!candidate.wake.ExpiresAt.After(now) {
			delete(store.wakes, wakeID)
			continue
		}
		if candidate.availableAt.After(now) ||
			(candidate.claimedBy != "" && candidate.leaseUntil.After(now)) {
			continue
		}
		if selected == nil ||
			candidate.wake.ExpiresAt.Before(selected.wake.ExpiresAt) ||
			(candidate.wake.ExpiresAt.Equal(selected.wake.ExpiresAt) &&
				candidate.wake.WakeID < selected.wake.WakeID) {
			selected = candidate
		}
	}
	if selected == nil {
		return Wake{}, false, nil
	}
	if selected.wake.Attempts >= maximumWakeAttempts {
		delete(store.wakes, selected.wake.WakeID)
		return Wake{}, false, nil
	}
	selected.claimedBy = workerID
	selected.leaseUntil = now.Add(lease)
	selected.wake.Attempts++
	return selected.wake, true, nil
}

func (store *Store) AcknowledgeWake(workerID, wakeID string,
	now time.Time) error {
	if store == nil || now.IsZero() || !validWakeWorker(workerID) ||
		!ValidChallengeID(wakeID) {
		return ErrInvalid
	}
	now = now.UTC()
	store.mu.Lock()
	defer store.mu.Unlock()
	wake, found := store.wakes[wakeID]
	if !found {
		return ErrNotFound
	}
	if !wake.wake.ExpiresAt.After(now) {
		delete(store.wakes, wakeID)
		return ErrExpired
	}
	if wake.claimedBy != workerID || !wake.leaseUntil.After(now) {
		return ErrConflict
	}
	delete(store.wakes, wakeID)
	return nil
}

func (store *Store) RetryWake(workerID, wakeID string, now time.Time,
	retryAfter time.Duration) error {
	if store == nil || now.IsZero() || !validWakeWorker(workerID) ||
		!ValidChallengeID(wakeID) || !validWakeRetry(retryAfter) {
		return ErrInvalid
	}
	now = now.UTC()
	store.mu.Lock()
	defer store.mu.Unlock()
	wake, found := store.wakes[wakeID]
	if !found {
		return ErrNotFound
	}
	if wake.claimedBy != workerID || !wake.leaseUntil.After(now) {
		return ErrConflict
	}
	availableAt := now.Add(retryAfter)
	if !wake.wake.ExpiresAt.After(availableAt) {
		delete(store.wakes, wakeID)
		return ErrExpired
	}
	wake.availableAt = availableAt
	wake.claimedBy = ""
	wake.leaseUntil = time.Time{}
	return nil
}

// Pending returns at most one exact undecided challenge for the current owner.
// It does not mark, lease, or consume the challenge: repeated App inbox polls
// return the same oldest challenge until it is decided or expires.
func (store *Store) Pending(actor Actor, now time.Time) (Record, bool, error) {
	if store == nil || now.IsZero() || !validActor(actor) {
		return Record{}, false, ErrInvalid
	}
	now = now.UTC()
	store.mu.Lock()
	defer store.mu.Unlock()
	var selected *storedRecord
	for _, candidate := range store.records {
		challenge := candidate.challenge
		if candidate.decision != "" || !candidate.consumedAt.IsZero() ||
			!challenge.ExpiresAt.After(now) ||
			challenge.OwnerID != actor.OwnerID ||
			challenge.TenantID != actor.TenantID ||
			challenge.DeviceID != actor.DeviceID ||
			challenge.OwnerRevision != actor.OwnerRevision {
			continue
		}
		if selected == nil ||
			challenge.ExpiresAt.Before(selected.challenge.ExpiresAt) ||
			(challenge.ExpiresAt.Equal(selected.challenge.ExpiresAt) &&
				challenge.ChallengeID < selected.challenge.ChallengeID) {
			selected = candidate
		}
	}
	if selected == nil {
		return Record{}, false, nil
	}
	return Record{Challenge: selected.challenge}, true, nil
}

func (store *Store) Decide(actor Actor, request Request,
	now time.Time) (Record, error) {
	if store == nil || now.IsZero() ||
		!auth.ValidIdentifier(actor.OwnerID, 128) ||
		!auth.ValidIdentifier(actor.TenantID, 128) ||
		!auth.ValidIdentifier(actor.DeviceID, 64) ||
		!auth.ValidBindingRevision(actor.OwnerRevision) ||
		!ValidChallengeID(request.ChallengeID) ||
		!auth.ValidIdentifier(request.DeviceID, 64) ||
		!auth.ValidBindingRevision(request.OwnerRevision) ||
		!auth.ValidIdentifier(request.SessionID, 64) ||
		request.RequestID == 0 || !validDecision(request.Decision) {
		return Record{}, ErrInvalid
	}
	now = now.UTC()
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[request.ChallengeID]
	if !exists {
		return Record{}, ErrNotFound
	}
	if record.decision != "" {
		return Record{}, ErrReplay
	}
	if !record.challenge.ExpiresAt.After(now) {
		return Record{}, ErrExpired
	}
	challenge := record.challenge
	if actor.OwnerID != challenge.OwnerID ||
		actor.TenantID != challenge.TenantID ||
		actor.DeviceID != challenge.DeviceID ||
		actor.OwnerRevision != challenge.OwnerRevision ||
		request.DeviceID != challenge.DeviceID ||
		request.OwnerRevision != challenge.OwnerRevision ||
		request.SessionID != challenge.SessionID ||
		request.RequestID != challenge.RequestID ||
		request.Action != challenge.Action {
		return Record{}, ErrConflict
	}
	record.decision = request.Decision
	record.decidedAt = now
	return Record{
		Challenge: challenge, Decision: record.decision,
		DecidedAt: record.decidedAt, ConsumedAt: record.consumedAt,
	}, nil
}

func (store *Store) Consume(request DeviceRequest,
	now time.Time) (Record, error) {
	if store == nil || now.IsZero() ||
		!ValidChallengeID(request.ChallengeID) ||
		!auth.ValidIdentifier(request.DeviceID, 64) ||
		!auth.ValidBindingRevision(request.OwnerRevision) ||
		!auth.ValidIdentifier(request.SessionID, 64) ||
		request.RequestID == 0 {
		return Record{}, ErrInvalid
	}
	now = now.UTC()
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[request.ChallengeID]
	if !exists {
		return Record{}, ErrNotFound
	}
	if !record.challenge.ExpiresAt.After(now) {
		return Record{}, ErrExpired
	}
	if !record.consumedAt.IsZero() {
		return Record{}, ErrReplay
	}
	challenge := record.challenge
	if request.DeviceID != challenge.DeviceID ||
		request.OwnerRevision != challenge.OwnerRevision ||
		request.SessionID != challenge.SessionID ||
		request.RequestID != challenge.RequestID ||
		request.Action != challenge.Action {
		return Record{}, ErrConflict
	}
	if record.decision == "" {
		return Record{}, ErrPending
	}
	record.consumedAt = now
	return Record{
		Challenge: challenge, Decision: record.decision,
		DecidedAt: record.decidedAt, ConsumedAt: record.consumedAt,
	}, nil
}
