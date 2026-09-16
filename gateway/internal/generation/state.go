package generation

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

const (
	PhaseStable     = "STABLE"
	PhasePreparing  = "PREPARING"
	PhaseDraining   = "DRAINING"
	PhaseCommitting = "COMMITTING"

	AckPrepared = "PREPARED"
	AckActive   = "ACTIVE"

	// StateLeaseDuration bounds how long a replica may act on one authenticated
	// coordinator snapshot. DrainDuration is deliberately twice that bound so
	// no old-generation lease can overlap a newly active generation.
	StateLeaseDuration = 5 * time.Second
	DrainDuration      = 10 * time.Second

	maximumStateBytes = 1024 * 1024
	zeroDigest        = "0000000000000000000000000000000000000000000000000000000000000000"
)

var (
	ErrConflict = errors.New("generation state conflict")
	ErrExpired  = errors.New("generation transition expired")
)

type Generation struct {
	ID            string `json:"generation_id"`
	Sequence      uint32 `json:"generation_sequence"`
	ReceiptSHA256 string `json:"receipt_sha256"`
}

type ReplicaRef struct {
	ID   string `json:"replica_id"`
	Role string `json:"role"`
}

type Acknowledgement struct {
	ReplicaID      string `json:"replica_id"`
	Role           string `json:"role"`
	Stage          string `json:"stage"`
	GenerationID   string `json:"generation_id"`
	ReceiptSHA256  string `json:"receipt_sha256"`
	AcknowledgedAt int64  `json:"acknowledged_at"`
}

type State struct {
	Schema               int               `json:"schema"`
	Revision             uint64            `json:"revision"`
	PreviousRecordSHA256 string            `json:"previous_record_sha256"`
	Phase                string            `json:"phase"`
	Active               Generation        `json:"active"`
	Pending              *Generation       `json:"pending"`
	RequiredReplicas     []ReplicaRef      `json:"required_replicas"`
	Acknowledgements     []Acknowledgement `json:"acknowledgements"`
	PrepareDeadline      int64             `json:"prepare_deadline"`
	DrainUntil           int64             `json:"drain_until"`
	CommitDeadline       int64             `json:"commit_deadline"`
	UpdatedAt            int64             `json:"updated_at"`
	RecordHMACB64URL     string            `json:"record_hmac_b64url"`
}

type unsignedState struct {
	Schema               int               `json:"schema"`
	Revision             uint64            `json:"revision"`
	PreviousRecordSHA256 string            `json:"previous_record_sha256"`
	Phase                string            `json:"phase"`
	Active               Generation        `json:"active"`
	Pending              *Generation       `json:"pending"`
	RequiredReplicas     []ReplicaRef      `json:"required_replicas"`
	Acknowledgements     []Acknowledgement `json:"acknowledgements"`
	PrepareDeadline      int64             `json:"prepare_deadline"`
	DrainUntil           int64             `json:"drain_until"`
	CommitDeadline       int64             `json:"commit_deadline"`
	UpdatedAt            int64             `json:"updated_at"`
}

type currentPointer struct {
	Revision     uint64 `json:"revision"`
	RecordSHA256 string `json:"record_sha256"`
}

type Store struct {
	mu           sync.Mutex
	root         string
	key          []byte
	state        State
	digest       string
	lockFile     *os.File
	failpoint    func(string) error
	drainStarted time.Time
}

func InitializeStore(root string, key []byte, initial Generation,
	replicas []ReplicaRef, now time.Time) (*Store, error) {
	if len(key) < 32 || len(key) > 128 || !validGeneration(initial) ||
		!validReplicas(replicas) || !validTime(now) {
		return nil, fmt.Errorf("generation store bootstrap inputs are invalid")
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		return nil, fmt.Errorf("create generation state directory: %w", err)
	}
	store, err := openEmptyStore(root, key)
	if err != nil {
		return nil, err
	}
	state := State{
		Schema: 1, Revision: 1, PreviousRecordSHA256: zeroDigest,
		Phase: PhaseStable, Active: initial,
		RequiredReplicas: append([]ReplicaRef(nil), replicas...),
		Acknowledgements: []Acknowledgement{}, UpdatedAt: now.UTC().Unix(),
	}
	sortReplicas(state.RequiredReplicas)
	if err := store.commitLocked(state); err != nil {
		_ = store.Close()
		return nil, err
	}
	return store, nil
}

func OpenStore(root string, key []byte) (*Store, error) {
	if len(key) < 32 || len(key) > 128 {
		return nil, fmt.Errorf("generation state HMAC key must be 32 through 128 bytes")
	}
	store, err := openEmptyStore(root, key)
	if err != nil {
		return nil, err
	}
	if err := store.loadLocked(); err != nil {
		_ = store.Close()
		return nil, err
	}
	return store, nil
}

func openEmptyStore(root string, key []byte) (*Store, error) {
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() ||
		info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("generation state directory must be a private non-symlink directory")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	lockFile, err := os.Open(absolute)
	if err != nil {
		return nil, fmt.Errorf("open generation state directory: %w", err)
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lockFile.Close()
		return nil, fmt.Errorf("generation state directory is already owned")
	}
	return &Store{root: absolute, key: append([]byte(nil), key...), lockFile: lockFile}, nil
}

func (store *Store) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.lockFile == nil {
		return nil
	}
	_ = syscall.Flock(int(store.lockFile.Fd()), syscall.LOCK_UN)
	err := store.lockFile.Close()
	store.lockFile = nil
	return err
}

func (store *Store) Snapshot() (State, string) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return cloneState(store.state), store.digest
}

func (store *Store) RequiredReplicasMatch(replicas []ReplicaRef) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	copyRefs := append([]ReplicaRef(nil), replicas...)
	sortReplicas(copyRefs)
	return replicasEqual(store.state.RequiredReplicas, copyRefs)
}

func (store *Store) Publish(expectedRevision uint64, expectedActive,
	pending Generation, prepareTimeout, commitTimeout time.Duration,
	now time.Time) (State, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.state.Revision != expectedRevision || store.state.Phase != PhaseStable ||
		!sameGeneration(store.state.Active, expectedActive) {
		return cloneState(store.state), ErrConflict
	}
	if !validGeneration(pending) || pending.Sequence != expectedActive.Sequence+1 ||
		pending.ID == expectedActive.ID || prepareTimeout < 30*time.Second ||
		prepareTimeout > 24*time.Hour || commitTimeout < 30*time.Second ||
		commitTimeout > 24*time.Hour || !validTime(now) {
		return cloneState(store.state), fmt.Errorf("generation publication inputs are invalid")
	}
	next := store.nextLocked(now)
	next.Phase = PhasePreparing
	next.Pending = generationPointer(pending)
	next.Acknowledgements = []Acknowledgement{}
	next.PrepareDeadline = now.UTC().Add(prepareTimeout).Unix()
	next.CommitDeadline = int64(commitTimeout / time.Second)
	if err := store.commitLocked(next); err != nil {
		return cloneState(store.state), err
	}
	return cloneState(store.state), nil
}

func (store *Store) Abort(expectedRevision uint64, pending Generation,
	now time.Time) (State, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.state.Revision != expectedRevision || store.state.Phase != PhasePreparing ||
		store.state.Pending == nil || !sameGeneration(*store.state.Pending, pending) {
		return cloneState(store.state), ErrConflict
	}
	next := store.nextLocked(now)
	makeStable(&next)
	if err := store.commitLocked(next); err != nil {
		return cloneState(store.state), err
	}
	return cloneState(store.state), nil
}

func (store *Store) Acknowledge(expectedRevision uint64, replica ReplicaRef,
	generation Generation, stage string, now time.Time) (State, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.state.Revision != expectedRevision || !containsReplica(
		store.state.RequiredReplicas, replica) || !validTime(now) {
		return cloneState(store.state), ErrConflict
	}
	if stage == AckPrepared {
		if store.state.Phase != PhasePreparing || store.state.Pending == nil ||
			!sameGeneration(*store.state.Pending, generation) {
			return cloneState(store.state), ErrConflict
		}
		if now.UTC().Unix() > store.state.PrepareDeadline {
			next := store.nextLocked(now)
			makeStable(&next)
			if err := store.commitLocked(next); err != nil {
				return cloneState(store.state), err
			}
			return cloneState(store.state), ErrExpired
		}
	} else if stage == AckActive {
		if store.state.Phase != PhaseCommitting || store.state.Pending == nil ||
			!sameGeneration(store.state.Active, generation) ||
			!sameGeneration(*store.state.Pending, generation) ||
			ackStage(store.state.Acknowledgements, replica.ID) != AckPrepared {
			return cloneState(store.state), ErrConflict
		}
	} else {
		return cloneState(store.state), fmt.Errorf("generation acknowledgement stage is invalid")
	}
	next := store.nextLocked(now)
	updated := false
	for index := range next.Acknowledgements {
		if next.Acknowledgements[index].ReplicaID == replica.ID {
			if next.Acknowledgements[index].Stage == stage {
				return cloneState(store.state), nil
			}
			next.Acknowledgements[index].Stage = stage
			next.Acknowledgements[index].AcknowledgedAt = now.UTC().Unix()
			updated = true
			break
		}
	}
	if !updated {
		next.Acknowledgements = append(next.Acknowledgements, Acknowledgement{
			ReplicaID: replica.ID, Role: replica.Role, Stage: stage,
			GenerationID: generation.ID, ReceiptSHA256: generation.ReceiptSHA256,
			AcknowledgedAt: now.UTC().Unix(),
		})
	}
	sort.Slice(next.Acknowledgements, func(left, right int) bool {
		return next.Acknowledgements[left].ReplicaID < next.Acknowledgements[right].ReplicaID
	})
	if allAcknowledged(next, stage) {
		if stage == AckPrepared {
			next.Phase = PhaseDraining
			next.PrepareDeadline = 0
			next.DrainUntil = now.UTC().Add(DrainDuration).Unix()
			store.drainStarted = now
		}
	}
	if err := store.commitLocked(next); err != nil {
		return cloneState(store.state), err
	}
	if stage == AckActive && allAcknowledged(store.state, AckActive) {
		converged := store.nextLocked(now)
		makeStable(&converged)
		if err := store.commitLocked(converged); err != nil {
			return cloneState(store.state), err
		}
	}
	return cloneState(store.state), nil
}

// Advance applies server-clock transitions. PREPARING safely aborts on
// timeout. DRAINING atomically flips active after every old lease has expired.
// COMMITTING never rolls back automatically, even after its convergence SLA.
func (store *Store) Advance(now time.Time) (State, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if !validTime(now) {
		return cloneState(store.state), fmt.Errorf("generation coordinator time is invalid")
	}
	switch store.state.Phase {
	case PhasePreparing:
		if now.UTC().Unix() <= store.state.PrepareDeadline {
			return cloneState(store.state), nil
		}
		next := store.nextLocked(now)
		makeStable(&next)
		if err := store.commitLocked(next); err != nil {
			return cloneState(store.state), err
		}
	case PhaseDraining:
		if store.drainStarted.IsZero() {
			store.drainStarted = now
		}
		if now.UTC().Unix() < store.state.DrainUntil ||
			now.Sub(store.drainStarted) < DrainDuration {
			return cloneState(store.state), nil
		}
		next := store.nextLocked(now)
		next.Phase = PhaseCommitting
		next.Active = *next.Pending
		next.DrainUntil = 0
		next.CommitDeadline = now.UTC().Add(
			time.Duration(store.state.CommitDeadline) * time.Second).Unix()
		if err := store.commitLocked(next); err != nil {
			return cloneState(store.state), err
		}
	case PhaseCommitting:
		if allAcknowledged(store.state, AckActive) {
			next := store.nextLocked(now)
			makeStable(&next)
			if err := store.commitLocked(next); err != nil {
				return cloneState(store.state), err
			}
		}
	}
	return cloneState(store.state), nil
}

func (store *Store) nextLocked(now time.Time) State {
	next := cloneState(store.state)
	next.Revision++
	next.PreviousRecordSHA256 = store.digest
	next.UpdatedAt = now.UTC().Unix()
	next.RecordHMACB64URL = ""
	return next
}

func makeStable(state *State) {
	state.Phase = PhaseStable
	state.Pending = nil
	state.Acknowledgements = []Acknowledgement{}
	state.PrepareDeadline = 0
	state.DrainUntil = 0
	state.CommitDeadline = 0
}

func (store *Store) commitLocked(state State) error {
	if err := validateState(state); err != nil {
		return err
	}
	if store.state.Revision != 0 {
		if err := validateTransition(store.state, state, store.digest); err != nil {
			return err
		}
	}
	unsigned := unsignedFromState(state)
	unsignedBytes, err := json.Marshal(unsigned)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, store.key)
	_, _ = mac.Write(unsignedBytes)
	state.RecordHMACB64URL = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	payload, err := json.Marshal(state)
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	digest := sha256.Sum256(payload)
	digestText := hex.EncodeToString(digest[:])
	recordName := filepath.Join(store.root, stateFileName(state.Revision))
	tempName := filepath.Join(store.root, ".state-tmp-"+strconv.FormatUint(state.Revision, 10))
	if err := writeSyncedExclusive(tempName, payload, 0o400); err != nil {
		return fmt.Errorf("write generation state record: %w", err)
	}
	if store.failpoint != nil {
		if err := store.failpoint("after_record_temp_sync"); err != nil {
			return err
		}
	}
	if err := os.Link(tempName, recordName); err != nil {
		return fmt.Errorf("commit generation state record: %w", err)
	}
	if err := os.Remove(tempName); err != nil {
		return fmt.Errorf("remove committed generation state temporary link: %w", err)
	}
	if err := syncDirectory(store.root); err != nil {
		return err
	}
	// The immutable record is the commit point. CURRENT is a repairable index.
	store.state = state
	store.digest = digestText
	if store.failpoint != nil {
		if err := store.failpoint("after_record_commit"); err != nil {
			return err
		}
	}
	if err := store.writeCurrentLocked(); err != nil {
		return err
	}
	return nil
}

func (store *Store) writeCurrentLocked() error {
	payload, err := json.Marshal(currentPointer{
		Revision: store.state.Revision, RecordSHA256: store.digest,
	})
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	tempName := filepath.Join(store.root, ".current-tmp-"+
		strconv.FormatUint(store.state.Revision, 10))
	_ = os.Remove(tempName)
	if err := writeSyncedExclusive(tempName, payload, 0o400); err != nil {
		return fmt.Errorf("write generation CURRENT: %w", err)
	}
	if err := os.Rename(tempName, filepath.Join(store.root, "CURRENT")); err != nil {
		return fmt.Errorf("commit generation CURRENT: %w", err)
	}
	return syncDirectory(store.root)
}

func (store *Store) loadLocked() error {
	entries, err := os.ReadDir(store.root)
	if err != nil {
		return err
	}
	records := make(map[uint64]string)
	for _, entry := range entries {
		name := entry.Name()
		if name == "CURRENT" {
			continue
		}
		if strings.HasPrefix(name, ".state-tmp-") || strings.HasPrefix(name, ".current-tmp-") {
			info, infoErr := entry.Info()
			if infoErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("unsafe generation state temporary entry")
			}
			if err := os.Remove(filepath.Join(store.root, name)); err != nil {
				return fmt.Errorf("remove incomplete generation state temporary file: %w", err)
			}
			continue
		}
		revision, ok := parseStateFileName(name)
		if !ok || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("unexpected generation state directory entry %q", name)
		}
		records[revision] = filepath.Join(store.root, name)
	}
	if len(records) == 0 {
		return fmt.Errorf("generation state directory is not initialized")
	}
	previous := State{}
	previousDigest := ""
	for revision := uint64(1); revision <= uint64(len(records)); revision++ {
		name, exists := records[revision]
		if !exists {
			return fmt.Errorf("generation state record sequence has a gap")
		}
		payload, err := readBoundedRegular(name, maximumStateBytes)
		if err != nil {
			return fmt.Errorf("read generation state record: %w", err)
		}
		state, err := decodeCanonicalState(payload, store.key)
		if err != nil {
			return fmt.Errorf("verify generation state record %d: %w", revision, err)
		}
		if state.Revision != revision {
			return fmt.Errorf("generation state filename/revision mismatch")
		}
		digest := sha256.Sum256(payload)
		digestText := hex.EncodeToString(digest[:])
		if revision == 1 {
			if state.PreviousRecordSHA256 != zeroDigest || state.Phase != PhaseStable {
				return fmt.Errorf("generation state genesis is invalid")
			}
		} else if err := validateTransition(previous, state, previousDigest); err != nil {
			return fmt.Errorf("generation state transition is invalid: %w", err)
		}
		previous = state
		previousDigest = digestText
	}
	store.state = previous
	store.digest = previousDigest
	if previous.Phase == PhaseDraining {
		// After restart, conservatively require a fresh full monotonic drain. The
		// durable wall-clock deadline is necessary but never sufficient alone.
		store.drainStarted = time.Now()
	}
	if !store.currentMatchesLocked() {
		if err := store.writeCurrentLocked(); err != nil {
			return fmt.Errorf("repair generation CURRENT: %w", err)
		}
	}
	return nil
}

func (store *Store) currentMatchesLocked() bool {
	payload, err := readBoundedRegular(filepath.Join(store.root, "CURRENT"), 256)
	if err != nil {
		return false
	}
	var pointer currentPointer
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&pointer); err != nil || pointer.Revision != store.state.Revision ||
		pointer.RecordSHA256 != store.digest {
		return false
	}
	canonical, _ := json.Marshal(pointer)
	canonical = append(canonical, '\n')
	return bytes.Equal(canonical, payload)
}

func decodeCanonicalState(payload, key []byte) (State, error) {
	var state State
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return State{}, err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return State{}, err
	}
	canonical, err := json.Marshal(state)
	if err != nil {
		return State{}, err
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(canonical, payload) {
		return State{}, fmt.Errorf("generation state JSON is not canonical")
	}
	if err := validateState(state); err != nil {
		return State{}, err
	}
	provided, err := base64.RawURLEncoding.DecodeString(state.RecordHMACB64URL)
	if err != nil || len(provided) != sha256.Size ||
		base64.RawURLEncoding.EncodeToString(provided) != state.RecordHMACB64URL {
		return State{}, fmt.Errorf("generation state HMAC encoding is invalid")
	}
	unsignedBytes, _ := json.Marshal(unsignedFromState(state))
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(unsignedBytes)
	if subtle.ConstantTimeCompare(provided, mac.Sum(nil)) != 1 {
		return State{}, fmt.Errorf("generation state HMAC is invalid")
	}
	return state, nil
}

func validateState(state State) error {
	if state.Schema != 1 || state.Revision == 0 ||
		!validSHA256(state.PreviousRecordSHA256) || !validGeneration(state.Active) ||
		!validReplicas(state.RequiredReplicas) || state.UpdatedAt < 1609459200 ||
		state.UpdatedAt > 4102444800 {
		return fmt.Errorf("generation state fields are invalid")
	}
	if state.RecordHMACB64URL != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(state.RecordHMACB64URL)
		if err != nil || len(decoded) != sha256.Size {
			return fmt.Errorf("generation state HMAC field is invalid")
		}
	}
	if !sort.SliceIsSorted(state.RequiredReplicas, func(left, right int) bool {
		return state.RequiredReplicas[left].ID < state.RequiredReplicas[right].ID
	}) || !sort.SliceIsSorted(state.Acknowledgements, func(left, right int) bool {
		return state.Acknowledgements[left].ReplicaID < state.Acknowledgements[right].ReplicaID
	}) {
		return fmt.Errorf("generation state arrays are not canonical")
	}
	seen := make(map[string]struct{}, len(state.Acknowledgements))
	for _, ack := range state.Acknowledgements {
		ref := ReplicaRef{ID: ack.ReplicaID, Role: ack.Role}
		if _, exists := seen[ack.ReplicaID]; exists || !containsReplica(state.RequiredReplicas, ref) ||
			(ack.Stage != AckPrepared && ack.Stage != AckActive) ||
			!auth.ValidIdentifier(ack.GenerationID, 64) || !validSHA256(ack.ReceiptSHA256) ||
			ack.AcknowledgedAt < 1609459200 || ack.AcknowledgedAt > state.UpdatedAt {
			return fmt.Errorf("generation acknowledgement is invalid")
		}
		seen[ack.ReplicaID] = struct{}{}
	}
	switch state.Phase {
	case PhaseStable:
		if state.Pending != nil || len(state.Acknowledgements) != 0 ||
			state.PrepareDeadline != 0 || state.DrainUntil != 0 || state.CommitDeadline != 0 {
			return fmt.Errorf("stable generation state is invalid")
		}
	case PhasePreparing:
		if !validPending(state) || state.PrepareDeadline <= state.UpdatedAt ||
			state.DrainUntil != 0 || state.CommitDeadline < 30 ||
			state.CommitDeadline > int64((24*time.Hour)/time.Second) {
			return fmt.Errorf("preparing generation state is invalid")
		}
		for _, ack := range state.Acknowledgements {
			if ack.Stage != AckPrepared || !ackMatches(ack, *state.Pending) {
				return fmt.Errorf("preparing acknowledgement is invalid")
			}
		}
	case PhaseDraining:
		if !validPending(state) || state.PrepareDeadline != 0 ||
			state.DrainUntil != state.UpdatedAt+int64(DrainDuration/time.Second) ||
			state.CommitDeadline < 30 ||
			!allAcknowledged(state, AckPrepared) {
			return fmt.Errorf("draining generation state is invalid")
		}
	case PhaseCommitting:
		if state.Pending == nil || !sameGeneration(state.Active, *state.Pending) ||
			state.PrepareDeadline != 0 || state.DrainUntil != 0 ||
			state.CommitDeadline <= state.UpdatedAt ||
			len(state.Acknowledgements) != len(state.RequiredReplicas) {
			return fmt.Errorf("committing generation state is invalid")
		}
		for _, ack := range state.Acknowledgements {
			if !ackMatches(ack, state.Active) {
				return fmt.Errorf("committing acknowledgement is invalid")
			}
		}
	default:
		return fmt.Errorf("generation state phase is invalid")
	}
	return nil
}

func validateTransition(prior, next State, priorDigest string) error {
	if next.Revision != prior.Revision+1 || next.PreviousRecordSHA256 != priorDigest ||
		next.UpdatedAt < prior.UpdatedAt || !replicasEqual(prior.RequiredReplicas, next.RequiredReplicas) {
		return fmt.Errorf("generation state chain metadata changed")
	}
	switch prior.Phase {
	case PhaseStable:
		if next.Phase != PhasePreparing || !sameGeneration(next.Active, prior.Active) ||
			next.Pending == nil || next.Pending.Sequence != prior.Active.Sequence+1 {
			return fmt.Errorf("stable state did not enter preparing")
		}
	case PhasePreparing:
		if !sameGeneration(next.Active, prior.Active) {
			return fmt.Errorf("preparing state changed active generation")
		}
		if next.Phase == PhaseStable {
			if next.Pending != nil {
				return fmt.Errorf("aborted generation retained pending state")
			}
			return nil
		}
		if next.Pending == nil || prior.Pending == nil ||
			!sameGeneration(*next.Pending, *prior.Pending) ||
			(next.Phase != PhasePreparing && next.Phase != PhaseDraining) ||
			!ackProgresses(prior.Acknowledgements, next.Acknowledgements, AckPrepared) {
			return fmt.Errorf("preparing acknowledgements did not progress")
		}
	case PhaseDraining:
		if next.Phase != PhaseCommitting || prior.Pending == nil || next.Pending == nil ||
			!sameGeneration(*prior.Pending, *next.Pending) ||
			!sameGeneration(next.Active, *next.Pending) ||
			!ackListsEqual(prior.Acknowledgements, next.Acknowledgements) {
			return fmt.Errorf("draining state did not atomically commit pending generation")
		}
	case PhaseCommitting:
		if next.Phase == PhaseStable {
			if !sameGeneration(next.Active, prior.Active) || next.Pending != nil {
				return fmt.Errorf("converged state changed active generation")
			}
			if !allAcknowledged(prior, AckActive) {
				return fmt.Errorf("generation converged before every active acknowledgement")
			}
			return nil
		}
		if next.Phase != PhaseCommitting || !sameGeneration(next.Active, prior.Active) ||
			next.Pending == nil || prior.Pending == nil ||
			!sameGeneration(*next.Pending, *prior.Pending) ||
			!ackProgresses(prior.Acknowledgements, next.Acknowledgements, AckActive) {
			return fmt.Errorf("active acknowledgements did not progress")
		}
	default:
		return fmt.Errorf("unknown prior generation phase")
	}
	return nil
}

func ackProgresses(prior, next []Acknowledgement, target string) bool {
	if len(next) < len(prior) || len(next) > len(prior)+1 {
		return false
	}
	changes := 0
	priorByID := make(map[string]Acknowledgement, len(prior))
	for _, ack := range prior {
		priorByID[ack.ReplicaID] = ack
	}
	for _, ack := range next {
		old, exists := priorByID[ack.ReplicaID]
		if !exists {
			if target != AckPrepared || ack.Stage != AckPrepared {
				return false
			}
			changes++
			continue
		}
		if old.Stage == ack.Stage {
			if old != ack {
				return false
			}
			continue
		}
		if target != AckActive || old.Stage != AckPrepared || ack.Stage != AckActive {
			return false
		}
		changes++
	}
	return changes == 1
}

func unsignedFromState(state State) unsignedState {
	return unsignedState{
		Schema: state.Schema, Revision: state.Revision,
		PreviousRecordSHA256: state.PreviousRecordSHA256,
		Phase:                state.Phase, Active: state.Active, Pending: state.Pending,
		RequiredReplicas: state.RequiredReplicas,
		Acknowledgements: state.Acknowledgements,
		PrepareDeadline:  state.PrepareDeadline, DrainUntil: state.DrainUntil,
		CommitDeadline: state.CommitDeadline, UpdatedAt: state.UpdatedAt,
	}
}

func validGeneration(value Generation) bool {
	return auth.ValidIdentifier(value.ID, 64) && validSHA256(value.ReceiptSHA256)
}

func validPending(state State) bool {
	return state.Pending != nil && validGeneration(*state.Pending) &&
		state.Pending.Sequence == state.Active.Sequence+1 && state.Pending.ID != state.Active.ID
}

func validReplicas(values []ReplicaRef) bool {
	if len(values) < 2 || len(values) > 64 {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	roles := make(map[string]int)
	for _, value := range values {
		if !auth.ValidIdentifier(value.ID, 64) ||
			(value.Role != "controlplane" && value.Role != "firmwareorigin") {
			return false
		}
		if _, exists := seen[value.ID]; exists {
			return false
		}
		seen[value.ID] = struct{}{}
		roles[value.Role]++
	}
	return roles["controlplane"] > 0 && roles["firmwareorigin"] > 0
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func validTime(value time.Time) bool {
	seconds := value.UTC().Unix()
	return seconds >= 1609459200 && seconds <= 4102444800
}

func sameGeneration(left, right Generation) bool {
	return left.ID == right.ID && left.Sequence == right.Sequence &&
		subtle.ConstantTimeCompare([]byte(left.ReceiptSHA256), []byte(right.ReceiptSHA256)) == 1
}

func generationPointer(value Generation) *Generation {
	copyValue := value
	return &copyValue
}

func cloneState(value State) State {
	result := value
	result.RequiredReplicas = append([]ReplicaRef(nil), value.RequiredReplicas...)
	result.Acknowledgements = append([]Acknowledgement(nil), value.Acknowledgements...)
	if value.Pending != nil {
		result.Pending = generationPointer(*value.Pending)
	}
	return result
}

func containsReplica(values []ReplicaRef, target ReplicaRef) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func sortReplicas(values []ReplicaRef) {
	sort.Slice(values, func(left, right int) bool { return values[left].ID < values[right].ID })
}

func replicasEqual(left, right []ReplicaRef) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func ackStage(values []Acknowledgement, replicaID string) string {
	for _, value := range values {
		if value.ReplicaID == replicaID {
			return value.Stage
		}
	}
	return ""
}

func ackMatches(ack Acknowledgement, generation Generation) bool {
	return ack.GenerationID == generation.ID && ack.ReceiptSHA256 == generation.ReceiptSHA256
}

func allAcknowledged(state State, stage string) bool {
	if len(state.Acknowledgements) != len(state.RequiredReplicas) {
		return false
	}
	for index, replica := range state.RequiredReplicas {
		ack := state.Acknowledgements[index]
		if ack.ReplicaID != replica.ID || ack.Role != replica.Role || ack.Stage != stage {
			return false
		}
	}
	return true
}

func ackListsEqual(left, right []Acknowledgement) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func stateFileName(revision uint64) string {
	return fmt.Sprintf("state-%020d.json", revision)
}

func parseStateFileName(name string) (uint64, bool) {
	if len(name) != len("state-")+20+len(".json") ||
		!strings.HasPrefix(name, "state-") || !strings.HasSuffix(name, ".json") {
		return 0, false
	}
	digits := strings.TrimSuffix(strings.TrimPrefix(name, "state-"), ".json")
	value, err := strconv.ParseUint(digits, 10, 64)
	return value, err == nil && value > 0 && fmt.Sprintf("%020d", value) == digits
}

func writeSyncedExclusive(name string, payload []byte, mode os.FileMode) error {
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(name)
		}
	}()
	if _, err := file.Write(payload); err != nil {
		return err
	}
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	remove = false
	return nil
}

func syncDirectory(name string) error {
	directory, err := os.Open(name)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func readBoundedRegular(name string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Size() < 1 || info.Size() > maximum {
		return nil, fmt.Errorf("file is unavailable or outside size bounds")
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, maximum+1))
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if !errors.Is(err, io.EOF) {
		return fmt.Errorf("JSON contains trailing content")
	}
	return nil
}
