package generation

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var (
	testStateKey = []byte("generation-state-key-0123456789abcdef012")
	testGenesis  = Generation{ID: "staging", Sequence: 0,
		ReceiptSHA256: strings.Repeat("a", 64)}
	testNext = Generation{ID: "release-15-g0001", Sequence: 1,
		ReceiptSHA256: strings.Repeat("b", 64)}
	testReplicas = []ReplicaRef{
		{ID: "controlplane-a", Role: "controlplane"},
		{ID: "controlplane-b", Role: "controlplane"},
		{ID: "firmwareorigin-a", Role: "firmwareorigin"},
		{ID: "firmwareorigin-b", Role: "firmwareorigin"},
	}
	testNow = time.Unix(1_800_000_000, 0)
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := InitializeStore(filepath.Join(t.TempDir(), "state"),
		testStateKey, testGenesis, testReplicas, testNow)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestDurableGenerationLifecycleAndConvergence(t *testing.T) {
	store := newTestStore(t)
	state, err := store.Publish(1, testGenesis, testNext,
		time.Minute, time.Minute, testNow.Add(time.Second))
	if err != nil || state.Phase != PhasePreparing || state.Revision != 2 {
		t.Fatalf("publish state=%#v err=%v", state, err)
	}
	for index, replica := range testReplicas {
		state, err = store.Acknowledge(state.Revision, replica, testNext,
			AckPrepared, testNow.Add(time.Duration(index+2)*time.Second))
		if err != nil {
			t.Fatalf("prepare %s: %v", replica.ID, err)
		}
	}
	if state.Phase != PhaseDraining || state.Active != testGenesis ||
		state.Pending == nil || *state.Pending != testNext {
		t.Fatalf("unexpected drain state: %#v", state)
	}
	state, err = store.Advance(time.Unix(state.DrainUntil-1, 0))
	if err != nil || state.Phase != PhaseDraining {
		t.Fatalf("early drain advanced: %#v %v", state, err)
	}
	state, err = store.Advance(time.Unix(state.DrainUntil, 0))
	if err != nil || state.Phase != PhaseCommitting || state.Active != testNext {
		t.Fatalf("commit state=%#v err=%v", state, err)
	}
	for index, replica := range testReplicas {
		state, err = store.Acknowledge(state.Revision, replica, testNext,
			AckActive, time.Unix(state.UpdatedAt+int64(index+1), 0))
		if err != nil {
			t.Fatalf("active %s: %v", replica.ID, err)
		}
	}
	if state.Phase != PhaseStable || state.Active != testNext ||
		state.Pending != nil || len(state.Acknowledgements) != 0 {
		t.Fatalf("generation did not converge: %#v", state)
	}
	root := store.root
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(root, testStateKey)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovered, _ := reopened.Snapshot()
	if recovered.Revision != state.Revision || recovered.Active != testNext ||
		recovered.Phase != PhaseStable {
		t.Fatalf("recovered wrong state: %#v", recovered)
	}
}

func TestPrepareTimeoutAbortsButCommittingTimeoutNeverRollsBack(t *testing.T) {
	store := newTestStore(t)
	state, err := store.Publish(1, testGenesis, testNext,
		30*time.Second, 30*time.Second, testNow.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	state, err = store.Advance(time.Unix(state.PrepareDeadline+1, 0))
	if err != nil || state.Phase != PhaseStable || state.Active != testGenesis {
		t.Fatalf("prepare timeout did not abort: %#v %v", state, err)
	}
	state, err = store.Publish(state.Revision, testGenesis, testNext,
		30*time.Second, 30*time.Second, time.Unix(state.UpdatedAt+1, 0))
	if err != nil {
		t.Fatal(err)
	}
	for index, replica := range testReplicas {
		state, err = store.Acknowledge(state.Revision, replica, testNext,
			AckPrepared, time.Unix(state.UpdatedAt+int64(index+1), 0))
		if err != nil {
			t.Fatal(err)
		}
	}
	state, err = store.Advance(time.Unix(state.DrainUntil, 0))
	if err != nil || state.Phase != PhaseCommitting {
		t.Fatal(err)
	}
	activeBefore := state.Active
	state, err = store.Advance(time.Unix(state.CommitDeadline+3600, 0))
	if err != nil || state.Phase != PhaseCommitting || state.Active != activeBefore {
		t.Fatalf("commit timeout rolled back: %#v %v", state, err)
	}
}

func TestPublicationAndAbortUseExactCAS(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.Publish(2, testGenesis, testNext,
		time.Minute, time.Minute, testNow); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale revision accepted: %v", err)
	}
	state, err := store.Publish(1, testGenesis, testNext,
		time.Minute, time.Minute, testNow.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	wrong := testNext
	wrong.ReceiptSHA256 = strings.Repeat("c", 64)
	if _, err := store.Abort(state.Revision, wrong,
		testNow.Add(2*time.Second)); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong pending abort accepted: %v", err)
	}
	state, err = store.Abort(state.Revision, testNext, testNow.Add(2*time.Second))
	if err != nil || state.Phase != PhaseStable || state.Active != testGenesis {
		t.Fatalf("abort failed: %#v %v", state, err)
	}
}

func TestCrashBeforeAndAfterRecordCommitRecoversExactly(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	store, err := InitializeStore(root, testStateKey, testGenesis,
		testReplicas, testNow)
	if err != nil {
		t.Fatal(err)
	}
	store.failpoint = func(point string) error {
		if point == "after_record_temp_sync" {
			return errors.New("crash before commit")
		}
		return nil
	}
	if _, err := store.Publish(1, testGenesis, testNext,
		time.Minute, time.Minute, testNow.Add(time.Second)); err == nil {
		t.Fatal("pre-commit crash was not injected")
	}
	_ = store.Close()
	store, err = OpenStore(root, testStateKey)
	if err != nil {
		t.Fatal(err)
	}
	state, _ := store.Snapshot()
	if state.Revision != 1 {
		t.Fatalf("uncommitted record recovered: %#v", state)
	}
	store.failpoint = func(point string) error {
		if point == "after_record_commit" {
			return errors.New("crash after commit")
		}
		return nil
	}
	if _, err := store.Publish(1, testGenesis, testNext,
		time.Minute, time.Minute, testNow.Add(time.Second)); err == nil {
		t.Fatal("post-commit crash was not injected")
	}
	_ = store.Close()
	store, err = OpenStore(root, testStateKey)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	state, _ = store.Snapshot()
	if state.Revision != 2 || state.Phase != PhasePreparing ||
		state.Pending == nil || *state.Pending != testNext {
		t.Fatalf("committed record was lost: %#v", state)
	}
}

func TestCurrentIsRepairableButRecordTamperingFailsClosed(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	store, err := InitializeStore(root, testStateKey, testGenesis,
		testReplicas, testNow)
	if err != nil {
		t.Fatal(err)
	}
	_, digest := store.Snapshot()
	_ = store.Close()
	current := filepath.Join(root, "CURRENT")
	if err := os.Chmod(current, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(current, []byte("corrupt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(root, testStateKey)
	if err != nil {
		t.Fatalf("CURRENT was not repaired: %v", err)
	}
	_, repairedDigest := store.Snapshot()
	if repairedDigest != digest {
		t.Fatal("CURRENT repair changed authoritative record")
	}
	_ = store.Close()
	record := filepath.Join(root, stateFileName(1))
	payload, err := os.ReadFile(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(record, 0o600); err != nil {
		t.Fatal(err)
	}
	payload[len(payload)-2] ^= 1
	if err := os.WriteFile(record, payload, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(root, testStateKey); err == nil {
		t.Fatal("tampered audit record was accepted")
	}
}
