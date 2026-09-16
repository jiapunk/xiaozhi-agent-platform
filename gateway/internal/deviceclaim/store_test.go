package deviceclaim

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func code(fill byte) string {
	return base64.RawURLEncoding.EncodeToString(
		[]byte(strings.Repeat(string([]byte{fill}), claimBytes)))
}

func nonce(fill byte) string {
	return base64.RawURLEncoding.EncodeToString(
		[]byte(strings.Repeat(string([]byte{fill}), nonceBytes)))
}

func testStore(t *testing.T) (*Store, time.Time) {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	randomBytes := make([]byte, 16*64)
	for block := 0; block < 64; block++ {
		for offset := 0; offset < 16; offset++ {
			randomBytes[block*16+offset] = byte(block + offset)
		}
	}
	random := bytes.NewReader(randomBytes)
	store, err := newStore(5*time.Minute, 16, random)
	if err != nil {
		t.Fatal(err)
	}
	return store, now
}

func TestPairingRequiresAppAndMatchingDeviceEvidence(t *testing.T) {
	store, now := testStore(t)
	pending, err := store.Begin("user-1", "tenant-1", "xz-001122334455", code('a'),
		nonce('n'), now)
	if err != nil || pending.Status != StatusPending ||
		!ValidRequestID(pending.RequestID) {
		t.Fatalf("begin: %#v %v", pending, err)
	}
	if _, found, err := store.Owner("xz-001122334455"); found || err != nil {
		t.Fatal("app intent alone created an owner")
	}
	if _, err := store.Confirm("xz-aabbccddeeff", code('a'), now); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong device: %v", err)
	}
	bound, err := store.Confirm("xz-001122334455", code('a'), now)
	if err != nil || bound.Status != StatusBound {
		t.Fatalf("confirm: %#v %v", bound, err)
	}
	owner, found, ownerErr := store.Owner("xz-001122334455")
	if ownerErr != nil || !found || owner.OwnerID != "user-1" ||
		owner.TenantID != "tenant-1" || !ValidBindingID(owner.BindingID) ||
		owner.BindingRevision != 1 ||
		!owner.Matches("user-1", "tenant-1", owner.BindingID, 1) {
		t.Fatalf("owner: %#v %v", owner, found)
	}
	status, err := store.Lookup("user-1", "tenant-1", pending.RequestID, now)
	if err != nil || status.Status != StatusBound {
		t.Fatalf("lookup: %#v %v", status, err)
	}
	if _, err := store.Lookup("user-2", "tenant-1", pending.RequestID, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cross-user status: %v", err)
	}
	if _, err := store.Lookup("user-1", "tenant-2", pending.RequestID, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cross-tenant status: %v", err)
	}
}

func TestReplayConflictIdempotenceAndExpiry(t *testing.T) {
	store, now := testStore(t)
	first, err := store.Begin("user-1", "tenant-1", "device-1", code('a'), nonce('a'), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Begin("user-1", "tenant-1", "device-1", code('a'), nonce('a'), now); !errors.Is(err, ErrReplay) {
		t.Fatalf("nonce replay: %v", err)
	}
	again, err := store.Begin("user-1", "tenant-1", "device-1", code('a'), nonce('b'), now)
	if err != nil || again.RequestID != first.RequestID {
		t.Fatalf("idempotent begin: %#v %v", again, err)
	}
	if _, err := store.Begin("user-2", "tenant-1", "device-1", code('a'), nonce('c'), now); !errors.Is(err, ErrConflict) {
		t.Fatalf("cross-user code: %v", err)
	}
	if _, err := store.Confirm("device-1", code('a'), now.Add(5*time.Minute)); !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrExpired) {
		t.Fatalf("expired confirm: %v", err)
	}
	expired, err := store.Lookup("user-1", "tenant-1", first.RequestID,
		now.Add(5*time.Minute))
	if err != nil || expired.Status != StatusExpired {
		t.Fatalf("expired lookup: %#v %v", expired, err)
	}
}

func TestExistingOwnerCannotBeOverwritten(t *testing.T) {
	store, now := testStore(t)
	first, err := store.Begin("user-1", "tenant-1", "device-1", code('a'), nonce('a'), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Confirm("device-1", code('a'), now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Begin("user-2", "tenant-2", "device-1", code('b'), nonce('b'), now); !errors.Is(err, ErrConflict) {
		t.Fatalf("owner overwrite: %v", err)
	}
	status, err := store.Lookup("user-1", "tenant-1", first.RequestID, now)
	if err != nil || status.Status != StatusBound {
		t.Fatalf("original binding changed: %#v %v", status, err)
	}
}

func TestSameOwnerReclaimPreservesBindingEpoch(t *testing.T) {
	store, now := testStore(t)
	if _, err := store.Begin("user-1", "tenant-1", "device-1", code('a'),
		nonce('a'), now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Confirm("device-1", code('a'), now); err != nil {
		t.Fatal(err)
	}
	first, found, err := store.Owner("device-1")
	if err != nil || !found {
		t.Fatalf("first owner: %#v %v", first, err)
	}
	if _, err := store.Begin("user-1", "tenant-1", "device-1", code('b'),
		nonce('b'), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Confirm("device-1", code('b'),
		now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	second, found, err := store.Owner("device-1")
	if err != nil || !found || second != first {
		t.Fatalf("same owner changed binding epoch: first=%#v second=%#v err=%v",
			first, second, err)
	}
}

func TestReleaseAndPhysicalRebindAdvanceEpoch(t *testing.T) {
	store, now := testStore(t)
	if _, err := store.Begin("user-1", "tenant-1", "device-1", code('a'),
		nonce('a'), now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Confirm("device-1", code('a'), now); err != nil {
		t.Fatal(err)
	}
	first, found, err := store.Owner("device-1")
	if err != nil || !found || first.BindingRevision != 1 {
		t.Fatalf("initial owner: %#v %v", first, err)
	}
	if _, err := store.Release("user-2", "tenant-1", "device-1",
		now.Add(time.Second)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("non-owner release: %v", err)
	}
	released, err := store.Release("user-1", "tenant-1", "device-1",
		now.Add(time.Second))
	if err != nil || released.BindingRevision != 2 ||
		released.BindingID != first.BindingID {
		t.Fatalf("release: %#v %v", released, err)
	}
	if _, found, err := store.Owner("device-1"); err != nil || found {
		t.Fatalf("released device remained serviceable: found=%v err=%v", found, err)
	}
	again, err := store.Release("user-1", "tenant-1", "device-1",
		now.Add(2*time.Second))
	if err != nil || again != released {
		t.Fatalf("release replay changed epoch: %#v %v", again, err)
	}
	if _, err := store.Begin("user-2", "tenant-2", "device-1", code('b'),
		nonce('b'), now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Confirm("device-1", code('b'),
		now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	second, found, err := store.Owner("device-1")
	if err != nil || !found || second.OwnerID != "user-2" ||
		second.TenantID != "tenant-2" || second.BindingRevision != 3 ||
		second.BindingID == first.BindingID {
		t.Fatalf("rebound owner: %#v found=%v err=%v", second, found, err)
	}
}

func TestSameUserCannotCrossTenantBoundary(t *testing.T) {
	store, now := testStore(t)
	if _, err := store.Begin("user-1", "tenant-1", "device-1", code('a'),
		nonce('a'), now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Begin("user-1", "tenant-2", "device-1", code('a'),
		nonce('b'), now); !errors.Is(err, ErrConflict) {
		t.Fatalf("cross-tenant claim reuse: %v", err)
	}
	if _, err := store.Confirm("device-1", code('a'), now); err != nil {
		t.Fatal(err)
	}
	owner, found, err := store.Owner("device-1")
	if err != nil || !found || owner.OwnerID != "user-1" ||
		owner.TenantID != "tenant-1" {
		t.Fatalf("tenant binding changed: %#v %v %v", owner, found, err)
	}
}

func TestConcurrentUsersProduceOneIntentAndOneOwner(t *testing.T) {
	store, now := testStore(t)
	var group sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	for index := 0; index < 32; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			user := "user-1"
			if index%2 == 1 {
				user = "user-2"
			}
			appNonce := base64.RawURLEncoding.EncodeToString(
				append(make([]byte, 15), byte(index)))
			if _, err := store.Begin(user, "tenant-1", "device-1", code('a'),
				appNonce, now); err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}(index)
	}
	group.Wait()
	if successes != 16 {
		t.Fatalf("same-user idempotent successes=%d, want 16", successes)
	}
	if _, err := store.Confirm("device-1", code('a'), now); err != nil {
		t.Fatal(err)
	}
	owner, found, ownerErr := store.Owner("device-1")
	if ownerErr != nil || !found ||
		(owner.OwnerID != "user-1" && owner.OwnerID != "user-2") ||
		owner.TenantID != "tenant-1" {
		t.Fatalf("owner: %#v %v", owner, found)
	}
}

func TestValidationAndCapacity(t *testing.T) {
	store, now := testStore(t)
	if ValidClaimCode("bad") || ValidAppNonce("bad") ||
		ValidRequestID("bad") || ValidBindingID("bad") {
		t.Fatal("noncanonical values accepted")
	}
	if _, err := store.Begin("user/1", "tenant-1", "device-1", code('a'), nonce('a'), now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unsafe user: %v", err)
	}
	small, err := newStore(time.Minute, 1,
		strings.NewReader(strings.Repeat("0123456789abcdef", 8)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := small.Begin("user-1", "tenant-1", "device-1", code('a'), nonce('a'), now); err != nil {
		t.Fatal(err)
	}
	if _, err := small.Begin("user-1", "tenant-1", "device-2", code('b'), nonce('b'), now); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity: %v", err)
	}
}

func TestPostgresStoreConfigurationAndRetryClassification(t *testing.T) {
	if _, err := NewPostgresStore(nil, 5*time.Minute, 16,
		time.Second); err == nil {
		t.Fatal("nil PostgreSQL database accepted")
	}
	database := new(sql.DB)
	if _, err := NewPostgresStore(database, 5*time.Minute, 16,
		time.Second); err != nil {
		t.Fatal(err)
	}
	for _, pgErr := range []*pgconn.PgError{
		{Code: "40001"},
		{Code: "40P01"},
		{Code: "23505", ConstraintName: "ownership_claims_claim_digest_key"},
	} {
		if !retryableDatabaseError(pgErr) {
			t.Fatalf("retryable PostgreSQL error rejected: %#v", pgErr)
		}
	}
	if retryableDatabaseError(&pgconn.PgError{Code: "23505",
		ConstraintName: "ownership_claims_pkey"}) {
		t.Fatal("request id collision must not be retried as a digest race")
	}
	if !errors.Is(unavailable("test", errors.New("database down")),
		ErrUnavailable) {
		t.Fatal("database error did not preserve unavailable classification")
	}
}
