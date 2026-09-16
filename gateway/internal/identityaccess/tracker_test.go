package identityaccess

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"xiaozhi-agent-platform/gateway/internal/provisioning"
)

func accessSnapshot(t *testing.T, revision uint64, disabled bool,
	now time.Time) *provisioning.Snapshot {
	t.Helper()
	seed := sha256.Sum256([]byte("identity-access-tracker-test-key"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	unsigned := fmt.Sprintf(
		`{"version":2,"revision":%d,"purpose":"access",`+
			`"issued_at":"%s","valid_until":"%s",`+
			`"devices":[{"device_id":"device-1","disabled":%t}]}`,
		revision, now.Add(-time.Minute).Format(time.RFC3339),
		now.Add(10*time.Minute).Format(time.RFC3339), disabled)
	signed, err := provisioning.SignRegistrySnapshot(strings.NewReader(unsigned),
		"identity-access-test", privateKey, now)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := provisioning.ParseSignedRegistrySnapshot(
		strings.NewReader(string(signed)), publicKey,
		"identity-access-test", now)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestTrackerCancelsEveryLeaseAndRejectsLaterAdmission(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	registry, err := provisioning.NewRegistryFromSnapshot(
		accessSnapshot(t, 1, false, now), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	tracker, err := New(registry)
	if err != nil {
		t.Fatal(err)
	}
	var callbacks atomic.Int32
	first, finishFirst, ok := tracker.Start(context.Background(), "device-1",
		func() { callbacks.Add(1) })
	if !ok {
		t.Fatal("first lease rejected")
	}
	defer finishFirst()
	second, finishSecond, ok := tracker.Start(context.Background(), "device-1",
		func() { callbacks.Add(1) })
	if !ok {
		t.Fatal("second lease rejected")
	}
	defer finishSecond()
	if changed, err := registry.ApplySnapshot(
		accessSnapshot(t, 2, true, now)); err != nil || !changed {
		t.Fatalf("apply revoke: changed=%v err=%v", changed, err)
	}
	if count := tracker.Reconcile(); count != 2 {
		t.Fatalf("reconciled %d leases", count)
	}
	if !Revoked(first) || !Revoked(second) || callbacks.Load() != 2 {
		t.Fatalf("revoke state first=%v second=%v callbacks=%d",
			context.Cause(first), context.Cause(second), callbacks.Load())
	}
	if count := tracker.Reconcile(); count != 0 {
		t.Fatalf("duplicate reconciliation canceled %d leases", count)
	}
	if _, _, ok := tracker.Start(context.Background(), "device-1", nil); ok {
		t.Fatal("revoked device acquired a later lease")
	}
}

func TestTrackerExpiryFailsReadinessAndCancelsLease(t *testing.T) {
	clock := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	registry, err := provisioning.NewRegistryFromSnapshot(
		accessSnapshot(t, 1, false, clock), func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	tracker, _ := New(registry)
	ctx, finish, ok := tracker.Start(context.Background(), "device-1", nil)
	if !ok {
		t.Fatal("lease rejected")
	}
	defer finish()
	clock = clock.Add(11 * time.Minute)
	if tracker.Ready() || tracker.Allowed("device-1") {
		t.Fatal("expired tracker remained ready")
	}
	if tracker.Reconcile() != 1 || !Revoked(ctx) {
		t.Fatalf("expired lease cause=%v", context.Cause(ctx))
	}
}

func TestTrackerAdmissionAndReconcileRaceCannotStrandLease(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	for range 100 {
		registry, err := provisioning.NewRegistryFromSnapshot(
			accessSnapshot(t, 1, false, now), func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		tracker, _ := New(registry)
		started := make(chan context.Context, 1)
		finished := make(chan func(), 1)
		go func() {
			ctx, finish, ok := tracker.Start(context.Background(), "device-1", nil)
			if !ok {
				started <- nil
				finished <- func() {}
				return
			}
			started <- ctx
			finished <- finish
		}()
		if _, err := registry.ApplySnapshot(
			accessSnapshot(t, 2, true, now)); err != nil {
			t.Fatal(err)
		}
		tracker.Reconcile()
		ctx := <-started
		finish := <-finished
		if ctx != nil && !Revoked(ctx) {
			t.Fatal("admission/reconcile race stranded an allowed lease")
		}
		finish()
	}
}
