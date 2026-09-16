package deviceclaim

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresOwnershipStoreIntegration(t *testing.T) {
	databaseURL := os.Getenv("OWNERSHIP_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("OWNERSHIP_TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	adminConfig, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgx.ConnectConfig(ctx, adminConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	rawSchema := make([]byte, 8)
	if _, err := rand.Read(rawSchema); err != nil {
		t.Fatal(err)
	}
	schema := "xz_ownership_test_" + hex.EncodeToString(rawSchema)
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupContext, cleanupCancel := context.WithTimeout(
			context.Background(), 10*time.Second)
		defer cleanupCancel()
		if _, err := admin.Exec(cleanupContext,
			"DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop test schema: %v", err)
		}
	}()

	migration, err := os.ReadFile(filepath.Join("..", "..", "migrations",
		"ownership", "0001_ownership.sql"))
	if err != nil {
		t.Fatal(err)
	}
	migrationConfig := adminConfig.Copy()
	migrationConfig.RuntimeParams["search_path"] = schema
	migrationConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	migrationConnection, err := pgx.ConnectConfig(ctx, migrationConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := migrationConnection.Exec(ctx, string(migration)); err != nil {
		_ = migrationConnection.Close(context.Background())
		t.Fatal(err)
	}
	if err := migrationConnection.Close(ctx); err != nil {
		t.Fatal(err)
	}

	openDatabase := func() *sql.DB {
		config := adminConfig.Copy()
		config.RuntimeParams["search_path"] = schema
		database := stdlib.OpenDB(*config)
		database.SetMaxOpenConns(8)
		database.SetMaxIdleConns(2)
		t.Cleanup(func() { _ = database.Close() })
		return database
	}
	storeA, err := NewPostgresStore(openDatabase(), time.Minute, 128,
		15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	storeB, err := NewPostgresStore(openDatabase(), time.Minute, 128,
		15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := storeA.VerifySchema(); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	claim := canonicalTestValue('a', claimBytes)
	appNonce := canonicalTestValue('n', nonceBytes)
	pending, err := storeA.Begin("user-1", "tenant-1", "device-1",
		claim, appNonce, now)
	if err != nil || pending.Status != StatusPending {
		t.Fatalf("begin: %#v %v", pending, err)
	}
	bound, err := storeB.Confirm("device-1", claim, now)
	if err != nil || bound.Status != StatusBound {
		t.Fatalf("cross-replica confirm: %#v %v", bound, err)
	}
	owner, found, err := storeA.Owner("device-1")
	if err != nil || !found || owner.OwnerID != "user-1" ||
		owner.TenantID != "tenant-1" || !ValidBindingID(owner.BindingID) ||
		owner.BindingRevision != 1 {
		t.Fatalf("cross-replica owner: %#v %v %v", owner, found, err)
	}
	if _, err := storeB.Lookup("user-1", "tenant-2", pending.RequestID,
		now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cross-tenant lookup: %v", err)
	}
	sameOwnerClaim := canonicalTestValue('d', claimBytes)
	if _, err := storeA.Begin("user-1", "tenant-1", "device-1",
		sameOwnerClaim, canonicalTestValue('p', nonceBytes), now); err != nil {
		t.Fatalf("same-owner begin: %v", err)
	}
	if _, err := storeB.Confirm("device-1", sameOwnerClaim, now); err != nil {
		t.Fatalf("same-owner confirm: %v", err)
	}
	ownerAfterReclaim, found, err := storeA.Owner("device-1")
	if err != nil || !found || ownerAfterReclaim != owner {
		t.Fatalf("same-owner reclaim changed binding: before=%#v after=%#v err=%v",
			owner, ownerAfterReclaim, err)
	}
	released, err := storeA.Release("user-1", "tenant-1", "device-1", now)
	if err != nil || released.BindingRevision != 2 ||
		released.BindingID != owner.BindingID {
		t.Fatalf("release: %#v %v", released, err)
	}
	if _, found, err := storeB.Owner("device-1"); err != nil || found {
		t.Fatalf("released owner still resolved: found=%v err=%v", found, err)
	}
	if replayed, err := storeB.Release("user-1", "tenant-1", "device-1", now); err != nil || replayed != released {
		t.Fatalf("release replay: %#v %v", replayed, err)
	}
	rebindClaim := canonicalTestValue('e', claimBytes)
	if _, err := storeA.Begin("user-2", "tenant-2", "device-1", rebindClaim,
		canonicalTestValue('q', nonceBytes), now); err != nil {
		t.Fatalf("rebind begin: %v", err)
	}
	if _, err := storeB.Confirm("device-1", rebindClaim, now); err != nil {
		t.Fatalf("rebind confirm: %v", err)
	}
	rebound, found, err := storeA.Owner("device-1")
	if err != nil || !found || rebound.OwnerID != "user-2" ||
		rebound.TenantID != "tenant-2" || rebound.BindingRevision != 3 ||
		rebound.BindingID == owner.BindingID {
		t.Fatalf("rebound owner: %#v found=%v err=%v", rebound, found, err)
	}
	resolver, err := NewPostgresResolver(storeA.db, 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := resolver.Owners([]string{"device-1", "missing-device"})
	if err != nil || len(batch) != 1 || batch["device-1"] != rebound {
		t.Fatalf("batch owner resolution: %#v err=%v", batch, err)
	}
	if _, err := storeB.Begin("user-1", "tenant-2", "device-1",
		canonicalTestValue('b', claimBytes),
		canonicalTestValue('o', nonceBytes), now); !errors.Is(err, ErrConflict) {
		t.Fatalf("cross-tenant overwrite: %v", err)
	}

	concurrentClaim := canonicalTestValue('c', claimBytes)
	var group sync.WaitGroup
	var resultMu sync.Mutex
	successes := make([]string, 0, 16)
	for index := 0; index < 32; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			userID := "user-a"
			if index%2 == 1 {
				userID = "user-b"
			}
			nonceBytesValue := make([]byte, nonceBytes)
			nonceBytesValue[len(nonceBytesValue)-1] = byte(index)
			nonceValue := base64.RawURLEncoding.EncodeToString(nonceBytesValue)
			store := storeA
			if index%3 == 0 {
				store = storeB
			}
			if _, err := store.Begin(userID, "tenant-race", "device-race",
				concurrentClaim, nonceValue, now); err == nil {
				resultMu.Lock()
				successes = append(successes, userID)
				resultMu.Unlock()
			} else if !errors.Is(err, ErrConflict) {
				t.Errorf("unexpected race result: %v", err)
			}
		}(index)
	}
	group.Wait()
	if len(successes) == 0 {
		t.Fatal("serializable race produced no winning intent")
	}
	for _, userID := range successes[1:] {
		if userID != successes[0] {
			t.Fatalf("multiple race winners: %v", successes)
		}
	}
	if _, err := storeB.Confirm("device-race", concurrentClaim, now); err != nil {
		t.Fatal(err)
	}
	raceOwner, found, err := storeA.Owner("device-race")
	if err != nil || !found || raceOwner.OwnerID != successes[0] ||
		raceOwner.TenantID != "tenant-race" {
		t.Fatalf("race owner: %#v %v %v winners=%v",
			raceOwner, found, err, successes)
	}

	var rawClaimMatches int
	if err := storeA.db.QueryRowContext(ctx, `
SELECT count(*) FROM ownership_claims
WHERE request_id = $1 OR device_id = $1 OR owner_id = $1 OR tenant_id = $1`,
		claim).Scan(&rawClaimMatches); err != nil {
		t.Fatal(err)
	}
	if rawClaimMatches != 0 {
		t.Fatal("raw claim crossed the durable storage boundary")
	}
	if _, err := storeA.db.ExecContext(ctx, `
UPDATE ownership_claims
SET expires_at = CURRENT_TIMESTAMP - INTERVAL '2 minutes'`); err != nil {
		t.Fatal(err)
	}
	if err := storeA.Prune(now.Add(3 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	var events, claims int
	if err := storeA.db.QueryRowContext(ctx,
		`SELECT count(*) FROM device_ownership_events`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := storeA.db.QueryRowContext(ctx,
		`SELECT count(*) FROM ownership_claims`).Scan(&claims); err != nil {
		t.Fatal(err)
	}
	if events != 4 || claims != 0 {
		t.Fatalf("audit retention after prune: events=%d claims=%d", events, claims)
	}
}

func canonicalTestValue(fill byte, size int) string {
	return base64.RawURLEncoding.EncodeToString(
		[]byte(strings.Repeat(string([]byte{fill}), size)))
}
