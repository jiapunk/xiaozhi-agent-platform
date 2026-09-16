package actionconsent

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresActionConsentStoreIntegration(t *testing.T) {
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
	schema := "xz_action_consent_test_" + hex.EncodeToString(rawSchema)
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

	migrationConfig := adminConfig.Copy()
	migrationConfig.RuntimeParams["search_path"] = schema
	migrationConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	migrationConnection, err := pgx.ConnectConfig(ctx, migrationConfig)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"0001_ownership.sql", "0002_action_consent.sql",
		"0003_action_consent_wake_outbox.sql",
	} {
		migration, err := os.ReadFile(filepath.Join("..", "..", "migrations",
			"ownership", name))
		if err != nil {
			_ = migrationConnection.Close(context.Background())
			t.Fatal(err)
		}
		if _, err := migrationConnection.Exec(ctx, string(migration)); err != nil {
			_ = migrationConnection.Close(context.Background())
			t.Fatalf("apply %s: %v", name, err)
		}
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
	storeA, err := NewPostgresStore(openDatabase(), 128, 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	storeB, err := NewPostgresStore(openDatabase(), 128, 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := storeA.VerifySchema(); err != nil {
		t.Fatal(err)
	}
	if _, err := storeA.db.ExecContext(ctx, `
INSERT INTO device_owners
    (device_id, tenant_id, owner_id, binding_id, binding_revision, status, bound_at)
VALUES ('device-1', 'tenant-1', 'user-1', $1, 7, 'active', CURRENT_TIMESTAMP)`,
		"QmluZGluZ0lEMDEyMzQ1Ng"); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	challenge := testChallenge(now)
	if err := storeA.Register(challenge, now); err != nil {
		t.Fatalf("cross-replica register: %v", err)
	}
	wake, found, err := storeB.ClaimWake(
		"notifier-1", now, 5*time.Second)
	if err != nil || !found || wake.WakeID != challenge.ChallengeID ||
		wake.Target != testActor() || wake.Attempts != 1 ||
		!wake.ExpiresAt.Equal(challenge.ExpiresAt) {
		t.Fatalf("cross-replica wake: %#v found=%t err=%v", wake, found, err)
	}
	if err := storeA.RetryWake("notifier-1", wake.WakeID, now,
		time.Second); err != nil {
		t.Fatalf("cross-replica wake retry: %v", err)
	}
	if _, found, err := storeB.ClaimWake(
		"notifier-2", now, 5*time.Second); err != nil || found {
		t.Fatalf("wake claimed before retry: found=%t err=%v", found, err)
	}
	wake, found, err = storeB.ClaimWake(
		"notifier-2", now.Add(time.Second), 5*time.Second)
	if err != nil || !found || wake.Attempts != 2 {
		t.Fatalf("retried wake: %#v found=%t err=%v", wake, found, err)
	}
	if err := storeA.AcknowledgeWake(
		"notifier-2", wake.WakeID, now.Add(time.Second)); err != nil {
		t.Fatalf("cross-replica wake acknowledge: %v", err)
	}
	pending, found, err := storeB.Pending(testActor(), now)
	if err != nil || !found || pending.Challenge != challenge {
		t.Fatalf("cross-replica inbox: %#v found=%t err=%v",
			pending, found, err)
	}
	if _, err := storeB.Consume(testDeviceRequest(), now); !errors.Is(err, ErrPending) {
		t.Fatalf("pending consume: %v", err)
	}
	mutated := testDeviceRequest()
	mutated.Action.IndicatorOn = false
	if _, err := storeB.Consume(mutated, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("mutated consume: %v", err)
	}
	decided, err := storeB.Decide(testActor(), testRequest(), now)
	if err != nil || decided.Decision != DecisionApprove {
		t.Fatalf("cross-replica decide: %#v %v", decided, err)
	}
	if _, found, err := storeA.Pending(testActor(), now); err != nil || found {
		t.Fatalf("decided challenge remained in inbox: found=%t err=%v", found, err)
	}
	consumed, err := storeA.Consume(testDeviceRequest(), now)
	if err != nil || consumed.Decision != DecisionApprove || consumed.ConsumedAt.IsZero() {
		t.Fatalf("cross-replica consume: %#v %v", consumed, err)
	}
	if _, err := storeB.Consume(testDeviceRequest(), now); !errors.Is(err, ErrReplay) {
		t.Fatalf("consume replay: %v", err)
	}

	raceChallenge := testChallenge(now)
	raceChallenge.ChallengeID = "YWJjZGVmZ2hpamtsbW5vcA"
	raceChallenge.SessionID = "session-2"
	raceChallenge.RequestID = 43
	if err := storeA.Register(raceChallenge, now); err != nil {
		t.Fatal(err)
	}
	var decisionWinners atomic.Int32
	var wait sync.WaitGroup
	for index := 0; index < 8; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			request := testRequest()
			request.ChallengeID = raceChallenge.ChallengeID
			request.SessionID = raceChallenge.SessionID
			request.RequestID = raceChallenge.RequestID
			if index%2 != 0 {
				request.Decision = DecisionDeny
			}
			store := storeA
			if index%2 != 0 {
				store = storeB
			}
			if _, err := store.Decide(testActor(), request, now); err == nil {
				decisionWinners.Add(1)
			} else if !errors.Is(err, ErrReplay) {
				t.Errorf("concurrent decision: %v", err)
			}
		}(index)
	}
	wait.Wait()
	if decisionWinners.Load() != 1 {
		t.Fatalf("decision winners=%d, want 1", decisionWinners.Load())
	}

	deviceRequest := testDeviceRequest()
	deviceRequest.ChallengeID = raceChallenge.ChallengeID
	deviceRequest.SessionID = raceChallenge.SessionID
	deviceRequest.RequestID = raceChallenge.RequestID
	var consumeWinners atomic.Int32
	for index := 0; index < 8; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			store := storeA
			if index%2 != 0 {
				store = storeB
			}
			if _, err := store.Consume(deviceRequest, now); err == nil {
				consumeWinners.Add(1)
			} else if !errors.Is(err, ErrReplay) {
				t.Errorf("concurrent consume: %v", err)
			}
		}(index)
	}
	wait.Wait()
	if consumeWinners.Load() != 1 {
		t.Fatalf("consume winners=%d, want 1", consumeWinners.Load())
	}

	staleChallenge := testChallenge(now)
	staleChallenge.ChallengeID = "cXdlcnR5dWlvcGFzZGZnaA"
	staleChallenge.SessionID = "session-3"
	staleChallenge.RequestID = 44
	if err := storeA.Register(staleChallenge, now); err != nil {
		t.Fatal(err)
	}
	if _, err := storeB.db.ExecContext(ctx, `
UPDATE device_owners
SET status = 'released', binding_revision = 8
WHERE device_id = 'device-1'`); err != nil {
		t.Fatal(err)
	}
	staleRequest := testRequest()
	staleRequest.ChallengeID = staleChallenge.ChallengeID
	staleRequest.SessionID = staleChallenge.SessionID
	staleRequest.RequestID = staleChallenge.RequestID
	if _, err := storeA.Decide(testActor(), staleRequest, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("released ownership accepted App decision: %v", err)
	}
	staleDeviceRequest := testDeviceRequest()
	staleDeviceRequest.ChallengeID = staleChallenge.ChallengeID
	staleDeviceRequest.SessionID = staleChallenge.SessionID
	staleDeviceRequest.RequestID = staleChallenge.RequestID
	if _, err := storeB.Consume(staleDeviceRequest, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("released ownership delivered decision: %v", err)
	}
}
