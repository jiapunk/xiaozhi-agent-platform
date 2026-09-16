package runtimecoordination

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresCoordinatorMultiReplicaIntegration(t *testing.T) {
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
	schema := "xz_runtime_coord_test_" + hex.EncodeToString(rawSchema)
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cleanupCancel := context.WithTimeout(context.Background(),
			10*time.Second)
		defer cleanupCancel()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
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
	for _, name := range []string{"0001_ownership.sql", "0005_runtime_coordination.sql"} {
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
	databaseA, databaseB := openDatabase(), openDatabase()
	coordinatorA, err := NewPostgresCoordinator(databaseA, "replica-a", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	coordinatorB, err := NewPostgresCoordinator(databaseB, "replica-b", 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinatorA.VerifySchema(ctx); err != nil {
		t.Fatal(err)
	}

	nonceOne := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	nonceTwo := base64.RawURLEncoding.EncodeToString([]byte("fedcba9876543210"))
	if err := coordinatorA.ReserveProof(ctx, 1, "device-raw-1", nonceOne,
		time.Minute, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := coordinatorB.ReserveProof(ctx, 1, "device-raw-1", nonceOne,
		time.Minute, time.Minute); !errors.Is(err, ErrReplay) {
		t.Fatalf("cross-replica proof replay: %v", err)
	}
	if err := coordinatorB.ReserveProof(ctx, 1, "device-raw-1", nonceTwo,
		time.Minute, time.Minute); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("cross-replica proof cadence: %v", err)
	}
	if err := coordinatorA.ReserveProof(ctx, 1, "device-raw-1", nonceTwo,
		time.Minute, time.Minute); !errors.Is(err, ErrReplay) {
		t.Fatalf("rate-limited nonce was not retained: %v", err)
	}
	if err := coordinatorB.ReserveProof(ctx, 2, "device-raw-1", nonceOne,
		time.Minute, 0); err != nil {
		t.Fatalf("proof scope was not domain isolated: %v", err)
	}
	for index := 0; index < MaximumProofNonces; index++ {
		raw := make([]byte, 16)
		raw[14], raw[15] = byte(index>>8), byte(index)
		nonce := base64.RawURLEncoding.EncodeToString(raw)
		if err := coordinatorA.ReserveProof(ctx, 3, "proof-capacity-device",
			nonce, time.Minute, 0); err != nil {
			t.Fatalf("proof capacity nonce %d: %v", index, err)
		}
	}
	overflowRaw := make([]byte, 16)
	overflowRaw[14], overflowRaw[15] = 1, 1
	if err := coordinatorB.ReserveProof(ctx, 3, "proof-capacity-device",
		base64.RawURLEncoding.EncodeToString(overflowRaw), time.Minute, 0); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("proof capacity overflow: %v", err)
	}
	var retainedNonces int
	if err := databaseA.QueryRowContext(ctx, `
SELECT count(*) FROM runtime_coordination_proof_nonces
WHERE proof_scope = 3`).Scan(&retainedNonces); err != nil {
		t.Fatal(err)
	}
	if retainedNonces != MaximumProofNonces {
		t.Fatalf("proof tombstone capacity=%d, want %d",
			retainedNonces, MaximumProofNonces)
	}

	retainUntil := time.Now().UTC().Add(time.Hour)
	if err := coordinatorA.ConsumeVoiceToken(ctx, "owned-scope-raw",
		"token-raw-1", retainUntil); err != nil {
		t.Fatal(err)
	}
	if err := coordinatorB.ConsumeVoiceToken(ctx, "owned-scope-raw",
		"token-raw-1", retainUntil); !errors.Is(err, ErrReplay) {
		t.Fatalf("cross-replica voice token replay: %v", err)
	}

	voiceA, err := coordinatorA.AcquireVoice(ctx, "device-raw-1", 1,
		30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinatorB.AcquireVoice(ctx, "device-raw-1", 2,
		30*time.Second); !errors.Is(err, ErrConflict) {
		t.Fatalf("cross-replica voice ownership: %v", err)
	}
	if _, err := coordinatorB.AcquireVoice(ctx, "device-raw-2", 1,
		30*time.Second); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("cross-replica voice capacity: %v", err)
	}
	if _, err := databaseA.ExecContext(ctx, `
UPDATE runtime_coordination_leases SET expires_at = CURRENT_TIMESTAMP - INTERVAL '1 second'
WHERE lease_id = $1`, voiceA.LeaseID[:]); err != nil {
		t.Fatal(err)
	}
	voiceB, err := coordinatorB.AcquireVoice(ctx, "device-raw-1", 1,
		30*time.Second)
	if err != nil {
		t.Fatalf("expired voice takeover: %v", err)
	}
	if err := coordinatorA.Release(ctx, voiceA); !errors.Is(err, ErrLeaseLost) {
		t.Fatalf("stale voice release fencing: %v", err)
	}
	if _, err := coordinatorB.Renew(ctx, voiceB, 30*time.Second); err != nil {
		t.Fatalf("successor voice lease was deleted: %v", err)
	}
	if err := coordinatorB.Release(ctx, voiceB); err != nil {
		t.Fatal(err)
	}

	agentA, err := coordinatorA.AcquireAgent(ctx, "owned-agent-1", 2, 1,
		30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinatorB.AcquireAgent(ctx, "owned-agent-1", 2, 2,
		30*time.Second); !errors.Is(err, ErrConflict) {
		t.Fatalf("same-device Agent inflight: %v", err)
	}
	if _, err := coordinatorB.AcquireAgent(ctx, "owned-agent-2", 2, 1,
		30*time.Second); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("global Agent inflight: %v", err)
	}
	if err := coordinatorA.Release(ctx, agentA); err != nil {
		t.Fatal(err)
	}
	agentSecond, err := coordinatorB.AcquireAgent(ctx, "owned-agent-1", 2, 1,
		30*time.Second)
	if err != nil {
		t.Fatalf("second Agent request: %v", err)
	}
	if err := coordinatorB.Release(ctx, agentSecond); err != nil {
		t.Fatal(err)
	}
	if _, err := coordinatorA.AcquireAgent(ctx, "owned-agent-1", 2, 1,
		30*time.Second); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("cross-replica Agent rate: %v", err)
	}

	if _, err := databaseA.ExecContext(ctx, `
UPDATE runtime_coordination_proof_nonces
SET expires_at = CURRENT_TIMESTAMP - INTERVAL '1 second'
WHERE proof_scope = 1`); err != nil {
		t.Fatal(err)
	}
	if _, err := databaseA.ExecContext(ctx, `
UPDATE runtime_coordination_proof_limits
SET expires_at = CURRENT_TIMESTAMP - INTERVAL '1 second'
WHERE proof_scope = 1`); err != nil {
		t.Fatal(err)
	}
	cleanupNonce := base64.RawURLEncoding.EncodeToString(
		[]byte("cleanup-proof-01"))
	if err := coordinatorB.ReserveProof(ctx, 4, "cleanup-trigger-device",
		cleanupNonce, time.Minute, 0); err != nil {
		t.Fatal(err)
	}
	var expiredProofRows int
	if err := databaseA.QueryRowContext(ctx, `
SELECT
  (SELECT count(*) FROM runtime_coordination_proof_nonces WHERE proof_scope = 1) +
  (SELECT count(*) FROM runtime_coordination_proof_limits WHERE proof_scope = 1)`).
		Scan(&expiredProofRows); err != nil {
		t.Fatal(err)
	}
	if expiredProofRows != 0 {
		t.Fatalf("expired proof rows retained: %d", expiredProofRows)
	}
	oldVoiceSubject, _, _ := subjectDigest("voice-token", "owned-scope-raw")
	if _, err := databaseA.ExecContext(ctx, `
UPDATE runtime_coordination_voice_tokens
SET expires_at = CURRENT_TIMESTAMP - INTERVAL '1 second'`); err != nil {
		t.Fatal(err)
	}
	if err := coordinatorB.ConsumeVoiceToken(ctx, "cleanup-voice-scope",
		"cleanup-token", time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	var expiredVoiceRows int
	if err := databaseA.QueryRowContext(ctx, `
SELECT count(*) FROM runtime_coordination_voice_tokens
WHERE subject_sha256 = $1`, oldVoiceSubject).Scan(&expiredVoiceRows); err != nil {
		t.Fatal(err)
	}
	if expiredVoiceRows != 0 {
		t.Fatalf("expired voice token rows retained: %d", expiredVoiceRows)
	}
	oldAgentSubject, _, _ := subjectDigest("agent-lease", "owned-agent-1")
	if _, err := databaseA.ExecContext(ctx, `
UPDATE runtime_coordination_agent_limits
SET expires_at = CURRENT_TIMESTAMP - INTERVAL '1 second'`); err != nil {
		t.Fatal(err)
	}
	cleanupAgent, err := coordinatorA.AcquireAgent(ctx, "cleanup-agent", 2, 1,
		30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := coordinatorA.Release(ctx, cleanupAgent); err != nil {
		t.Fatal(err)
	}
	var expiredAgentRows int
	if err := databaseA.QueryRowContext(ctx, `
SELECT count(*) FROM runtime_coordination_agent_limits
WHERE subject_sha256 = $1`, oldAgentSubject).Scan(&expiredAgentRows); err != nil {
		t.Fatal(err)
	}
	if expiredAgentRows != 0 {
		t.Fatalf("expired Agent rate rows retained: %d", expiredAgentRows)
	}

	for _, raw := range []string{"device-raw-1", "owned-scope-raw",
		"token-raw-1", "owned-agent-1"} {
		var matches int
		if err := databaseA.QueryRowContext(ctx, `
SELECT
  (SELECT count(*) FROM runtime_coordination_leases WHERE holder_id = $1) +
  (SELECT count(*) FROM xz_runtime_coordination_schema WHERE contract_id = $1)`,
			raw).Scan(&matches); err != nil {
			t.Fatal(err)
		}
		if matches != 0 {
			t.Fatalf("raw coordination identity crossed storage boundary: %s", raw)
		}
	}
}
