package speechbudget

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestPostgresLedgerCrossReplicaIntegration(t *testing.T) {
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
	schema := "xz_speech_budget_test_" + hex.EncodeToString(rawSchema)
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
	for _, name := range []string{"0001_ownership.sql", "0007_speech_usage_budget.sql"} {
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
	pricingA := testPricing()
	pricingA.DailyBudgetMicrousd = 30_000
	key := []byte("0123456789abcdef0123456789abcdef")
	ledgerA, err := NewPostgresLedger(openDatabase(), pricingA, key,
		10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledgerA.VerifySchema(ctx); err != nil {
		t.Fatal(err)
	}
	stt, err := ledgerA.Reserve(ctx, "raw-owned-scope", STTUsage(6_000))
	if err != nil {
		t.Fatal(err)
	}
	settlement, err := ledgerA.Settle(ctx, stt, STTUsage(3_000))
	if err != nil || settlement.CostMicrousd != 3_000 {
		t.Fatalf("STT settlement=%#v err=%v", settlement, err)
	}

	pricingB := pricingA
	pricingB.ProfileID = "speech-provider-contract-2"
	ledgerB, err := NewPostgresLedger(openDatabase(), pricingB, key,
		10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	tts, err := ledgerB.Reserve(ctx, "raw-owned-scope", TTSUsage(2_000, 10_000))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledgerA.Reserve(ctx, "raw-owned-scope", STTUsage(6_000)); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("cross-profile speech budget: %v", err)
	}
	if _, err := ledgerB.MarkUncertain(ctx, tts); err != nil {
		t.Fatal(err)
	}

	abandoned, err := ledgerA.Reserve(ctx, "expiry-scope", STTUsage(6_000))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledgerA.db.ExecContext(ctx, `
UPDATE speech_usage_reservations
SET expires_at = CURRENT_TIMESTAMP - INTERVAL '1 second'
WHERE reservation_id = $1`, abandoned.ID[:]); err != nil {
		t.Fatal(err)
	}
	trigger, err := ledgerB.Reserve(ctx, "cleanup-trigger", STTUsage(6_000))
	if err != nil {
		t.Fatal(err)
	}
	if err := ledgerB.Release(ctx, trigger); err != nil {
		t.Fatal(err)
	}
	var uncertain, reserved int64
	if err := ledgerA.db.QueryRowContext(ctx, `
SELECT uncertain_cost_microusd, reserved_cost_microusd
FROM speech_usage_budget_daily
WHERE subject_hmac = $1`, ledgerA.subjectHMAC("expiry-scope")).
		Scan(&uncertain, &reserved); err != nil {
		t.Fatal(err)
	}
	if uncertain != 6_000 || reserved != 0 {
		t.Fatalf("expired reservation uncertain=%d reserved=%d", uncertain, reserved)
	}

	changedPricing := pricingA
	changedPricing.STTMicrousdPerMillionAudioMS++
	changed, err := NewPostgresLedger(openDatabase(), changedPricing, key,
		10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := changed.Reserve(ctx, "new-scope", STTUsage(6_000)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("reused speech profile changed rates: %v", err)
	}

	var storedSubject []byte
	if err := ledgerA.db.QueryRowContext(ctx, `
SELECT subject_hmac FROM speech_usage_budget_daily
WHERE subject_hmac = $1`, ledgerA.subjectHMAC("raw-owned-scope")).
		Scan(&storedSubject); err != nil {
		t.Fatal(err)
	}
	if len(storedSubject) != 32 || string(storedSubject) == "raw-owned-scope" {
		t.Fatal("raw owned scope crossed the speech storage boundary")
	}
}
