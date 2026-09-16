package factorytime

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
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

func TestPostgresFactoryTimeIntegration(t *testing.T) {
	databaseURL := os.Getenv("FACTORY_TIME_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("FACTORY_TIME_TEST_DATABASE_URL is not configured")
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
	schema := "xz_factory_time_test_" + hex.EncodeToString(rawSchema)
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
		"factorytime", "0001_factory_trusted_time.sql"))
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
		database.SetMaxOpenConns(16)
		database.SetMaxIdleConns(4)
		t.Cleanup(func() { _ = database.Close() })
		return database
	}
	databaseA := openDatabase()
	databaseB := openDatabase()
	storeA, _ := NewPostgresStore(databaseA, 10*time.Second)
	storeB, _ := NewPostgresStore(databaseB, 10*time.Second)
	if err := storeA.VerifySchema(); err != nil {
		t.Fatal(err)
	}

	certificateDER := []byte("M61 integration station certificate DER")
	certificateDigest := sha256.Sum256(certificateDER)
	if _, err := databaseA.ExecContext(ctx, `
INSERT INTO factory_time_stations (
    station_id, fixture_id, fixture_version,
    client_certificate_sha256, enabled
) VALUES ($1, $2, $3, $4, TRUE)`,
		"station-1", "fixture-1", "v1", certificateDigest[:]); err != nil {
		t.Fatal(err)
	}

	request := fixtureRequest(time.Now().UTC().Truncate(time.Second))
	reservation := reservationForTest(t, request, certificateDER)
	var successes, replays, other atomic.Int32
	var wait sync.WaitGroup
	for index := 0; index < 16; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			store := storeA
			if index%2 == 1 {
				store = storeB
			}
			_, err := store.Reserve(ctx, reservation, 5*time.Second)
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, ErrReplay):
				replays.Add(1)
			default:
				other.Add(1)
			}
		}(index)
	}
	wait.Wait()
	if successes.Load() != 1 || replays.Load() != 15 || other.Load() != 0 {
		t.Fatalf("race success=%d replay=%d other=%d", successes.Load(),
			replays.Load(), other.Load())
	}
	var rows int
	if err := databaseA.QueryRowContext(ctx,
		`SELECT count(*) FROM factory_trusted_time_requests`).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("ledger rows=%d err=%v", rows, err)
	}
	rawNonce, _ := base64.RawURLEncoding.DecodeString(request.NonceB64URL)
	var rawNonceRows int
	if err := databaseA.QueryRowContext(ctx, `
SELECT count(*) FROM factory_trusted_time_requests WHERE nonce_sha256 = $1`,
		rawNonce).Scan(&rawNonceRows); err != nil || rawNonceRows != 0 {
		t.Fatalf("raw nonce crossed database boundary: count=%d err=%v",
			rawNonceRows, err)
	}

	// A fresh request/nonce for the same sacrificial attempt is permitted after
	// transport or signer failure; the local M59 ledger still limits actual
	// attempt consumption to one winner.
	fresh := request
	fresh.RequestID = "time-fedcba9876543210fedcba9876543210"
	fresh.NonceB64URL = base64.RawURLEncoding.EncodeToString(bytes32(7))
	freshObserved, err := storeA.Reserve(ctx, reservationForTest(t, fresh,
		certificateDER), 5*time.Second)
	if err != nil {
		t.Fatalf("fresh ticket for same attempt: %v", err)
	}
	requestBody, _ := CanonicalJSON(fresh)
	requestDigest := sha256.Sum256(requestBody)
	receipt := Receipt{
		Schema: ReceiptSchema, Environment: Environment, Scope: Scope,
		RequestSHA256: hex.EncodeToString(requestDigest[:]),
		RequestID:     fresh.RequestID, NonceB64URL: fresh.NonceB64URL,
		Ledger: fresh.Ledger, Authorization: fresh.Authorization,
		Transaction: fresh.Transaction, Station: fresh.Station,
		AuthorityKeyID: "factory-time-key-1",
		ObservedAt: freshObserved.UTC().Truncate(time.Second).
			Format("2006-01-02T15:04:05Z"),
		ExpiresAt: freshObserved.UTC().Truncate(time.Second).Add(5 * time.Second).
			Format("2006-01-02T15:04:05Z"),
		Result: ReceiptResult, SignatureAlgorithm: SignatureAlgorithm,
	}
	signerAuthorizer, err := NewPostgresSignerAuthorizer(databaseB,
		10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := signerAuthorizer.VerifySchema(); err != nil {
		t.Fatal(err)
	}
	if err := signerAuthorizer.AuthorizeSigning(ctx, receipt); err != nil {
		t.Fatalf("committed receipt not authorized for signer: %v", err)
	}
	tamperedReceipt := receipt
	tamperedReceipt.RequestID = "time-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := signerAuthorizer.AuthorizeSigning(ctx, tamperedReceipt); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("tampered receipt signer authorization: %v", err)
	}

	unauthorized := fresh
	unauthorized.RequestID = "time-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	unauthorized.NonceB64URL = base64.RawURLEncoding.EncodeToString(bytes32(8))
	unauthorized.Station.FixtureVersion = "v2"
	if _, err := storeA.Reserve(ctx, reservationForTest(t, unauthorized,
		certificateDER), 5*time.Second); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong fixture version: %v", err)
	}
}

func reservationForTest(t *testing.T, request Request,
	certificateDER []byte) Reservation {
	t.Helper()
	body, err := CanonicalJSON(request)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := base64.RawURLEncoding.DecodeString(request.NonceB64URL)
	if err != nil {
		t.Fatal(err)
	}
	return Reservation{Request: request, RequestSHA256: sha256.Sum256(body),
		NonceSHA256:             sha256.Sum256(nonce),
		ClientCertificateSHA256: sha256.Sum256(certificateDER),
		AuthorityKeyID:          "factory-time-key-1"}
}

func bytes32(value byte) []byte {
	output := make([]byte, 32)
	for index := range output {
		output[index] = value
	}
	return output
}
