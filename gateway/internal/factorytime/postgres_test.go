package factorytime

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestPostgresConfigurationAndErrorClassification(t *testing.T) {
	if _, err := NewPostgresStore(nil, time.Second); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil database: %v", err)
	}
	for _, timeout := range []time.Duration{99 * time.Millisecond, 31 * time.Second} {
		if _, err := NewPostgresStore(new(sql.DB), timeout); !errors.Is(err, ErrInvalid) {
			t.Fatalf("timeout %s: %v", timeout, err)
		}
	}
	unique := &pgconn.PgError{Code: "23505"}
	serial := &pgconn.PgError{Code: "40001"}
	deadlock := &pgconn.PgError{Code: "40P01"}
	other := &pgconn.PgError{Code: "22000"}
	if !postgresUniqueViolation(unique) || postgresUniqueViolation(serial) ||
		!postgresRetryable(serial) || !postgresRetryable(deadlock) ||
		postgresRetryable(unique) || postgresRetryable(other) {
		t.Fatal("PostgreSQL error classification changed")
	}
}

func signerLedgerRecordForTest(t *testing.T, receipt Receipt) signerLedgerRecord {
	t.Helper()
	nonce, err := base64.RawURLEncoding.DecodeString(receipt.NonceB64URL)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := hex.DecodeString(receipt.Ledger.PolicySHA256)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := hex.DecodeString(receipt.Authorization.PlanSHA256)
	if err != nil {
		t.Fatal(err)
	}
	issued, _ := parseTimestamp(receipt.Authorization.IssuedAt)
	planExpires, _ := parseTimestamp(receipt.Authorization.ExpiresAt)
	observed, _ := parseTimestamp(receipt.ObservedAt)
	receiptExpires, _ := parseTimestamp(receipt.ExpiresAt)
	nonceDigest := sha256.Sum256(nonce)
	return signerLedgerRecord{
		RequestID: receipt.RequestID, NonceSHA256: nonceDigest[:],
		StationID: receipt.Station.ID, FixtureID: receipt.Station.FixtureID,
		FixtureVersion: receipt.Station.FixtureVersion,
		PolicySHA256:   policy, PolicyID: receipt.Ledger.PolicyID,
		LedgerID: receipt.Ledger.LedgerID, PlanSHA256: plan,
		PlanID:              receipt.Authorization.PlanID,
		AuthorizationIssued: issued, AuthorizationExpires: planExpires,
		AttemptID:      receipt.Transaction.AttemptID,
		DeviceID:       receipt.Transaction.DeviceID,
		BaseMAC:        receipt.Transaction.BaseMAC,
		AuthorityKeyID: receipt.AuthorityKeyID, ObservedAt: observed,
		ReceiptExpiresAt: receiptExpires,
		DatabaseNow:      observed.Add(time.Second),
	}
}

func TestSignerLedgerAuthorizationRequiresExactLiveCommittedRow(t *testing.T) {
	unsigned := unsignedReceiptForRemoteSigner(t, "factory-time-key-1")
	receipt, err := ParseUnsignedReceipt(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	record := signerLedgerRecordForTest(t, receipt)
	if err := validateSignerLedgerRecord(receipt, record); err != nil {
		t.Fatal(err)
	}
	mutations := []func(*signerLedgerRecord){
		func(item *signerLedgerRecord) { item.RequestID = "other-request" },
		func(item *signerLedgerRecord) { item.NonceSHA256 = make([]byte, 32) },
		func(item *signerLedgerRecord) { item.StationID = "other-station" },
		func(item *signerLedgerRecord) { item.FixtureVersion = "v2" },
		func(item *signerLedgerRecord) { item.PolicySHA256 = make([]byte, 32) },
		func(item *signerLedgerRecord) { item.LedgerID = "other-ledger" },
		func(item *signerLedgerRecord) { item.PlanSHA256 = make([]byte, 32) },
		func(item *signerLedgerRecord) { item.AttemptID = "other-attempt" },
		func(item *signerLedgerRecord) { item.DeviceID = "xz-ffeeddccbbaa" },
		func(item *signerLedgerRecord) { item.AuthorityKeyID = "other-key" },
		func(item *signerLedgerRecord) {
			item.ReceiptExpiresAt = item.ReceiptExpiresAt.Add(time.Second)
		},
	}
	for index, mutate := range mutations {
		candidate := record
		candidate.NonceSHA256 = append([]byte(nil), record.NonceSHA256...)
		candidate.PolicySHA256 = append([]byte(nil), record.PolicySHA256...)
		candidate.PlanSHA256 = append([]byte(nil), record.PlanSHA256...)
		mutate(&candidate)
		if err := validateSignerLedgerRecord(receipt, candidate); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("row mutation %d err=%v", index, err)
		}
	}
	for _, now := range []time.Time{
		record.ObservedAt.Add(-time.Nanosecond),
		record.ReceiptExpiresAt,
		record.AuthorizationExpires.Add(time.Nanosecond),
	} {
		candidate := record
		candidate.DatabaseNow = now
		if err := validateSignerLedgerRecord(receipt, candidate); !errors.Is(err, ErrOutsideWindow) {
			t.Fatalf("unsafe database time %s err=%v", now, err)
		}
	}
}

func TestPostgresSignerAuthorizerRejectsInvalidConfiguration(t *testing.T) {
	if _, err := NewPostgresSignerAuthorizer(nil, time.Second); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil database: %v", err)
	}
	for _, timeout := range []time.Duration{99 * time.Millisecond, 31 * time.Second} {
		if _, err := NewPostgresSignerAuthorizer(new(sql.DB), timeout); !errors.Is(err, ErrInvalid) {
			t.Fatalf("timeout %s: %v", timeout, err)
		}
	}
}

func TestPostgresStoreRejectsUnboundReservationBeforeDatabase(t *testing.T) {
	store, err := NewPostgresStore(new(sql.DB), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	request := fixtureRequest(time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC))
	reservation := Reservation{Request: request, AuthorityKeyID: "key-1"}
	if _, err := store.Reserve(context.Background(), reservation,
		5*time.Second); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unbound reservation reached database: %v", err)
	}
}
