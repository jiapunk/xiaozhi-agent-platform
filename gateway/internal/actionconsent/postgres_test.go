package actionconsent

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestPostgresStoreRejectsInvalidConfiguration(t *testing.T) {
	database := &sql.DB{}
	for _, testCase := range []struct {
		name    string
		db      *sql.DB
		maximum int
		timeout time.Duration
	}{
		{name: "nil database", db: nil, maximum: 1, timeout: time.Second},
		{name: "zero maximum", db: database, maximum: 0, timeout: time.Second},
		{name: "huge maximum", db: database, maximum: 100001, timeout: time.Second},
		{name: "short timeout", db: database, maximum: 1, timeout: 99 * time.Millisecond},
		{name: "long timeout", db: database, maximum: 1, timeout: 31 * time.Second},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewPostgresStore(testCase.db, testCase.maximum,
				testCase.timeout); err == nil {
				t.Fatal("invalid configuration was accepted")
			}
		})
	}
	if _, err := NewPostgresStore(database, 4096, 5*time.Second); err != nil {
		t.Fatalf("valid configuration: %v", err)
	}
}

func TestPostgresErrorClassification(t *testing.T) {
	serial := &pgconn.PgError{Code: "40001"}
	deadlock := &pgconn.PgError{Code: "40P01"}
	unique := &pgconn.PgError{Code: "23505"}
	other := &pgconn.PgError{Code: "22000"}
	if !postgresRetryable(serial) || !postgresRetryable(deadlock) ||
		postgresRetryable(unique) || postgresRetryable(other) {
		t.Fatal("retryable PostgreSQL error classification changed")
	}
	if !postgresUniqueViolation(unique) || postgresUniqueViolation(serial) {
		t.Fatal("unique PostgreSQL error classification changed")
	}
	for _, businessError := range []error{
		ErrInvalid, ErrReplay, ErrCapacity, ErrConflict, ErrNotFound,
		ErrExpired, ErrPending,
	} {
		if !postgresBusinessError(businessError) {
			t.Fatalf("business error %v was not preserved", businessError)
		}
	}
	if postgresBusinessError(errors.New("database failure")) {
		t.Fatal("database failure was classified as a business error")
	}
	if err := postgresUnavailable("test", nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unavailable wrapping: %v", err)
	}
}

func TestNilPostgresStoreFailsClosed(t *testing.T) {
	var store *PostgresStore
	now := time.Now().UTC()
	if err := store.VerifySchema(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil VerifySchema: %v", err)
	}
	if err := store.Register(testChallenge(now), now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil Register: %v", err)
	}
	if _, err := store.Decide(testActor(), testRequest(), now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil Decide: %v", err)
	}
	if _, found, err := store.Pending(testActor(), now); !errors.Is(err, ErrInvalid) || found {
		t.Fatalf("nil Pending: found=%t err=%v", found, err)
	}
	if _, err := store.Consume(testDeviceRequest(), now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil Consume: %v", err)
	}
}
