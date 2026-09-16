package accountauth

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestPostgresStoreConfigurationAndErrorClassification(t *testing.T) {
	database := &sql.DB{}
	for _, testCase := range []struct {
		name    string
		db      *sql.DB
		timeout time.Duration
	}{
		{name: "nil database", db: nil, timeout: time.Second},
		{name: "short timeout", db: database, timeout: 99 * time.Millisecond},
		{name: "long timeout", db: database, timeout: 31 * time.Second},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewPostgresStore(testCase.db, testCase.timeout); err == nil {
				t.Fatal("invalid PostgreSQL configuration accepted")
			}
		})
	}
	if _, err := NewPostgresStore(database, 5*time.Second); err != nil {
		t.Fatalf("valid PostgreSQL configuration: %v", err)
	}
	serial := &pgconn.PgError{Code: "40001"}
	deadlock := &pgconn.PgError{Code: "40P01"}
	unique := &pgconn.PgError{Code: "23505"}
	other := &pgconn.PgError{Code: "22000"}
	if !postgresRetryable(serial) || !postgresRetryable(deadlock) ||
		postgresRetryable(unique) || postgresRetryable(other) {
		t.Fatal("retryable PostgreSQL classification changed")
	}
	if !postgresUniqueViolation(unique) || postgresUniqueViolation(serial) {
		t.Fatal("unique PostgreSQL classification changed")
	}
	for _, businessError := range []error{
		ErrInvalid, ErrNotFound, ErrConflict, ErrStaleSession, ErrSuspended,
		ErrInactive, ErrCapacity, ErrRevisionExhausted, ErrUnavailable,
	} {
		if !postgresBusinessError(businessError) {
			t.Fatalf("business error %v was not preserved", businessError)
		}
	}
	if postgresBusinessError(errors.New("database failure")) {
		t.Fatal("database error was classified as a business error")
	}
}

func TestNilPostgresStoreFailsClosed(t *testing.T) {
	var store *PostgresStore
	if err := store.VerifySchema(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil VerifySchema: %v", err)
	}
	if _, err := store.BeginAuthenticatedSession(nil, Principal{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil begin session: %v", err)
	}
	if _, _, err := store.Introspect(nil, TokenBinding{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil introspection: %v", err)
	}
	if err := store.PruneExpired(nil, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil prune: %v", err)
	}
}
