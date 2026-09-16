package runtimecoordination

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestDigestDomainsAndCanonicalInputs(t *testing.T) {
	leftRaw, leftText, err := subjectDigest("proof", "device-1")
	if err != nil || len(leftRaw) != 32 || len(leftText) != 64 ||
		strings.Contains(leftText, "device-1") {
		t.Fatalf("subject digest: %x %q %v", leftRaw, leftText, err)
	}
	rightRaw, rightText, err := subjectDigest("voice-lease", "device-1")
	if err != nil || string(leftRaw) == string(rightRaw) || leftText == rightText {
		t.Fatal("subject digest was not domain separated")
	}
	nonce := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	nonceDigest, err := proofNonceDigest(nonce)
	if err != nil || len(nonceDigest) != 32 || strings.Contains(
		string(nonceDigest), nonce) {
		t.Fatalf("proof nonce digest: %x %v", nonceDigest, err)
	}
	if _, err := proofNonceDigest(nonce + "="); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-canonical nonce: %v", err)
	}
	token, err := tokenDigest("voice-token-1")
	if err != nil || len(token) != 32 {
		t.Fatalf("token digest: %x %v", token, err)
	}
}

func TestPostgresCoordinatorConfigurationAndFailClosedInputs(t *testing.T) {
	database := &sql.DB{}
	for _, testCase := range []struct {
		name    string
		db      *sql.DB
		holder  string
		timeout time.Duration
	}{
		{"nil database", nil, "worker-1", time.Second},
		{"invalid holder", database, "worker id", time.Second},
		{"short timeout", database, "worker-1", 99 * time.Millisecond},
		{"long timeout", database, "worker-1", 31 * time.Second},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewPostgresCoordinator(testCase.db, testCase.holder,
				testCase.timeout); err == nil {
				t.Fatal("invalid coordinator accepted")
			}
		})
	}
	coordinator, err := NewPostgresCoordinator(database, "worker-1", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	nonce := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	if err := coordinator.ReserveProof(nil, 1, "device-1", nonce,
		time.Minute, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil proof context: %v", err)
	}
	if _, err := coordinator.AcquireVoice(context.Background(), "device-1", 0,
		30*time.Second); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero voice maximum: %v", err)
	}
	if _, err := coordinator.AcquireAgent(context.Background(), "device-1", 0,
		1, 30*time.Second); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero Agent rate: %v", err)
	}
	var nilCoordinator *PostgresCoordinator
	if err := nilCoordinator.VerifySchema(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil schema verification: %v", err)
	}
	if err := nilCoordinator.Release(context.Background(), Lease{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil release: %v", err)
	}
}

func TestRetryAndUnavailableErrorClassification(t *testing.T) {
	if !retryable(&pgconn.PgError{Code: "40001"}) ||
		!retryable(&pgconn.PgError{Code: "40P01"}) ||
		retryable(&pgconn.PgError{Code: "23505"}) {
		t.Fatal("PostgreSQL retry classification changed")
	}
	err := unavailable("coordinate request", errors.New("postgres://secret"))
	if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("database detail crossed error boundary: %v", err)
	}
}
