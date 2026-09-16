package databasequalification

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestManagedDatabaseURLRequiresRemoteVerifyFullAndBoundedOptions(t *testing.T) {
	valid := "postgresql://qualifier:secret@db.example.com:5432/product?" +
		"sslmode=verify-full&sslrootcert=%2Frun%2Ftrust%2Fdb.pem&" +
		"connect_timeout=5&application_name=m73-qualifier"
	if !validManagedDatabaseURL(valid) {
		t.Fatal("valid managed PostgreSQL URL rejected")
	}
	for _, invalid := range []string{
		"postgresql://user:secret@db.example.com/product",
		"postgresql://user:secret@db.example.com/product?sslmode=require",
		"postgresql://user:secret@localhost/product?sslmode=verify-full",
		"postgresql://user:secret@127.0.0.1/product?sslmode=verify-full",
		"postgresql://user:secret@db.example.com/product?sslmode=verify-full&sslmode=verify-full",
		"postgresql://user:secret@db.example.com/product?sslmode=verify-full&connect_timeout=00",
		"postgresql://user:secret@db.example.com/product?sslmode=verify-full&connect_timeout=abc",
		"postgresql://user:secret@db.example.com/product?sslmode=verify-full&statement_timeout=1",
		"postgresql://user:secret@db.example.com/product?sslmode=verify-full&sslrootcert=relative.pem",
	} {
		if validManagedDatabaseURL(invalid) {
			t.Fatalf("unsafe database URL accepted: %s", invalid)
		}
	}
}

func TestExactDatabaseRolesAndSchemaContracts(t *testing.T) {
	if !equalRoles([]Role{RoleOwnership, RoleAccountAuthorization,
		RoleFactoryTimeAuthority}) || equalRoles([]Role{RoleOwnership}) {
		t.Fatal("exact database role set changed")
	}
	expectedChecks := map[Role]int{
		RoleOwnership: 3, RoleAccountAuthorization: 3,
		RoleFactoryTimeAuthority: 1,
	}
	for role, count := range expectedChecks {
		checks, err := roleSchemaChecks(role)
		if err != nil || len(checks) != count {
			t.Fatalf("role=%s checks=%v err=%v", role, checks, err)
		}
	}
	if _, err := roleSchemaChecks("unknown"); err == nil {
		t.Fatal("unknown database role accepted")
	}
}

func TestEventInputsAndExactReconciliation(t *testing.T) {
	nonce := make([]byte, 16)
	digest := strings.Repeat("a", 64)
	if _, err := decodeEventInput("m73-run-1", nonce, 1, PhasePre,
		digest); err != nil {
		t.Fatal(err)
	}
	for _, testCase := range []struct {
		id       string
		nonce    []byte
		sequence uint64
		phase    Phase
		digest   string
	}{
		{"bad id!", nonce, 1, PhasePre, digest},
		{"m73-run-1", nonce[:15], 1, PhasePre, digest},
		{"m73-run-1", nonce, 0, PhasePre, digest},
		{"m73-run-1", nonce, maximumEventSequence + 1, PhasePre, digest},
		{"m73-run-1", nonce, 1, "unknown", digest},
		{"m73-run-1", nonce, 1, PhasePre, strings.Repeat("A", 64)},
	} {
		if _, err := decodeEventInput(testCase.id, testCase.nonce,
			testCase.sequence, testCase.phase, testCase.digest); err == nil {
			t.Fatalf("invalid event accepted: %+v", testCase)
		}
	}
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	expected := []Event{{Sequence: 1, Phase: PhasePre,
		PayloadSHA256: digest, CommittedAt: now}}
	actual := append([]Event(nil), expected...)
	actual[0].Existing = true
	if !EventsMatch(actual, expected) {
		t.Fatal("idempotently recovered event did not reconcile")
	}
	actual[0].PayloadSHA256 = strings.Repeat("b", 64)
	if EventsMatch(actual, expected) {
		t.Fatal("payload mismatch reconciled")
	}
}

func TestStoreConfigurationAndErrorsFailClosedWithoutLeakingDriverText(t *testing.T) {
	if _, err := NewStore(nil, RoleOwnership, time.Second); err == nil {
		t.Fatal("nil database accepted")
	}
	if _, err := NewStore(new(sql.DB), "unknown", time.Second); err == nil {
		t.Fatal("unknown role accepted")
	}
	store, err := NewStore(new(sql.DB), RoleOwnership, time.Second)
	if err != nil || store.Role() != RoleOwnership {
		t.Fatalf("store=%+v err=%v", store, err)
	}
	secret := errors.New("password=do-not-log")
	if err := unavailable("connect", secret); !errors.Is(err, ErrUnavailable) ||
		strings.Contains(err.Error(), "do-not-log") {
		t.Fatalf("unavailable error leaked driver text: %v", err)
	}
	conflict := databaseError("insert", &pgconn.PgError{Code: "23505",
		Message: "secret row"})
	if !errors.Is(conflict, ErrConflict) || strings.Contains(conflict.Error(), "secret") {
		t.Fatalf("conflict error leaked database text: %v", conflict)
	}
}
