package factorytime

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

const (
	postgresSchemaVersion  = 1
	postgresSchemaContract = "xz-factory-time-db-v1-20260810"
	maximumDBAttempts      = 4
)

type PostgresStore struct {
	db               *sql.DB
	operationTimeout time.Duration
}

var _ Store = (*PostgresStore)(nil)

func NewPostgresStore(database *sql.DB,
	operationTimeout time.Duration) (*PostgresStore, error) {
	if database == nil || operationTimeout < 100*time.Millisecond ||
		operationTimeout > 30*time.Second {
		return nil, ErrInvalid
	}
	return &PostgresStore{db: database,
		operationTimeout: operationTimeout}, nil
}

// VerifySchema is a startup gate. The serving identity never applies schema
// migrations or enrolls stations.
func (store *PostgresStore) VerifySchema() error {
	if store == nil || store.db == nil {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(),
		store.operationTimeout)
	defer cancel()
	if err := store.db.PingContext(ctx); err != nil {
		return unavailable("ping factory-time database", err)
	}
	var version int
	var contract string
	if err := store.db.QueryRowContext(ctx, `
SELECT version, contract_id
FROM xz_factory_time_schema WHERE singleton = TRUE`).
		Scan(&version, &contract); err != nil {
		return unavailable("read factory-time schema", err)
	}
	if version != postgresSchemaVersion || contract != postgresSchemaContract {
		return unavailable("verify factory-time schema", ErrUnavailable)
	}
	return nil
}

func (store *PostgresStore) Reserve(ctx context.Context,
	reservation Reservation, receiptLifetime time.Duration) (time.Time, error) {
	if store == nil || store.db == nil || !validReservation(reservation) ||
		receiptLifetime < time.Second ||
		receiptLifetime > MaximumReceiptSeconds*time.Second ||
		receiptLifetime%time.Second != 0 {
		return time.Time{}, ErrInvalid
	}
	operationContext, cancel := context.WithTimeout(ctx, store.operationTimeout)
	defer cancel()
	var lastErr error
	for attempt := 0; attempt < maximumDBAttempts; attempt++ {
		tx, err := store.db.BeginTx(operationContext,
			&sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			return time.Time{}, unavailable("begin factory-time transaction", err)
		}
		observedAt, err := reserveTransaction(operationContext, tx,
			reservation, receiptLifetime)
		if err == nil {
			err = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
		if err == nil {
			return observedAt, nil
		}
		if postgresUniqueViolation(err) {
			return time.Time{}, ErrReplay
		}
		if businessError(err) {
			return time.Time{}, err
		}
		lastErr = err
		if !postgresRetryable(err) || operationContext.Err() != nil {
			break
		}
	}
	return time.Time{}, unavailable("factory-time transaction", lastErr)
}

func reserveTransaction(ctx context.Context, tx *sql.Tx,
	reservation Reservation, receiptLifetime time.Duration) (time.Time, error) {
	var databaseNow time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).
		Scan(&databaseNow); err != nil {
		return time.Time{}, err
	}
	databaseNow = databaseNow.UTC()
	observedAt := databaseNow.Truncate(time.Second)
	planIssued, _ := parseTimestamp(reservation.Request.Authorization.IssuedAt)
	planExpires, _ := parseTimestamp(reservation.Request.Authorization.ExpiresAt)
	if databaseNow.Before(planIssued) || databaseNow.After(planExpires) {
		return time.Time{}, ErrOutsideWindow
	}
	var fixtureID, fixtureVersion string
	var enrolledCertificate []byte
	var enabled bool
	err := tx.QueryRowContext(ctx, `
SELECT fixture_id, fixture_version, client_certificate_sha256, enabled
FROM factory_time_stations
WHERE station_id = $1
FOR SHARE`, reservation.Request.Station.ID).
		Scan(&fixtureID, &fixtureVersion, &enrolledCertificate, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, ErrUnauthorized
	}
	if err != nil {
		return time.Time{}, err
	}
	if !enabled || fixtureID != reservation.Request.Station.FixtureID ||
		fixtureVersion != reservation.Request.Station.FixtureVersion ||
		!equalDigest(enrolledCertificate,
			reservation.ClientCertificateSHA256[:]) {
		return time.Time{}, ErrUnauthorized
	}
	policyDigest, err := hex.DecodeString(reservation.Request.Ledger.PolicySHA256)
	if err != nil || len(policyDigest) != sha256.Size {
		return time.Time{}, ErrInvalid
	}
	planDigest, err := hex.DecodeString(reservation.Request.Authorization.PlanSHA256)
	if err != nil || len(planDigest) != sha256.Size {
		return time.Time{}, ErrInvalid
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO factory_trusted_time_requests (
    request_sha256, request_id, nonce_sha256,
    station_id, fixture_id, fixture_version,
    client_certificate_sha256,
    policy_sha256, policy_id, ledger_id,
	plan_sha256, plan_id, authorization_issued_at, authorization_expires_at,
	attempt_id, device_id, base_mac, authority_key_id,
    observed_at, receipt_expires_at
) VALUES (
    $1, $2, $3,
    $4, $5, $6,
    $7,
    $8, $9, $10,
	$11, $12, $13, $14,
	$15, $16, $17, $18,
	$19, $20
)`,
		reservation.RequestSHA256[:], reservation.Request.RequestID,
		reservation.NonceSHA256[:], reservation.Request.Station.ID,
		reservation.Request.Station.FixtureID,
		reservation.Request.Station.FixtureVersion,
		reservation.ClientCertificateSHA256[:],
		policyDigest,
		reservation.Request.Ledger.PolicyID,
		reservation.Request.Ledger.LedgerID,
		planDigest,
		reservation.Request.Authorization.PlanID,
		planIssued, planExpires,
		reservation.Request.Transaction.AttemptID,
		reservation.Request.Transaction.DeviceID,
		reservation.Request.Transaction.BaseMAC,
		reservation.AuthorityKeyID,
		observedAt, observedAt.Add(receiptLifetime))
	if err != nil {
		return time.Time{}, err
	}
	return observedAt, nil
}

func validReservation(reservation Reservation) bool {
	if ValidateRequest(reservation.Request) != nil ||
		!validIdentifier(reservation.AuthorityKeyID) {
		return false
	}
	canonical, err := CanonicalJSON(reservation.Request)
	if err != nil || sha256.Sum256(canonical) != reservation.RequestSHA256 {
		return false
	}
	nonce, err := base64.RawURLEncoding.DecodeString(
		reservation.Request.NonceB64URL)
	return err == nil && sha256.Sum256(nonce) == reservation.NonceSHA256
}

func postgresRetryable(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) &&
		(postgresError.Code == "40001" || postgresError.Code == "40P01")
}

func postgresUniqueViolation(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && postgresError.Code == "23505"
}

func unavailable(operation string, err error) error {
	if err == nil {
		err = ErrUnavailable
	}
	return fmt.Errorf("%w: %s: %v", ErrUnavailable, operation, err)
}
