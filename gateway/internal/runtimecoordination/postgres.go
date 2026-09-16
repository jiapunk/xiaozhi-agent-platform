package runtimecoordination

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

const (
	ownershipSchemaVersion  = 3
	ownershipSchemaContract = "xz-owner-v3-20260809-lifecycle"
	maximumTokenRetention   = 2 * time.Hour
	maximumLeaseTTL         = 5 * time.Minute
	maximumTransactionTries = 4
)

type PostgresCoordinator struct {
	db               *sql.DB
	holderID         string
	operationTimeout time.Duration
	random           io.Reader
}

func NewPostgresCoordinator(database *sql.DB, holderID string,
	operationTimeout time.Duration) (*PostgresCoordinator, error) {
	if database == nil || !auth.ValidIdentifier(holderID, 64) ||
		operationTimeout < 100*time.Millisecond || operationTimeout > 30*time.Second {
		return nil, fmt.Errorf("invalid PostgreSQL runtime coordinator configuration")
	}
	return &PostgresCoordinator{db: database, holderID: holderID,
		operationTimeout: operationTimeout, random: rand.Reader}, nil
}

func (coordinator *PostgresCoordinator) VerifySchema(ctx context.Context) error {
	if coordinator == nil || coordinator.db == nil || ctx == nil {
		return ErrUnavailable
	}
	operation, cancel := context.WithTimeout(ctx, coordinator.operationTimeout)
	defer cancel()
	if err := coordinator.db.PingContext(operation); err != nil {
		return unavailable("ping coordination database", err)
	}
	checks := []struct {
		table    string
		version  int
		contract string
	}{
		{"xz_ownership_schema", ownershipSchemaVersion, ownershipSchemaContract},
		{"xz_runtime_coordination_schema", SchemaVersion, SchemaContract},
	}
	for _, check := range checks {
		var version int
		var contract string
		query := "SELECT version, contract_id FROM " + check.table +
			" WHERE singleton = TRUE"
		if err := coordinator.db.QueryRowContext(operation, query).
			Scan(&version, &contract); err != nil {
			return unavailable("read coordination schema", err)
		}
		if version != check.version || contract != check.contract {
			return ErrConflict
		}
	}
	return nil
}

func (coordinator *PostgresCoordinator) ReserveProof(ctx context.Context,
	scope uint8, subject, nonce string, maximumSkew,
	minimumInterval time.Duration) error {
	subjectRaw, _, subjectErr := subjectDigest("proof", subject)
	nonceRaw, nonceErr := proofNonceDigest(nonce)
	if coordinator == nil || coordinator.db == nil || ctx == nil ||
		scope < 1 || scope > 6 || subjectErr != nil || nonceErr != nil ||
		maximumSkew < 10*time.Second || maximumSkew > 5*time.Minute ||
		minimumInterval < 0 || minimumInterval > time.Minute {
		return ErrInvalid
	}
	return coordinator.serializable(ctx, func(operation context.Context,
		tx *sql.Tx) (error, error) {
		var databaseNow time.Time
		if err := tx.QueryRowContext(operation, `SELECT CURRENT_TIMESTAMP`).
			Scan(&databaseNow); err != nil {
			return nil, err
		}
		retention := 2 * maximumSkew
		if minimumInterval > retention {
			retention = minimumInterval
		}
		if _, err := tx.ExecContext(operation, `
DELETE FROM runtime_coordination_proof_nonces WHERE expires_at <= $1`,
			databaseNow); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(operation, `
DELETE FROM runtime_coordination_proof_limits WHERE expires_at <= $1`,
			databaseNow); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(operation, `
INSERT INTO runtime_coordination_proof_limits
    (proof_scope, subject_sha256, last_accepted_at, expires_at)
VALUES ($1, $2, NULL, $3)
ON CONFLICT (proof_scope, subject_sha256) DO NOTHING`,
			int(scope), subjectRaw, databaseNow.Add(retention)); err != nil {
			return nil, err
		}
		var last sql.NullTime
		if err := tx.QueryRowContext(operation, `
SELECT last_accepted_at FROM runtime_coordination_proof_limits
WHERE proof_scope = $1 AND subject_sha256 = $2 FOR UPDATE`,
			int(scope), subjectRaw).Scan(&last); err != nil {
			return nil, err
		}
		var replay bool
		if err := tx.QueryRowContext(operation, `
SELECT EXISTS (
    SELECT 1 FROM runtime_coordination_proof_nonces
    WHERE proof_scope = $1 AND subject_sha256 = $2 AND nonce_sha256 = $3
)`, int(scope), subjectRaw, nonceRaw).Scan(&replay); err != nil {
			return nil, err
		}
		if replay {
			return ErrReplay, nil
		}
		var active int
		if err := tx.QueryRowContext(operation, `
SELECT count(*) FROM runtime_coordination_proof_nonces
WHERE proof_scope = $1 AND subject_sha256 = $2 AND expires_at > $3`,
			int(scope), subjectRaw, databaseNow).Scan(&active); err != nil {
			return nil, err
		}
		if active >= MaximumProofNonces {
			return ErrRateLimited, nil
		}
		if _, err := tx.ExecContext(operation, `
INSERT INTO runtime_coordination_proof_nonces
    (proof_scope, subject_sha256, nonce_sha256, expires_at)
VALUES ($1, $2, $3, $4)`, int(scope), subjectRaw, nonceRaw,
			databaseNow.Add(2*maximumSkew)); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(operation, `
UPDATE runtime_coordination_proof_limits SET expires_at = $3
WHERE proof_scope = $1 AND subject_sha256 = $2`, int(scope), subjectRaw,
			databaseNow.Add(retention)); err != nil {
			return nil, err
		}
		/* Preserve the nonce when only the issuance cadence rejects it. */
		if last.Valid && databaseNow.Sub(last.Time) < minimumInterval {
			return ErrRateLimited, nil
		}
		if _, err := tx.ExecContext(operation, `
UPDATE runtime_coordination_proof_limits SET last_accepted_at = $3
WHERE proof_scope = $1 AND subject_sha256 = $2`,
			int(scope), subjectRaw, databaseNow); err != nil {
			return nil, err
		}
		return nil, nil
	})
}

func (coordinator *PostgresCoordinator) ConsumeVoiceToken(ctx context.Context,
	subject, tokenID string, retainUntil time.Time) error {
	subjectRaw, _, subjectErr := subjectDigest("voice-token", subject)
	tokenRaw, tokenErr := tokenDigest(tokenID)
	if coordinator == nil || coordinator.db == nil || ctx == nil ||
		subjectErr != nil || tokenErr != nil || retainUntil.IsZero() {
		return ErrInvalid
	}
	retainUntil = retainUntil.UTC()
	return coordinator.serializable(ctx, func(operation context.Context,
		tx *sql.Tx) (error, error) {
		var databaseNow time.Time
		if err := tx.QueryRowContext(operation, `SELECT CURRENT_TIMESTAMP`).
			Scan(&databaseNow); err != nil {
			return nil, err
		}
		if !retainUntil.After(databaseNow) ||
			retainUntil.After(databaseNow.Add(maximumTokenRetention)) {
			return ErrInvalid, nil
		}
		if _, err := tx.ExecContext(operation, `
DELETE FROM runtime_coordination_voice_tokens WHERE expires_at <= $1`,
			databaseNow); err != nil {
			return nil, err
		}
		result, err := tx.ExecContext(operation, `
INSERT INTO runtime_coordination_voice_tokens
    (subject_sha256, token_sha256, expires_at)
VALUES ($1, $2, $3)
ON CONFLICT (subject_sha256, token_sha256) DO NOTHING`,
			subjectRaw, tokenRaw, retainUntil)
		if err != nil {
			return nil, err
		}
		inserted, err := exactlyZeroOrOne(result)
		if err != nil {
			return nil, err
		}
		if !inserted {
			return ErrReplay, nil
		}
		return nil, nil
	})
}

func (coordinator *PostgresCoordinator) AcquireVoice(ctx context.Context,
	subject string, globalMaximum int, ttl time.Duration) (Lease, error) {
	subjectRaw, subjectSHA, digestErr := subjectDigest("voice-lease", subject)
	if coordinator == nil || coordinator.db == nil || ctx == nil ||
		digestErr != nil || globalMaximum < 1 || globalMaximum > 1000000 ||
		ttl < 5*time.Second || ttl > maximumLeaseTTL {
		return Lease{}, ErrInvalid
	}
	lease := Lease{Kind: VoiceLease, SubjectSHA256: subjectSHA,
		HolderID: coordinator.holderID}
	if _, err := io.ReadFull(coordinator.random, lease.LeaseID[:]); err != nil {
		return Lease{}, unavailable("generate voice lease fencing id", err)
	}
	err := coordinator.serializable(ctx, func(operation context.Context,
		tx *sql.Tx) (error, error) {
		var guard bool
		if err := tx.QueryRowContext(operation, `
SELECT singleton FROM runtime_coordination_guard
WHERE singleton = TRUE FOR UPDATE`).Scan(&guard); err != nil {
			return nil, err
		}
		if !guard {
			return nil, fmt.Errorf("invalid runtime coordination guard")
		}
		var databaseNow time.Time
		if err := tx.QueryRowContext(operation, `SELECT CURRENT_TIMESTAMP`).
			Scan(&databaseNow); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(operation, `
DELETE FROM runtime_coordination_leases
WHERE lease_kind = 1 AND expires_at <= $1`, databaseNow); err != nil {
			return nil, err
		}
		var existing int
		if err := tx.QueryRowContext(operation, `
SELECT count(*) FROM runtime_coordination_leases
WHERE lease_kind = 1 AND subject_sha256 = $1 AND expires_at > $2`,
			subjectRaw, databaseNow).Scan(&existing); err != nil {
			return nil, err
		}
		if existing != 0 {
			return ErrConflict, nil
		}
		var globalActive int
		if err := tx.QueryRowContext(operation, `
SELECT count(*) FROM runtime_coordination_leases
WHERE lease_kind = 1 AND expires_at > $1`, databaseNow).
			Scan(&globalActive); err != nil {
			return nil, err
		}
		if globalActive >= globalMaximum {
			return ErrRateLimited, nil
		}
		var expires time.Time
		err := tx.QueryRowContext(operation, `
INSERT INTO runtime_coordination_leases
    (lease_kind, subject_sha256, lease_id, holder_id, acquired_at,
     renewed_at, expires_at)
VALUES (1, $1, $2, $3, $4, $4,
        $4 + ($5 * INTERVAL '1 millisecond'))
RETURNING expires_at`, subjectRaw, lease.LeaseID[:], coordinator.holderID,
			databaseNow, ttl.Milliseconds()).Scan(&expires)
		if err != nil {
			return nil, err
		}
		lease.ExpiresAt = expires.UTC()
		return nil, nil
	})
	if err != nil {
		return Lease{}, err
	}
	return lease, nil
}

func (coordinator *PostgresCoordinator) AcquireAgent(ctx context.Context,
	subject string, requestsPerMinute, globalMaximum int,
	ttl time.Duration) (Lease, error) {
	subjectRaw, subjectSHA, digestErr := subjectDigest("agent-lease", subject)
	if coordinator == nil || coordinator.db == nil || ctx == nil ||
		digestErr != nil || requestsPerMinute < 1 || requestsPerMinute > 600 ||
		globalMaximum < 1 || globalMaximum > 10000 || ttl < 5*time.Second ||
		ttl > maximumLeaseTTL {
		return Lease{}, ErrInvalid
	}
	lease := Lease{Kind: AgentLease, SubjectSHA256: subjectSHA,
		HolderID: coordinator.holderID}
	if _, err := io.ReadFull(coordinator.random, lease.LeaseID[:]); err != nil {
		return Lease{}, unavailable("generate Agent permit fencing id", err)
	}
	err := coordinator.serializable(ctx, func(operation context.Context,
		tx *sql.Tx) (error, error) {
		var guard bool
		if err := tx.QueryRowContext(operation, `
SELECT singleton FROM runtime_coordination_guard
			WHERE singleton = TRUE FOR UPDATE`).Scan(&guard); err != nil {
			return nil, err
		}
		if !guard {
			return nil, fmt.Errorf("invalid runtime coordination guard")
		}
		var databaseNow time.Time
		if err := tx.QueryRowContext(operation, `SELECT CURRENT_TIMESTAMP`).
			Scan(&databaseNow); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(operation, `
DELETE FROM runtime_coordination_leases
WHERE lease_kind = 2 AND expires_at <= $1`, databaseNow); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(operation, `
DELETE FROM runtime_coordination_agent_limits WHERE expires_at <= $1`,
			databaseNow); err != nil {
			return nil, err
		}
		var existing int
		if err := tx.QueryRowContext(operation, `
SELECT count(*) FROM runtime_coordination_leases
WHERE lease_kind = 2 AND subject_sha256 = $1 AND expires_at > $2`,
			subjectRaw, databaseNow).Scan(&existing); err != nil {
			return nil, err
		}
		if existing != 0 {
			return ErrConflict, nil
		}
		if _, err := tx.ExecContext(operation, `
INSERT INTO runtime_coordination_agent_limits
    (subject_sha256, window_started_at, accepted_requests, expires_at)
VALUES ($1, $2, 0, $3)
ON CONFLICT (subject_sha256) DO NOTHING`, subjectRaw, databaseNow,
			databaseNow.Add(time.Minute)); err != nil {
			return nil, err
		}
		var window time.Time
		var accepted int
		if err := tx.QueryRowContext(operation, `
SELECT window_started_at, accepted_requests
FROM runtime_coordination_agent_limits
WHERE subject_sha256 = $1 FOR UPDATE`, subjectRaw).
			Scan(&window, &accepted); err != nil {
			return nil, err
		}
		if databaseNow.Sub(window) >= time.Minute {
			window, accepted = databaseNow, 0
		}
		var globalActive int
		if err := tx.QueryRowContext(operation, `
SELECT count(*) FROM runtime_coordination_leases
WHERE lease_kind = 2 AND expires_at > $1`, databaseNow).
			Scan(&globalActive); err != nil {
			return nil, err
		}
		if accepted >= requestsPerMinute || globalActive >= globalMaximum {
			return ErrRateLimited, nil
		}
		if _, err := tx.ExecContext(operation, `
INSERT INTO runtime_coordination_leases
    (lease_kind, subject_sha256, lease_id, holder_id, acquired_at,
     renewed_at, expires_at)
VALUES (2, $1, $2, $3, $4, $4,
        $4 + ($5 * INTERVAL '1 millisecond'))`,
			subjectRaw, lease.LeaseID[:], coordinator.holderID,
			databaseNow, ttl.Milliseconds()); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(operation, `
UPDATE runtime_coordination_agent_limits
SET window_started_at = $2, accepted_requests = $3, expires_at = $4
WHERE subject_sha256 = $1`, subjectRaw, window, accepted+1,
			databaseNow.Add(time.Minute)); err != nil {
			return nil, err
		}
		lease.ExpiresAt = databaseNow.Add(ttl).UTC()
		return nil, nil
	})
	if err != nil {
		return Lease{}, err
	}
	return lease, nil
}

func (coordinator *PostgresCoordinator) Renew(ctx context.Context, lease Lease,
	ttl time.Duration) (Lease, error) {
	subjectRaw, err := decodeLease(lease, coordinator)
	if ctx == nil || err != nil || ttl < 5*time.Second || ttl > maximumLeaseTTL {
		return Lease{}, ErrInvalid
	}
	operation, cancel := context.WithTimeout(ctx, coordinator.operationTimeout)
	defer cancel()
	var expires time.Time
	err = coordinator.db.QueryRowContext(operation, `
UPDATE runtime_coordination_leases SET
    renewed_at = CURRENT_TIMESTAMP,
    expires_at = CURRENT_TIMESTAMP + ($5 * INTERVAL '1 millisecond')
WHERE lease_kind = $1 AND subject_sha256 = $2 AND lease_id = $3
  AND holder_id = $4 AND expires_at > CURRENT_TIMESTAMP
RETURNING expires_at`, int(lease.Kind), subjectRaw, lease.LeaseID[:],
		coordinator.holderID, ttl.Milliseconds()).Scan(&expires)
	if errors.Is(err, sql.ErrNoRows) {
		return Lease{}, ErrLeaseLost
	}
	if err != nil {
		return Lease{}, unavailable("renew runtime lease", err)
	}
	lease.ExpiresAt = expires.UTC()
	return lease, nil
}

func (coordinator *PostgresCoordinator) Release(ctx context.Context,
	lease Lease) error {
	subjectRaw, err := decodeLease(lease, coordinator)
	if ctx == nil || err != nil {
		return ErrInvalid
	}
	operation, cancel := context.WithTimeout(ctx, coordinator.operationTimeout)
	defer cancel()
	result, err := coordinator.db.ExecContext(operation, `
DELETE FROM runtime_coordination_leases
WHERE lease_kind = $1 AND subject_sha256 = $2 AND lease_id = $3
  AND holder_id = $4`, int(lease.Kind), subjectRaw, lease.LeaseID[:],
		coordinator.holderID)
	if err != nil {
		return unavailable("release runtime lease", err)
	}
	deleted, err := exactlyZeroOrOne(result)
	if err != nil {
		return unavailable("inspect runtime lease release", err)
	}
	if !deleted {
		return ErrLeaseLost
	}
	return nil
}

func decodeLease(lease Lease, coordinator *PostgresCoordinator) ([]byte, error) {
	if coordinator == nil || coordinator.db == nil || !lease.Kind.valid() ||
		lease.HolderID != coordinator.holderID || !auth.ValidIdentifier(lease.HolderID, 64) {
		return nil, ErrInvalid
	}
	subjectRaw, err := hex.DecodeString(lease.SubjectSHA256)
	if err != nil || len(subjectRaw) != 32 ||
		hex.EncodeToString(subjectRaw) != lease.SubjectSHA256 {
		return nil, ErrInvalid
	}
	zero := true
	for _, value := range lease.LeaseID {
		zero = zero && value == 0
	}
	if zero {
		return nil, ErrInvalid
	}
	return subjectRaw, nil
}

type transactionAction func(context.Context, *sql.Tx) (business error, failure error)

func (coordinator *PostgresCoordinator) serializable(ctx context.Context,
	action transactionAction) error {
	if coordinator == nil || coordinator.db == nil || ctx == nil || action == nil {
		return ErrInvalid
	}
	operation, cancel := context.WithTimeout(ctx, coordinator.operationTimeout)
	defer cancel()
	var last error
	for attempt := 0; attempt < maximumTransactionTries; attempt++ {
		tx, err := coordinator.db.BeginTx(operation,
			&sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			last = err
			if retryable(err) {
				continue
			}
			return unavailable("begin coordination transaction", err)
		}
		business, failure := action(operation, tx)
		if failure != nil {
			_ = tx.Rollback()
			last = failure
			if retryable(failure) {
				continue
			}
			return unavailable("execute coordination transaction", failure)
		}
		if err := tx.Commit(); err != nil {
			last = err
			if retryable(err) {
				continue
			}
			return unavailable("commit coordination transaction", err)
		}
		return business
	}
	return unavailable("retry coordination transaction", last)
}

func exactlyZeroOrOne(result sql.Result) (bool, error) {
	if result == nil {
		return false, fmt.Errorf("missing SQL result")
	}
	rows, err := result.RowsAffected()
	if err != nil || (rows != 0 && rows != 1) {
		return false, fmt.Errorf("unexpected affected row count")
	}
	return rows == 1, nil
}

func retryable(err error) bool {
	var postgres *pgconn.PgError
	return errors.As(err, &postgres) &&
		(postgres.Code == "40001" || postgres.Code == "40P01")
}

func unavailable(action string, err error) error {
	if err == nil {
		return ErrUnavailable
	}
	return fmt.Errorf("%w: %s", ErrUnavailable, action)
}
