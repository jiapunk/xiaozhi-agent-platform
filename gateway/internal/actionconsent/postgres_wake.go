package actionconsent

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (store *PostgresStore) ClaimWake(workerID string, now time.Time,
	lease time.Duration) (Wake, bool, error) {
	if store == nil || now.IsZero() || !validWakeWorker(workerID) ||
		!validWakeLease(lease) {
		return Wake{}, false, ErrInvalid
	}
	wake, err := store.runWakeTransaction(func(ctx context.Context,
		tx *sql.Tx) (Wake, error) {
		databaseNow, err := postgresTransactionTime(ctx, tx)
		if err != nil {
			return Wake{}, err
		}
		if _, err := tx.ExecContext(ctx, `
DELETE FROM action_consent_wake_outbox AS wake
USING action_consent_challenges AS challenge
WHERE wake.challenge_id = challenge.challenge_id
  AND (wake.expires_at <= $1 OR challenge.decision IS NOT NULL)`,
			databaseNow); err != nil {
			return Wake{}, err
		}
		var attempts uint32
		row := tx.QueryRowContext(ctx, `
SELECT wake.challenge_id, challenge.owner_id, challenge.tenant_id,
       challenge.device_id, challenge.owner_revision,
       wake.expires_at, wake.attempts
FROM action_consent_wake_outbox AS wake
JOIN action_consent_challenges AS challenge
  ON challenge.challenge_id = wake.challenge_id
WHERE wake.available_at <= $1 AND wake.expires_at > $1
  AND challenge.decision IS NULL
  AND (wake.claimed_by IS NULL OR wake.lease_until <= $1)
ORDER BY wake.expires_at, wake.challenge_id
LIMIT 1 FOR UPDATE OF wake SKIP LOCKED`, databaseNow)
		var wake Wake
		if err := row.Scan(&wake.WakeID, &wake.Target.OwnerID,
			&wake.Target.TenantID, &wake.Target.DeviceID,
			&wake.Target.OwnerRevision, &wake.ExpiresAt, &attempts); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return Wake{}, ErrNotFound
			}
			return Wake{}, err
		}
		if !ValidChallengeID(wake.WakeID) || !validActor(wake.Target) {
			return Wake{}, ErrInvalid
		}
		if attempts >= maximumWakeAttempts {
			if _, err := tx.ExecContext(ctx, `
DELETE FROM action_consent_wake_outbox WHERE challenge_id = $1`, wake.WakeID); err != nil {
				return Wake{}, err
			}
			return Wake{}, nil
		}
		result, err := tx.ExecContext(ctx, `
UPDATE action_consent_wake_outbox
SET claimed_by = $2, lease_until = $3, attempts = attempts + 1
WHERE challenge_id = $1`, wake.WakeID, workerID, databaseNow.Add(lease))
		if err != nil {
			return Wake{}, err
		}
		if changed, err := result.RowsAffected(); err != nil || changed != 1 {
			return Wake{}, ErrConflict
		}
		wake.ExpiresAt = wake.ExpiresAt.UTC()
		wake.Attempts = attempts + 1
		return wake, nil
	})
	if errors.Is(err, ErrNotFound) {
		return Wake{}, false, nil
	}
	if err != nil {
		return Wake{}, false, err
	}
	if wake.WakeID == "" {
		return Wake{}, false, nil
	}
	return wake, true, nil
}

func (store *PostgresStore) AcknowledgeWake(workerID, wakeID string,
	now time.Time) error {
	if store == nil || now.IsZero() || !validWakeWorker(workerID) ||
		!ValidChallengeID(wakeID) {
		return ErrInvalid
	}
	_, err := store.runWakeTransaction(func(ctx context.Context,
		tx *sql.Tx) (Wake, error) {
		databaseNow, err := postgresTransactionTime(ctx, tx)
		if err != nil {
			return Wake{}, err
		}
		var expiresAt time.Time
		var claimedBy sql.NullString
		var leaseUntil sql.NullTime
		err = tx.QueryRowContext(ctx, `
SELECT expires_at, claimed_by, lease_until
FROM action_consent_wake_outbox
WHERE challenge_id = $1 FOR UPDATE`, wakeID).
			Scan(&expiresAt, &claimedBy, &leaseUntil)
		if errors.Is(err, sql.ErrNoRows) {
			return Wake{}, ErrNotFound
		}
		if err != nil {
			return Wake{}, err
		}
		if !expiresAt.After(databaseNow) {
			if _, err := tx.ExecContext(ctx, `
DELETE FROM action_consent_wake_outbox WHERE challenge_id = $1`, wakeID); err != nil {
				return Wake{}, err
			}
			return Wake{}, ErrExpired
		}
		if !claimedBy.Valid || claimedBy.String != workerID ||
			!leaseUntil.Valid || !leaseUntil.Time.After(databaseNow) {
			return Wake{}, ErrConflict
		}
		result, err := tx.ExecContext(ctx, `
DELETE FROM action_consent_wake_outbox
WHERE challenge_id = $1 AND claimed_by = $2`, wakeID, workerID)
		if err != nil {
			return Wake{}, err
		}
		if changed, err := result.RowsAffected(); err != nil || changed != 1 {
			return Wake{}, ErrConflict
		}
		return Wake{}, nil
	})
	return err
}

func (store *PostgresStore) RetryWake(workerID, wakeID string, now time.Time,
	retryAfter time.Duration) error {
	if store == nil || now.IsZero() || !validWakeWorker(workerID) ||
		!ValidChallengeID(wakeID) || !validWakeRetry(retryAfter) {
		return ErrInvalid
	}
	_, err := store.runWakeTransaction(func(ctx context.Context,
		tx *sql.Tx) (Wake, error) {
		databaseNow, err := postgresTransactionTime(ctx, tx)
		if err != nil {
			return Wake{}, err
		}
		var expiresAt time.Time
		var claimedBy sql.NullString
		var leaseUntil sql.NullTime
		err = tx.QueryRowContext(ctx, `
SELECT expires_at, claimed_by, lease_until
FROM action_consent_wake_outbox
WHERE challenge_id = $1 FOR UPDATE`, wakeID).
			Scan(&expiresAt, &claimedBy, &leaseUntil)
		if errors.Is(err, sql.ErrNoRows) {
			return Wake{}, ErrNotFound
		}
		if err != nil {
			return Wake{}, err
		}
		if !claimedBy.Valid || claimedBy.String != workerID ||
			!leaseUntil.Valid || !leaseUntil.Time.After(databaseNow) {
			return Wake{}, ErrConflict
		}
		availableAt := databaseNow.Add(retryAfter)
		if !expiresAt.After(availableAt) {
			if _, err := tx.ExecContext(ctx, `
DELETE FROM action_consent_wake_outbox WHERE challenge_id = $1`, wakeID); err != nil {
				return Wake{}, err
			}
			return Wake{}, ErrExpired
		}
		result, err := tx.ExecContext(ctx, `
UPDATE action_consent_wake_outbox
SET available_at = $2, claimed_by = NULL, lease_until = NULL
WHERE challenge_id = $1 AND claimed_by = $3`,
			wakeID, availableAt, workerID)
		if err != nil {
			return Wake{}, err
		}
		if changed, err := result.RowsAffected(); err != nil || changed != 1 {
			return Wake{}, ErrConflict
		}
		return Wake{}, nil
	})
	return err
}

type wakeTransactionOperation func(context.Context, *sql.Tx) (Wake, error)

func (store *PostgresStore) runWakeTransaction(
	operation wakeTransactionOperation) (Wake, error) {
	ctx, cancel := context.WithTimeout(context.Background(),
		store.operationTimeout)
	defer cancel()
	var lastErr error
	for attempt := 0; attempt < maximumDBAttempts; attempt++ {
		tx, err := store.db.BeginTx(ctx,
			&sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			return Wake{}, postgresUnavailable("begin action wake transaction", err)
		}
		wake, err := operation(ctx, tx)
		if err == nil {
			err = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
		if err == nil {
			return wake, nil
		}
		if postgresBusinessError(err) {
			return Wake{}, err
		}
		lastErr = err
		if !postgresRetryable(err) || ctx.Err() != nil {
			break
		}
	}
	return Wake{}, postgresUnavailable("action wake transaction", lastErr)
}
