package actionconsent

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

const (
	postgresSchemaVersion   = 1
	postgresSchemaContract  = "xz-action-consent-db-v1-20260810"
	wakeSchemaVersion       = 1
	wakeSchemaContract      = "xz-action-consent-wake-db-v1-20260810"
	ownershipSchemaVersion  = 3
	ownershipSchemaContract = "xz-owner-v3-20260809-lifecycle"
	maximumDBAttempts       = 4
)

// PostgresStore is the durable, multi-replica action-consent implementation.
// Each mutation uses a serializable transaction and locks the current
// device_owners row, so release/rebind and action authorization share one
// ordering domain.
type PostgresStore struct {
	db               *sql.DB
	maxRecords       int
	operationTimeout time.Duration
}

var _ DecisionStore = (*PostgresStore)(nil)
var _ ReadyDecisionStore = (*PostgresStore)(nil)
var _ WakeOutbox = (*PostgresStore)(nil)

func NewPostgresStore(db *sql.DB, maxRecords int,
	operationTimeout time.Duration) (*PostgresStore, error) {
	if db == nil || maxRecords < 1 || maxRecords > 100000 ||
		operationTimeout < 100*time.Millisecond ||
		operationTimeout > 30*time.Second {
		return nil, fmt.Errorf("invalid PostgreSQL action consent configuration")
	}
	return &PostgresStore{
		db: db, maxRecords: maxRecords, operationTimeout: operationTimeout,
	}, nil
}

func (store *PostgresStore) VerifySchema() error {
	if store == nil {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(),
		store.operationTimeout)
	defer cancel()
	if err := store.db.PingContext(ctx); err != nil {
		return postgresUnavailable("ping action consent database", err)
	}
	var ownerVersion, consentVersion, wakeVersion int
	var ownerContract, consentContract, wakeContract string
	if err := store.db.QueryRowContext(ctx, `
SELECT version, contract_id FROM xz_ownership_schema WHERE singleton = TRUE`).
		Scan(&ownerVersion, &ownerContract); err != nil {
		return postgresUnavailable("read ownership schema", err)
	}
	if err := store.db.QueryRowContext(ctx, `
SELECT version, contract_id FROM xz_action_consent_schema WHERE singleton = TRUE`).
		Scan(&consentVersion, &consentContract); err != nil {
		return postgresUnavailable("read action consent schema", err)
	}
	if err := store.db.QueryRowContext(ctx, `
SELECT version, contract_id FROM xz_action_consent_wake_schema WHERE singleton = TRUE`).
		Scan(&wakeVersion, &wakeContract); err != nil {
		return postgresUnavailable("read action consent wake schema", err)
	}
	if ownerVersion != ownershipSchemaVersion ||
		ownerContract != ownershipSchemaContract ||
		consentVersion != postgresSchemaVersion ||
		consentContract != postgresSchemaContract ||
		wakeVersion != wakeSchemaVersion || wakeContract != wakeSchemaContract {
		return fmt.Errorf("%w: unsupported action consent schema contract",
			ErrUnavailable)
	}
	return nil
}

func (store *PostgresStore) Register(challenge Challenge, now time.Time) error {
	if store == nil || !ValidChallenge(challenge, now) {
		return ErrInvalid
	}
	challenge.ExpiresAt = challenge.ExpiresAt.UTC()
	_, err := store.runTransaction(func(ctx context.Context,
		tx *sql.Tx) (Record, error) {
		databaseNow, err := postgresTransactionTime(ctx, tx)
		if err != nil {
			return Record{}, err
		}
		lifetime := challenge.ExpiresAt.Sub(databaseNow)
		if lifetime <= 0 || lifetime > MaximumLifetime {
			return Record{}, ErrExpired
		}
		owner, found, err := selectCurrentOwner(ctx, tx, challenge.DeviceID)
		if err != nil {
			return Record{}, err
		}
		if !found || !owner.active || owner.ownerID != challenge.OwnerID ||
			owner.tenantID != challenge.TenantID ||
			owner.revision != challenge.OwnerRevision {
			return Record{}, ErrConflict
		}
		var active int
		if err := tx.QueryRowContext(ctx, `
SELECT count(*) FROM action_consent_challenges
WHERE expires_at > $1 AND consumed_at IS NULL`, databaseNow).
			Scan(&active); err != nil {
			return Record{}, err
		}
		if active >= store.maxRecords {
			return Record{}, ErrCapacity
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO action_consent_challenges
    (challenge_id, device_id, tenant_id, owner_id, owner_revision,
     session_id, request_id, capability, indicator_on, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			challenge.ChallengeID, challenge.DeviceID, challenge.TenantID,
			challenge.OwnerID, challenge.OwnerRevision, challenge.SessionID,
			challenge.RequestID, Capability, challenge.Action.IndicatorOn,
			databaseNow, challenge.ExpiresAt)
		if err != nil {
			return Record{}, err
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO action_consent_wake_outbox
    (challenge_id, created_at, available_at, expires_at)
VALUES ($1, $2, $2, $3)`, challenge.ChallengeID, databaseNow,
			challenge.ExpiresAt)
		if err != nil {
			return Record{}, err
		}
		return Record{Challenge: challenge}, nil
	})
	return err
}

func (store *PostgresStore) Pending(actor Actor,
	now time.Time) (Record, bool, error) {
	if store == nil || now.IsZero() || !validActor(actor) {
		return Record{}, false, ErrInvalid
	}
	record, err := store.runTransaction(func(ctx context.Context,
		tx *sql.Tx) (Record, error) {
		databaseNow, err := postgresTransactionTime(ctx, tx)
		if err != nil {
			return Record{}, err
		}
		owner, owned, err := selectCurrentOwner(ctx, tx, actor.DeviceID)
		if err != nil {
			return Record{}, err
		}
		if !owned || !owner.active || owner.ownerID != actor.OwnerID ||
			owner.tenantID != actor.TenantID ||
			owner.revision != actor.OwnerRevision {
			return Record{}, ErrConflict
		}
		row := tx.QueryRowContext(ctx, `
SELECT challenge_id, device_id, owner_id, tenant_id, owner_revision,
       session_id, request_id, capability, indicator_on, expires_at,
       decision, decided_at, consumed_at
FROM action_consent_challenges
WHERE device_id = $1 AND owner_id = $2 AND tenant_id = $3
  AND owner_revision = $4 AND expires_at > $5
  AND decision IS NULL AND consumed_at IS NULL
ORDER BY expires_at, challenge_id
LIMIT 1 FOR UPDATE`, actor.DeviceID, actor.OwnerID, actor.TenantID,
			actor.OwnerRevision, databaseNow)
		record, found, err := scanChallenge(row)
		if err != nil {
			return Record{}, err
		}
		if !found {
			return Record{}, ErrNotFound
		}
		return record, nil
	})
	if errors.Is(err, ErrNotFound) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, err
	}
	return record, true, nil
}

func (store *PostgresStore) Decide(actor Actor, request Request,
	now time.Time) (Record, error) {
	if store == nil || now.IsZero() || !validActor(actor) ||
		!validAppRequest(request) {
		return Record{}, ErrInvalid
	}
	return store.runTransaction(func(ctx context.Context,
		tx *sql.Tx) (Record, error) {
		databaseNow, err := postgresTransactionTime(ctx, tx)
		if err != nil {
			return Record{}, err
		}
		record, found, err := selectChallenge(ctx, tx, request.ChallengeID)
		if err != nil {
			return Record{}, err
		}
		if !found {
			return Record{}, ErrNotFound
		}
		if record.Decision != "" {
			return Record{}, ErrReplay
		}
		if !record.Challenge.ExpiresAt.After(databaseNow) {
			return Record{}, ErrExpired
		}
		owner, owned, err := selectCurrentOwner(ctx, tx,
			record.Challenge.DeviceID)
		if err != nil {
			return Record{}, err
		}
		if !owned || !owner.active ||
			owner.ownerID != record.Challenge.OwnerID ||
			owner.tenantID != record.Challenge.TenantID ||
			owner.revision != record.Challenge.OwnerRevision ||
			actor.OwnerID != owner.ownerID || actor.TenantID != owner.tenantID ||
			actor.DeviceID != record.Challenge.DeviceID ||
			actor.OwnerRevision != owner.revision ||
			!matchesAppRequest(record.Challenge, request) {
			return Record{}, ErrConflict
		}
		result, err := tx.ExecContext(ctx, `
UPDATE action_consent_challenges
SET decision = $2, decided_at = $3
WHERE challenge_id = $1 AND decision IS NULL`,
			request.ChallengeID, request.Decision, databaseNow)
		if err != nil {
			return Record{}, err
		}
		if changed, err := result.RowsAffected(); err != nil || changed != 1 {
			return Record{}, ErrReplay
		}
		record.Decision = request.Decision
		record.DecidedAt = databaseNow
		return record, nil
	})
}

func (store *PostgresStore) Consume(request DeviceRequest,
	now time.Time) (Record, error) {
	if store == nil || now.IsZero() || !validDeviceRequest(request) {
		return Record{}, ErrInvalid
	}
	return store.runTransaction(func(ctx context.Context,
		tx *sql.Tx) (Record, error) {
		databaseNow, err := postgresTransactionTime(ctx, tx)
		if err != nil {
			return Record{}, err
		}
		record, found, err := selectChallenge(ctx, tx, request.ChallengeID)
		if err != nil {
			return Record{}, err
		}
		if !found {
			return Record{}, ErrNotFound
		}
		if !record.Challenge.ExpiresAt.After(databaseNow) {
			return Record{}, ErrExpired
		}
		if !record.ConsumedAt.IsZero() {
			return Record{}, ErrReplay
		}
		owner, owned, err := selectCurrentOwner(ctx, tx,
			record.Challenge.DeviceID)
		if err != nil {
			return Record{}, err
		}
		if !owned || !owner.active ||
			owner.ownerID != record.Challenge.OwnerID ||
			owner.tenantID != record.Challenge.TenantID ||
			owner.revision != record.Challenge.OwnerRevision ||
			!matchesDeviceRequest(record.Challenge, request) {
			return Record{}, ErrConflict
		}
		if record.Decision == "" {
			return Record{}, ErrPending
		}
		result, err := tx.ExecContext(ctx, `
UPDATE action_consent_challenges
SET consumed_at = $2
WHERE challenge_id = $1 AND consumed_at IS NULL`,
			request.ChallengeID, databaseNow)
		if err != nil {
			return Record{}, err
		}
		if changed, err := result.RowsAffected(); err != nil || changed != 1 {
			return Record{}, ErrReplay
		}
		record.ConsumedAt = databaseNow
		return record, nil
	})
}

type currentOwner struct {
	ownerID  string
	tenantID string
	revision uint64
	active   bool
}

func selectCurrentOwner(ctx context.Context, tx *sql.Tx,
	deviceID string) (currentOwner, bool, error) {
	var owner currentOwner
	var status string
	err := tx.QueryRowContext(ctx, `
SELECT owner_id, tenant_id, binding_revision, status
FROM device_owners WHERE device_id = $1 FOR UPDATE`, deviceID).
		Scan(&owner.ownerID, &owner.tenantID, &owner.revision, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return currentOwner{}, false, nil
	}
	if err != nil {
		return currentOwner{}, false, err
	}
	owner.active = status == "active"
	return owner, true, nil
}

func selectChallenge(ctx context.Context, tx *sql.Tx,
	challengeID string) (Record, bool, error) {
	return scanChallenge(tx.QueryRowContext(ctx, `
SELECT challenge_id, device_id, owner_id, tenant_id, owner_revision,
       session_id, request_id, capability, indicator_on, expires_at,
       decision, decided_at, consumed_at
FROM action_consent_challenges WHERE challenge_id = $1 FOR UPDATE`, challengeID))
}

type challengeScanner interface {
	Scan(dest ...any) error
}

func scanChallenge(row challengeScanner) (Record, bool, error) {
	var record Record
	var capability string
	var decision sql.NullString
	var decidedAt, consumedAt sql.NullTime
	err := row.Scan(&record.Challenge.ChallengeID, &record.Challenge.DeviceID,
		&record.Challenge.OwnerID, &record.Challenge.TenantID,
		&record.Challenge.OwnerRevision, &record.Challenge.SessionID,
		&record.Challenge.RequestID, &capability,
		&record.Challenge.Action.IndicatorOn, &record.Challenge.ExpiresAt,
		&decision, &decidedAt, &consumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, err
	}
	if capability != Capability || !ValidChallengeID(record.Challenge.ChallengeID) ||
		!auth.ValidIdentifier(record.Challenge.DeviceID, 64) ||
		!auth.ValidIdentifier(record.Challenge.OwnerID, 128) ||
		!auth.ValidIdentifier(record.Challenge.TenantID, 128) ||
		!auth.ValidBindingRevision(record.Challenge.OwnerRevision) ||
		!auth.ValidIdentifier(record.Challenge.SessionID, 64) ||
		record.Challenge.RequestID == 0 {
		return Record{}, false, ErrInvalid
	}
	if decision.Valid {
		record.Decision = Decision(decision.String)
		if !validDecision(record.Decision) || !decidedAt.Valid {
			return Record{}, false, ErrInvalid
		}
		record.DecidedAt = decidedAt.Time.UTC()
	}
	if consumedAt.Valid {
		if record.Decision == "" {
			return Record{}, false, ErrInvalid
		}
		record.ConsumedAt = consumedAt.Time.UTC()
	}
	record.Challenge.ExpiresAt = record.Challenge.ExpiresAt.UTC()
	return record, true, nil
}

func validActor(actor Actor) bool {
	return auth.ValidIdentifier(actor.OwnerID, 128) &&
		auth.ValidIdentifier(actor.TenantID, 128) &&
		auth.ValidIdentifier(actor.DeviceID, 64) &&
		auth.ValidBindingRevision(actor.OwnerRevision)
}

func validAppRequest(request Request) bool {
	return ValidChallengeID(request.ChallengeID) &&
		auth.ValidIdentifier(request.DeviceID, 64) &&
		auth.ValidBindingRevision(request.OwnerRevision) &&
		auth.ValidIdentifier(request.SessionID, 64) && request.RequestID != 0 &&
		validDecision(request.Decision)
}

func validDeviceRequest(request DeviceRequest) bool {
	return ValidChallengeID(request.ChallengeID) &&
		auth.ValidIdentifier(request.DeviceID, 64) &&
		auth.ValidBindingRevision(request.OwnerRevision) &&
		auth.ValidIdentifier(request.SessionID, 64) && request.RequestID != 0
}

func matchesAppRequest(challenge Challenge, request Request) bool {
	return request.ChallengeID == challenge.ChallengeID &&
		request.DeviceID == challenge.DeviceID &&
		request.OwnerRevision == challenge.OwnerRevision &&
		request.SessionID == challenge.SessionID &&
		request.RequestID == challenge.RequestID && request.Action == challenge.Action
}

func matchesDeviceRequest(challenge Challenge, request DeviceRequest) bool {
	return request.ChallengeID == challenge.ChallengeID &&
		request.DeviceID == challenge.DeviceID &&
		request.OwnerRevision == challenge.OwnerRevision &&
		request.SessionID == challenge.SessionID &&
		request.RequestID == challenge.RequestID && request.Action == challenge.Action
}

type transactionOperation func(context.Context, *sql.Tx) (Record, error)

func (store *PostgresStore) runTransaction(
	operation transactionOperation) (Record, error) {
	ctx, cancel := context.WithTimeout(context.Background(),
		store.operationTimeout)
	defer cancel()
	var lastErr error
	for attempt := 0; attempt < maximumDBAttempts; attempt++ {
		tx, err := store.db.BeginTx(ctx,
			&sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			return Record{}, postgresUnavailable("begin action consent transaction", err)
		}
		record, err := operation(ctx, tx)
		if err == nil {
			err = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
		if err == nil {
			return record, nil
		}
		if postgresUniqueViolation(err) {
			return Record{}, ErrConflict
		}
		if postgresBusinessError(err) {
			return Record{}, err
		}
		lastErr = err
		if !postgresRetryable(err) || ctx.Err() != nil {
			break
		}
	}
	return Record{}, postgresUnavailable("action consent transaction", lastErr)
}

func postgresTransactionTime(ctx context.Context, tx *sql.Tx) (time.Time, error) {
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).Scan(&now); err != nil {
		return time.Time{}, err
	}
	return now.UTC(), nil
}

func postgresRetryable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) &&
		(pgErr.Code == "40001" || pgErr.Code == "40P01")
}

func postgresUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func postgresBusinessError(err error) bool {
	if errors.Is(err, ErrInvalid) || errors.Is(err, ErrReplay) ||
		errors.Is(err, ErrCapacity) || errors.Is(err, ErrConflict) ||
		errors.Is(err, ErrNotFound) || errors.Is(err, ErrExpired) ||
		errors.Is(err, ErrPending) {
		return true
	}
	return false
}

func postgresUnavailable(operation string, err error) error {
	if err == nil {
		err = ErrUnavailable
	}
	return fmt.Errorf("%w: %s: %v", ErrUnavailable, operation, err)
}
