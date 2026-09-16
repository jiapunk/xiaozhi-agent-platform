package accountauth

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
	postgresSchemaVersion            = 1
	postgresPushSchemaVersion        = 1
	postgresEntitlementSchemaVersion = 1
	maximumDBAttempts                = 4
)

// PostgresStore is the durable multi-replica ledger. Every issuance,
// account-revision mutation and introspection runs in a serializable
// transaction and locks the same account row, establishing one database
// ordering domain across serving replicas.
type PostgresStore struct {
	db               *sql.DB
	operationTimeout time.Duration
}

var _ Ledger = (*PostgresStore)(nil)
var _ ReadyLedger = (*PostgresStore)(nil)

func NewPostgresStore(db *sql.DB,
	operationTimeout time.Duration) (*PostgresStore, error) {
	if db == nil || operationTimeout < 100*time.Millisecond ||
		operationTimeout > 30*time.Second {
		return nil, fmt.Errorf("invalid PostgreSQL Companion authorization configuration")
	}
	return &PostgresStore{db: db, operationTimeout: operationTimeout}, nil
}

func (store *PostgresStore) VerifySchema() error {
	if store == nil || store.db == nil {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(),
		store.operationTimeout)
	defer cancel()
	if err := store.db.PingContext(ctx); err != nil {
		return postgresUnavailable("ping Companion authorization database", err)
	}
	var version int
	var contract string
	if err := store.db.QueryRowContext(ctx, `
SELECT version, contract_id
FROM xz_companion_authorization_schema WHERE singleton = TRUE`).
		Scan(&version, &contract); err != nil {
		return postgresUnavailable("read Companion authorization schema", err)
	}
	if version != postgresSchemaVersion || contract != DatabaseContract {
		return fmt.Errorf("%w: unsupported Companion authorization schema contract",
			ErrUnavailable)
	}
	if err := store.db.QueryRowContext(ctx, `
SELECT version, contract_id
FROM xz_companion_push_schema WHERE singleton = TRUE`).
		Scan(&version, &contract); err != nil {
		return postgresUnavailable("read Companion push schema", err)
	}
	if version != postgresPushSchemaVersion ||
		contract != PushInstallationDatabaseContract {
		return fmt.Errorf("%w: unsupported Companion push schema contract",
			ErrUnavailable)
	}
	if err := store.db.QueryRowContext(ctx, `
SELECT version, contract_id
FROM xz_service_entitlement_schema WHERE singleton = TRUE`).
		Scan(&version, &contract); err != nil {
		return postgresUnavailable("read service entitlement schema", err)
	}
	if version != postgresEntitlementSchemaVersion ||
		contract != ServiceEntitlementDatabaseContract {
		return fmt.Errorf("%w: unsupported service entitlement schema contract",
			ErrUnavailable)
	}
	return nil
}

func (store *PostgresStore) BeginAuthenticatedSession(ctx context.Context,
	principal Principal) (Session, error) {
	if store == nil || ctx == nil || !ValidPrincipal(principal) {
		return Session{}, ErrInvalid
	}
	return runPostgresTransaction(store, ctx, func(ctx context.Context,
		tx *sql.Tx) (Session, error) {
		now, err := postgresTime(ctx, tx)
		if err != nil {
			return Session{}, err
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO companion_accounts
    (tenant_id, subject, revision, status, created_at, updated_at)
VALUES ($1, $2, 1, 'active', $3, $3)
ON CONFLICT (tenant_id, subject) DO NOTHING`,
			principal.TenantID, principal.Subject, now); err != nil {
			return Session{}, err
		}
		account, found, err := selectAccount(ctx, tx, principal)
		if err != nil {
			return Session{}, err
		}
		if !found {
			return Session{}, ErrNotFound
		}
		if account.Status != AccountActive {
			return Session{}, ErrSuspended
		}
		return Session{Principal: principal,
			AccountRevision: account.Revision}, nil
	})
}

func (store *PostgresStore) RegisterToken(ctx context.Context, session Session,
	binding TokenBinding) (Authorization, error) {
	if store == nil || ctx == nil || !ValidSession(session) ||
		!ValidTokenBinding(binding) ||
		binding.Subject != session.Principal.Subject ||
		binding.TenantID != session.Principal.TenantID {
		return Authorization{}, ErrInvalid
	}
	return runPostgresTransaction(store, ctx, func(ctx context.Context,
		tx *sql.Tx) (Authorization, error) {
		now, err := postgresTime(ctx, tx)
		if err != nil {
			return Authorization{}, err
		}
		if binding.ExpiresAt <= now.Unix() ||
			binding.IssuedAt > now.Add(maximumClockSkew).Unix() {
			return Authorization{}, ErrInactive
		}
		account, found, err := selectAccount(ctx, tx, session.Principal)
		if err != nil {
			return Authorization{}, err
		}
		if !found {
			return Authorization{}, ErrNotFound
		}
		if account.Status != AccountActive {
			return Authorization{}, ErrSuspended
		}
		if account.Revision != session.AccountRevision {
			return Authorization{}, ErrStaleSession
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO companion_tokens
    (token_id, tenant_id, subject, account_revision, action, device_id,
     issued_at_unix, expires_at_unix, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			binding.TokenID, binding.TenantID, binding.Subject,
			account.Revision, binding.Action, binding.DeviceID,
			binding.IssuedAt, binding.ExpiresAt, now)
		if err != nil {
			return Authorization{}, err
		}
		return Authorization{Binding: binding,
			AccountRevision: account.Revision,
			ValidUntil:      binding.ExpiresAt}, nil
	})
}

func (store *PostgresStore) Introspect(ctx context.Context,
	binding TokenBinding) (Authorization, bool, error) {
	if store == nil || ctx == nil || !ValidTokenBinding(binding) {
		return Authorization{}, false, ErrInvalid
	}
	type introspectionResult struct {
		authorization Authorization
		active        bool
	}
	result, err := runPostgresTransaction(store, ctx, func(ctx context.Context,
		tx *sql.Tx) (introspectionResult, error) {
		now, err := postgresTime(ctx, tx)
		if err != nil {
			return introspectionResult{}, err
		}
		var (
			stored          TokenBinding
			tokenRevision   uint64
			accountRevision uint64
			accountStatus   string
			revokedAt       sql.NullTime
		)
		err = tx.QueryRowContext(ctx, `
SELECT token.token_id, token.subject, token.tenant_id, token.action,
       token.device_id, token.issued_at_unix, token.expires_at_unix,
       token.account_revision, token.revoked_at,
       account.revision, account.status
FROM companion_tokens AS token
JOIN companion_accounts AS account
  ON account.tenant_id = token.tenant_id AND account.subject = token.subject
WHERE token.token_id = $1
FOR SHARE OF token, account`, binding.TokenID).
			Scan(&stored.TokenID, &stored.Subject, &stored.TenantID,
				&stored.Action, &stored.DeviceID, &stored.IssuedAt,
				&stored.ExpiresAt, &tokenRevision, &revokedAt,
				&accountRevision, &accountStatus)
		if errors.Is(err, sql.ErrNoRows) {
			return introspectionResult{}, nil
		}
		if err != nil {
			return introspectionResult{}, err
		}
		if !ValidTokenBinding(stored) ||
			!ValidAccountRevision(tokenRevision) ||
			!ValidAccountRevision(accountRevision) {
			return introspectionResult{}, ErrUnavailable
		}
		if stored != binding || revokedAt.Valid ||
			accountStatus != string(AccountActive) ||
			tokenRevision != accountRevision ||
			stored.ExpiresAt <= now.Unix() {
			return introspectionResult{}, nil
		}
		return introspectionResult{active: true,
			authorization: Authorization{Binding: stored,
				AccountRevision: accountRevision,
				ValidUntil:      stored.ExpiresAt}}, nil
	})
	if err != nil {
		return Authorization{}, false, err
	}
	return result.authorization, result.active, nil
}

func (store *PostgresStore) Logout(ctx context.Context,
	session Session) (Account, error) {
	if store == nil || ctx == nil || !ValidSession(session) {
		return Account{}, ErrInvalid
	}
	return runPostgresTransaction(store, ctx, func(ctx context.Context,
		tx *sql.Tx) (Account, error) {
		account, found, err := selectAccount(ctx, tx, session.Principal)
		if err != nil {
			return Account{}, err
		}
		if !found {
			return Account{}, ErrNotFound
		}
		if account.Revision != session.AccountRevision {
			return Account{}, ErrStaleSession
		}
		return rotateAccount(ctx, tx, account, AccountActive,
			RevocationLogout)
	})
}

func (store *PostgresStore) Suspend(ctx context.Context,
	principal Principal) (Account, error) {
	return store.setStatus(ctx, principal, AccountSuspended)
}

func (store *PostgresStore) Resume(ctx context.Context,
	principal Principal) (Account, error) {
	return store.setStatus(ctx, principal, AccountActive)
}

func (store *PostgresStore) setStatus(ctx context.Context, principal Principal,
	status AccountStatus) (Account, error) {
	if store == nil || ctx == nil || !ValidPrincipal(principal) ||
		(status != AccountActive && status != AccountSuspended) {
		return Account{}, ErrInvalid
	}
	return runPostgresTransaction(store, ctx, func(ctx context.Context,
		tx *sql.Tx) (Account, error) {
		account, found, err := selectAccount(ctx, tx, principal)
		if err != nil {
			return Account{}, err
		}
		if !found {
			return Account{}, ErrNotFound
		}
		if account.Status == status {
			return account, nil
		}
		return rotateAccount(ctx, tx, account, status,
			RevocationSuspended)
	})
}

func (store *PostgresStore) RevokeToken(ctx context.Context,
	principal Principal, tokenID string) error {
	if store == nil || ctx == nil || !ValidPrincipal(principal) ||
		!validTokenID(tokenID) {
		return ErrInvalid
	}
	_, err := runPostgresTransaction(store, ctx, func(ctx context.Context,
		tx *sql.Tx) (bool, error) {
		var subject, tenantID string
		var revokedAt sql.NullTime
		err := tx.QueryRowContext(ctx, `
SELECT subject, tenant_id, revoked_at
FROM companion_tokens WHERE token_id = $1 FOR UPDATE`, tokenID).
			Scan(&subject, &tenantID, &revokedAt)
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrNotFound
		}
		if err != nil {
			return false, err
		}
		if subject != principal.Subject || tenantID != principal.TenantID {
			return false, ErrNotFound
		}
		if revokedAt.Valid {
			return true, nil
		}
		result, err := tx.ExecContext(ctx, `
UPDATE companion_tokens
SET revoked_at = CURRENT_TIMESTAMP, revocation_reason = $2
WHERE token_id = $1 AND revoked_at IS NULL`, tokenID, RevocationToken)
		if err != nil {
			return false, err
		}
		changed, err := result.RowsAffected()
		if err != nil || changed != 1 {
			return false, ErrConflict
		}
		return true, nil
	})
	return err
}

// PruneExpired removes expired JTI rows after an operator-selected retention
// interval. Account revisions and account state are never pruned by serving
// code.
func (store *PostgresStore) PruneExpired(ctx context.Context,
	retention time.Duration) error {
	if store == nil || ctx == nil || retention < 0 || retention > 90*24*time.Hour {
		return ErrInvalid
	}
	operationContext, cancel := context.WithTimeout(ctx, store.operationTimeout)
	defer cancel()
	_, err := store.db.ExecContext(operationContext, `
DELETE FROM companion_tokens
WHERE expires_at_unix <= FLOOR(EXTRACT(EPOCH FROM CURRENT_TIMESTAMP))::bigint - $1`,
		int64(retention/time.Second))
	if err != nil {
		return postgresUnavailable("prune expired Companion tokens", err)
	}
	return nil
}

func selectAccount(ctx context.Context, tx *sql.Tx,
	principal Principal) (Account, bool, error) {
	var account Account
	var status string
	err := tx.QueryRowContext(ctx, `
SELECT revision, status, updated_at
FROM companion_accounts
WHERE tenant_id = $1 AND subject = $2
FOR UPDATE`, principal.TenantID, principal.Subject).
		Scan(&account.Revision, &status, &account.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Account{}, false, nil
	}
	if err != nil {
		return Account{}, false, err
	}
	account.Principal = principal
	account.Status = AccountStatus(status)
	account.UpdatedAt = account.UpdatedAt.UTC()
	if !ValidAccountRevision(account.Revision) ||
		(account.Status != AccountActive && account.Status != AccountSuspended) {
		return Account{}, false, ErrUnavailable
	}
	return account, true, nil
}

func rotateAccount(ctx context.Context, tx *sql.Tx, account Account,
	status AccountStatus, reason RevocationReason) (Account, error) {
	if account.Revision >= maximumAccountRevision {
		return Account{}, ErrRevisionExhausted
	}
	now, err := postgresTime(ctx, tx)
	if err != nil {
		return Account{}, err
	}
	oldRevision := account.Revision
	result, err := tx.ExecContext(ctx, `
UPDATE companion_accounts
SET revision = revision + 1, status = $3, updated_at = $4
WHERE tenant_id = $1 AND subject = $2 AND revision = $5`,
		account.Principal.TenantID, account.Principal.Subject,
		status, now, oldRevision)
	if err != nil {
		return Account{}, err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return Account{}, ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE companion_tokens
SET revoked_at = COALESCE(revoked_at, $3),
    revocation_reason = COALESCE(revocation_reason, $4)
WHERE tenant_id = $1 AND subject = $2
  AND account_revision <= $5`,
		account.Principal.TenantID, account.Principal.Subject,
		now, reason, oldRevision); err != nil {
		return Account{}, err
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM companion_push_installations
WHERE tenant_id = $1 AND subject = $2
  AND account_revision <= $3`, account.Principal.TenantID,
		account.Principal.Subject, oldRevision); err != nil {
		return Account{}, err
	}
	account.Revision++
	account.Status = status
	account.UpdatedAt = now
	return account, nil
}

func postgresTime(ctx context.Context, tx *sql.Tx) (time.Time, error) {
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).
		Scan(&now); err != nil {
		return time.Time{}, err
	}
	return now.UTC(), nil
}

func validTokenID(tokenID string) bool {
	return auth.ValidIdentifier(tokenID, 128)
}

func runPostgresTransaction[T any](store *PostgresStore, ctx context.Context,
	operation func(context.Context, *sql.Tx) (T, error)) (T, error) {
	var zero T
	operationContext, cancel := context.WithTimeout(ctx, store.operationTimeout)
	defer cancel()
	var lastErr error
	for attempt := 0; attempt < maximumDBAttempts; attempt++ {
		tx, err := store.db.BeginTx(operationContext,
			&sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			return zero, postgresUnavailable(
				"begin Companion authorization transaction", err)
		}
		value, err := operation(operationContext, tx)
		if err == nil {
			err = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
		if err == nil {
			return value, nil
		}
		if postgresUniqueViolation(err) {
			return zero, ErrConflict
		}
		if postgresBusinessError(err) {
			return zero, err
		}
		lastErr = err
		if !postgresRetryable(err) || operationContext.Err() != nil {
			break
		}
	}
	return zero, postgresUnavailable("Companion authorization transaction",
		lastErr)
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

func postgresBusinessError(err error) bool {
	for _, target := range []error{
		ErrInvalid, ErrNotFound, ErrConflict, ErrStaleSession, ErrSuspended,
		ErrInactive, ErrCapacity, ErrRevisionExhausted, ErrStaleEntitlement,
		ErrUnavailable,
	} {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

func postgresUnavailable(operation string, err error) error {
	return unavailable(operation, err)
}
