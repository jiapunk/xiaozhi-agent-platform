package deviceclaim

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

const (
	postgresSchemaVersion  = 3
	postgresSchemaContract = "xz-owner-v3-20260809-lifecycle"
	postgresLockSeed       = int64(0x58415a4f574e4552)
	maximumDBAttempts      = 4
)

// PostgresStore is the durable multi-replica OwnershipStore adapter. Every
// mutating operation is serializable and additionally takes transaction-scoped
// advisory locks for its device and claim digest, so replicas share one
// ordering domain even before a row exists. It never writes the raw claim.
type PostgresStore struct {
	db               *sql.DB
	ttl              time.Duration
	maxRecords       int
	operationTimeout time.Duration
	random           io.Reader
}

// PostgresResolver is the least-privilege read path used by Voice Gateway and
// Agent Proxy. Their database role needs SELECT on the schema marker and
// device_owners only; it cannot create claims or mutate ownership.
type PostgresResolver struct {
	db               *sql.DB
	operationTimeout time.Duration
}

var _ ReadyOwnershipResolver = (*PostgresResolver)(nil)
var _ BatchOwnershipResolver = (*PostgresResolver)(nil)

func NewPostgresResolver(db *sql.DB,
	operationTimeout time.Duration) (*PostgresResolver, error) {
	if db == nil || operationTimeout < 100*time.Millisecond ||
		operationTimeout > 30*time.Second {
		return nil, fmt.Errorf("invalid PostgreSQL ownership resolver configuration")
	}
	return &PostgresResolver{db: db, operationTimeout: operationTimeout}, nil
}

func (resolver *PostgresResolver) VerifySchema() error {
	if resolver == nil {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(),
		resolver.operationTimeout)
	defer cancel()
	if err := resolver.db.PingContext(ctx); err != nil {
		return unavailable("ping ownership database", err)
	}
	var version int
	var contract string
	err := resolver.db.QueryRowContext(ctx, `
SELECT version, contract_id FROM xz_ownership_schema WHERE singleton = TRUE`).
		Scan(&version, &contract)
	if err != nil {
		return unavailable("read ownership schema version", err)
	}
	if version != postgresSchemaVersion || contract != postgresSchemaContract {
		return fmt.Errorf("%w: unsupported ownership schema contract",
			ErrUnavailable)
	}
	return nil
}

func (resolver *PostgresResolver) Owner(deviceID string) (Ownership, bool, error) {
	if resolver == nil || !auth.ValidIdentifier(deviceID, 64) {
		return Ownership{}, false, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(context.Background(),
		resolver.operationTimeout)
	defer cancel()
	return queryOwner(ctx, resolver.db, deviceID)
}

func (resolver *PostgresResolver) Owners(
	deviceIDs []string) (map[string]Ownership, error) {
	if resolver == nil {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(context.Background(),
		resolver.operationTimeout)
	defer cancel()
	return queryOwners(ctx, resolver.db, deviceIDs)
}

var _ OwnershipStore = (*PostgresStore)(nil)

func NewPostgresStore(db *sql.DB, ttl time.Duration, maxRecords int,
	operationTimeout time.Duration) (*PostgresStore, error) {
	if db == nil || ttl < time.Minute || ttl > 10*time.Minute ||
		maxRecords < 1 || maxRecords > 100000 ||
		operationTimeout < 100*time.Millisecond ||
		operationTimeout > 30*time.Second {
		return nil, fmt.Errorf("invalid PostgreSQL ownership store configuration")
	}
	return &PostgresStore{
		db: db, ttl: ttl, maxRecords: maxRecords,
		operationTimeout: operationTimeout, random: rand.Reader,
	}, nil
}

// VerifySchema is a startup gate. Schema application belongs to a separately
// authorized migration role; the serving workload only verifies the exact
// supported version and connectivity.
func (store *PostgresStore) VerifySchema() error {
	if store == nil {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(),
		store.operationTimeout)
	defer cancel()
	if err := store.db.PingContext(ctx); err != nil {
		return unavailable("ping ownership database", err)
	}
	var version int
	var contract string
	err := store.db.QueryRowContext(ctx,
		`SELECT version, contract_id FROM xz_ownership_schema WHERE singleton = TRUE`).
		Scan(&version, &contract)
	if err != nil {
		return unavailable("read ownership schema version", err)
	}
	if version != postgresSchemaVersion || contract != postgresSchemaContract {
		return fmt.Errorf("%w: unsupported ownership schema contract",
			ErrUnavailable)
	}
	return nil
}

func (store *PostgresStore) Begin(userID, tenantID, deviceID, code,
	appNonce string, now time.Time) (Record, error) {
	if store == nil || !auth.ValidIdentifier(userID, 128) ||
		!auth.ValidIdentifier(tenantID, 128) ||
		!auth.ValidIdentifier(deviceID, 64) || !ValidClaimCode(code) ||
		!ValidAppNonce(appNonce) || now.IsZero() {
		return Record{}, ErrInvalid
	}
	_ = now
	digest := claimDigest(code)
	requestID, err := store.randomID(requestBytes)
	if err != nil {
		return Record{}, fmt.Errorf("generate claim request id: %w", err)
	}
	return store.runRecordTransaction(func(ctx context.Context,
		tx *sql.Tx) (Record, error) {
		databaseNow, err := transactionTime(ctx, tx)
		if err != nil {
			return Record{}, err
		}
		expiresAt := databaseNow.Add(store.ttl)
		if err := lockOwnershipKeys(ctx, tx, deviceID, digest); err != nil {
			return Record{}, err
		}
		var nonceAccepted int
		err = tx.QueryRowContext(ctx, `
INSERT INTO ownership_app_nonces
    (tenant_id, owner_id, app_nonce, expires_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (tenant_id, owner_id, app_nonce) DO UPDATE
SET expires_at = EXCLUDED.expires_at
WHERE ownership_app_nonces.expires_at <= $5
RETURNING 1`, tenantID, userID, appNonce, expiresAt, databaseNow).
			Scan(&nonceAccepted)
		if errors.Is(err, sql.ErrNoRows) {
			return Record{}, ErrReplay
		}
		if err != nil {
			return Record{}, err
		}

		existing, existingUser, existingTenant, found, err :=
			selectClaimByDigest(ctx, tx, digest)
		if err != nil {
			return Record{}, err
		}
		if found {
			if existingUser != userID || existingTenant != tenantID ||
				existing.DeviceID != deviceID ||
				!existing.ExpiresAt.After(databaseNow) {
				return Record{}, ErrConflict
			}
			return existing, nil
		}

		owner, owned, err := selectOwner(ctx, tx, deviceID, false)
		if err != nil {
			return Record{}, err
		}
		if owned && owner.active &&
			(owner.OwnerID != userID || owner.TenantID != tenantID) {
			return Record{}, ErrConflict
		}
		var active int
		if err := tx.QueryRowContext(ctx, `
SELECT count(*) FROM ownership_claims WHERE expires_at > $1`, databaseNow).
			Scan(&active); err != nil {
			return Record{}, err
		}
		if active >= store.maxRecords {
			return Record{}, ErrCapacity
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO ownership_claims
    (request_id, tenant_id, owner_id, device_id, claim_digest,
     status, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, 'pending', $6, $7)`,
			requestID, tenantID, userID, deviceID, digest[:], expiresAt, databaseNow)
		if err != nil {
			return Record{}, err
		}
		return Record{
			RequestID: requestID, DeviceID: deviceID,
			Status: StatusPending, ExpiresAt: expiresAt,
		}, nil
	})
}

func (store *PostgresStore) Confirm(deviceID, code string,
	now time.Time) (Record, error) {
	if store == nil || !auth.ValidIdentifier(deviceID, 64) ||
		!ValidClaimCode(code) || now.IsZero() {
		return Record{}, ErrInvalid
	}
	_ = now
	digest := claimDigest(code)
	eventID, err := store.randomID(requestBytes)
	if err != nil {
		return Record{}, fmt.Errorf("generate ownership event id: %w", err)
	}
	bindingID, err := store.randomID(bindingBytes)
	if err != nil {
		return Record{}, fmt.Errorf("generate ownership binding id: %w", err)
	}
	return store.runRecordTransaction(func(ctx context.Context,
		tx *sql.Tx) (Record, error) {
		databaseNow, err := transactionTime(ctx, tx)
		if err != nil {
			return Record{}, err
		}
		if err := lockOwnershipKeys(ctx, tx, deviceID, digest); err != nil {
			return Record{}, err
		}
		record, userID, tenantID, found, err :=
			selectClaimByDigest(ctx, tx, digest)
		if err != nil {
			return Record{}, err
		}
		if !found {
			return Record{}, ErrNotFound
		}
		if record.DeviceID != deviceID {
			return Record{}, ErrConflict
		}
		if !record.ExpiresAt.After(databaseNow) {
			return Record{}, ErrExpired
		}
		owner, owned, err := selectOwner(ctx, tx, deviceID, true)
		if err != nil {
			return Record{}, err
		}
		if owned && owner.active &&
			(owner.OwnerID != userID || owner.TenantID != tenantID) {
			return Record{}, ErrConflict
		}
		createdBinding := !owned || !owner.active
		bindingRevision := uint64(1)
		if owned {
			if owner.BindingRevision >= auth.MaximumBindingRevision {
				return Record{}, ErrConflict
			}
			bindingRevision = owner.BindingRevision + 1
		}
		if !owned {
			_, err = tx.ExecContext(ctx, `
INSERT INTO device_owners
    (device_id, tenant_id, owner_id, binding_id, binding_revision, status, bound_at)
VALUES ($1, $2, $3, $4, 1, 'active', $5)`, deviceID, tenantID, userID,
				bindingID, databaseNow)
			if err != nil {
				return Record{}, err
			}
		} else if !owner.active {
			_, err = tx.ExecContext(ctx, `
UPDATE device_owners
SET tenant_id = $2, owner_id = $3, binding_id = $4,
    binding_revision = $5, status = 'active', bound_at = $6
WHERE device_id = $1`, deviceID, tenantID, userID, bindingID,
				bindingRevision, databaseNow)
			if err != nil {
				return Record{}, err
			}
		}
		if record.Status != StatusBound {
			if _, err := tx.ExecContext(ctx, `
UPDATE ownership_claims SET status = 'bound'
WHERE request_id = $1`, record.RequestID); err != nil {
				return Record{}, err
			}
			if createdBinding {
				if _, err := tx.ExecContext(ctx, `
INSERT INTO device_ownership_events
    (event_id, event_type, device_id, tenant_id, owner_id, binding_id,
     binding_revision, request_id, occurred_at)
		VALUES ($1, 'bind', $2, $3, $4, $5, $6, $7, $8)`,
					eventID, deviceID, tenantID, userID, bindingID,
					bindingRevision, record.RequestID, databaseNow); err != nil {
					return Record{}, err
				}
			}
		}
		record.Status = StatusBound
		return record, nil
	})
}

func (store *PostgresStore) Lookup(userID, tenantID, requestID string,
	now time.Time) (Record, error) {
	if store == nil || !auth.ValidIdentifier(userID, 128) ||
		!auth.ValidIdentifier(tenantID, 128) ||
		!ValidRequestID(requestID) || now.IsZero() {
		return Record{}, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(context.Background(),
		store.operationTimeout)
	defer cancel()
	var record Record
	var storedUser, storedTenant string
	var databaseNow time.Time
	err := store.db.QueryRowContext(ctx, `
SELECT request_id, device_id, owner_id, tenant_id, status, expires_at,
       CURRENT_TIMESTAMP
FROM ownership_claims WHERE request_id = $1`, requestID).
		Scan(&record.RequestID, &record.DeviceID, &storedUser, &storedTenant,
			&record.Status, &record.ExpiresAt, &databaseNow)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, unavailable("lookup ownership claim", err)
	}
	if storedUser != userID || storedTenant != tenantID {
		return Record{}, ErrUnauthorized
	}
	if !record.ExpiresAt.After(databaseNow) {
		record.Status = StatusExpired
	}
	return record, nil
}

func (store *PostgresStore) Owner(deviceID string) (Ownership, bool, error) {
	if store == nil || !auth.ValidIdentifier(deviceID, 64) {
		return Ownership{}, false, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(context.Background(),
		store.operationTimeout)
	defer cancel()
	return queryOwner(ctx, store.db, deviceID)
}

func (store *PostgresStore) Owners(
	deviceIDs []string) (map[string]Ownership, error) {
	if store == nil {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(context.Background(),
		store.operationTimeout)
	defer cancel()
	return queryOwners(ctx, store.db, deviceIDs)
}

func (store *PostgresStore) Release(userID, tenantID, deviceID string,
	now time.Time) (Ownership, error) {
	if store == nil || !auth.ValidIdentifier(userID, 128) ||
		!auth.ValidIdentifier(tenantID, 128) ||
		!auth.ValidIdentifier(deviceID, 64) || now.IsZero() {
		return Ownership{}, ErrInvalid
	}
	_ = now
	eventID, err := store.randomID(requestBytes)
	if err != nil {
		return Ownership{}, fmt.Errorf("generate ownership release event id: %w", err)
	}
	return store.runOwnershipTransaction(func(ctx context.Context,
		tx *sql.Tx) (Ownership, error) {
		databaseNow, err := transactionTime(ctx, tx)
		if err != nil {
			return Ownership{}, err
		}
		if err := lockDevice(ctx, tx, deviceID); err != nil {
			return Ownership{}, err
		}
		owner, found, err := selectOwner(ctx, tx, deviceID, true)
		if err != nil {
			return Ownership{}, err
		}
		if !found {
			return Ownership{}, ErrNotFound
		}
		if owner.OwnerID != userID || owner.TenantID != tenantID {
			return Ownership{}, ErrUnauthorized
		}
		if !owner.active {
			return owner.Ownership, nil
		}
		if owner.BindingRevision >= auth.MaximumBindingRevision {
			return Ownership{}, ErrConflict
		}
		owner.BindingRevision++
		if _, err := tx.ExecContext(ctx, `
UPDATE device_owners
SET binding_revision = $2, status = 'released'
WHERE device_id = $1`, deviceID, owner.BindingRevision); err != nil {
			return Ownership{}, err
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO device_ownership_events
    (event_id, event_type, device_id, tenant_id, owner_id, binding_id,
     binding_revision, request_id, occurred_at)
VALUES ($1, 'release', $2, $3, $4, $5, $6, NULL, $7)`,
			eventID, deviceID, tenantID, userID, owner.BindingID,
			owner.BindingRevision, databaseNow); err != nil {
			return Ownership{}, err
		}
		return owner.Ownership, nil
	})
}

type rowQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type rowsQuerier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func queryOwner(ctx context.Context, db rowQuerier,
	deviceID string) (Ownership, bool, error) {
	var owner Ownership
	err := db.QueryRowContext(ctx, `
SELECT owner_id, tenant_id, binding_id, binding_revision
FROM device_owners WHERE device_id = $1 AND status = 'active'`, deviceID).
		Scan(&owner.OwnerID, &owner.TenantID, &owner.BindingID,
			&owner.BindingRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return Ownership{}, false, nil
	}
	if err != nil {
		return Ownership{}, false, unavailable("resolve device owner", err)
	}
	return owner, true, nil
}

func queryOwners(ctx context.Context, db rowsQuerier,
	deviceIDs []string) (map[string]Ownership, error) {
	if len(deviceIDs) > 1000 {
		return nil, ErrInvalid
	}
	owners := make(map[string]Ownership, len(deviceIDs))
	if len(deviceIDs) == 0 {
		return owners, nil
	}
	arguments := make([]any, len(deviceIDs))
	seen := make(map[string]struct{}, len(deviceIDs))
	var query strings.Builder
	query.WriteString(`SELECT device_id, owner_id, tenant_id, binding_id,
       binding_revision
FROM device_owners WHERE status = 'active' AND device_id IN (`)
	for index, deviceID := range deviceIDs {
		if !auth.ValidIdentifier(deviceID, 64) {
			return nil, ErrInvalid
		}
		if _, exists := seen[deviceID]; exists {
			return nil, ErrInvalid
		}
		seen[deviceID] = struct{}{}
		if index > 0 {
			query.WriteByte(',')
		}
		_, _ = fmt.Fprintf(&query, "$%d", index+1)
		arguments[index] = deviceID
	}
	query.WriteByte(')')
	rows, err := db.QueryContext(ctx, query.String(), arguments...)
	if err != nil {
		return nil, unavailable("resolve device owners", err)
	}
	defer rows.Close()
	for rows.Next() {
		var deviceID string
		var owner Ownership
		if err := rows.Scan(&deviceID, &owner.OwnerID, &owner.TenantID,
			&owner.BindingID, &owner.BindingRevision); err != nil {
			return nil, unavailable("scan device owner", err)
		}
		if _, requested := seen[deviceID]; !requested ||
			!auth.ValidIdentifier(owner.OwnerID, 128) ||
			!auth.ValidIdentifier(owner.TenantID, 128) ||
			!ValidBindingID(owner.BindingID) ||
			!auth.ValidBindingRevision(owner.BindingRevision) {
			return nil, unavailable("validate device owner", ErrInvalid)
		}
		owners[deviceID] = owner
	}
	if err := rows.Err(); err != nil {
		return nil, unavailable("iterate device owners", err)
	}
	return owners, nil
}

// Prune removes expired replay material and old claim workflow rows. Ownership
// and ownership events are never pruned by the serving process.
func (store *PostgresStore) Prune(now time.Time) error {
	if store == nil || now.IsZero() {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(context.Background(),
		store.operationTimeout)
	defer cancel()
	tx, err := store.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return unavailable("begin ownership prune", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM ownership_app_nonces WHERE expires_at <= CURRENT_TIMESTAMP`); err != nil {
		return unavailable("prune ownership nonces", err)
	}
	if _, err := tx.ExecContext(ctx, `
DELETE FROM ownership_claims
WHERE expires_at <= CURRENT_TIMESTAMP - ($1 * INTERVAL '1 second')`,
		int64(store.ttl/time.Second)); err != nil {
		return unavailable("prune ownership claims", err)
	}
	if err := tx.Commit(); err != nil {
		return unavailable("commit ownership prune", err)
	}
	return nil
}

type recordTransaction func(context.Context, *sql.Tx) (Record, error)

type ownershipTransaction func(context.Context, *sql.Tx) (Ownership, error)

func (store *PostgresStore) runOwnershipTransaction(
	operation ownershipTransaction) (Ownership, error) {
	ctx, cancel := context.WithTimeout(context.Background(),
		store.operationTimeout)
	defer cancel()
	var lastErr error
	for attempt := 0; attempt < maximumDBAttempts; attempt++ {
		tx, err := store.db.BeginTx(ctx,
			&sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			return Ownership{}, unavailable("begin ownership transaction", err)
		}
		ownership, err := operation(ctx, tx)
		if err == nil {
			err = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
		if err == nil {
			return ownership, nil
		}
		if isBusinessError(err) {
			return Ownership{}, err
		}
		lastErr = err
		if !retryableDatabaseError(err) || ctx.Err() != nil {
			break
		}
	}
	return Ownership{}, unavailable("ownership transaction", lastErr)
}

func (store *PostgresStore) runRecordTransaction(
	operation recordTransaction) (Record, error) {
	ctx, cancel := context.WithTimeout(context.Background(),
		store.operationTimeout)
	defer cancel()
	var lastErr error
	for attempt := 0; attempt < maximumDBAttempts; attempt++ {
		tx, err := store.db.BeginTx(ctx,
			&sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			return Record{}, unavailable("begin ownership transaction", err)
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
		if isBusinessError(err) {
			return Record{}, err
		}
		lastErr = err
		if !retryableDatabaseError(err) || ctx.Err() != nil {
			break
		}
	}
	return Record{}, unavailable("ownership transaction", lastErr)
}

func selectClaimByDigest(ctx context.Context, tx *sql.Tx,
	digest [32]byte) (Record, string, string, bool, error) {
	var record Record
	var userID, tenantID string
	err := tx.QueryRowContext(ctx, `
SELECT request_id, device_id, owner_id, tenant_id, status, expires_at
FROM ownership_claims WHERE claim_digest = $1 FOR UPDATE`, digest[:]).
		Scan(&record.RequestID, &record.DeviceID, &userID, &tenantID,
			&record.Status, &record.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, "", "", false, nil
	}
	if err != nil {
		return Record{}, "", "", false, err
	}
	return record, userID, tenantID, true, nil
}

func transactionTime(ctx context.Context, tx *sql.Tx) (time.Time, error) {
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT CURRENT_TIMESTAMP`).
		Scan(&now); err != nil {
		return time.Time{}, err
	}
	return now.UTC(), nil
}

type ownershipRow struct {
	Ownership
	active bool
}

func selectOwner(ctx context.Context, tx *sql.Tx, deviceID string,
	forUpdate bool) (ownershipRow, bool, error) {
	query := `SELECT owner_id, tenant_id, binding_id, binding_revision, status
FROM device_owners WHERE device_id = $1`
	if forUpdate {
		query += ` FOR UPDATE`
	}
	var owner ownershipRow
	var status string
	err := tx.QueryRowContext(ctx, query, deviceID).
		Scan(&owner.OwnerID, &owner.TenantID, &owner.BindingID,
			&owner.BindingRevision, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return ownershipRow{}, false, nil
	}
	if err != nil {
		return ownershipRow{}, false, err
	}
	owner.active = status == "active"
	return owner, true, nil
}

func lockOwnershipKeys(ctx context.Context, tx *sql.Tx, deviceID string,
	digest [32]byte) error {
	keys := []string{
		"claim:" + hex.EncodeToString(digest[:]),
		"device:" + deviceID,
	}
	sort.Strings(keys)
	for _, key := range keys {
		if _, err := tx.ExecContext(ctx,
			`SELECT pg_advisory_xact_lock(hashtextextended($1, $2))`,
			key, postgresLockSeed); err != nil {
			return err
		}
	}
	return nil
}

func lockDevice(ctx context.Context, tx *sql.Tx, deviceID string) error {
	_, err := tx.ExecContext(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, $2))`,
		"device:"+deviceID, postgresLockSeed)
	return err
}

func (store *PostgresStore) randomID(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := io.ReadFull(store.random, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func retryableDatabaseError(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return pgErr.Code == "40001" || pgErr.Code == "40P01" ||
		pgErr.ConstraintName == "ownership_claims_claim_digest_key"
}

func isBusinessError(err error) bool {
	return errors.Is(err, ErrInvalid) || errors.Is(err, ErrReplay) ||
		errors.Is(err, ErrCapacity) || errors.Is(err, ErrConflict) ||
		errors.Is(err, ErrNotFound) || errors.Is(err, ErrExpired) ||
		errors.Is(err, ErrUnauthorized)
}

func unavailable(operation string, err error) error {
	if err == nil {
		err = ErrUnavailable
	}
	return fmt.Errorf("%w: %s: %v", ErrUnavailable, operation, err)
}
