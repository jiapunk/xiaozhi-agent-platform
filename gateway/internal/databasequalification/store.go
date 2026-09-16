package databasequalification

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

const (
	qualificationSchemaVersion  = 1
	qualificationSchemaContract = "xz-managed-db-qualification-v1-20260810"
	maximumEventSequence        = uint64(100000)
	minimumPostgresVersion      = 140000
)

var (
	ErrInvalid     = errors.New("invalid managed database qualification")
	ErrUnavailable = errors.New("managed database qualification unavailable")
	ErrConflict    = errors.New("managed database qualification conflict")
)

type Phase string

const (
	PhasePre              Phase = "pre"
	PhaseRestoreMarker    Phase = "restore-marker"
	PhaseRestoreExclusion Phase = "restore-exclusion"
	PhaseHeartbeat        Phase = "heartbeat"
	PhasePost             Phase = "post"
)

func (phase Phase) valid() bool {
	return phase == PhasePre || phase == PhaseRestoreMarker ||
		phase == PhaseRestoreExclusion || phase == PhaseHeartbeat ||
		phase == PhasePost
}

type Event struct {
	Sequence      uint64
	Phase         Phase
	PayloadSHA256 string
	CommittedAt   time.Time
	Existing      bool
}

type NodeSnapshot struct {
	BindingSHA256   string
	DatabaseTime    time.Time
	PostgresVersion int
}

type Store struct {
	db               *sql.DB
	role             Role
	operationTimeout time.Duration
}

func NewStore(database *sql.DB, role Role,
	operationTimeout time.Duration) (*Store, error) {
	if database == nil || !role.Valid() ||
		operationTimeout < 100*time.Millisecond || operationTimeout > 10*time.Second {
		return nil, fmt.Errorf("invalid managed database qualification store")
	}
	return &Store{db: database, role: role,
		operationTimeout: operationTimeout}, nil
}

func (store *Store) Close() error {
	if store == nil || store.db == nil {
		return ErrInvalid
	}
	return store.db.Close()
}

func (store *Store) Role() Role {
	if store == nil {
		return ""
	}
	return store.role
}

func (store *Store) VerifySchema(ctx context.Context) error {
	if store == nil || store.db == nil || ctx == nil {
		return ErrInvalid
	}
	operation, cancel := context.WithTimeout(ctx, store.operationTimeout)
	defer cancel()
	if err := store.db.PingContext(operation); err != nil {
		return unavailable("ping managed database", err)
	}
	checks, err := roleSchemaChecks(store.role)
	if err != nil {
		return err
	}
	checks = append(checks, schemaCheck{
		"xz_managed_database_qualification_schema",
		qualificationSchemaVersion, qualificationSchemaContract})
	for _, check := range checks {
		var version int
		var contract string
		query := "SELECT version, contract_id FROM " + check.table +
			" WHERE singleton = TRUE"
		if err := store.db.QueryRowContext(operation, query).
			Scan(&version, &contract); err != nil {
			return unavailable("read managed database schema", err)
		}
		if version != check.version || contract != check.contract {
			return fmt.Errorf("%w: managed database schema contract mismatch",
				ErrConflict)
		}
	}
	return nil
}

func (store *Store) Snapshot(ctx context.Context, nonce []byte) (
	NodeSnapshot, error) {
	if store == nil || store.db == nil || ctx == nil || len(nonce) != 16 {
		return NodeSnapshot{}, ErrInvalid
	}
	operation, cancel := context.WithTimeout(ctx, store.operationTimeout)
	defer cancel()
	var databaseName, serverAddress, readOnly, versionText string
	var postmasterStarted, databaseTime time.Time
	var recovery bool
	err := store.db.QueryRowContext(operation, `
SELECT current_database(), COALESCE(inet_server_addr()::text, 'local'),
       pg_postmaster_start_time(), pg_is_in_recovery(),
       current_setting('transaction_read_only'),
       current_setting('server_version_num'), CURRENT_TIMESTAMP`).
		Scan(&databaseName, &serverAddress, &postmasterStarted, &recovery,
			&readOnly, &versionText, &databaseTime)
	if err != nil {
		return NodeSnapshot{}, unavailable("read managed database node identity", err)
	}
	version, err := strconv.Atoi(versionText)
	if err != nil || version < minimumPostgresVersion || recovery ||
		readOnly != "off" || databaseName == "" || serverAddress == "" ||
		serverAddress == "local" {
		return NodeSnapshot{}, fmt.Errorf("%w: managed database node is not a writable primary",
			ErrConflict)
	}
	payload := bytes.NewBuffer(nil)
	payload.WriteString("XIAOZHI-M73-MANAGED-DATABASE-NODE-V1\x00")
	payload.Write(nonce)
	writeBounded(payload, string(store.role))
	writeBounded(payload, databaseName)
	writeBounded(payload, serverAddress)
	writeBounded(payload, postmasterStarted.UTC().Format(time.RFC3339Nano))
	writeBounded(payload, versionText)
	digest := sha256.Sum256(payload.Bytes())
	return NodeSnapshot{BindingSHA256: hex.EncodeToString(digest[:]),
		DatabaseTime: databaseTime.UTC(), PostgresVersion: version}, nil
}

func (store *Store) AppendEvent(ctx context.Context, qualificationID string,
	nonce []byte, sequence uint64, phase Phase, payloadSHA256 string) (
	Event, error) {
	payload, err := decodeEventInput(qualificationID, nonce, sequence,
		phase, payloadSHA256)
	if store == nil || store.db == nil || ctx == nil || err != nil {
		return Event{}, ErrInvalid
	}
	operation, cancel := context.WithTimeout(ctx, store.operationTimeout)
	defer cancel()
	tx, err := store.db.BeginTx(operation,
		&sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return Event{}, unavailable("begin managed database event", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	result, err := tx.ExecContext(operation, `
INSERT INTO managed_database_qualification_events
    (qualification_id, run_nonce, event_sequence, phase, payload_sha256)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (qualification_id, run_nonce, event_sequence) DO NOTHING`,
		qualificationID, nonce, sequence, string(phase), payload)
	if err != nil {
		return Event{}, databaseError("insert managed database event", err)
	}
	rows, err := result.RowsAffected()
	if err != nil || (rows != 0 && rows != 1) {
		return Event{}, databaseError("inspect managed database event insert", err)
	}
	var storedPhase string
	var storedPayload []byte
	var committedAt time.Time
	err = tx.QueryRowContext(operation, `
SELECT phase, payload_sha256, committed_at
FROM managed_database_qualification_events
WHERE qualification_id = $1 AND run_nonce = $2 AND event_sequence = $3`,
		qualificationID, nonce, sequence).
		Scan(&storedPhase, &storedPayload, &committedAt)
	if err != nil {
		return Event{}, databaseError("read managed database event", err)
	}
	if storedPhase != string(phase) || !bytes.Equal(storedPayload, payload) {
		return Event{}, ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return Event{}, databaseError("commit managed database event", err)
	}
	committed = true
	return Event{Sequence: sequence, Phase: phase,
		PayloadSHA256: payloadSHA256, CommittedAt: committedAt.UTC(),
		Existing: rows == 0}, nil
}

func (store *Store) LoadEvents(ctx context.Context, qualificationID string,
	nonce []byte) ([]Event, error) {
	if store == nil || store.db == nil || ctx == nil ||
		!auth.ValidIdentifier(qualificationID, 64) || len(nonce) != 16 {
		return nil, ErrInvalid
	}
	operation, cancel := context.WithTimeout(ctx, store.operationTimeout)
	defer cancel()
	rows, err := store.db.QueryContext(operation, `
SELECT event_sequence, phase, payload_sha256, committed_at
FROM managed_database_qualification_events
WHERE qualification_id = $1 AND run_nonce = $2
ORDER BY event_sequence`, qualificationID, nonce)
	if err != nil {
		return nil, unavailable("list managed database events", err)
	}
	defer rows.Close()
	events := make([]Event, 0, 64)
	for rows.Next() {
		var event Event
		var phase string
		var payload []byte
		if err := rows.Scan(&event.Sequence, &phase, &payload,
			&event.CommittedAt); err != nil {
			return nil, unavailable("scan managed database event", err)
		}
		event.Phase = Phase(phase)
		event.PayloadSHA256 = hex.EncodeToString(payload)
		event.CommittedAt = event.CommittedAt.UTC()
		if event.Sequence == 0 || event.Sequence > maximumEventSequence ||
			!event.Phase.valid() || len(payload) != sha256.Size {
			return nil, ErrConflict
		}
		events = append(events, event)
		if len(events) > int(maximumEventSequence) {
			return nil, ErrConflict
		}
	}
	if err := rows.Err(); err != nil {
		return nil, unavailable("iterate managed database events", err)
	}
	return events, nil
}

func EventsMatch(actual, expected []Event) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		if actual[index].Sequence != expected[index].Sequence ||
			actual[index].Phase != expected[index].Phase ||
			actual[index].PayloadSHA256 != expected[index].PayloadSHA256 ||
			!actual[index].CommittedAt.Equal(expected[index].CommittedAt) {
			return false
		}
	}
	return true
}

func decodeEventInput(qualificationID string, nonce []byte, sequence uint64,
	phase Phase, payloadSHA256 string) ([]byte, error) {
	if !auth.ValidIdentifier(qualificationID, 64) || len(nonce) != 16 ||
		sequence == 0 || sequence > maximumEventSequence || !phase.valid() ||
		len(payloadSHA256) != 64 {
		return nil, ErrInvalid
	}
	payload, err := hex.DecodeString(payloadSHA256)
	if err != nil || len(payload) != sha256.Size ||
		hex.EncodeToString(payload) != payloadSHA256 {
		return nil, ErrInvalid
	}
	return payload, nil
}

func writeBounded(buffer *bytes.Buffer, value string) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	buffer.Write(length[:])
	buffer.WriteString(value)
}

func databaseError(action string, err error) error {
	if err == nil {
		return ErrUnavailable
	}
	var postgres *pgconn.PgError
	if errors.As(err, &postgres) &&
		(postgres.Code == "23505" || postgres.Code == "23514") {
		return fmt.Errorf("%w: %s", ErrConflict, action)
	}
	return unavailable(action, err)
}

func unavailable(action string, err error) error {
	if err == nil {
		return ErrUnavailable
	}
	return fmt.Errorf("%w: %s", ErrUnavailable, action)
}
