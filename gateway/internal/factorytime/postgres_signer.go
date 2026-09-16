package factorytime

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"
)

// PostgresSignerAuthorizer is a read-only, independent signer-side check. It
// signs only receipts that exactly match an already committed authority row and
// whose database-time validity has not elapsed.
type PostgresSignerAuthorizer struct {
	db               *sql.DB
	operationTimeout time.Duration
}

var _ ReceiptSigningAuthorizer = (*PostgresSignerAuthorizer)(nil)

func NewPostgresSignerAuthorizer(database *sql.DB,
	operationTimeout time.Duration) (*PostgresSignerAuthorizer, error) {
	if database == nil || operationTimeout < 100*time.Millisecond ||
		operationTimeout > 30*time.Second {
		return nil, ErrInvalid
	}
	return &PostgresSignerAuthorizer{db: database,
		operationTimeout: operationTimeout}, nil
}

func (authorizer *PostgresSignerAuthorizer) VerifySchema() error {
	if authorizer == nil || authorizer.db == nil {
		return ErrUnavailable
	}
	store, err := NewPostgresStore(authorizer.db, authorizer.operationTimeout)
	if err != nil {
		return err
	}
	return store.VerifySchema()
}

type signerLedgerRecord struct {
	RequestID            string
	NonceSHA256          []byte
	StationID            string
	FixtureID            string
	FixtureVersion       string
	PolicySHA256         []byte
	PolicyID             string
	LedgerID             string
	PlanSHA256           []byte
	PlanID               string
	AuthorizationIssued  time.Time
	AuthorizationExpires time.Time
	AttemptID            string
	DeviceID             string
	BaseMAC              string
	AuthorityKeyID       string
	ObservedAt           time.Time
	ReceiptExpiresAt     time.Time
	DatabaseNow          time.Time
}

func (authorizer *PostgresSignerAuthorizer) AuthorizeSigning(
	ctx context.Context, receipt Receipt) error {
	if authorizer == nil || authorizer.db == nil || ctx == nil ||
		ValidateUnsignedReceipt(receipt) != nil {
		return ErrInvalid
	}
	requestDigest, err := hex.DecodeString(receipt.RequestSHA256)
	if err != nil || len(requestDigest) != sha256.Size {
		return ErrInvalid
	}
	operationContext, cancel := context.WithTimeout(ctx,
		authorizer.operationTimeout)
	defer cancel()
	var record signerLedgerRecord
	err = authorizer.db.QueryRowContext(operationContext, `
SELECT
    request_id, nonce_sha256,
    station_id, fixture_id, fixture_version,
    policy_sha256, policy_id, ledger_id,
    plan_sha256, plan_id,
    authorization_issued_at, authorization_expires_at,
    attempt_id, device_id, base_mac, authority_key_id,
    observed_at, receipt_expires_at, CURRENT_TIMESTAMP
FROM factory_trusted_time_requests
WHERE request_sha256 = $1`, requestDigest).Scan(
		&record.RequestID, &record.NonceSHA256,
		&record.StationID, &record.FixtureID, &record.FixtureVersion,
		&record.PolicySHA256, &record.PolicyID, &record.LedgerID,
		&record.PlanSHA256, &record.PlanID,
		&record.AuthorizationIssued, &record.AuthorizationExpires,
		&record.AttemptID, &record.DeviceID, &record.BaseMAC,
		&record.AuthorityKeyID, &record.ObservedAt,
		&record.ReceiptExpiresAt, &record.DatabaseNow)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUnauthorized
	}
	if err != nil {
		return unavailable("read committed signer receipt", err)
	}
	return validateSignerLedgerRecord(receipt, record)
}

func validateSignerLedgerRecord(receipt Receipt,
	record signerLedgerRecord) error {
	nonce, err := base64.RawURLEncoding.DecodeString(receipt.NonceB64URL)
	if err != nil || len(nonce) != 32 {
		return ErrInvalid
	}
	nonceDigest := sha256.Sum256(nonce)
	policyDigest, err := hex.DecodeString(receipt.Ledger.PolicySHA256)
	if err != nil || len(policyDigest) != sha256.Size {
		return ErrInvalid
	}
	planDigest, err := hex.DecodeString(receipt.Authorization.PlanSHA256)
	if err != nil || len(planDigest) != sha256.Size {
		return ErrInvalid
	}
	issued, issuedErr := parseTimestamp(receipt.Authorization.IssuedAt)
	planExpires, expiresErr := parseTimestamp(receipt.Authorization.ExpiresAt)
	observed, observedErr := parseTimestamp(receipt.ObservedAt)
	receiptExpires, receiptExpiresErr := parseTimestamp(receipt.ExpiresAt)
	if issuedErr != nil || expiresErr != nil || observedErr != nil ||
		receiptExpiresErr != nil {
		return ErrInvalid
	}
	if record.RequestID != receipt.RequestID ||
		!equalDigest(record.NonceSHA256, nonceDigest[:]) ||
		record.StationID != receipt.Station.ID ||
		record.FixtureID != receipt.Station.FixtureID ||
		record.FixtureVersion != receipt.Station.FixtureVersion ||
		!equalDigest(record.PolicySHA256, policyDigest) ||
		record.PolicyID != receipt.Ledger.PolicyID ||
		record.LedgerID != receipt.Ledger.LedgerID ||
		!equalDigest(record.PlanSHA256, planDigest) ||
		record.PlanID != receipt.Authorization.PlanID ||
		!record.AuthorizationIssued.Equal(issued) ||
		!record.AuthorizationExpires.Equal(planExpires) ||
		record.AttemptID != receipt.Transaction.AttemptID ||
		record.DeviceID != receipt.Transaction.DeviceID ||
		record.BaseMAC != receipt.Transaction.BaseMAC ||
		record.AuthorityKeyID != receipt.AuthorityKeyID ||
		!record.ObservedAt.Equal(observed) ||
		!record.ReceiptExpiresAt.Equal(receiptExpires) {
		return ErrUnauthorized
	}
	databaseNow := record.DatabaseNow.UTC()
	if databaseNow.Before(observed) || databaseNow.After(planExpires) ||
		!databaseNow.Before(receiptExpires) {
		return ErrOutsideWindow
	}
	return nil
}
