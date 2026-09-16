package factorytime

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

type Reservation struct {
	Request                 Request
	RequestSHA256           [32]byte
	NonceSHA256             [32]byte
	ClientCertificateSHA256 [32]byte
	AuthorityKeyID          string
}

// Store is the atomic station-authorization and replay-ledger boundary. A
// successful Reserve permanently consumes the request ID and nonce, even if a
// later external signing operation fails.
type Store interface {
	Reserve(context.Context, Reservation, time.Duration) (time.Time, error)
}

// Signer is implemented by an external HSM/KMS adapter. Implementations must
// sign the supplied payload with Ed25519 and return exactly 64 signature bytes.
type Signer interface {
	KeyID() string
	Sign(context.Context, []byte) ([]byte, error)
}

type Authority struct {
	store           Store
	signer          Signer
	keyID           string
	receiptLifetime time.Duration
}

func NewAuthority(store Store, signer Signer,
	receiptLifetime time.Duration) (*Authority, error) {
	if store == nil || signer == nil || !validIdentifier(signer.KeyID()) ||
		receiptLifetime < time.Second ||
		receiptLifetime > MaximumReceiptSeconds*time.Second ||
		receiptLifetime%time.Second != 0 {
		return nil, ErrInvalid
	}
	return &Authority{store: store, signer: signer, keyID: signer.KeyID(),
		receiptLifetime: receiptLifetime}, nil
}

func (authority *Authority) Issue(ctx context.Context, request Request,
	requestSHA256 [32]byte, clientCertificateDER []byte) ([]byte, error) {
	if authority == nil || authority.store == nil || authority.signer == nil ||
		len(clientCertificateDER) == 0 || ValidateRequest(request) != nil {
		return nil, ErrInvalid
	}
	canonicalRequest, err := CanonicalJSON(request)
	if err != nil || sha256.Sum256(canonicalRequest) != requestSHA256 {
		return nil, ErrInvalid
	}
	nonce, err := base64.RawURLEncoding.DecodeString(request.NonceB64URL)
	if err != nil || len(nonce) != 32 {
		return nil, ErrInvalid
	}
	reservation := Reservation{
		Request: request, RequestSHA256: requestSHA256,
		NonceSHA256:             sha256.Sum256(nonce),
		ClientCertificateSHA256: sha256.Sum256(clientCertificateDER),
		AuthorityKeyID:          authority.keyID,
	}
	observedAt, err := authority.store.Reserve(ctx, reservation,
		authority.receiptLifetime)
	if err != nil {
		return nil, err
	}
	observedAt = observedAt.UTC().Truncate(time.Second)
	planIssued, _ := parseTimestamp(request.Authorization.IssuedAt)
	planExpires, _ := parseTimestamp(request.Authorization.ExpiresAt)
	if observedAt.Before(planIssued) || observedAt.After(planExpires) {
		return nil, fmt.Errorf("%w: store returned unsafe time", ErrUnavailable)
	}
	receipt := Receipt{
		Schema: ReceiptSchema, Environment: Environment, Scope: Scope,
		RequestSHA256: hex.EncodeToString(requestSHA256[:]),
		RequestID:     request.RequestID, NonceB64URL: request.NonceB64URL,
		Ledger: request.Ledger, Authorization: request.Authorization,
		Transaction: request.Transaction, Station: request.Station,
		AuthorityKeyID: authority.keyID,
		ObservedAt:     observedAt.Format("2006-01-02T15:04:05Z"),
		ExpiresAt: observedAt.Add(authority.receiptLifetime).
			Format("2006-01-02T15:04:05Z"),
		Result: ReceiptResult, SignatureAlgorithm: SignatureAlgorithm,
	}
	unsigned, err := CanonicalJSON(receipt)
	if err != nil {
		return nil, fmt.Errorf("%w: canonicalize receipt", ErrUnavailable)
	}
	payload := make([]byte, 0, len(SignatureDomain)+len(unsigned))
	payload = append(payload, []byte(SignatureDomain)...)
	payload = append(payload, unsigned...)
	signature, err := authority.signer.Sign(ctx, payload)
	if err != nil || len(signature) != 64 {
		return nil, fmt.Errorf("%w: external signer failed", ErrUnavailable)
	}
	receipt.SignatureB64URL = base64.RawURLEncoding.EncodeToString(signature)
	response, err := CanonicalJSON(receipt)
	if err != nil || len(response) == 0 || len(response) > MaximumResponseBytes {
		return nil, fmt.Errorf("%w: encode receipt", ErrUnavailable)
	}
	return response, nil
}

func equalDigest(left, right []byte) bool {
	return len(left) == sha256.Size && len(right) == sha256.Size &&
		subtle.ConstantTimeCompare(left, right) == 1
}

func businessError(err error) bool {
	return errors.Is(err, ErrInvalid) || errors.Is(err, ErrUnauthorized) ||
		errors.Is(err, ErrReplay) || errors.Is(err, ErrOutsideWindow) ||
		errors.Is(err, ErrUnavailable)
}
