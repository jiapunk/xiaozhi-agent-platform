// Package entitlementadapter provides the stable outbound SDK used by a
// selected billing or App Store adapter. It deliberately exposes normalized
// product entitlement state, never provider receipts or payment data.
package entitlementadapter

import (
	"context"
	"errors"
	"time"

	"xiaozhi-agent-platform/gateway/internal/accountauth"
)

const (
	APIVersion      = 1
	UpdateContract  = accountauth.ServiceEntitlementUpdateContract
	ApplyPath       = accountauth.ServiceEntitlementUpdatePath
	ContractHeader  = accountauth.EntitlementUpdateContractHeader
	KeyIDHeader     = accountauth.EntitlementUpdateKeyIDHeader
	SignatureHeader = accountauth.EntitlementUpdateSignatureHeader
)

var (
	ErrInvalid      = errors.New("invalid service entitlement update")
	ErrUnauthorized = errors.New("service entitlement signer unauthorized")
	ErrNotFound     = errors.New("product account not found")
	ErrConflict     = errors.New("service entitlement revision conflict")
	ErrUnavailable  = errors.New("service entitlement service unavailable")
)

type State string

const (
	StateActive    State = "active"
	StateGrace     State = "grace"
	StateSuspended State = "suspended"
	StateEnded     State = "ended"
)

type Principal struct {
	TenantID string
	Subject  string
}

// Update is intentionally provider-neutral. SourceEventID and PlanID must be
// opaque product identifiers; raw receipts, webhook bodies, prices, invoices,
// payment instruments, and provider customer identifiers have no SDK field.
type Update struct {
	Principal        Principal
	SourceEventID    string
	PreviousRevision uint64
	Revision         uint64
	PlanID           string
	State            State
	VoiceEnabled     bool
	AgentEnabled     bool
	AccessUntil      time.Time
}

type Disposition string

const (
	DispositionApplied  Disposition = "applied"
	DispositionReplayed Disposition = "replayed"
)

type Result struct {
	Disposition   Disposition
	SourceEventID string
	Revision      uint64
}

// Signer is implemented by the selected adapter's HSM/KMS integration. Sign
// receives exact domain-separated canonical bytes and returns one raw Ed25519
// signature. Private-key bytes never cross this interface.
type Signer interface {
	KeyID() string
	Sign(context.Context, []byte) ([]byte, error)
}

// MTLSClient is an opaque product-owned transport. It cannot be assembled or
// have its trust store, proxy behavior, or RoundTripper replaced by consumers.
type MTLSClient struct {
	inner *accountauth.EntitlementUpdateMTLSClient
}

// Client performs one signed delivery per Apply call and never retries.
type Client struct {
	inner *accountauth.HTTPServiceEntitlementUpdater
}

func NewMTLSClient(caPEM, certificatePEM, keyPEM []byte,
	timeout time.Duration) (*MTLSClient, error) {
	inner, err := accountauth.NewServiceEntitlementUpdateMTLSClient(
		caPEM, certificatePEM, keyPEM, timeout)
	if err != nil {
		return nil, ErrInvalid
	}
	return &MTLSClient{inner: inner}, nil
}

func ValidEndpoint(endpoint string) bool {
	return accountauth.ValidServiceEntitlementUpdateURL(endpoint)
}

func NewClient(endpoint string, transport *MTLSClient, signer Signer,
	authorizationTTL time.Duration) (*Client, error) {
	if transport == nil || transport.inner == nil || signer == nil {
		return nil, ErrInvalid
	}
	inner, err := accountauth.NewHTTPServiceEntitlementUpdater(
		endpoint, transport.inner, signer, authorizationTTL)
	if err != nil {
		return nil, ErrInvalid
	}
	return &Client{inner: inner}, nil
}

func (client *Client) Apply(ctx context.Context, update Update) (Result, error) {
	if client == nil || client.inner == nil {
		return Result{}, ErrInvalid
	}
	result, err := client.inner.Apply(ctx, accountauth.ServiceEntitlementUpdate{
		Principal: accountauth.Principal{
			TenantID: update.Principal.TenantID,
			Subject:  update.Principal.Subject,
		},
		SourceEventID:    update.SourceEventID,
		PreviousRevision: update.PreviousRevision,
		Revision:         update.Revision,
		PlanID:           update.PlanID,
		State:            accountauth.EntitlementState(update.State),
		VoiceEnabled:     update.VoiceEnabled,
		AgentEnabled:     update.AgentEnabled,
		AccessUntil:      update.AccessUntil,
	})
	if err != nil {
		return Result{}, publicError(err)
	}
	return Result{
		Disposition:   Disposition(result.Disposition),
		SourceEventID: result.SourceEventID,
		Revision:      result.Revision,
	}, nil
}

func publicError(err error) error {
	switch {
	case errors.Is(err, accountauth.ErrInvalid):
		return ErrInvalid
	case errors.Is(err, accountauth.ErrEntitlementUpdateUnauthorized):
		return ErrUnauthorized
	case errors.Is(err, accountauth.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, accountauth.ErrConflict):
		return ErrConflict
	default:
		return ErrUnavailable
	}
}
