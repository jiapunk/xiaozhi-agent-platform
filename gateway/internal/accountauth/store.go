// Package accountauth owns the durable account revision and Companion JTI
// ordering domain. Authentication itself remains an external IdP adapter
// responsibility; callers may begin a session only after that adapter has
// verified the exact tenant and subject.
package accountauth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

const (
	DatabaseContract       = "xz-companion-auth-db-v1-20260810"
	MaximumTokenLifetime   = time.Hour
	MinimumTokenLifetime   = time.Minute
	maximumClockSkew       = 30 * time.Second
	maximumAccountRevision = auth.MaximumBindingRevision
)

var (
	ErrInvalid           = errors.New("invalid Companion account authorization")
	ErrNotFound          = errors.New("Companion account authorization not found")
	ErrConflict          = errors.New("Companion account authorization conflict")
	ErrStaleSession      = errors.New("stale Companion account session")
	ErrSuspended         = errors.New("Companion account suspended")
	ErrInactive          = errors.New("Companion token inactive")
	ErrCapacity          = errors.New("Companion token capacity reached")
	ErrRevisionExhausted = errors.New("Companion account revision exhausted")
	ErrStaleEntitlement  = errors.New("stale service entitlement revision")
	ErrUnavailable       = errors.New("Companion account authorization unavailable")
)

type AccountStatus string

const (
	AccountActive    AccountStatus = "active"
	AccountSuspended AccountStatus = "suspended"
)

type Principal struct {
	TenantID string
	Subject  string
}

// Session is the revision observed after a selected IdP adapter authenticates
// Principal. RegisterToken requires this exact revision so a login flow racing
// with logout or suspension cannot publish a token after the revocation point.
type Session struct {
	Principal       Principal
	AccountRevision uint64
}

type Account struct {
	Principal Principal
	Revision  uint64
	Status    AccountStatus
	UpdatedAt time.Time
}

// TokenBinding is the only token material persisted or introspected. It never
// contains the raw JWT or signing key.
type TokenBinding struct {
	TokenID   string
	Subject   string
	TenantID  string
	Action    string
	DeviceID  string
	IssuedAt  int64
	ExpiresAt int64
}

type Authorization struct {
	Binding         TokenBinding
	AccountRevision uint64
	ValidUntil      int64
}

type RevocationReason string

const (
	RevocationLogout    RevocationReason = "account_logout"
	RevocationSuspended RevocationReason = "account_suspended"
	RevocationToken     RevocationReason = "token_revoked"
)

// Ledger is the single ordering boundary used for issuance, logout,
// suspension and introspection. A production implementation must serialize
// these operations across all replicas.
type Ledger interface {
	BeginAuthenticatedSession(context.Context, Principal) (Session, error)
	RegisterToken(context.Context, Session, TokenBinding) (Authorization, error)
	Introspect(context.Context, TokenBinding) (Authorization, bool, error)
	Logout(context.Context, Session) (Account, error)
	Suspend(context.Context, Principal) (Account, error)
	Resume(context.Context, Principal) (Account, error)
	RevokeToken(context.Context, Principal, string) error
}

type ReadyLedger interface {
	Ledger
	VerifySchema() error
}

type storedToken struct {
	authorization Authorization
	revokedAt     time.Time
	reason        RevocationReason
}

// Store is a bounded, single-process reference ledger for development and
// contract tests. It is not a production persistence adapter.
type Store struct {
	mu                sync.Mutex
	maximum           int
	now               func() time.Time
	accounts          map[Principal]Account
	tokens            map[string]*storedToken
	installations     map[Principal]map[string]*storedPushInstallation
	entitlements      map[Principal]ServiceEntitlement
	entitlementEvents map[string]storedEntitlementEvent
}

var _ Ledger = (*Store)(nil)

func NewStore(maximumTokens int) (*Store, error) {
	if maximumTokens < 1 || maximumTokens > 100000 {
		return nil, fmt.Errorf("invalid Companion authorization store configuration")
	}
	return &Store{
		maximum:           maximumTokens,
		now:               time.Now,
		accounts:          make(map[Principal]Account),
		tokens:            make(map[string]*storedToken),
		installations:     make(map[Principal]map[string]*storedPushInstallation),
		entitlements:      make(map[Principal]ServiceEntitlement),
		entitlementEvents: make(map[string]storedEntitlementEvent),
	}, nil
}

func ValidPrincipal(principal Principal) bool {
	return auth.ValidIdentifier(principal.TenantID, 128) &&
		auth.ValidIdentifier(principal.Subject, 128)
}

func ValidAccountRevision(revision uint64) bool {
	return revision > 0 && revision <= maximumAccountRevision
}

func ValidSession(session Session) bool {
	return ValidPrincipal(session.Principal) &&
		ValidAccountRevision(session.AccountRevision)
}

func ValidTokenBinding(binding TokenBinding) bool {
	if !auth.ValidIdentifier(binding.TokenID, 128) ||
		!auth.ValidIdentifier(binding.Subject, 128) ||
		!auth.ValidIdentifier(binding.TenantID, 128) ||
		binding.IssuedAt <= 0 || binding.ExpiresAt <= binding.IssuedAt ||
		binding.ExpiresAt-binding.IssuedAt < int64(MinimumTokenLifetime/time.Second) ||
		binding.ExpiresAt-binding.IssuedAt > int64(MaximumTokenLifetime/time.Second) {
		return false
	}
	switch binding.Action {
	case auth.CompanionClaimAction:
		return binding.DeviceID == ""
	case auth.CompanionReleaseAction, auth.CompanionConsentAction:
		return auth.ValidIdentifier(binding.DeviceID, 64)
	default:
		return false
	}
}

func BindingFromClaims(claims auth.Claims) (TokenBinding, error) {
	binding := TokenBinding{
		TokenID: claims.TokenID, Subject: claims.Subject,
		TenantID: claims.TenantID, Action: claims.Action,
		DeviceID: claims.DeviceID, IssuedAt: claims.IssuedAt,
		ExpiresAt: claims.Expires,
	}
	if claims.Audience != auth.CompanionAudience ||
		!auth.ValidHTTPSIssuer(claims.Issuer) || claims.OwnerID != "" ||
		claims.BindingID != "" || claims.BindingRevision != 0 ||
		claims.ReleaseID != "" || claims.ImageSHA256 != "" ||
		!ValidTokenBinding(binding) {
		return TokenBinding{}, ErrInvalid
	}
	return binding, nil
}

func (store *Store) BeginAuthenticatedSession(ctx context.Context,
	principal Principal) (Session, error) {
	if store == nil || ctx == nil || !ValidPrincipal(principal) {
		return Session{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Session{}, unavailable("begin authenticated session", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	now := store.now().UTC()
	account, found := store.accounts[principal]
	if !found {
		account = Account{Principal: principal, Revision: 1,
			Status: AccountActive, UpdatedAt: now}
		store.accounts[principal] = account
	}
	if account.Status != AccountActive {
		return Session{}, ErrSuspended
	}
	return Session{Principal: principal,
		AccountRevision: account.Revision}, nil
}

func (store *Store) RegisterToken(ctx context.Context, session Session,
	binding TokenBinding) (Authorization, error) {
	if store == nil || ctx == nil || !ValidSession(session) ||
		!ValidTokenBinding(binding) ||
		binding.Subject != session.Principal.Subject ||
		binding.TenantID != session.Principal.TenantID {
		return Authorization{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Authorization{}, unavailable("register token", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	now := store.now().UTC()
	account, found := store.accounts[session.Principal]
	if !found {
		return Authorization{}, ErrNotFound
	}
	if account.Status != AccountActive {
		return Authorization{}, ErrSuspended
	}
	if account.Revision != session.AccountRevision {
		return Authorization{}, ErrStaleSession
	}
	if binding.ExpiresAt <= now.Unix() ||
		binding.IssuedAt > now.Add(maximumClockSkew).Unix() {
		return Authorization{}, ErrInactive
	}
	if _, exists := store.tokens[binding.TokenID]; exists {
		return Authorization{}, ErrConflict
	}
	store.pruneExpiredLocked(now.Unix())
	if len(store.tokens) >= store.maximum {
		return Authorization{}, ErrCapacity
	}
	authorization := Authorization{Binding: binding,
		AccountRevision: account.Revision, ValidUntil: binding.ExpiresAt}
	store.tokens[binding.TokenID] = &storedToken{authorization: authorization}
	return authorization, nil
}

func (store *Store) Introspect(ctx context.Context,
	binding TokenBinding) (Authorization, bool, error) {
	if store == nil || ctx == nil || !ValidTokenBinding(binding) {
		return Authorization{}, false, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Authorization{}, false, unavailable("introspect token", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, found := store.tokens[binding.TokenID]
	if !found || record.authorization.Binding != binding ||
		!record.revokedAt.IsZero() || binding.ExpiresAt <= store.now().UTC().Unix() {
		return Authorization{}, false, nil
	}
	principal := Principal{TenantID: binding.TenantID, Subject: binding.Subject}
	account, found := store.accounts[principal]
	if !found || account.Status != AccountActive ||
		account.Revision != record.authorization.AccountRevision {
		return Authorization{}, false, nil
	}
	return record.authorization, true, nil
}

func (store *Store) Logout(ctx context.Context, session Session) (Account, error) {
	if store == nil || ctx == nil || !ValidSession(session) {
		return Account{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Account{}, unavailable("logout account", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	account, found := store.accounts[session.Principal]
	if !found {
		return Account{}, ErrNotFound
	}
	if account.Revision != session.AccountRevision {
		return Account{}, ErrStaleSession
	}
	return store.rotateLocked(account, AccountActive, RevocationLogout)
}

func (store *Store) Suspend(ctx context.Context,
	principal Principal) (Account, error) {
	return store.setStatus(ctx, principal, AccountSuspended)
}

func (store *Store) Resume(ctx context.Context,
	principal Principal) (Account, error) {
	return store.setStatus(ctx, principal, AccountActive)
}

func (store *Store) setStatus(ctx context.Context, principal Principal,
	status AccountStatus) (Account, error) {
	if store == nil || ctx == nil || !ValidPrincipal(principal) ||
		(status != AccountActive && status != AccountSuspended) {
		return Account{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Account{}, unavailable("change account status", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	account, found := store.accounts[principal]
	if !found {
		return Account{}, ErrNotFound
	}
	if account.Status == status {
		return account, nil
	}
	reason := RevocationSuspended
	if status == AccountActive {
		// Resume still advances the epoch, but previously revoked token rows keep
		// their original reason and can never become active again.
		reason = RevocationSuspended
	}
	return store.rotateLocked(account, status, reason)
}

func (store *Store) RevokeToken(ctx context.Context, principal Principal,
	tokenID string) error {
	if store == nil || ctx == nil || !ValidPrincipal(principal) ||
		!auth.ValidIdentifier(tokenID, 128) {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return unavailable("revoke token", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, found := store.tokens[tokenID]
	if !found || record.authorization.Binding.Subject != principal.Subject ||
		record.authorization.Binding.TenantID != principal.TenantID {
		return ErrNotFound
	}
	if record.revokedAt.IsZero() {
		record.revokedAt = store.now().UTC()
		record.reason = RevocationToken
	}
	return nil
}

func (store *Store) rotateLocked(account Account, status AccountStatus,
	reason RevocationReason) (Account, error) {
	if account.Revision >= maximumAccountRevision {
		return Account{}, ErrRevisionExhausted
	}
	now := store.now().UTC()
	oldRevision := account.Revision
	account.Revision++
	account.Status = status
	account.UpdatedAt = now
	store.accounts[account.Principal] = account
	for _, token := range store.tokens {
		binding := token.authorization.Binding
		if binding.Subject == account.Principal.Subject &&
			binding.TenantID == account.Principal.TenantID &&
			token.authorization.AccountRevision <= oldRevision &&
			token.revokedAt.IsZero() {
			token.revokedAt = now
			token.reason = reason
		}
	}
	delete(store.installations, account.Principal)
	return account, nil
}

func (store *Store) pruneExpiredLocked(nowUnix int64) {
	for tokenID, token := range store.tokens {
		if token.authorization.Binding.ExpiresAt <= nowUnix {
			delete(store.tokens, tokenID)
		}
	}
}

func unavailable(operation string, err error) error {
	if err == nil {
		err = ErrUnavailable
	}
	return fmt.Errorf("%w: %s: %v", ErrUnavailable, operation, err)
}
