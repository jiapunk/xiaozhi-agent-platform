package accountauth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"sort"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

const (
	PushInstallationDatabaseContract   = "xz-companion-push-db-v1-20260810"
	MaximumPushInstallationsPerAccount = 16
	MaximumPushInstallationLifetime    = 35 * 24 * time.Hour
	pushInstallationIDBytes            = 16
)

type PushPlatform string

const (
	PushPlatformAPNSProduction  PushPlatform = "apns-production"
	PushPlatformAPNSDevelopment PushPlatform = "apns-development"
	PushPlatformFCM             PushPlatform = "fcm"
)

// ProtectedPushToken is the only provider-address material accepted by the
// ledger. The BFF seals the raw token before this boundary. Ciphertext is
// opaque; Digest is a keyed lookup/CAS digest produced by the same protector.
type ProtectedPushToken struct {
	Ciphertext []byte
	KeyID      string
	Digest     [32]byte
}

type PushInstallationRegistration struct {
	InstallationID string
	Platform       PushPlatform
	Token          ProtectedPushToken
}

type PushInstallation struct {
	InstallationID  string
	Principal       Principal
	AccountRevision uint64
	Platform        PushPlatform
	Token           ProtectedPushToken
	RegisteredAt    time.Time
	RefreshedAt     time.Time
	ValidUntil      time.Time
}

// PushInstallationStore shares the account revision ordering domain. Logout,
// suspension and registration therefore cannot race across replicas and leave
// an old provider token active.
type PushInstallationStore interface {
	UpsertPushInstallation(context.Context, Session,
		PushInstallationRegistration) (PushInstallation, error)
	RemovePushInstallation(context.Context, Session, string) error
	ActivePushInstallations(context.Context, Principal) ([]PushInstallation, error)
	InvalidatePushInstallation(context.Context, Principal, string, [32]byte) error
}

var _ PushInstallationStore = (*Store)(nil)

type storedPushInstallation struct {
	installation PushInstallation
}

func ValidPushInstallationID(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == pushInstallationIDBytes &&
		base64.RawURLEncoding.EncodeToString(decoded) == value
}

func ValidPushPlatform(platform PushPlatform) bool {
	return platform == PushPlatformAPNSProduction ||
		platform == PushPlatformAPNSDevelopment || platform == PushPlatformFCM
}

func ValidProtectedPushToken(token ProtectedPushToken) bool {
	if len(token.Ciphertext) < 32 || len(token.Ciphertext) > 8*1024 ||
		!auth.ValidIdentifier(token.KeyID, 64) {
		return false
	}
	var zero [32]byte
	return subtle.ConstantTimeCompare(token.Digest[:], zero[:]) == 0
}

func ValidPushInstallationRegistration(registration PushInstallationRegistration) bool {
	return ValidPushInstallationID(registration.InstallationID) &&
		ValidPushPlatform(registration.Platform) &&
		ValidProtectedPushToken(registration.Token)
}

func (store *Store) UpsertPushInstallation(ctx context.Context, session Session,
	registration PushInstallationRegistration) (PushInstallation, error) {
	if store == nil || ctx == nil || !ValidSession(session) ||
		!ValidPushInstallationRegistration(registration) {
		return PushInstallation{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return PushInstallation{}, unavailable("upsert push installation", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	account, found := store.accounts[session.Principal]
	if !found {
		return PushInstallation{}, ErrNotFound
	}
	if account.Status != AccountActive {
		return PushInstallation{}, ErrSuspended
	}
	if account.Revision != session.AccountRevision {
		return PushInstallation{}, ErrStaleSession
	}
	now := store.now().UTC()
	store.prunePushInstallationsLocked(now)
	installations := store.installations[session.Principal]
	if installations == nil {
		installations = make(map[string]*storedPushInstallation)
		store.installations[session.Principal] = installations
	}
	for principal, candidates := range store.installations {
		for installationID, candidate := range candidates {
			if principal != session.Principal || installationID != registration.InstallationID {
				if candidate.installation.Platform == registration.Platform &&
					subtle.ConstantTimeCompare(candidate.installation.Token.Digest[:],
						registration.Token.Digest[:]) == 1 {
					return PushInstallation{}, ErrConflict
				}
			}
		}
	}
	existing, replacing := installations[registration.InstallationID]
	if !replacing && len(installations) >= MaximumPushInstallationsPerAccount {
		return PushInstallation{}, ErrCapacity
	}
	registeredAt := now
	if replacing {
		registeredAt = existing.installation.RegisteredAt
	}
	installation := PushInstallation{
		InstallationID: registration.InstallationID,
		Principal:      session.Principal, AccountRevision: account.Revision,
		Platform: registration.Platform, Token: cloneProtectedPushToken(registration.Token),
		RegisteredAt: registeredAt, RefreshedAt: now,
		ValidUntil: now.Add(MaximumPushInstallationLifetime),
	}
	installations[registration.InstallationID] = &storedPushInstallation{
		installation: clonePushInstallation(installation),
	}
	return clonePushInstallation(installation), nil
}

func (store *Store) RemovePushInstallation(ctx context.Context, session Session,
	installationID string) error {
	if store == nil || ctx == nil || !ValidSession(session) ||
		!ValidPushInstallationID(installationID) {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return unavailable("remove push installation", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	account, found := store.accounts[session.Principal]
	if !found {
		return ErrNotFound
	}
	if account.Status != AccountActive {
		return ErrSuspended
	}
	if account.Revision != session.AccountRevision {
		return ErrStaleSession
	}
	delete(store.installations[session.Principal], installationID)
	return nil
}

func (store *Store) ActivePushInstallations(ctx context.Context,
	principal Principal) ([]PushInstallation, error) {
	if store == nil || ctx == nil || !ValidPrincipal(principal) {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, unavailable("list push installations", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	now := store.now().UTC()
	store.prunePushInstallationsLocked(now)
	account, found := store.accounts[principal]
	if !found || account.Status != AccountActive {
		return nil, nil
	}
	result := make([]PushInstallation, 0, len(store.installations[principal]))
	for _, candidate := range store.installations[principal] {
		if candidate.installation.AccountRevision == account.Revision &&
			candidate.installation.ValidUntil.After(now) {
			result = append(result, clonePushInstallation(candidate.installation))
		}
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].InstallationID < result[right].InstallationID
	})
	return result, nil
}

func (store *Store) InvalidatePushInstallation(ctx context.Context,
	principal Principal, installationID string, digest [32]byte) error {
	if store == nil || ctx == nil || !ValidPrincipal(principal) ||
		!ValidPushInstallationID(installationID) {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return unavailable("invalidate push installation", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	candidate, found := store.installations[principal][installationID]
	if !found || subtle.ConstantTimeCompare(candidate.installation.Token.Digest[:],
		digest[:]) != 1 {
		return ErrNotFound
	}
	delete(store.installations[principal], installationID)
	return nil
}

func (store *Store) prunePushInstallationsLocked(now time.Time) {
	for principal, installations := range store.installations {
		for installationID, candidate := range installations {
			if !candidate.installation.ValidUntil.After(now) {
				delete(installations, installationID)
			}
		}
		if len(installations) == 0 {
			delete(store.installations, principal)
		}
	}
}

func cloneProtectedPushToken(token ProtectedPushToken) ProtectedPushToken {
	clone := token
	clone.Ciphertext = append([]byte(nil), token.Ciphertext...)
	return clone
}

func clonePushInstallation(installation PushInstallation) PushInstallation {
	clone := installation
	clone.Token = cloneProtectedPushToken(installation.Token)
	return clone
}
