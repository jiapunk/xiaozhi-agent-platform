package accountauth

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

const (
	ServiceEntitlementContract         = "xz-service-entitlement-v1"
	ServiceEntitlementDatabaseContract = "xz-service-entitlement-db-v1-20260811"
	maximumEntitlementValidity         = 400 * 24 * time.Hour
	entitlementDigestDomain            = "xiaozhi-service-entitlement-event-v1\x00"
)

type ProductService string

const (
	ProductServiceVoice ProductService = "voice"
	ProductServiceAgent ProductService = "agent"
)

type EntitlementState string

const (
	EntitlementActive    EntitlementState = "active"
	EntitlementGrace     EntitlementState = "grace"
	EntitlementSuspended EntitlementState = "suspended"
	EntitlementEnded     EntitlementState = "ended"
)

type ServiceEntitlement struct {
	Principal     Principal
	Revision      uint64
	PlanID        string
	State         EntitlementState
	VoiceEnabled  bool
	AgentEnabled  bool
	AccessUntil   time.Time
	SourceEventID string
	AppliedAt     time.Time
}

type ServiceEntitlementUpdate struct {
	Principal        Principal
	SourceEventID    string
	PreviousRevision uint64
	Revision         uint64
	PlanID           string
	State            EntitlementState
	VoiceEnabled     bool
	AgentEnabled     bool
	AccessUntil      time.Time
}

type ServiceEntitlementGrant struct {
	Revision   uint64
	State      EntitlementState
	ValidUntil time.Time
}

type ServiceEntitlementLedger interface {
	ApplyServiceEntitlement(context.Context, ServiceEntitlementUpdate) (
		ServiceEntitlement, bool, error)
	AuthorizeService(context.Context, Principal, ProductService) (
		ServiceEntitlementGrant, bool, error)
}

type ServiceEntitlementAuthorizer interface {
	AuthorizeService(context.Context, Principal, ProductService) (
		ServiceEntitlementGrant, bool, error)
}

type storedEntitlementEvent struct {
	digest      [sha256.Size]byte
	entitlement ServiceEntitlement
}

var _ ServiceEntitlementLedger = (*Store)(nil)

func ValidProductService(service ProductService) bool {
	return service == ProductServiceVoice || service == ProductServiceAgent
}

func ValidEntitlementState(state EntitlementState) bool {
	switch state {
	case EntitlementActive, EntitlementGrace,
		EntitlementSuspended, EntitlementEnded:
		return true
	default:
		return false
	}
}

func ValidServiceEntitlementUpdate(update ServiceEntitlementUpdate,
	now time.Time) bool {
	if !ValidPrincipal(update.Principal) ||
		!auth.ValidIdentifier(update.SourceEventID, 128) ||
		!auth.ValidIdentifier(update.PlanID, 64) ||
		!ValidEntitlementState(update.State) ||
		update.Revision == 0 || update.Revision > maximumAccountRevision ||
		update.PreviousRevision >= update.Revision ||
		update.Revision != update.PreviousRevision+1 ||
		!validEntitlementTime(update.AccessUntil) {
		return false
	}
	now = now.UTC()
	accessUntil := update.AccessUntil.UTC()
	if accessUntil.After(now.Add(maximumEntitlementValidity)) {
		return false
	}
	available := update.State == EntitlementActive ||
		update.State == EntitlementGrace
	if available {
		return (update.VoiceEnabled || update.AgentEnabled) &&
			accessUntil.After(now)
	}
	return !update.VoiceEnabled && !update.AgentEnabled
}

func validServiceEntitlement(entitlement ServiceEntitlement) bool {
	if !ValidPrincipal(entitlement.Principal) ||
		!ValidAccountRevision(entitlement.Revision) ||
		!auth.ValidIdentifier(entitlement.PlanID, 64) ||
		!auth.ValidIdentifier(entitlement.SourceEventID, 128) ||
		!ValidEntitlementState(entitlement.State) ||
		!validEntitlementTime(entitlement.AccessUntil) ||
		!validEntitlementTime(entitlement.AppliedAt) {
		return false
	}
	available := entitlement.State == EntitlementActive ||
		entitlement.State == EntitlementGrace
	return available == (entitlement.VoiceEnabled || entitlement.AgentEnabled)
}

func validEntitlementTime(value time.Time) bool {
	if value.IsZero() || value.Nanosecond() != 0 ||
		value.Location() != time.UTC {
		return false
	}
	unix := value.Unix()
	return unix >= 1609459200 && unix <= 4102444800
}

func entitlementUpdateDigest(update ServiceEntitlementUpdate) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte(entitlementDigestDomain))
	writeDigestString(hash, update.Principal.TenantID)
	writeDigestString(hash, update.Principal.Subject)
	writeDigestString(hash, update.SourceEventID)
	writeDigestUint64(hash, update.PreviousRevision)
	writeDigestUint64(hash, update.Revision)
	writeDigestString(hash, update.PlanID)
	writeDigestString(hash, string(update.State))
	if update.VoiceEnabled {
		_, _ = hash.Write([]byte{1})
	} else {
		_, _ = hash.Write([]byte{0})
	}
	if update.AgentEnabled {
		_, _ = hash.Write([]byte{1})
	} else {
		_, _ = hash.Write([]byte{0})
	}
	writeDigestUint64(hash, uint64(update.AccessUntil.Unix()))
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

type digestWriter interface {
	Write([]byte) (int, error)
}

func writeDigestString(writer digestWriter, value string) {
	writeDigestUint64(writer, uint64(len(value)))
	_, _ = writer.Write([]byte(value))
}

func writeDigestUint64(writer digestWriter, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	_, _ = writer.Write(encoded[:])
}

func (store *Store) ApplyServiceEntitlement(ctx context.Context,
	update ServiceEntitlementUpdate) (ServiceEntitlement, bool, error) {
	if store == nil || ctx == nil {
		return ServiceEntitlement{}, false, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return ServiceEntitlement{}, false,
			unavailable("apply service entitlement", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	now := store.now().UTC().Truncate(time.Second)
	update.AccessUntil = update.AccessUntil.UTC()
	if !ValidServiceEntitlementUpdate(update, now) {
		return ServiceEntitlement{}, false, ErrInvalid
	}
	digest := entitlementUpdateDigest(update)
	if event, found := store.entitlementEvents[update.SourceEventID]; found {
		if event.digest != digest {
			return ServiceEntitlement{}, false, ErrConflict
		}
		return event.entitlement, false, nil
	}
	account, found := store.accounts[update.Principal]
	if !found {
		return ServiceEntitlement{}, false, ErrNotFound
	}
	current, found := store.entitlements[update.Principal]
	currentRevision := uint64(0)
	if found {
		currentRevision = current.Revision
	}
	if currentRevision != update.PreviousRevision {
		return ServiceEntitlement{}, false, ErrStaleEntitlement
	}
	entitlement := ServiceEntitlement{
		Principal: update.Principal, Revision: update.Revision,
		PlanID: update.PlanID, State: update.State,
		VoiceEnabled: update.VoiceEnabled,
		AgentEnabled: update.AgentEnabled,
		AccessUntil:  update.AccessUntil, SourceEventID: update.SourceEventID,
		AppliedAt: now,
	}
	if !validServiceEntitlement(entitlement) ||
		!ValidAccountRevision(account.Revision) {
		return ServiceEntitlement{}, false, ErrUnavailable
	}
	store.entitlements[update.Principal] = entitlement
	store.entitlementEvents[update.SourceEventID] = storedEntitlementEvent{
		digest: digest, entitlement: entitlement,
	}
	return entitlement, true, nil
}

func (store *Store) AuthorizeService(ctx context.Context,
	principal Principal, service ProductService) (
	ServiceEntitlementGrant, bool, error) {
	if store == nil || ctx == nil || !ValidPrincipal(principal) ||
		!ValidProductService(service) {
		return ServiceEntitlementGrant{}, false, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return ServiceEntitlementGrant{}, false,
			unavailable("authorize service entitlement", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	account, accountFound := store.accounts[principal]
	entitlement, found := store.entitlements[principal]
	if !accountFound || account.Status != AccountActive || !found {
		return ServiceEntitlementGrant{}, false, nil
	}
	if !validServiceEntitlement(entitlement) {
		return ServiceEntitlementGrant{}, false, ErrUnavailable
	}
	now := store.now().UTC().Truncate(time.Second)
	availableState := entitlement.State == EntitlementActive ||
		entitlement.State == EntitlementGrace
	enabled := (service == ProductServiceVoice && entitlement.VoiceEnabled) ||
		(service == ProductServiceAgent && entitlement.AgentEnabled)
	if !availableState || !enabled || !entitlement.AccessUntil.After(now) {
		return ServiceEntitlementGrant{}, false, nil
	}
	return ServiceEntitlementGrant{Revision: entitlement.Revision,
		State: entitlement.State, ValidUntil: entitlement.AccessUntil}, true, nil
}

func isEntitlementDenied(err error) bool {
	return errors.Is(err, ErrNotFound) || errors.Is(err, ErrSuspended) ||
		errors.Is(err, ErrInactive)
}
