package accountauth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"time"
)

var _ ServiceEntitlementLedger = (*PostgresStore)(nil)

func (store *PostgresStore) ApplyServiceEntitlement(ctx context.Context,
	update ServiceEntitlementUpdate) (ServiceEntitlement, bool, error) {
	if store == nil || store.db == nil || ctx == nil {
		return ServiceEntitlement{}, false, ErrInvalid
	}
	update.AccessUntil = update.AccessUntil.UTC()
	type result struct {
		entitlement ServiceEntitlement
		applied     bool
	}
	value, err := runPostgresTransaction(store, ctx, func(ctx context.Context,
		tx *sql.Tx) (result, error) {
		now, err := postgresTime(ctx, tx)
		if err != nil {
			return result{}, err
		}
		now = now.Truncate(time.Second)
		if !ValidServiceEntitlementUpdate(update, now) {
			return result{}, ErrInvalid
		}
		account, found, err := selectAccount(ctx, tx, update.Principal)
		if err != nil {
			return result{}, err
		}
		if !found {
			return result{}, ErrNotFound
		}
		digest := entitlementUpdateDigest(update)
		replayed, found, err := selectEntitlementEvent(
			ctx, tx, update.SourceEventID)
		if err != nil {
			return result{}, err
		}
		if found {
			if subtle.ConstantTimeCompare(replayed.digest[:], digest[:]) != 1 {
				return result{}, ErrConflict
			}
			return result{entitlement: replayed.entitlement}, nil
		}
		var currentRevision uint64
		err = tx.QueryRowContext(ctx, `
SELECT revision FROM service_entitlements
WHERE tenant_id = $1 AND subject = $2
FOR UPDATE`, update.Principal.TenantID, update.Principal.Subject).
			Scan(&currentRevision)
		if errors.Is(err, sql.ErrNoRows) {
			currentRevision = 0
		} else if err != nil {
			return result{}, err
		}
		if currentRevision != update.PreviousRevision {
			return result{}, ErrStaleEntitlement
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO service_entitlement_events
    (source_event_id, tenant_id, subject, previous_revision, revision,
     update_digest, plan_id, state, voice_enabled, agent_enabled,
     access_until, applied_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
			update.SourceEventID, update.Principal.TenantID,
			update.Principal.Subject, update.PreviousRevision, update.Revision,
			digest[:], update.PlanID, update.State, update.VoiceEnabled,
			update.AgentEnabled, update.AccessUntil, now); err != nil {
			return result{}, err
		}
		if currentRevision == 0 {
			_, err = tx.ExecContext(ctx, `
INSERT INTO service_entitlements
    (tenant_id, subject, revision, plan_id, state, voice_enabled,
     agent_enabled, access_until, source_event_id, applied_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)`,
				update.Principal.TenantID, update.Principal.Subject,
				update.Revision, update.PlanID, update.State,
				update.VoiceEnabled, update.AgentEnabled, update.AccessUntil,
				update.SourceEventID, now)
		} else {
			var changed sql.Result
			changed, err = tx.ExecContext(ctx, `
UPDATE service_entitlements
SET revision = $3, plan_id = $4, state = $5, voice_enabled = $6,
    agent_enabled = $7, access_until = $8, source_event_id = $9,
    updated_at = $10
WHERE tenant_id = $1 AND subject = $2 AND revision = $11`,
				update.Principal.TenantID, update.Principal.Subject,
				update.Revision, update.PlanID, update.State,
				update.VoiceEnabled, update.AgentEnabled, update.AccessUntil,
				update.SourceEventID, now, currentRevision)
			if err == nil {
				var count int64
				count, err = changed.RowsAffected()
				if err == nil && count != 1 {
					err = ErrStaleEntitlement
				}
			}
		}
		if err != nil {
			return result{}, err
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
			return result{}, ErrUnavailable
		}
		return result{entitlement: entitlement, applied: true}, nil
	})
	if err != nil {
		return ServiceEntitlement{}, false, err
	}
	return value.entitlement, value.applied, nil
}

func (store *PostgresStore) AuthorizeService(ctx context.Context,
	principal Principal, service ProductService) (
	ServiceEntitlementGrant, bool, error) {
	if store == nil || store.db == nil || ctx == nil ||
		!ValidPrincipal(principal) || !ValidProductService(service) {
		return ServiceEntitlementGrant{}, false, ErrInvalid
	}
	type result struct {
		grant   ServiceEntitlementGrant
		allowed bool
	}
	value, err := runPostgresTransaction(store, ctx, func(ctx context.Context,
		tx *sql.Tx) (result, error) {
		now, err := postgresTime(ctx, tx)
		if err != nil {
			return result{}, err
		}
		now = now.Truncate(time.Second)
		account, found, err := selectAccount(ctx, tx, principal)
		if err != nil {
			return result{}, err
		}
		if !found || account.Status != AccountActive {
			return result{}, nil
		}
		entitlement, found, err := selectCurrentEntitlement(ctx, tx, principal)
		if err != nil {
			return result{}, err
		}
		if !found {
			return result{}, nil
		}
		if !validServiceEntitlement(entitlement) {
			return result{}, ErrUnavailable
		}
		availableState := entitlement.State == EntitlementActive ||
			entitlement.State == EntitlementGrace
		enabled := (service == ProductServiceVoice && entitlement.VoiceEnabled) ||
			(service == ProductServiceAgent && entitlement.AgentEnabled)
		if !availableState || !enabled || !entitlement.AccessUntil.After(now) {
			return result{}, nil
		}
		return result{allowed: true, grant: ServiceEntitlementGrant{
			Revision: entitlement.Revision, State: entitlement.State,
			ValidUntil: entitlement.AccessUntil,
		}}, nil
	})
	if err != nil {
		return ServiceEntitlementGrant{}, false, err
	}
	return value.grant, value.allowed, nil
}

func selectEntitlementEvent(ctx context.Context, tx *sql.Tx,
	eventID string) (storedEntitlementEvent, bool, error) {
	var (
		event  storedEntitlementEvent
		digest []byte
		state  string
	)
	err := tx.QueryRowContext(ctx, `
SELECT tenant_id, subject, revision, plan_id, state, voice_enabled,
       agent_enabled, access_until, source_event_id, applied_at,
       update_digest
FROM service_entitlement_events
WHERE source_event_id = $1
FOR SHARE`, eventID).Scan(
		&event.entitlement.Principal.TenantID,
		&event.entitlement.Principal.Subject,
		&event.entitlement.Revision, &event.entitlement.PlanID, &state,
		&event.entitlement.VoiceEnabled, &event.entitlement.AgentEnabled,
		&event.entitlement.AccessUntil, &event.entitlement.SourceEventID,
		&event.entitlement.AppliedAt, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return storedEntitlementEvent{}, false, nil
	}
	if err != nil {
		return storedEntitlementEvent{}, false, err
	}
	if len(digest) != len(event.digest) {
		return storedEntitlementEvent{}, false, ErrUnavailable
	}
	copy(event.digest[:], digest)
	event.entitlement.State = EntitlementState(state)
	event.entitlement.AccessUntil = event.entitlement.AccessUntil.UTC()
	event.entitlement.AppliedAt = event.entitlement.AppliedAt.UTC()
	if !validServiceEntitlement(event.entitlement) {
		return storedEntitlementEvent{}, false, ErrUnavailable
	}
	return event, true, nil
}

func selectCurrentEntitlement(ctx context.Context, tx *sql.Tx,
	principal Principal) (ServiceEntitlement, bool, error) {
	var entitlement ServiceEntitlement
	var state string
	err := tx.QueryRowContext(ctx, `
SELECT revision, plan_id, state, voice_enabled, agent_enabled,
       access_until, source_event_id, applied_at
FROM service_entitlements
WHERE tenant_id = $1 AND subject = $2
FOR SHARE`, principal.TenantID, principal.Subject).Scan(
		&entitlement.Revision, &entitlement.PlanID, &state,
		&entitlement.VoiceEnabled, &entitlement.AgentEnabled,
		&entitlement.AccessUntil, &entitlement.SourceEventID,
		&entitlement.AppliedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ServiceEntitlement{}, false, nil
	}
	if err != nil {
		return ServiceEntitlement{}, false, err
	}
	entitlement.Principal = principal
	entitlement.State = EntitlementState(state)
	entitlement.AccessUntil = entitlement.AccessUntil.UTC()
	entitlement.AppliedAt = entitlement.AppliedAt.UTC()
	return entitlement, true, nil
}
