package accountauth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func entitlementUpdate(principal Principal, event string,
	previous, revision uint64, state EntitlementState,
	voice, agent bool, until time.Time) ServiceEntitlementUpdate {
	return ServiceEntitlementUpdate{
		Principal: principal, SourceEventID: event,
		PreviousRevision: previous, Revision: revision,
		PlanID: "launch-plan", State: state,
		VoiceEnabled: voice, AgentEnabled: agent,
		AccessUntil: until,
	}
}

func TestServiceEntitlementOrderedIdempotentLifecycle(t *testing.T) {
	store, err := NewStore(16)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	principal := Principal{TenantID: "tenant-1", Subject: "owner-1"}
	if _, err := store.BeginAuthenticatedSession(context.Background(),
		principal); err != nil {
		t.Fatal(err)
	}
	update := entitlementUpdate(principal, "billing-event-1", 0, 1,
		EntitlementActive, true, true, now.Add(30*24*time.Hour))
	entitlement, applied, err := store.ApplyServiceEntitlement(
		context.Background(), update)
	if err != nil || !applied || entitlement.Revision != 1 {
		t.Fatalf("apply=%#v applied=%t err=%v", entitlement, applied, err)
	}
	replay, applied, err := store.ApplyServiceEntitlement(
		context.Background(), update)
	if err != nil || applied || replay != entitlement {
		t.Fatalf("replay=%#v applied=%t err=%v", replay, applied, err)
	}
	tampered := update
	tampered.AgentEnabled = false
	if _, _, err := store.ApplyServiceEntitlement(context.Background(),
		tampered); !errors.Is(err, ErrConflict) {
		t.Fatalf("tampered replay=%v", err)
	}
	stale := entitlementUpdate(principal, "billing-event-2", 0, 1,
		EntitlementGrace, true, false, now.Add(time.Hour))
	if _, _, err := store.ApplyServiceEntitlement(context.Background(),
		stale); !errors.Is(err, ErrStaleEntitlement) {
		t.Fatalf("stale update=%v", err)
	}
	for _, service := range []ProductService{
		ProductServiceVoice, ProductServiceAgent,
	} {
		grant, allowed, err := store.AuthorizeService(
			context.Background(), principal, service)
		if err != nil || !allowed || grant.Revision != 1 ||
			grant.ValidUntil != update.AccessUntil {
			t.Fatalf("service=%s grant=%#v allowed=%t err=%v",
				service, grant, allowed, err)
		}
	}
}

func TestServiceEntitlementFailClosedStatesExpiryAndAccount(t *testing.T) {
	store, _ := NewStore(16)
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	principal := Principal{TenantID: "tenant-1", Subject: "owner-1"}
	if _, allowed, err := store.AuthorizeService(context.Background(),
		principal, ProductServiceVoice); err != nil || allowed {
		t.Fatalf("missing entitlement allowed=%t err=%v", allowed, err)
	}
	if _, err := store.BeginAuthenticatedSession(context.Background(),
		principal); err != nil {
		t.Fatal(err)
	}
	active := entitlementUpdate(principal, "event-active", 0, 1,
		EntitlementGrace, true, false, now.Add(time.Hour))
	if _, _, err := store.ApplyServiceEntitlement(context.Background(),
		active); err != nil {
		t.Fatal(err)
	}
	if _, allowed, _ := store.AuthorizeService(context.Background(),
		principal, ProductServiceAgent); allowed {
		t.Fatal("disabled Agent service was authorized")
	}
	now = now.Add(2 * time.Hour)
	if _, allowed, _ := store.AuthorizeService(context.Background(),
		principal, ProductServiceVoice); allowed {
		t.Fatal("expired Voice service was authorized")
	}
	suspended := entitlementUpdate(principal, "event-suspended", 1, 2,
		EntitlementSuspended, false, false, now)
	if _, _, err := store.ApplyServiceEntitlement(context.Background(),
		suspended); err != nil {
		t.Fatal(err)
	}
	if _, allowed, _ := store.AuthorizeService(context.Background(),
		principal, ProductServiceVoice); allowed {
		t.Fatal("suspended entitlement was authorized")
	}
	active = entitlementUpdate(principal, "event-renew", 2, 3,
		EntitlementActive, true, true, now.Add(time.Hour))
	if _, _, err := store.ApplyServiceEntitlement(context.Background(),
		active); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Suspend(context.Background(), principal); err != nil {
		t.Fatal(err)
	}
	if _, allowed, _ := store.AuthorizeService(context.Background(),
		principal, ProductServiceVoice); allowed {
		t.Fatal("suspended account was authorized")
	}
}

func TestServiceEntitlementValidationRejectsContradictions(t *testing.T) {
	now := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	principal := Principal{TenantID: "tenant-1", Subject: "owner-1"}
	base := entitlementUpdate(principal, "event-1", 0, 1,
		EntitlementActive, true, true, now.Add(time.Hour))
	for name, mutate := range map[string]func(*ServiceEntitlementUpdate){
		"skipped revision": func(value *ServiceEntitlementUpdate) {
			value.Revision = 2
		},
		"active without service": func(value *ServiceEntitlementUpdate) {
			value.VoiceEnabled, value.AgentEnabled = false, false
		},
		"suspended with service": func(value *ServiceEntitlementUpdate) {
			value.State = EntitlementSuspended
		},
		"already expired": func(value *ServiceEntitlementUpdate) {
			value.AccessUntil = now
		},
		"excessive validity": func(value *ServiceEntitlementUpdate) {
			value.AccessUntil = now.Add(maximumEntitlementValidity + time.Second)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			if ValidServiceEntitlementUpdate(candidate, now) {
				t.Fatal("invalid entitlement update accepted")
			}
		})
	}
}
