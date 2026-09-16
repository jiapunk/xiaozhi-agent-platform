package generation

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type ServingGate interface {
	AllowOTA() bool
	Ready() bool
}

type ReplicaGuard struct {
	client  *Client
	local   Generation
	replica ReplicaRef

	refreshMu  sync.Mutex
	mu         sync.RWMutex
	view       StateView
	validUntil time.Time
	now        func() time.Time
}

func NewReplicaGuard(client *Client, local Generation) (*ReplicaGuard, error) {
	if client == nil || !validGeneration(local) ||
		(client.principal.Role != "controlplane" &&
			client.principal.Role != "firmwareorigin") {
		return nil, fmt.Errorf("generation replica guard inputs are invalid")
	}
	return &ReplicaGuard{
		client: client, local: local,
		replica: ReplicaRef{ID: client.principal.ID, Role: client.principal.Role},
		now:     time.Now,
	}, nil
}

func (guard *ReplicaGuard) Run(ctx context.Context) {
	_ = guard.Refresh(ctx)
	ticker := time.NewTicker(StateLeaseDuration / 3)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshContext, cancel := context.WithTimeout(ctx, 4*time.Second)
			_ = guard.Refresh(refreshContext)
			cancel()
		}
	}
}

func (guard *ReplicaGuard) Refresh(ctx context.Context) error {
	guard.refreshMu.Lock()
	defer guard.refreshMu.Unlock()
	requestStarted := guard.now()
	view, err := guard.client.GetState(ctx)
	if err != nil {
		return err
	}
	guard.accept(view, requestStarted)
	for attempts := 0; attempts < 2; attempts++ {
		stage := guard.stageFor(view)
		if stage == "" {
			return nil
		}
		requestStarted = guard.now()
		view, err = guard.client.Acknowledge(ctx, AckRequest{
			ExpectedRevision: view.Revision, Generation: guard.local, Stage: stage,
		})
		if err != nil {
			if err == ErrConflict {
				requestStarted = guard.now()
				view, err = guard.client.GetState(ctx)
				if err == nil {
					guard.accept(view, requestStarted)
					continue
				}
			}
			return err
		}
		guard.accept(view, requestStarted)
	}
	return nil
}

func (guard *ReplicaGuard) stageFor(view StateView) string {
	if !containsReplica(view.RequiredReplicas, guard.replica) {
		return ""
	}
	if view.Phase == PhasePreparing && view.Pending != nil &&
		sameGeneration(*view.Pending, guard.local) &&
		ackStage(view.Acknowledgements, guard.replica.ID) == "" {
		return AckPrepared
	}
	if view.Phase == PhaseCommitting && sameGeneration(view.Active, guard.local) &&
		ackStage(view.Acknowledgements, guard.replica.ID) == AckPrepared {
		return AckActive
	}
	return ""
}

func (guard *ReplicaGuard) accept(view StateView, requestStarted time.Time) {
	guard.mu.Lock()
	defer guard.mu.Unlock()
	if guard.view.Revision > view.Revision {
		return
	}
	guard.view = view
	// The lease begins when the request starts, not when a potentially delayed
	// response arrives. A pre-drain response therefore cannot extend its lease.
	guard.validUntil = requestStarted.Add(StateLeaseDuration)
}

func (guard *ReplicaGuard) AllowOTA() bool {
	guard.mu.RLock()
	defer guard.mu.RUnlock()
	if !guard.now().Before(guard.validUntil) ||
		!sameGeneration(guard.view.Active, guard.local) {
		return false
	}
	switch guard.view.Phase {
	case PhaseStable, PhasePreparing, PhaseCommitting:
		return true
	default:
		return false
	}
}

func (guard *ReplicaGuard) Ready() bool { return guard.AllowOTA() }

func (guard *ReplicaGuard) Status() (StateView, time.Time) {
	guard.mu.RLock()
	defer guard.mu.RUnlock()
	return guard.view, guard.validUntil
}

type StaticGate bool

func (gate StaticGate) AllowOTA() bool { return bool(gate) }
func (gate StaticGate) Ready() bool    { return bool(gate) }
