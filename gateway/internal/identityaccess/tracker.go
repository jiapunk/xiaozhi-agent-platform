package identityaccess

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"xiaozhi-agent-platform/gateway/internal/provisioning"
)

var ErrRevoked = errors.New("device identity revoked")

type Tracker struct {
	registry *provisioning.Registry
	mu       sync.Mutex
	active   map[string]map[*lease]struct{}
}

type lease struct {
	cancel   context.CancelCauseFunc
	onRevoke func()
}

func New(registry *provisioning.Registry) (*Tracker, error) {
	if registry == nil {
		return nil, fmt.Errorf("device access registry is required")
	}
	return &Tracker{
		registry: registry,
		active:   make(map[string]map[*lease]struct{}),
	}, nil
}

func (tracker *Tracker) Ready() bool {
	return tracker != nil && tracker.registry.Ready()
}

func (tracker *Tracker) Allowed(deviceID string) bool {
	return tracker != nil && tracker.registry.DeviceAllowed(deviceID)
}

func (tracker *Tracker) Start(parent context.Context, deviceID string,
	onRevoke func()) (context.Context, func(), bool) {
	if tracker == nil || parent == nil || deviceID == "" {
		return nil, nil, false
	}
	ctx, cancel := context.WithCancelCause(parent)
	current := &lease{cancel: cancel, onRevoke: onRevoke}
	tracker.mu.Lock()
	if !tracker.registry.DeviceAllowed(deviceID) {
		tracker.mu.Unlock()
		cancel(ErrRevoked)
		return nil, nil, false
	}
	leases := tracker.active[deviceID]
	if leases == nil {
		leases = make(map[*lease]struct{})
		tracker.active[deviceID] = leases
	}
	leases[current] = struct{}{}
	tracker.mu.Unlock()

	var once sync.Once
	finish := func() {
		once.Do(func() {
			tracker.mu.Lock()
			if existing := tracker.active[deviceID]; existing != nil {
				delete(existing, current)
				if len(existing) == 0 {
					delete(tracker.active, deviceID)
				}
			}
			tracker.mu.Unlock()
			cancel(nil)
		})
	}
	return ctx, finish, true
}

func (tracker *Tracker) Reconcile() int {
	if tracker == nil {
		return 0
	}
	type revokedLease struct {
		cancel   context.CancelCauseFunc
		onRevoke func()
	}
	revoked := make([]revokedLease, 0)
	tracker.mu.Lock()
	for deviceID, leases := range tracker.active {
		if tracker.registry.DeviceAllowed(deviceID) {
			continue
		}
		for current := range leases {
			revoked = append(revoked, revokedLease{
				cancel: current.cancel, onRevoke: current.onRevoke,
			})
		}
		delete(tracker.active, deviceID)
	}
	tracker.mu.Unlock()
	for _, current := range revoked {
		current.cancel(ErrRevoked)
		if current.onRevoke != nil {
			current.onRevoke()
		}
	}
	return len(revoked)
}

func Revoked(ctx context.Context) bool {
	return ctx != nil && errors.Is(context.Cause(ctx), ErrRevoked)
}
