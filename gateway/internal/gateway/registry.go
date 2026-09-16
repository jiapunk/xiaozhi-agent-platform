package gateway

import "sync"

type registry struct {
	mu      sync.Mutex
	devices map[string]struct{}
	limit   int
}

func newRegistry(limit int) *registry {
	return &registry{devices: make(map[string]struct{}), limit: limit}
}

func (registry *registry) acquire(deviceID string) bool {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, exists := registry.devices[deviceID]; exists ||
		(registry.limit > 0 && len(registry.devices) >= registry.limit) {
		return false
	}
	registry.devices[deviceID] = struct{}{}
	return true
}

func (registry *registry) release(deviceID string) {
	registry.mu.Lock()
	delete(registry.devices, deviceID)
	registry.mu.Unlock()
}
