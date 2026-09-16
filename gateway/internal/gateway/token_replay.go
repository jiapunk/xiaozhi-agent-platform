package gateway

import (
	"sync"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

const tokenReplayRetentionSeconds = 60

type tokenReplayGuard struct {
	mu       sync.Mutex
	used     map[string]int64
	capacity int
	now      func() time.Time
}

func newTokenReplayGuard(capacity int) *tokenReplayGuard {
	if capacity < 1024 {
		capacity = 1024
	}
	return &tokenReplayGuard{
		used: make(map[string]int64), capacity: capacity, now: time.Now,
	}
}

func (guard *tokenReplayGuard) consume(claims auth.Claims) bool {
	if guard == nil || claims.TokenID == "" {
		return false
	}
	scope, ok := auth.OwnedDeviceScope(claims)
	if !ok {
		return false
	}
	now := guard.now().Unix()
	key := scope + "\x00" + claims.TokenID
	guard.mu.Lock()
	defer guard.mu.Unlock()
	for existing, expires := range guard.used {
		if expires <= now {
			delete(guard.used, existing)
		}
	}
	if _, exists := guard.used[key]; exists || len(guard.used) >= guard.capacity {
		return false
	}
	/* Retain through the verifier's clock-skew grace period. */
	guard.used[key] = claims.Expires + tokenReplayRetentionSeconds
	return true
}
