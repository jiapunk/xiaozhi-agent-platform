package gateway

import (
	"testing"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

func TestTokenReplayGuardRejectsReuseAndExpiresEntries(t *testing.T) {
	guard := newTokenReplayGuard(1)
	now := time.Unix(1_800_000_000, 0)
	guard.now = func() time.Time { return now }
	claims := auth.Claims{
		DeviceID: "device-1", OwnerID: "user-1", TenantID: "tenant-1",
		BindingID: "MDEyMzQ1Njc4OWFiY2RlZg", BindingRevision: 1,
		Audience: auth.VoiceAudience, TokenID: "token-1",
		Expires: now.Add(time.Minute).Unix(),
	}
	if !guard.consume(claims) || guard.consume(claims) {
		t.Fatal("token must be accepted exactly once")
	}
	now = now.Add(70 * time.Second)
	if guard.consume(claims) {
		t.Fatal("replay tombstone must survive token clock-skew grace")
	}
	now = now.Add(50 * time.Second)
	replacement := auth.Claims{
		DeviceID: "device-1", OwnerID: "user-1", TenantID: "tenant-1",
		BindingID: "MDEyMzQ1Njc4OWFiY2RlZg", BindingRevision: 1,
		Audience: auth.VoiceAudience, TokenID: "token-2",
		Expires: now.Add(time.Minute).Unix(),
	}
	if !guard.consume(replacement) {
		t.Fatal("expired replay entries must be reclaimed")
	}
	if guard.consume(auth.Claims{DeviceID: "legacy", Expires: replacement.Expires}) {
		t.Fatal("ownerless legacy token must fail closed")
	}
}
