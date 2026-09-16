package actionconsent

import (
	"bytes"
	"time"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

const (
	WakeContract        = "xz-action-consent-wake-v1"
	MaximumWakeLease    = 10 * time.Second
	MaximumWakeRetry    = 5 * time.Second
	minimumWakeLease    = 100 * time.Millisecond
	maximumWakeAttempts = 100000
)

var wakePayload = []byte(`{"version":1,"kind":"action-consent-wake"}`)

// Wake contains routing metadata for the trusted notification worker. None of
// these fields may be copied into the provider payload; the App must fetch the
// exact challenge from its authenticated foreground inbox.
type Wake struct {
	WakeID    string
	Target    Actor
	ExpiresAt time.Time
	Attempts  uint32
}

type WakeOutbox interface {
	ClaimWake(workerID string, now time.Time,
		lease time.Duration) (Wake, bool, error)
	AcknowledgeWake(workerID, wakeID string, now time.Time) error
	RetryWake(workerID, wakeID string, now time.Time,
		retryAfter time.Duration) error
}

// CanonicalWakePayload returns a fresh copy of the only permitted push body.
// It is intentionally constant and contains no device, owner, challenge,
// action, arguments, prompt, decision, expiry, URL, or provider instruction.
func CanonicalWakePayload() []byte {
	return bytes.Clone(wakePayload)
}

func validWakeWorker(workerID string) bool {
	return auth.ValidIdentifier(workerID, 64)
}

func validWakeLease(lease time.Duration) bool {
	return lease >= minimumWakeLease && lease <= MaximumWakeLease
}

func validWakeRetry(retryAfter time.Duration) bool {
	return retryAfter >= 0 && retryAfter <= MaximumWakeRetry
}

func wakeFromChallenge(challenge Challenge) Wake {
	return Wake{
		WakeID: challenge.ChallengeID,
		Target: Actor{
			OwnerID: challenge.OwnerID, TenantID: challenge.TenantID,
			DeviceID:      challenge.DeviceID,
			OwnerRevision: challenge.OwnerRevision,
		},
		ExpiresAt: challenge.ExpiresAt.UTC(),
	}
}
