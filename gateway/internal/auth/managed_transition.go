package auth

import (
	"crypto/subtle"
	"fmt"
	"time"
)

const (
	ManagedTokenTransitionRotate         = "rotate"
	ManagedTokenTransitionForwardRecover = "forward-recovery"
	managedTokenTransitionSkew           = 30 * time.Second
)

// ManagedTokenTransitionSummary contains only non-secret metadata suitable for
// an operator preflight receipt. It does not expose key material or file paths.
type ManagedTokenTransitionSummary struct {
	Transition            string
	CurrentRevision       uint64
	TargetRevision        uint64
	CurrentActiveKeyID    string
	TargetActiveKeyID     string
	CutoverUnix           int64
	MinimumDrainUntilUnix int64
	OldKeyVerifyUntilUnix int64
}

// ValidateManagedTokenTransition proves that a target verifier ring can be
// deployed before the issuer switches. Every still-valid current key is
// preserved by ID and material. A normal rotation adds one new active key; a
// forward recovery reactivates one existing retiring key without lowering the
// revision. Neither transition permits a rollback to an older document.
func ValidateManagedTokenTransition(current, target *ManagedTokenKeyring,
	transition string, maxTTL time.Duration,
	now time.Time) (ManagedTokenTransitionSummary, error) {
	if current == nil || target == nil || now.IsZero() ||
		maxTTL < minimumIssuedTTL || maxTTL > maximumIssuedTTL ||
		(transition != ManagedTokenTransitionRotate &&
			transition != ManagedTokenTransitionForwardRecover) {
		return ManagedTokenTransitionSummary{},
			fmt.Errorf("managed token transition configuration is invalid")
	}
	now = now.UTC()
	if target.revision <= current.revision {
		return ManagedTokenTransitionSummary{},
			fmt.Errorf("managed token transition revision must move forward")
	}
	currentActive, currentFound := current.keys[current.activeKeyID]
	targetActive, targetFound := target.keys[target.activeKeyID]
	oldInTarget, oldFound := target.keys[current.activeKeyID]
	if !currentFound || currentActive.state != "active" ||
		!targetFound || targetActive.state != "active" ||
		!oldFound || oldInTarget.state != "retiring" ||
		!sameManagedSecret(currentActive.secret, oldInTarget.secret) {
		return ManagedTokenTransitionSummary{},
			fmt.Errorf("managed token transition active-key lineage is invalid")
	}
	cutover := oldInTarget.issueBefore
	minimumDrain := cutover.Add(maxTTL + managedTokenTransitionSkew)
	if !cutover.After(now.Add(managedTokenTransitionSkew)) ||
		currentActive.verifyUntil.Before(minimumDrain) ||
		oldInTarget.verifyUntil.Before(minimumDrain) ||
		targetActive.verifyUntil.Before(minimumDrain) ||
		oldInTarget.verifyUntil.Before(currentActive.verifyUntil) {
		return ManagedTokenTransitionSummary{},
			fmt.Errorf("managed token transition cutover window is unsafe")
	}

	switch transition {
	case ManagedTokenTransitionRotate:
		if _, reused := current.keys[target.activeKeyID]; reused ||
			len(target.keys) != len(current.keys)+1 {
			return ManagedTokenTransitionSummary{},
				fmt.Errorf("managed token rotation requires one new active key")
		}
	case ManagedTokenTransitionForwardRecover:
		prior, found := current.keys[target.activeKeyID]
		if !found || prior.state != "retiring" ||
			current.legacyUnkeyedKeyID == target.activeKeyID ||
			len(target.keys) != len(current.keys) ||
			!sameManagedSecret(prior.secret, targetActive.secret) ||
			targetActive.verifyUntil.Before(prior.verifyUntil) {
			return ManagedTokenTransitionSummary{},
				fmt.Errorf("managed token forward recovery lineage is invalid")
		}
	}

	if current.legacyUnkeyedKeyID != target.legacyUnkeyedKeyID ||
		!current.legacyVerifyUntil.Equal(target.legacyVerifyUntil) {
		return ManagedTokenTransitionSummary{},
			fmt.Errorf("managed token transition cannot alter legacy migration")
	}
	for id, currentKey := range current.keys {
		targetKey, found := target.keys[id]
		if !found || !sameManagedSecret(currentKey.secret, targetKey.secret) {
			return ManagedTokenTransitionSummary{},
				fmt.Errorf("managed token transition dropped or replaced a current key")
		}
		switch {
		case id == current.activeKeyID:
			if targetKey.state != "retiring" ||
				targetKey.issueBefore != cutover ||
				!targetKey.verifyUntil.Equal(currentKey.verifyUntil) {
				return ManagedTokenTransitionSummary{},
					fmt.Errorf("managed token transition changed the current active key unsafely")
			}
		case transition == ManagedTokenTransitionForwardRecover &&
			id == target.activeKeyID:
			if targetKey.state != "active" || !targetKey.issueBefore.IsZero() ||
				targetKey.verifyUntil.Before(currentKey.verifyUntil) {
				return ManagedTokenTransitionSummary{},
					fmt.Errorf("managed token recovery target is invalid")
			}
		default:
			if targetKey.state != currentKey.state ||
				!targetKey.issueBefore.Equal(currentKey.issueBefore) ||
				!targetKey.verifyUntil.Equal(currentKey.verifyUntil) {
				return ManagedTokenTransitionSummary{},
					fmt.Errorf("managed token transition changed an existing retiring key")
			}
		}
	}
	return ManagedTokenTransitionSummary{
		Transition: transition, CurrentRevision: current.revision,
		TargetRevision:     target.revision,
		CurrentActiveKeyID: current.activeKeyID,
		TargetActiveKeyID:  target.activeKeyID,
		CutoverUnix:        cutover.Unix(), MinimumDrainUntilUnix: minimumDrain.Unix(),
		OldKeyVerifyUntilUnix: oldInTarget.verifyUntil.Unix(),
	}, nil
}

func sameManagedSecret(first, second []byte) bool {
	return len(first) == len(second) && len(first) >= 32 &&
		subtle.ConstantTimeCompare(first, second) == 1
}
