package runtimecoordination

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"unicode/utf8"

	"xiaozhi-agent-platform/gateway/internal/auth"
)

const maximumSubjectBytes = 512

func subjectDigest(purpose, subject string) ([]byte, string, error) {
	if purpose == "" || len(purpose) > 64 || subject == "" ||
		len(subject) > maximumSubjectBytes || !utf8.ValidString(subject) {
		return nil, "", ErrInvalid
	}
	digest := sha256.Sum256([]byte(
		"XIAOZHI-RUNTIME-COORDINATION-SUBJECT-V1\x00" + purpose + "\x00" + subject))
	return digest[:], hex.EncodeToString(digest[:]), nil
}

func proofNonceDigest(nonce string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(decoded) < 16 || len(decoded) > 32 ||
		base64.RawURLEncoding.EncodeToString(decoded) != nonce {
		return nil, ErrInvalid
	}
	digest := sha256.Sum256(append(
		[]byte("XIAOZHI-RUNTIME-COORDINATION-PROOF-NONCE-V1\x00"), decoded...))
	return digest[:], nil
}

func tokenDigest(tokenID string) ([]byte, error) {
	if !auth.ValidIdentifier(tokenID, 64) {
		return nil, ErrInvalid
	}
	digest := sha256.Sum256([]byte(
		"XIAOZHI-RUNTIME-COORDINATION-VOICE-TOKEN-V1\x00" + tokenID))
	return digest[:], nil
}

func leasePurpose(kind LeaseKind) string {
	switch kind {
	case VoiceLease:
		return "voice-lease"
	case AgentLease:
		return "agent-lease"
	default:
		return fmt.Sprintf("invalid-%d", kind)
	}
}
