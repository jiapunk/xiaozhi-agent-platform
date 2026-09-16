package runtimecoordination

import (
	"context"
	"errors"
	"time"
)

const (
	SchemaVersion      = 1
	SchemaContract     = "xz-runtime-coordination-v1-20260810"
	MaximumProofNonces = 64
)

var (
	ErrInvalid     = errors.New("invalid runtime coordination request")
	ErrUnavailable = errors.New("runtime coordination unavailable")
	ErrReplay      = errors.New("runtime coordination replay")
	ErrRateLimited = errors.New("runtime coordination rate limited")
	ErrConflict    = errors.New("runtime coordination lease conflict")
	ErrLeaseLost   = errors.New("runtime coordination lease lost")
)

type LeaseKind uint8

const (
	VoiceLease LeaseKind = iota + 1
	AgentLease
)

func (kind LeaseKind) valid() bool {
	return kind == VoiceLease || kind == AgentLease
}

type Lease struct {
	Kind          LeaseKind
	SubjectSHA256 string
	LeaseID       [16]byte
	HolderID      string
	ExpiresAt     time.Time
}

type Coordinator interface {
	VerifySchema(context.Context) error
	ReserveProof(context.Context, uint8, string, string,
		time.Duration, time.Duration) error
	ConsumeVoiceToken(context.Context, string, string, time.Time) error
	AcquireVoice(context.Context, string, int, time.Duration) (Lease, error)
	AcquireAgent(context.Context, string, int, int,
		time.Duration) (Lease, error)
	Renew(context.Context, Lease, time.Duration) (Lease, error)
	Release(context.Context, Lease) error
}
