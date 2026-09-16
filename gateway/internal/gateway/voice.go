package gateway

import (
	"context"
	"errors"
)

var ErrVoiceBackendUnavailable = errors.New("STT-only voice backend unavailable")

type VoiceSessionConfig struct {
	DeviceID string
	// OwnerID and TenantID are product-internal authorization metadata.
	// Backends must not forward them to external speech providers.
	OwnerID         string
	TenantID        string
	ClientID        string
	SessionID       string
	SampleRate      int
	FrameDuration   int
	ProtocolVersion int
}

type VoiceEmitter interface {
	SendSTT(ctx context.Context, text string) error
	SendJSON(ctx context.Context, payload []byte) error
	FailVoice(cause error)
}

type VoiceSession interface {
	HandleAudio(ctx context.Context, opus []byte) error
	HandleControl(ctx context.Context, payload []byte) error
	Close() error
}

type VoiceBackend interface {
	Open(ctx context.Context, config VoiceSessionConfig, emitter VoiceEmitter) (VoiceSession, error)
	Ready(ctx context.Context) error
}

type DisabledVoiceBackend struct{}

func (DisabledVoiceBackend) Open(context.Context, VoiceSessionConfig, VoiceEmitter) (VoiceSession, error) {
	return nil, ErrVoiceBackendUnavailable
}

func (DisabledVoiceBackend) Ready(context.Context) error {
	return ErrVoiceBackendUnavailable
}
