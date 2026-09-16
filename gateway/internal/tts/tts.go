package tts

import "context"

type EmitFrame func(opus []byte) error

type Request struct {
	DeviceID  string
	SessionID string
	RequestID uint32
	Text      string
}

type Synthesizer interface {
	Stream(ctx context.Context, request Request, emit EmitFrame) error
	Ready(ctx context.Context) error
}
