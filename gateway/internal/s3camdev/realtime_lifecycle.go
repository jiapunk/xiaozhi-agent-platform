package s3camdev

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/coder/websocket"
)

func (session *openAIRealtimeSession) responseOutputActive(generation uint64,
	responseContext context.Context) bool {
	if session.closed.Load() || (responseContext != nil && responseContext.Err() != nil) {
		return false
	}
	session.stateMu.Lock()
	defer session.stateMu.Unlock()
	return generation == session.responseGeneration && !session.responseBlocked
}

// A response cancellation is not a connection cancellation. The websocket
// package closes a connection when its Write context expires, so response
// contexts may only gate work / waits, never tts control-frame transport.
// Holding the socket writer and state locks also prevents stale finish/stop
// from overtaking a new generation's start/interrupt.
func (session *openAIRealtimeSession) writeDevicePlaybackControl(generation uint64,
	state string) error {
	payload, err := json.Marshal(map[string]any{
		"session_id": session.device.sessionID, "type": "tts", "state": state,
	})
	if err != nil {
		return err
	}
	session.device.writeMu.Lock()
	defer session.device.writeMu.Unlock()
	session.stateMu.Lock()
	defer session.stateMu.Unlock()
	if session.closed.Load() || generation != session.responseGeneration ||
		(session.responseBlocked && state != "interrupt") {
		return context.Canceled
	}
	return session.device.connection.Write(session.ctx, websocket.MessageText, payload)
}

func (session *openAIRealtimeSession) waitForDevicePlaybackDrain(
	responseContext context.Context, generation uint64) error {
	channel := make(chan struct{}, 1)
	device := session.device
	device.stateMu.Lock()
	if device.playbackDrain != nil {
		device.stateMu.Unlock()
		return fmt.Errorf("playback drain is already pending")
	}
	device.playbackDrain = channel
	device.stateMu.Unlock()
	defer func() {
		device.stateMu.Lock()
		if device.playbackDrain == channel {
			device.playbackDrain = nil
		}
		device.stateMu.Unlock()
	}()
	if err := session.writeDevicePlaybackControl(generation, "finish"); err != nil {
		return err
	}
	started := time.Now()
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	select {
	case <-responseContext.Done():
		return responseContext.Err()
	case <-timer.C:
		return fmt.Errorf("device playback drain acknowledgement timed out")
	case <-channel:
		session.gateway.config.Logger.Info("device playback drained",
			"generation", generation, "wait_ms", time.Since(started).Milliseconds())
		return nil
	}
}
