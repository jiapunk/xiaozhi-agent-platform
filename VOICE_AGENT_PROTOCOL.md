# Device Agent Voice Protocol v1

Status: firmware contract and production-shaped Go gateway implemented and
tested; speech-provider deployment and hardware validation remain pending.

This protocol is a small, product-owned extension to XiaoZhi's existing JSON
control channel. It lets an on-device ESP-Claw Agent request speech synthesis
without confusing replies from an interrupted turn with the active turn.

## Reference transport

M1 uses XiaoZhi WebSocket transport. Its ordered control and binary frames make
barge-in behavior testable without changing XiaoZhi's audio frame format.
MQTT plus UDP is out of scope for M1 because audio packets do not carry a
`request_id`; it must not be enabled for Agent mode until the audio stream has
an equivalent correlation/epoch mechanism and packet-reordering tests.

All JSON is UTF-8. Unknown fields are ignored. Unknown message types remain
available to XiaoZhi's existing handlers.

## Capability negotiation

The device advertises the extension in its existing client hello:

```json
{
  "type": "hello",
  "version": 2,
  "transport": "websocket",
  "features": {
    "mcp": true,
    "device_agent": {
      "version": 1,
      "request_correlation": true
    }
  },
  "audio_params": {
    "format": "opus",
    "sample_rate": 16000,
    "channels": 1,
    "frame_duration": 60
  }
}
```

The gateway must echo the same object in its server hello:

```json
{
  "type": "hello",
  "transport": "websocket",
  "session_id": "voice:device-123:connection-456",
  "features": {
    "device_agent": {
      "version": 1,
      "request_correlation": true
    }
  },
  "audio_params": {
    "format": "opus",
    "sample_rate": 24000,
    "channels": 1,
    "frame_duration": 60
  }
}
```

The device enables Agent mode only after that exact Agent acknowledgement,
`transport: "websocket"`, a non-empty session of at most 63 bytes, and the
exact configured downlink audio profile. The BOX-3 profile requires mono Opus
at 24 kHz with 60 ms frames. A legacy or malformed hello may continue in
conventional XiaoZhi mode under product policy, but it must never accept
uncorrelated TTS lifecycle events as Agent events.

## Identifiers and ordering

- `session_id` is the active XiaoZhi transport session and is at most 63 UTF-8
  bytes in the firmware bridge. An Agent-extension message with a different
  session is stale and rejected.
- `request_id` is a JSON integer from 1 through 4,294,967,295. The device owns
  allocation. Zero, fractions, strings, negative numbers, and larger numbers
  are invalid.
- The initial controller allows one active request. IDs increment and wrap from
  4,294,967,295 to 1.
- Agent and network callbacks must be marshalled onto one serialized product
  event loop before they touch the controller.
- A terminal `stop` or `error` returns the controller to idle. A stale event
  must not alter state, display, or audio playback.

## Turn sequence

### 1. Speech-to-text final: gateway to device

The existing XiaoZhi STT message begins an Agent turn:

```json
{
  "session_id": "voice:device-123:connection-456",
  "type": "stt",
  "text": "Turn on the desk lamp"
}
```

For compatibility, the adapter can use the transport-bound `session_id` when
the STT message omits it. If the field is present, it must match the transport
session. Empty text is invalid. The controller assigns the next `request_id`
and submits the text to ESP-Claw.

### 2. TTS request: device to gateway

When ESP-Claw returns a final answer, the device sends:

```json
{
  "session_id": "voice:device-123:connection-456",
  "type": "tts_request",
  "request_id": 42,
  "text": "The desk lamp is now on."
}
```

The device uses an allocation-free JSON writer and escapes quotes, backslashes,
control characters, and newlines. A reply that cannot fit the caller-owned TX
buffer fails the turn instead of sending truncated JSON.

### 3. TTS lifecycle: gateway to device

The gateway sends `start` before the first audio frame and one terminal `stop`
or `error` after the last audio frame:

```json
{"session_id":"voice:device-123:connection-456","type":"tts","state":"start","request_id":42}
```

```json
{"session_id":"voice:device-123:connection-456","type":"tts","state":"stop","request_id":42}
```

```json
{"session_id":"voice:device-123:connection-456","type":"tts","state":"error","request_id":42,"code":"synthesis_failed"}
```

`start`, `stop`, and `error` must contain the exact active `session_id` and
`request_id`. The firmware rejects legacy lifecycle messages without
`request_id`.

The existing optional `sentence_start` message is UI-only in this firmware
slice and does not change controller state. The product gateway should include
the same `request_id` on it so a later UI correlation gate can reject stale
captions without another wire-protocol change:

```json
{"session_id":"voice:device-123:connection-456","type":"tts","state":"sentence_start","request_id":42,"text":"The desk lamp is now on."}
```

On WebSocket, the gateway must preserve this order for a request:

1. `tts start`
2. zero or more `sentence_start` messages and audio frames
3. exactly one `tts stop` or `tts error`

## Binary audio framing and playback admission

The firmware and gateway share XiaoZhi's three WebSocket binary formats:

| Transport version | Header | Payload |
| --- | --- | --- |
| 1 | none | raw Opus |
| 2 | 16 bytes, big-endian: `u16 version=2`, `u16 type=0`, `u32 reserved=0`, `u32 timestamp_ms`, `u32 payload_size` | Opus |
| 3 | 4 bytes, big-endian: `u8 type=0`, `u8 reserved=0`, `u16 payload_size` | Opus |

An Opus payload is 1 through 4,096 bytes. The receiver rejects unknown
versions, nonzero type/reserved fields, a short header, a zero/oversized
payload, or any declared-length mismatch before the codec sees the bytes.

The BOX-3 product profile sends 16 kHz mono, 60 ms Opus uplink and accepts
24 kHz mono, 60 ms Opus downlink. Binary downlink is admitted only between the
correlated `tts start` and `tts stop`/`error` events. Admission attaches the
active request generation to every copied packet; a generation is rechecked
immediately before the hardware write.

`tts stop` means graceful drain: no new packets are admitted, but packets
already accepted for that request play before output is disabled. `tts error`
and every interruption mean immediate invalidation and queue flush. A bounded
four-packet queue drops the oldest queued packet if overloaded rather than
allowing latency to grow without bound.

## Interruption and barge-in

If a button, network loss, session close, or new STT final interrupts pending
or playing TTS, the device sends:

```json
{
  "session_id": "voice:device-123:connection-456",
  "type": "tts_abort",
  "request_id": 42,
  "reason": "barge_in"
}
```

Allowed reasons are `barge_in`, `button`, `network_lost`, and
`session_closed`. For barge-in, the controller sends `tts_abort` before it
submits the new Agent request. It immediately invalidates the interrupted ID;
a late terminal event is expected to be rejected as stale.

The gateway must stop generating and sending audio for that request as soon as
it receives the abort. The device integration must also stop playback and flush
the decoder queue locally. Under M1's ordered WebSocket transport, the gateway
must not send frames for the aborted request after its terminal event.

## Failure and reconnect rules

- If Agent submission fails, the request is cleared and no TTS request is sent.
- If the TTS JSON cannot be built or sent, the request is cleared.
- If an abort send fails, local state is still cleared; the reconnect path must
  close the old transport session and flush playback.
- Disconnect invalidates the session and active request. IDs from the old
  session remain stale after reconnect even if their numeric value is reused.
- Protocol violations are counted and logged without user text or credentials.
  Repeated violations close the channel and fall back to a safe non-Agent
  state.

## Initial product limits

The M1 product configuration should enforce these limits before calling the
controller:

| Field | Limit |
| --- | ---: |
| `session_id` | 63 UTF-8 bytes |
| STT `text` | 2,048 UTF-8 bytes |
| TTS reply `text` | 512 UTF-8 bytes |
| Control JSON frame | 4,096 bytes |

The 512-byte reply cap fits a 4 KiB TX scratch buffer even under worst-case JSON
escaping. Longer Agent output should be summarized before M1 TTS; streaming or
chunked TTS is a later, separately versioned extension.

## Security requirements

- Use TLS with server certificate verification. Production devices additionally
  pin a product trust anchor or public key according to the rotation design.
- Authenticate a device with a short-lived, device-scoped gateway token. Never
  embed the model provider's master API key in firmware.
- Authorize Capabilities locally with least privilege; a valid voice session is
  not permission to invoke every device action.
- Redact STT/TTS text, tokens, and tool arguments from production logs by
  default. Emit request IDs, state transitions, durations, and error classes.
- Rate-limit requests, validate frame size before parsing, and reject malformed
  UTF-8/JSON at the transport boundary.

## Firmware implementation map

- `voice_agent_protocol`: safe `tts_request` and `tts_abort` serialization.
- `agent_bridge`: request lifecycle, interruption, and stale-result rejection.
- `voice_agent_controller`: operations that connect the bridge to ESP-Claw and
  the XiaoZhi transport.
- `xiaozhi_agent_adapter`: hello negotiation and XiaoZhi STT/TTS JSON parsing.
- `device_voice_runtime`: negotiated session ownership and the serialized JSON,
  Agent completion, binary audio, interruption, and disconnect boundary.
- `voice_audio_protocol`: allocation-free XiaoZhi v1/v2/v3 binary framing.
- `voice_audio_session`: request/generation admission, drain, in-flight, and
  stale-packet invalidation.
- `box3_voice_audio`: BOX-3 PCM selection, 24→16 kHz conversion, Opus codecs,
  bounded workers/queues, and playback lifecycle.

The host tests are the executable contract for escaping, event ordering,
request wraparound, stale sessions/IDs/generations, malformed audio headers,
errors, buffer exhaustion, and legacy server rejection.
