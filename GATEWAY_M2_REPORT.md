# M2 Gateway Milestone Report

Date: 2026-08-09

## Result

A production-shaped Go gateway now implements the real Device Agent v1
WebSocket boundary. It authenticates short-lived device tokens before upgrade,
negotiates the XiaoZhi hello, accepts XiaoZhi WebSocket Opus formats 1/2/3,
routes microphone audio to a private STT-only service, and streams correlated
TTS audio from a private framed-HTTP service.

This proves the product-owned gateway architecture and its concurrency rules.
It does not prove a production deployment because actual speech providers,
distributed fleet state, operational infrastructure, hardware, and external
security/load validation are not present.

## Implemented controls

- HMAC-SHA256 short-lived, audience-bound, device-scoped tokens with a
  current/previous rotation keyring
- device/header/claim binding before WebSocket upgrade
- strict JSON numeric types and 32-bit request IDs
- exact hello/version/correlation negotiation
- random per-connection session IDs
- one active connection per device and one active TTS per connection
- separate control-message and audio-packet limits
- 4 KiB control/Opus packet limits and 4 MiB synthesis limit
- serialized WebSocket writes and cancellation-safe request state
- stale audio suppression after barge-in
- TLS-by-default configuration and TLS 1.2 minimum
- dependency readiness, process health, metadata-only metrics/logs
- graceful active-WebSocket shutdown

## Verification

- Go 1.26.5, `go test ./...`: passed
- Go race detector, `go test -race ./...`: passed
- `go vet ./...`: passed
- `go build ./cmd/gateway`: passed
- static Linux amd64 cross-build: passed, 7,409,790 bytes
- static Linux arm64 cross-build: passed, 6,946,942 bytes
- real WebSocket integration path: passed
- interrupted-request/next-request ordering: passed
- STT and TTS private upstream framing tests: passed
- authentication, malformed input, limits, and shutdown tests: passed

The direct gateway dependency is `github.com/coder/websocket` v1.8.15, locked
in `go.sum` and distributed under the ISC License with its notice.

## Important architecture result

The STT service is not allowed to emit TTS or tool/control messages. It only
returns final transcript text. ESP-Claw remains the on-device owner of reasoning
and Capabilities, while the gateway owns identity, voice transport, request
correlation, and provider isolation.

This avoids the failure mode where an unmodified XiaoZhi server and the local
ESP-Claw Agent both answer the same utterance.

## Remaining gates

1. Implement the selected speech-provider adapters behind the tested private
   STT/TTS contracts.
2. Add distributed connection ownership, token revocation/replay, workload
   identity, traces/SLOs, load/failover tests, and an SBOM/image pipeline.
3. Integrate the firmware with one concrete XiaoZhi audio/board target.
4. Run the end-to-end path on physical hardware, including an 8-hour soak and
   measured barge-in, memory, stack, latency, reconnect, and thermal results.
