# M25 speech-provider conformance gate report

Date: 2026-08-09

## Result

M25 hardens the provider-neutral private STT/TTS boundary before selecting a
commercial speech vendor. The voice gateway now requires explicit version
agreement on WebSocket upgrades, synthesis responses, and optional readiness
checks; parses every production Opus packet structurally; and rejects stereo or
any packet whose total duration differs from the negotiated 60 ms.

This closes a concrete failure mode in the earlier reference contract: any 2xx
health response and any length-bounded byte string could previously be treated
as valid speech data, pushing provider/configuration failures down to the
ESP32 decoder.

## Versioned contracts

- STT: `xiaozhi-private-stt-v1`
- TTS: `xiaozhi-private-tts-v1`
- Header: `X-Xiaozhi-Speech-Contract`

STT sends the version in both the WSS upgrade header and start JSON and requires
it in the upgrade response. TTS sends it in the request header and JSON and
requires it in the synthesis response. Configured health endpoints must return
the same version; a generic 2xx is no longer readiness evidence.

## Opus validation

The new pure-Go parser has no native codec or cgo dependency, preserving the
static/non-root backend image policy. It validates:

- TOC mode, stereo bit, and 2.5/5/10/20/40/60 ms frame duration;
- packet codes 0, 1, 2, and 3;
- one, two, and arbitrary-frame packets up to the Opus 120 ms limit;
- CBR/VBR size encoding, extended sizes, padding, truncation, and the
  1,275-byte per-frame limit;
- product mono policy and exact 60 ms total packet duration.

The STT adapter validates device uplink before forwarding it. The TTS adapter
validates provider output before invoking the gateway emitter, so invalid audio
cannot enter request-correlated device framing.

The parser validates container structure and timing, not speech semantics. A
candidate provider must still pass reference/ESP decoder tests; this limitation
is explicit in the acceptance runbook.

## Verification

Focused tests cover single-frame and multi-frame 60 ms packets, CBR, VBR,
padding, two-frame modes, stereo, wrong duration, excessive duration, empty and
truncated data, invalid lengths/frame counts, missing contract negotiation, and
strict readiness. Production gateway and TTS package tests pass.

The complete Go package suite, `go vet ./...`, and `go test -race ./...` pass.
M25 changes only the backend speech boundary, so ESP firmware bytes and the M24
reproducibility/security evidence are unchanged.

## Honest boundary

No real STT/TTS provider was selected or called, and no audio was decoded on a
physical BOX3. Provider credentials, regional/privacy terms, Mandarin quality,
latency, cancellation, quota behavior, cost, AEC/duplex behavior, and soak
remain release gates. The exact next procedure is documented in
`SPEECH_PROVIDER_ACCEPTANCE.md`.
