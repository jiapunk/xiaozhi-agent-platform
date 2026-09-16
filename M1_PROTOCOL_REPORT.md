# M1 Voice Protocol Slice Report

> Post-M9 memory correction: the recorded `IRAM 16,384/16,384` row is
> ESP32-S3's dedicated subrange, not its complete linkable IRAM capacity. The
> earlier exhaustion/gate interpretation is superseded by the combined
> IRAM/DIRAM link-map audit in
> [M10_STATIC_MEMORY_BUDGET_REPORT.md](M10_STATIC_MEMORY_BUDGET_REPORT.md); the
> original milestone measurements below remain historical evidence.

Date: 2026-08-09

## Result

The product-owned firmware now contains a compiled, request-correlated bridge
between XiaoZhi STT/TTS messages and the ESP-Claw Agent seam. It negotiates the
Device Agent v1 feature, safely serializes TTS requests/aborts, rejects stale or
legacy lifecycle events, and has an explicit single-event-loop ownership model.
The project also includes a dependency-free gateway-side reference state
machine and conformance suite; it is an executable contract, not a production
network/TTS service.

All host suites pass and the ESP32-S3 firmware builds with every public protocol
path retained by a harmless boot-time linkage probe. No task, network request,
or live Agent is started by the probe.

This is a firmware/protocol milestone, not the completed M1 voice milestone:
the gateway extension, selected XiaoZhi audio/board modules, and physical-device
measurements are still pending.

## Reproducible inputs

- Target: ESP32-S3
- Reference module budget: ESP32-S3-WROOM-2-N32R16V
- ESP-IDF: 6.0.2
- Compiler: xtensa-esp-elf GCC 15.2.0
- ESP-Claw: `9ba07d013329df480e34a1a59d1513ab783d8a52`
- XiaoZhi: `18a60b8051f5ee6a25beed6248ed84c7fcc742bf`
- cJSON: 1.7.19~2
- Partition layout: 32 MiB flash, two 7 MiB OTA application slots
- Build mode: ESP-IDF minimal build

## Static footprint

| Measurement | M0 baseline | Current | Change |
| --- | ---: | ---: | ---: |
| Firmware `.bin` | 547,456 | 550,848 bytes | +3,392 bytes |
| ELF image content | 547,337 | 550,737 bytes | +3,400 bytes |
| Flash code | 325,048 | 328,080 bytes | +3,032 bytes |
| Flash data | 159,248 | 159,616 bytes | +368 bytes |
| DIRAM used | 53,117 | 53,117 bytes | 0 |
| IRAM used | 16,384 | 16,384 bytes | 0 |

The application still fits a 7 MiB OTA slot with 92% reported free. The one
percentage-point display change from M0 is rounding at the reporting boundary,
not a meaningful capacity loss.

Current directly retained archives:

| Archive | Retained bytes |
| --- | ---: |
| ESP-Claw Core | 20,730 |
| ESP-Claw Capabilities | 4,323 |
| Product voice Agent controller/protocol | 1,354 |
| Product ESP-Claw runtime adapter | 1,044 |
| Product XiaoZhi Agent adapter | 796 |
| ESP-Claw Event Router | 785 |
| Product Agent bridge | 688 |
| ESP-Claw utilities | 309 |

The three product-owned voice protocol archives total 2,838 bytes. The full
binary change also includes retained probe/call-site code, strings, alignment,
and transitive library sections.

IRAM remains exactly full in ESP-IDF's dedicated 16 KiB region, while DIRAM is
unchanged. Importing audio, Wi-Fi, codec, wake-word, or ISR code therefore still
requires a link-map diff and hardware measurement; static flash headroom does
not remove this gate.

## Implemented contract

- Client hello advertises `features.device_agent.version = 1` and
  `request_correlation = true`.
- Agent mode fails closed unless the server hello explicitly acknowledges both.
- Existing XiaoZhi `stt` becomes a serialized Agent request.
- Final Agent text becomes safely escaped `tts_request` JSON.
- Interrupting pending/playing TTS sends `tts_abort` before the next Agent turn.
- TTS `start`, `stop`, and `error` require the exact active session and request
  ID; stale or uncorrelated events cannot advance state.
- Serialization is allocation-free and reports exact required capacity instead
  of truncating output.

See `VOICE_AGENT_PROTOCOL.md` for the wire contract and
`XIAOZHI_INTEGRATION.md` for the pinned-source hook points.

## Verification performed

- Host compilation with C11, `-Wall -Wextra -Werror -pedantic`
- Bridge state-machine tests
- Voice controller and JSON writer tests
- XiaoZhi cJSON adapter and hello-negotiation tests
- Gateway-side hello, lifecycle, correlation, abort, type, and size tests
- ESP-IDF firmware build and partition-size check
- ESP-IDF total and per-component size analysis
- ELF symbol audit confirming all public bridge/controller/adapter paths are
  retained in the measured image

Covered paths include successful turns, Agent failure, TTS error, four abort
reasons, barge-in ordering, stale session/ID rejection, missing/fractional/
overflow IDs, request-ID wraparound, JSON injection escaping, insufficient TX
buffer, send failure, and legacy server rejection.

Result: all checks passed.

## Remaining M1 gates

1. Implement the production gateway's WebSocket and TTS service against the
   completed gateway reference/conformance contract.
2. Add the narrow `Protocol::SendAgentControl` API and typed event marshalling
   described in `XIAOZHI_INTEGRATION.md`.
3. Selectively import one supported board's audio/codec/wake path.
4. Run the end-to-end path on hardware and measure latency, heap/PSRAM minima,
   fragmentation, stacks, IRAM delta, reconnect, barge-in, and an 8-hour soak.
5. Keep MQTT plus UDP Agent mode disabled until audio frames carry an equivalent
   request/epoch correlation mechanism.
