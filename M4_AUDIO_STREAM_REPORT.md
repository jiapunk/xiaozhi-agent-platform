# M4 BOX-3 voice-stream report

> Post-M9 memory correction: the recorded `IRAM 16,384/16,384` row is
> ESP32-S3's dedicated subrange, not its complete linkable IRAM capacity. The
> earlier exhaustion/gate interpretation is superseded by the combined
> IRAM/DIRAM link-map audit in
> [M10_STATIC_MEMORY_BUDGET_REPORT.md](M10_STATIC_MEMORY_BUDGET_REPORT.md); the
> original milestone measurements below remain historical evidence.

## Outcome

The product shell now owns a complete transport-neutral voice path between the
BOX-3 PCM HAL and a XiaoZhi-compatible WebSocket boundary:

```text
ES7210 24 kHz TDM -> mic slot 0 -> 24-to-16 kHz conversion
  -> 16 kHz mono Opus/60 ms -> XiaoZhi binary frame -> transport callback

transport binary frame -> strict framing parser -> bounded generation queue
  -> 24 kHz mono Opus/60 ms -> ES8311 playback
```

The same product-owned runtime binds Device Agent v1 hello negotiation, final
STT, request-correlated ESP-Claw submission/completion, TTS control messages,
binary audio admission, interruption, and disconnect invalidation. This is a
compile/link and host-contract milestone; it is not a claim of physical audio
validation.

## Lifecycle and latency policy

- Capture and playback have independent workers and the HAL uses separate
  input/output locks, allowing full-duplex I/O.
- Uplink input is the ES7210 microphone in TDM slot 0. Slot 1 remains available
  as the speaker reference, but AEC is not implemented in this milestone.
- The downlink queue owns four fixed 4,096-byte packet buffers, preferably in
  PSRAM. At 60 ms per packet, it bounds queued audio to at most 240 ms.
- A full queue drops the oldest queued packet rather than extending stale
  latency.
- TTS `start` creates a new request generation; `stop` closes admission and
  drains accepted packets; error, barge-in, button, disconnect, or session
  close invalidates the generation and flushes queued packets.
- A generation tag is checked again immediately before the hardware write, so
  an already-dequeued packet from an interrupted turn cannot resume later.
- A write already in progress may finish before `FLUSH` acquires the lifecycle
  lock. The current worst-case software bound is one 60 ms playback frame and
  must be measured on hardware.
- The uplink callback must copy/enqueue and return promptly. Blocking socket I/O
  in that callback would stall the real-time capture worker and is prohibited
  by the interface contract.

## Protocol behavior

- XiaoZhi WebSocket transport versions 1, 2, and 3 are supported.
- Version 1 is raw Opus. Version 2 uses the 16-byte big-endian XiaoZhi header;
  version 3 uses its 4-byte compact header.
- Payloads are non-empty and at most 4,096 bytes. Exact payload length, message
  type, transport version, and reserved-zero fields are validated on both the
  firmware and Go gateway sides.
- Agent mode only becomes ready after the server echoes Device Agent version 1,
  request correlation, WebSocket transport, a bounded session ID, mono Opus,
  24 kHz downlink, and 60 ms frames.
- Binary downlink is rejected unless the correlated controller state is
  `TTS_PLAYING`.

## Build and memory evidence

Both configurations were rebuilt from the same source with ESP-IDF 6.0.2,
XiaoZhi commit `18a60b8051f5ee6a25beed6248ed84c7fcc742bf`, and ESP-Claw commit
`9ba07d013329df480e34a1a59d1513ab783d8a52`.

| Measurement | Generic N32R16 | BOX-3 N16R8 | Difference |
|---|---:|---:|---:|
| Firmware `.bin` | 553,472 B | 827,952 B | +274,480 B |
| Linked image | 553,357 B | 827,828 B | +274,471 B |
| Flash code | 330,188 B | 557,700 B | +227,512 B |
| Flash data | 159,720 B | 204,924 B | +45,204 B |
| DIRAM | 53,525 B | 55,752 B | +2,227 B |
| DIRAM free | 288,235 B | 286,008 B | -2,227 B |
| IRAM | 16,384 B | 16,384 B | unchanged; 100% used |

The BOX-3 binary leaves 4,939,216 bytes (86%) free in each 5,767,168-byte OTA
application slot. Compared with the M3 HAL-only BOX-3 image, the complete voice
stream adds 199,728 bytes. Direct archive contributions include 170,561 bytes
from `esp_audio_codec`, 10,362 bytes from `esp_audio_effects`, 3,110 bytes from
the product stream wrapper, and 1,017 bytes from the shared device voice
runtime. Remaining growth is supporting code and alignment.

The generic binary adds only 2,608 bytes over M3. Its archive report contains
the 1,017-byte device voice runtime but no contributing BOX-3 stream, audio
codec, or audio effects archive, confirming that SKU-specific implementation is
not retained in the generic image.

## Automated verification

The following pass:

- six strict C host suites covering the bridge, controller, binary framing,
  generation gate, XiaoZhi JSON adapter, and device voice runtime;
- seven Python gateway protocol-contract tests;
- all Go gateway tests, `go vet`, and `go test -race ./...`;
- shell syntax validation for every script;
- generic N32R16 and BOX-3 N16R8 ESP-IDF builds, size, and per-component size
  analysis.

The tests prove malformed-frame rejection, strict hello negotiation, correlated
turn flow, playback begin/drain/flush order, stale generation rejection,
disconnect cleanup, transport failure propagation, and that invalid STT cannot
flush valid active playback.

## Production gates still open

1. Implement the ESP-side WebSocket/TLS client and bind it to the product event
   loop, Wi-Fi provisioning, device identity, and short-lived gateway token.
2. Connect a real STT/TTS provider and verify cancellation semantics end to
   end; no provider master secret may be stored in firmware.
3. Run physical BOX-3 codec discovery, mic/speaker loop, duplex, gain, clipping,
   underrun, reconnect, and barge-in timing tests.
4. Add and calibrate AEC using the retained reference channel, or explicitly
   define a half-duplex product policy.
5. Measure runtime internal heap/PSRAM minima, fragmentation, worker stack
   high-water marks, frame loss, latency percentiles, watchdog behavior, and an
   eight-hour soak.
6. Reduce or explicitly re-budget the 100% IRAM reading before release. A build
   that fits flash is not sufficient evidence of runtime headroom.
7. Complete secure boot, flash encryption, eFuse/key provisioning, OTA rollback,
   factory test, privacy logging, SBOM, and fleet operations.

Until those gates pass, this code is a credible product integration baseline,
not production-approved firmware.
