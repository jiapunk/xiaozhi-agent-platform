# M0 Build and Resource Report

> Post-M9 memory correction: the recorded `IRAM 16,384/16,384` row is
> ESP32-S3's dedicated subrange, not its complete linkable IRAM capacity. The
> earlier exhaustion/gate interpretation is superseded by the combined
> IRAM/DIRAM link-map audit in
> [M10_STATIC_MEMORY_BUDGET_REPORT.md](M10_STATIC_MEMORY_BUDGET_REPORT.md); the
> original milestone measurements below remain historical evidence.

Date: 2026-08-09

## Result

The product-owned M0 application clean-builds successfully for ESP32-S3. The
build links the ESP-Claw Agent Core startup path, product Capability adapter,
HTTP/TLS dependencies, and the product event bridge. It does not start a live
Agent because no provider credential is embedded in firmware.

## Reproducible inputs

- Target module baseline: ESP32-S3-WROOM-2-N32R16V
- ESP-IDF: 6.0.2
- Compiler: xtensa-esp-elf GCC 15.2.0
- ESP-Claw: `9ba07d013329df480e34a1a59d1513ab783d8a52`
- XiaoZhi: `18a60b8051f5ee6a25beed6248ed84c7fcc742bf`
- Partition scheme: 32 MiB flash, two 7 MiB OTA application slots
- Build mode: ESP-IDF minimal build

The exact upstream revisions and licenses are recorded in
`upstream.lock.json` and `THIRD_PARTY_NOTICES.md`.

## Measured static footprint

| Measurement | Result |
| --- | ---: |
| Firmware `.bin` | 547,456 bytes (534.6 KiB) |
| ELF image content | 547,337 bytes |
| Smallest application slot | 7,340,032 bytes (7 MiB) |
| Free application-slot space | 93% |
| Flash code | 325,048 bytes |
| Flash data | 159,248 bytes |
| DIRAM used | 53,117 / 341,760 bytes (15.5%) |
| RTC slow memory used | 36 / 8,192 bytes |
| RTC fast memory used | 24 / 8,192 bytes |

The dedicated IRAM region is reported as 16,384 / 16,384 bytes. The build is
valid and DIRAM remains mostly free, but IRAM is an explicit M1 gate: XiaoZhi
audio, Wi-Fi, and interrupt-resident code must be integrated with an IRAM map
diff and on-device measurements.

Direct archive contributions retained by the M0 linkage probe are:

| Archive | Retained bytes |
| --- | ---: |
| ESP-Claw Core | 20,734 |
| ESP-Claw Capabilities | 4,323 |
| ESP-Claw Event Router | 785 |
| Product ESP-Claw runtime adapter | 1,044 |
| ESP-Claw utilities | 309 |
| Product event bridge probe path | 82 |

The Agent-specific archives total 27,195 bytes. Their transitive HTTP, TLS,
JSON, FreeRTOS, and networking requirements are included in the full firmware
number above. Only the bridge initialization path is retained in this M0 image;
all bridge state transitions are nevertheless compiled and exercised by the
host tests.

## Verification performed

- Clean `idf.py set-target esp32s3` from `sdkconfig.defaults`
- Clean `idf.py build`
- ESP-IDF partition-size check
- ESP-IDF size and per-component analysis
- Host tests covering happy path, Agent and TTS interruption, stale replies,
  operation failures, and request-ID wraparound

Result: all checks passed.

## What this proves

- A product-owned application shell is compatible with the pinned ESP-Claw
  core on ESP-IDF 6.0.2.
- Selective reuse compiles and links without importing two complete firmware
  applications.
- The 32 MiB / 16 MiB PSRAM baseline has ample static flash headroom for M1.
- Request correlation and barge-in behavior have a tested, allocation-free
  state-machine boundary.

## What this does not prove

- Live LLM correctness, latency, or provider compatibility
- XiaoZhi audio capture, wake word, codec, or board-driver integration
- Peak heap/PSRAM use, fragmentation, task-stack high-water marks, or thermal
  behavior on hardware
- Wi-Fi reconnect behavior, OTA rollback on hardware, secure boot, flash
  encryption, device identity, or production credential rotation
- Skills, Memory, Lua, MCP, observability, fleet management, or cloud-gateway
  readiness

## M1 acceptance gate

M1 should import only XiaoZhi's audio/voice seams and complete one vertical
slice: wake or button -> speech-to-text final -> local ESP-Claw request ->
request-correlated TTS -> barge-in cancellation. Acceptance requires a new
size-map diff plus on-device heap, PSRAM, stack, latency, reconnect, and 8-hour
soak measurements.
