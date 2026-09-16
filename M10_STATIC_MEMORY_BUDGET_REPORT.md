# M10 ESP32-S3 static internal-memory budget report

Date: 2026-08-09  
ESP-IDF: 6.0.2  
XiaoZhi pin: `18a60b8051f5ee6a25beed6248ed84c7fcc742bf`  
ESP-Claw pin: `9ba07d013329df480e34a1a59d1513ab783d8a52`

## Outcome

M10 corrects the earlier interpretation of ESP-IDF's
`IRAM 16,384/16,384` size row. That row describes only the dedicated address
range before ESP32-S3's shared D/IRAM window; it is not the complete linkable
IRAM capacity and does not prove that instruction RAM is exhausted.

The BOX-3 link map proves:

- `iram0_0_seg` spans `0x40374000..0x403cb700`, or 358,144 bytes;
- the dedicated instruction-only subrange ends at `_diram_i_start =
  0x40378000`, so it contributes the reported 16,384 bytes;
- vectors plus IRAM-resident code end at `_iram_end = 0x40380c00`, for an
  executable span of 52,224 bytes;
- 35,840 of those bytes occupy the instruction alias of shared D/IRAM;
- the linker deliberately advances `.dram0.dummy` by the same shared amount,
  preventing code/data overlap;
- static data ends at `_heap_low_start = 0x3fc95bc0`; and
- the combined exact linker footprint is 72,640 of 358,144 bytes, leaving
  285,504 bytes of static internal-memory headroom.

The 100% dedicated-IRAM row is therefore expected once IRAM-resident code
crosses the dedicated/shared boundary. The applicable static release gate is
the combined physical IRAM/DIRAM budget, not that subrange percentage.

## Authoritative layout evidence

ESP-IDF 6.0.2's ESP32-S3 linker source defines:

```text
0x40370000 <- instruction cache / IRAM
0x40378000 <- instruction alias of shared D/IRAM
0x3fc88000 <- data alias of shared D/IRAM
```

With the configured 16 KiB instruction cache, the application IRAM origin is
`0x40374000`. The generated linker region is:

```text
iram0_0_seg  origin 0x40374000  length 0x57700
dram0_0_seg  origin 0x3fc88000  length 0x53700
```

The ESP-IDF size tool's own documentation states that an ESP32-S3
`iram0_0_seg` can encompass multiple memory types (`IRAM` and `DRAM_1`). Its
chip description splits the same region at the D/IRAM boundary, which explains
why the top-level table displays 16 KiB as one fully used memory type and the
remaining executable bytes under DIRAM.

Sources inspected from the pinned local toolchain:

- `components/esp_system/ld/esp32s3/memory.ld.in`;
- `components/esp_system/ld/esp32s3/sections.ld.in`;
- `esp_idf_size/chip_info/esp32s3.yaml`; and
- `esp_idf_size/docs/readme.md`.

## Machine-enforced release policy

The new [memory-budget checker](tools/check_memory_budget.py) parses the final
link map rather than a human-formatted size table. It validates segment/symbol
consistency and enforces two versioned pre-hardware limits:

| Gate | Limit | Generic | BOX-3 | Result |
| --- | ---: | ---: | ---: | --- |
| IRAM executable span | ≤ 98,304 B | 50,176 B | 52,224 B | pass |
| Combined static internal headroom | ≥ 196,608 B | 287,872 B | 285,504 B | pass |
| Combined exact static use | informational | 70,272 B | 72,640 B | 19.62% / 20.28% |

The 192 KiB headroom policy deliberately preserves room for the missing Wi-Fi
integration, internal-DMA/runtime allocations, future ISR-safe paths, and
measurement variance. It is a product budget, not a claim that every remaining
byte is safely allocatable at runtime.

`tools/build_box3.sh` now runs the checker after every clean build. Three Python
unit tests cover the shared layout, both budget failures, missing definitions,
and code/data overlap rejection. Direct checks of both current final maps pass.

## Corrected release boundary

The earlier M0–M9 reports correctly recorded the ESP-IDF size output but
overstated its meaning when calling the dedicated 16 KiB row an IRAM exhaustion
gate. That interpretation is superseded by this link-map audit.

The static internal-memory gate now passes. Product release still requires a
different, runtime gate because the current minimal build does not yet link the
final Wi-Fi onboarding/driver configuration and a link map cannot measure
dynamic behavior. On physical hardware the product must still record:

- `MALLOC_CAP_INTERNAL` and `MALLOC_CAP_DMA` boot/steady-state/minimum free
  bytes;
- PSRAM minima and fragmentation;
- every task's stack high-water mark;
- audio DMA, TLS, WebSocket, ESP-Claw, codec, and provider-failure peaks;
- Wi-Fi reconnect, OTA, coredump, and low-memory behavior; and
- 100-turn, eight-hour, and 72-hour trends.

M10 removes a false static blocker while retaining the real product risk. Any
future SDK, cache-size, Wi-Fi, audio, security, or component change must rebuild
both variants and pass the map-based budget before hardware stress acceptance.
