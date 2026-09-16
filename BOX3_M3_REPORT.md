# M3 selective BOX-3 audio report

> Post-M9 memory correction: the recorded `IRAM 16,384/16,384` row is
> ESP32-S3's dedicated subrange, not its complete linkable IRAM capacity. The
> earlier exhaustion/gate interpretation is superseded by the combined
> IRAM/DIRAM link-map audit in
> [M10_STATIC_MEMORY_BUDGET_REPORT.md](M10_STATIC_MEMORY_BUDGET_REPORT.md); the
> original milestone measurements below remain historical evidence.

## Outcome

The product shell now has a dedicated ESP32-S3-BOX-3 profile and a
product-owned audio lifecycle API. It selectively adapts XiaoZhi's proven
`BoxAudioCodec` behavior instead of importing XiaoZhi's complete application or
rewriting the codec path from scratch.

The full audio link closure builds with ESP-IDF 6.0.2. This is a compile/link
milestone, not a hardware acceptance result.

## Pinned source and retained behavior

- XiaoZhi commit: `18a60b8051f5ee6a25beed6248ed84c7fcc742bf`.
- ESP-Claw commit: `9ba07d013329df480e34a1a59d1513ab783d8a52`.
- Board: ESP32-S3-BOX-3, ESP32-S3-WROOM-1-N16R8.
- Audio rate: 24 kHz input and output.
- Output codec: ES8311, mono PCM, PA enable on GPIO 46.
- Input codec: ES7210, four-slot TDM with microphone and reference slots 0/1.
- I2S0: MCLK 2, WS 45, BCLK 17, DIN 16, DOUT 15.
- I2C1: SDA 8, SCL 18.
- DMA settings: six descriptors and 240 frames, matching XiaoZhi.

The adaptation removes XiaoZhi's `Board`, `Application`, `Settings`, UI, and
singleton ownership. The product owns construction, teardown, enable/disable,
volume, PCM read, and PCM write through `components/box3_audio`.

## Build and memory evidence

The dedicated build used the checked-in 16 MB A/B partition table and confirmed
that `CONFIG_PRODUCT_BOARD_ESP_BOX_3=y` was active. All public audio functions
were retained through harmless invalid-argument probes, so the codec and driver
closure could not be discarded by the linker.

| Measurement | Reference N32R16 | BOX-3 N16R8 | Difference |
|---|---:|---:|---:|
| Firmware `.bin` | 550,864 B | 628,224 B | +77,360 B |
| Linked image | 550,741 B | 628,104 B | +77,363 B |
| Flash code | 327,668 B | 385,396 B | +57,728 B |
| Flash data | 159,624 B | 177,876 B | +18,252 B |
| DIRAM | 53,525 B | 55,380 B | +1,855 B |
| DIRAM free | 288,235 B | 286,380 B | -1,855 B |
| IRAM | 16,384 B | 16,384 B | unchanged; 100% used |

Each BOX-3 OTA application slot is 5,767,168 bytes. The 628,224-byte binary
leaves 5,138,944 bytes, or 89%, free in each slot.

Because this fixed board uses the QIO Flash/Octal PSRAM combination already
specified by XiaoZhi, the BOX-3 profile disables ESP-IDF's flash-mode automatic
detection. Compared with the first complete audio build, that recovered 876
bytes of DIRAM and reduced the binary by 160 bytes.

Direct linked archive contributions include 16,382 bytes from the I2S driver,
14,005 bytes from `esp_codec_dev`, 9,781 bytes from the I2C driver, and 1,331
bytes from the product audio wrapper. The rest of the delta is their required
runtime/link closure.

## What this proves

- The BOX-3 board choice, flash/PSRAM profile, and exact 16 MB partition layout
  are accepted by ESP-IDF.
- The product API compiles against ESP-IDF 6 rather than depending on XiaoZhi's
  older I2S port type.
- ES8311, ES7210, I2C, I2S standard output, TDM input, lifecycle cleanup, PCM
  I/O, volume, and gain paths all survive the final link.
- The reference product still builds at 550,864 bytes; BOX-3 code is not pulled
  into its firmware image.

## What remains unproven

- Physical I2C codec discovery, microphone capture, PA output, clock stability,
  and long-running duplex behavior on a real BOX-3.
- Acoustic echo/reference quality, gain calibration, clipping, underruns,
  latency, thermal behavior, and barge-in timing.
- Connection of this PCM HAL to the XiaoZhi Opus stream and the live product
  gateway.
- The existing 100% IRAM reading is a release gate. It did not worsen in this
  milestone, but Wi-Fi/audio stress and future features need measured headroom
  or an explicit placement reduction before production approval.
- Display, buttons, provisioning, secure boot/eFuse production policy, and
  factory test are intentionally outside this audio slice.

## Reproduction

Activate ESP-IDF 6.0.2, download the pinned upstreams, and run:

```sh
./tools/sync_upstreams.sh
./tools/build_box3.sh
```

The script uses a separate `build-box3` directory and does not overwrite the
reference product configuration.
