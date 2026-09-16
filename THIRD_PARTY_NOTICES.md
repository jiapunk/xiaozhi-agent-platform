# Third-party notices

This scaffold pins the following upstream source repositories:

- `78/xiaozhi-esp32`, MIT License, commit
  `18a60b8051f5ee6a25beed6248ed84c7fcc742bf`.
- `espressif/esp-claw`, Apache License 2.0, commit
  `9ba07d013329df480e34a1a59d1513ab783d8a52`.

The pinned ESP-Claw source is locally modified by
`patches/esp-claw/0001-redact-agent-content-logs.patch`. The patch removes
Agent content from logs and discards provider error bodies while preserving
metadata-only diagnostics. It is distributed in the firmware SBOM bundle at
`sources/esp-claw/0001-redact-agent-content-logs.patch`; the modified source
remains under Apache License 2.0.

`components/box3_audio` is an API/lifecycle adaptation of XiaoZhi's BOX-3
`BoxAudioCodec` at the pinned commit. It retains the proven pinout,
ES8311/ES7210 configuration, and I2S/TDM format under the MIT License. The full
license is in `third_party/xiaozhi-esp32-LICENSE.txt`.

The gateway redistributes:

- `github.com/coder/websocket` v1.8.15, ISC License. The full notice is in
  `gateway/third_party/coder-websocket-LICENSE.txt`.
- Unmodified text dictionaries from `BYVoid/OpenCC`, pinned at commit
  `4f90418b9ed73a91023897095c762e5fdaadc016`, Apache License 2.0. They are
  embedded under `gateway/internal/s3camdev/textlocale_data/`; the full license
  is included there as `OpenCC-LICENSE.txt`. The product-owned conversion code
  does not link third-party OpenCC ports.

The watch's `noto-tc-v1` common font and the Japan Gateway's matching on-demand
full glyph bundle are generated from Noto Sans CJK TC Regular 2.004, pinned to
`notofonts/noto-cjk` commit `523d033d6cb47f4a80c58a35753646f5c3608a78`,
under the SIL Open Font License 1.1. The source-font license and provenance are
kept beside the build input in the XiaoZhi fonts component.

The BOX-3 profile uses `espressif/esp_codec_dev` v1.5.11, Apache License 2.0,
resolved by the ESP-IDF Component Manager and pinned in `dependencies.lock`.
Its full license is distributed in the managed component's `LICENSE` file.

The secure device transport uses `espressif/esp_websocket_client` v1.8.0,
Apache License 2.0, also pinned by version and content hash in
`dependencies.lock`. A redistribution copy is included as
`third_party/esp_websocket_client-LICENSE.txt`; the unmodified managed
component retains its original copyright and license notices.

The secure onboarding transport uses `espressif/network_provisioning` v1.2.4,
Apache License 2.0, pinned by exact version and content hash in
`dependencies.lock`. Only its standard network-configuration data handler is
linked; radio and credential lifecycle remain product-owned. The unmodified
managed component retains its original copyright and license notices and its
`LICENSE` file.

The BOX-3 PCM/Opus stream additionally uses these ESP-IDF managed components,
all pinned by version and content hash in `dependencies.lock`:

- `espressif/esp_audio_codec` v2.5.0;
- `espressif/esp_audio_effects` v1.3.0~1;
- transitive `espressif/gmf_fft` v1.0.0.

These three components use `LicenseRef-Espressif-Modified-MIT`, which permits
use exclusively with Espressif Systems products and requires retention of its
copyright and permission notice. This project targets ESP32 devices and is
within that stated hardware scope; redistribution for non-Espressif products
is prohibited. Exact license texts are included as
`third_party/esp_audio_codec-LICENSE.txt`,
`third_party/esp_audio_effects-LICENSE.txt`, and
`third_party/gmf_fft-LICENSE.txt`.

`tools/sync_upstreams.sh` downloads those repositories into ignored
`third_party/` directories. M26 generates release-specific App and bootloader
SPDX graphs, reconciles their linker maps, supplements directly linked prebuilt
audio archives, and bundles the frozen firmware license corpus. Before
distribution, legal review must still conclude all `NOASSERTION` fields and
separately inventory fonts, media assets, wake-word data, models, datasets,
Apps, provider SDKs and factory tools that are outside the firmware build graph.

M27 fixture and M28 adapter-harness qualification were performed with a separately supplied,
GPL-enabled FFmpeg 7.0 binary. The project pins its hash as test evidence but
does not copy, link, package, or redistribute that binary in firmware, gateway
services, or release bundles. Any future redistribution of FFmpeg or its codec
dependencies requires a separate license and source-offer review.
