# M11 Product Wi-Fi Lifecycle Report

Date: 2026-08-09

## Outcome

M11 replaces the previous compile-only network assumption with one
product-owned ESP-IDF station lifecycle. The firmware now links the real
ESP32-S3 Wi-Fi, PHY, WPA supplicant, LwIP, and coexistence closures, while the
product layer remains a small C component rather than a second application or
board manager.

This milestone does **not** claim end-user onboarding is finished. It defines
the trusted onboarding boundary and implements the station, storage, retry,
event-serialization, and Agent-supervisor handoff underneath it. A secure
SoftAP/BLE transport, physical-button integration, encrypted credential
storage in the production security profile, and physical RF/runtime tests
remain release gates.

## Upstream audit and reuse decision

The pinned XiaoZhi revision declares `78/esp-wifi-connect: ~3.2.2` and its
`WifiBoard` wraps `WifiManager`, `WifiStation`, and `SsidManager`. That code is
useful reference behavior, but it is not imported as the product owner:

- `WifiBoard` reaches into XiaoZhi `Application`, display, alerts, sounds, and
  global board state.
- The pinned flow starts a 60-second timer and falls into configuration mode
  after the timer expires, which conflates temporary infrastructure failure
  with deliberate onboarding.
- `esp-wifi-connect` is a C++ singleton that owns station plus captive portal,
  stores up to ten plaintext SSID/password pairs in the shared `wifi`
  namespace, and initializes the default NVS partition.
- Its initialization recovery erases the complete default NVS partition on
  `NO_FREE_PAGES` or `NEW_VERSION_FOUND`.
- Its captive portal starts an open SoftAP with unauthenticated HTTP endpoints.
  Physical-presence policy, proof of possession, CSRF/session policy, and the
  product's OTA/settings authorization boundary are not supplied by that
  component.

The component is MIT-licensed and remains a valid prototype/reference, but
the product uses only its useful behavioral lessons. It directly reuses the
official ESP-IDF Wi-Fi driver and implements a narrow product policy layer.
No Wi-Fi driver or WPA implementation was rewritten.

Audited primary sources:

- <https://github.com/78/xiaozhi-esp32/tree/18a60b8051f5ee6a25beed6248ed84c7fcc742bf>
- <https://github.com/78/esp-wifi-connect>
- <https://components.espressif.com/components/78/esp-wifi-connect>

## Implemented ownership boundary

`components/product_wifi` now owns exactly one station lifecycle:

```text
STOPPED
  | start + no credential
  v
UNPROVISIONED --physical action--> ONBOARDING --validated save--> CONNECTING
                                           |                         |
                                           | clear                   | got IP
                                           v                         v
                                     UNPROVISIONED               ONLINE
                                                                    |
                                              transient loss        |
                                            +-----------------------+
                                            v
                                         BACKOFF --deadline--> CONNECTING

Three consecutive authentication/security failures:
CONNECTING -> CREDENTIAL_REJECTED -> physical action -> ONBOARDING
```

The component provides:

- one FreeRTOS worker as the sole policy/event owner;
- non-blocking ESP Wi-Fi/IP callbacks that enqueue typed events;
- fail-closed handling if event ordering cannot be preserved because the
  bounded queue overflows;
- all-channel, strongest-signal station selection with WPA2-or-better
  threshold and PMF capability;
- open-network and control-character credential rejection;
- jittered exponential reconnect from 2 seconds to 5 minutes;
- automatic retry pause after three consecutive authentication/security
  failures, requiring explicit onboarding rather than opening a portal;
- IP readiness only after `IP_EVENT_STA_GOT_IP`, and immediate readiness
  removal on disconnect/lost-IP;
- metadata-only events and statistics with no SSID/password logging;
- a retry-safe stop path that unregisters event handlers before destroying
  the station interface and Wi-Fi driver.

`box3_agent_supervisor_product_wifi_event()` is a direct callback adapter. A
`PRODUCT_WIFI_EVENT_NETWORK_CHANGED` event is the only Wi-Fi signal forwarded
to `box3_agent_supervisor_set_network_available()`. Token refresh, WSS startup,
audio, and Agent startup therefore remain gated on a usable IP address.

## Credential persistence and recovery policy

The implementation deliberately does not call `nvs_flash_erase()`.

- Partition: `nvs`
- Namespace: `prod_wifi`
- Key: `credential`
- Format: one fixed-size, versioned 108-byte blob
- Integrity: magic, exact lengths, zero padding, and CRC32
- Mutation: one committed blob overwrite, or explicit deletion of that key
  only while onboarding

Malformed or incompatible data makes the device unprovisioned and reports a
metadata-only error. It does not erase `nvs_factory`, another namespace, or
the complete `nvs` partition. Submission scratch is securely cleared after it
is committed; the active in-memory copy is cleared on replacement and stop.

The development profiles currently have `CONFIG_NVS_ENCRYPTION` disabled, so
the Wi-Fi credential is **not encrypted at rest in these test images**. The
component emits an explicit development warning. Production release must use
the factory-owned NVS-encryption/flash-encryption design with a separately
allocated and audited key purpose; it must not let application startup
silently generate or burn an eFuse key. Migration and reset behavior must be
validated on sacrificial devices before enabling that profile.

## Onboarding trust boundary

M11 intentionally does not start SoftAP, BLE, SmartConfig, or a web server.

1. The product's physical-presence owner calls
   `product_wifi_begin_onboarding()` after an explicit button/UX action.
2. Only while in `ONBOARDING` may a trusted transport call
   `product_wifi_submit_credentials()` or clear the product key.
3. The component validates and persists credentials, stops the onboarding
   phase, and restarts the station lifecycle.

The next transport must add proof of possession, a bounded session lifetime,
attempt limits, no credential echo, and immediate teardown after success. An
open unauthenticated captive portal will not be accepted as a product default.

## Verification

The new host suite covers:

- invalid policy configurations;
- unprovisioned boot and mandatory explicit onboarding;
- credential-save transition to station startup and IP readiness;
- bounded jittered retry and retry deadlines;
- three authentication failures entering `CREDENTIAL_REJECTED` with no
  further automatic connect;
- onboarding while online forcing network-down and station-stop;
- stop/fatal fail-closed behavior;
- credential format round-trip, bounds, tamper, and truncation rejection.

Final full verification passed:

- 14 native C host suites;
- 7 gateway-contract Python tests;
- 5 factory-receipt Python tests;
- 3 static-memory Python tests;
- all Go unit/integration tests and `go vet`;
- generic ESP32-S3 full-clean build and memory gate;
- ESP32-S3-BOX-3 full-clean build and memory gate;
- shell syntax checks for both build scripts and the test runners.

No board was flashed and no RF association, DHCP, roaming, AP reboot, bad
password, or long-running reconnect sequence was exercised.

## Final size and static-memory evidence

| Metric | Generic N32R16 | BOX-3 N16R8 |
|---|---:|---:|
| Firmware `.bin` | 978,816 B (`0xeef80`) | 1,268,704 B (`0x135be0`) |
| OTA slot free | 6,361,216 B (87%) | 4,498,464 B (78%) |
| Flash code | 671,936 B | 914,924 B |
| Flash data | 206,160 B | 251,732 B |
| Executable IRAM span | 79,360 B | 80,896 B |
| Shared DIRAM code | 62,976 B | 64,512 B |
| Exact internal static use | 118,672 / 358,144 B (33.14%) | 120,480 / 358,144 B (33.64%) |
| Exact internal static headroom | 239,472 B | 237,664 B |

The M10 pre-Wi-Fi comparison is intentionally large because it did not link
the Wi-Fi/PHY/supplicant closure:

| Delta from M10 | Generic | BOX-3 |
|---|---:|---:|
| Firmware `.bin` | +393,040 B | +390,912 B |
| Executable IRAM span | +29,184 B | +28,672 B |
| Exact internal static use | +48,400 B | +47,840 B |
| Exact internal headroom | -48,400 B | -47,840 B |

The product-owned `libproduct_wifi.a` contribution itself is only 5,142 B
(generic) or 5,154 B (BOX-3), almost entirely flash code. Most of the M11
increase is the real vendor Wi-Fi, net80211/PP, PHY, WPA-supplicant, LwIP, and
network-interface closure that any functional station requires.

Both variants still pass the established limits:

- executable IRAM span at most 98,304 B;
- combined static internal headroom at least 196,608 B.

The BOX-3 margin above the static headroom floor is now 41,056 B. Static
link-map success does not include the 6 KiB Wi-Fi worker stack, ESP Wi-Fi
runtime allocations, TLS buffers, audio DMA, other task stacks, or heap
fragmentation. Physical runtime heap/stack measurement is therefore a hard
gate rather than a documentation follow-up.

## Remaining release gates

1. Choose and implement the SKU onboarding transport with physical presence,
   proof of possession, bounded lifetime, and abuse tests.
2. Define and factory-provision the production NVS encryption scheme without
   colliding with the Agent identity HMAC slot.
3. Wire the actual BOX-3 button/UX owner and run bad-password, AP-unavailable,
   router-reboot, DHCP-loss, roaming, credential-replacement, and reset tests.
4. Record internal/DMA heap minima, PSRAM minima, every task stack high-water
   mark, audio loss, and TLS/WSS behavior under concurrent Wi-Fi reconnect.
5. Run 8-hour and 72-hour soak tests before accepting the lifecycle for
   release.

M11 demonstrates why the chosen rewrite boundary is efficient: the product
owns the parts that determine security, recoverability, and lifecycle, while
the radio, WPA, TCP/IP, codecs, and Agent runtime remain mature reused
implementations.
