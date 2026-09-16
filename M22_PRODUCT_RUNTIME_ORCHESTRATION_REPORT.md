# M22 product runtime orchestration report

## Result

M22 closes the software startup gap between the previously implemented
identity, control-plane, credential, Agent, Wi-Fi, provisioning, and memory
components. A BOX-3 release build can now opt into one product-owned
composition root that creates, connects, reports, and stops the complete
implemented runtime graph.

This validates the project's selective-rewrite strategy. Rewriting the product
shell, security policy, configuration, and lifecycle owner is more efficient
than merging the two upstream applications. Rewriting XiaoZhi's proven audio
and protocol work or ESP-Claw's Agent core would add cost without creating a
product boundary. M22 therefore composes those retained capabilities behind a
new product-owned runtime rather than replacing every module.

This is a compiled and host-tested software milestone, not a market-readiness
claim. No physical BOX-3, production service authority, factory eFuse station,
companion App, or alpha fleet was available for this gate.

## Product-owned composition root

`box3_product_runtime` is the single owner for seven dependency-ordered
resources:

```mermaid
flowchart LR
    I["Protected identity"] --> C["Authenticated control client"]
    C --> K["Short-lived credential client"]
    K --> S["Agent session supervisor"]
    S --> T["Approximate-time bootstrap"]
    T --> W["Product Wi-Fi"]
    W --> P["Physical-presence provisioning"]
```

Startup must acquire the exact left-to-right prefix. Normal shutdown and every
partial-start failure unwind right to left. A child cleanup timeout retains the
child handle, its callback owner, and the aggregate handle; the caller retries
the same `box3_product_runtime_stop()` operation instead of leaking or freeing
a live callback context.

The aggregate reports product state, Wi-Fi, approximate-time, provisioning,
supervisor, and error events. It also owns Agent interruption, onboarding
open/close, and combined runtime statistics. The caller continues to own Agent
memory and any trusted memory-consent context, so the aggregate cannot outlive
them.

## Cold-boot time trust

The startup audit found a circular dependency that component-level tests did
not expose: verified HTTPS needs a plausible process clock for certificate
validity, while the protected identity refuses to sign a proof until it has
accepted authenticated product time.

`product_time_bootstrap` resolves availability without weakening identity:

1. Wi-Fi usable-IP first wakes a bounded ESP-NETIF SNTP worker.
2. A plausible retained clock may enable TLS immediately, but the worker still
   refreshes once per network attachment.
3. SNTP success is recognized only after the ESP-NETIF sync wait succeeds and
   the clock lies in the bounded 2021–2100 range.
4. The supervisor receives network-ready only while approximate time is
   available; IP loss immediately removes readiness.
5. The protected identity never imports the SNTP component. It still accepts
   proof time only from the nonce-, device-, and client-bound `/v1/time`
   response authenticated by the product control plane.

The worker has bounded 1-second stop/network-loss polling, a 10-second default
sync attempt, a 60-second post-sync plausibility check, and capped exponential
retry with jitter. A clock that leaves the accepted range withdraws supervisor
readiness before retry. One to three reviewed DNS hostnames are public release
configuration, not credentials.

## Identity and release configuration

`app_main` now derives the saleable registry ID from the ESP base MAC:

```text
xz-<12 lowercase base-MAC hexadecimal digits>
```

It generates a separate random `boot-<16 lowercase hex>` client ID on every
boot using the ESP hardware RNG. The factory receipt schema and verifier now
require the receipt device ID to equal the base-MAC-derived ID; a serial number
does not replace this binding.

The release supplies exact public HTTPS authorities for the product control
plane and Agent proxy. The runtime rejects schemes, paths, userinfo, query,
fragment, whitespace, and oversized values, then appends only `/v1/time`,
`/v1/agent-token`, `/v1/session`, and Agent-proxy `/v1`. Provider master keys
and long-lived voice/Agent credentials cannot be supplied in the static
template. TLS verification remains mandatory.

Live startup is opt-in and BOX-3-only. Build configuration fails when the
control authority, Agent-proxy authority, primary SNTP hostname, certificate
policy, or valid identity key slot is missing, and it rejects sharing the
identity and encrypted-NVS HMAC slots. Ordinary Generic and BOX-3 profiles keep
the runtime disabled.

The separate Live compile profile uses only `.example.invalid` authorities. It
proves the complete branch links with secure storage, but its output must never
be flashed, signed, published, promoted, or shipped.

## Onboarding and memory boundaries

Boot never opens provisioning automatically. A board/App owner must validate a
local physical action and call the aggregate onboarding API. That call creates
one in-memory grant, and the provisioning component consumes it synchronously
and once. Speech, remote requests, and saved state cannot synthesize or replay
the grant.

The reference startup attaches the M21 bounded Agent-memory handle but supplies
no trusted consent callback. Reads remain possible under the established
untrusted-data policy; `memory.put` and `memory.forget` remain disabled until a
real product UI issues request- and session-bound one-use consent.

## Host and policy evidence

Two new C suites cover deterministic device/client identifiers, invalid MAC and
RNG inputs, exact HTTPS endpoint construction, illegal resource acquisition,
complete reverse cleanup, cleanup retry accounting, partial-start unwind,
plausible-time bounds, and capped jittered retry. Six product-runtime policy
tests pin opt-in Kconfig, fail-fast release configuration, non-routable compile
defaults, identity derivation, no automatic onboarding, exact endpoint paths,
reverse cleanup order, the SNTP/identity trust separation, and factory receipt
binding.

The final complete local regression passed:

- 22 C host suites;
- 7 gateway contract tests;
- 12 factory tests;
- 66 tooling, policy, OTA, rollout, generation, OCI, and memory tests;
- 5 independent generation-state validator tests;
- every Go package test and `go vet ./...` with pinned Go 1.26.5.

These tests exercise the deterministic lifecycle core and static architecture.
They do not simulate FreeRTOS scheduling, RF loss during SNTP, physical button
bounce, real certificate chains, eFuse behavior, or audio load on hardware.

## Firmware evidence

All five ESP-IDF 6.0.2 gates compile, link, and pass the 192 KiB minimum static
internal-memory headroom rule.

| Profile | Firmware `.bin` bytes | Static internal memory | Headroom |
| --- | ---: | ---: | ---: |
| Generic development | 1,078,528 | 118,992 / 358,144 | 239,152 |
| BOX-3 development | 1,379,664 | 120,928 / 358,144 | 237,216 |
| Generic secure storage | 1,087,872 | 119,376 / 358,144 | 238,768 |
| BOX-3 secure storage | 1,388,480 | 121,296 / 358,144 | 236,848 |
| BOX-3 Live compile-only | 1,389,680 | 121,344 / 358,144 | 236,800 |

Compared with M21, the statically retained runtime/time closure adds 9,648
bytes to BOX-3 development and 9,696 bytes to BOX-3 secure storage. Enabling
the complete Live branch adds another 1,200 bytes and 48 bytes of static
internal memory over BOX-3 secure storage. The compile-only image still leaves
76% of its smallest app partition free.

## Implemented artifacts

- `components/box3_product_runtime`: aggregate API, deterministic core,
  endpoint/identity helpers, callbacks, lifecycle, retry-safe stop, one-use
  onboarding authorization, and statistics;
- `components/product_time_bootstrap`: approximate certificate-time worker and
  host-testable plausibility/retry core;
- BOX-3 opt-in Live startup in `main/app_main.c` plus release Kconfig and CMake
  fail-fast checks;
- `sdkconfig.live-runtime-compile.defaults` and
  `tools/build_box3_live_compile_gate.sh`;
- base-MAC-bound factory receipt schema, fixture, verifier, and negative test;
- host and static product-policy tests;
- `PRODUCT_RUNTIME_RUNBOOK.md`, integration guide, README, product blueprint,
  and this report.

## Gates still open

1. Wire an approved BOX-3 long-press/button owner, display/LED states, and
   companion-App onboarding flow; execute wrong-PoP, lockout, rollback,
   replacement, power-cut, and accessibility cases.
2. On factory-provisioned hardware, prove separate identity/NVS eFuse keys,
   signed receipt activation, encrypted-NVS reboot, deterministic ID, verified
   control TLS, and WSS session establishment.
3. Run live STT/TTS/Agent-provider, barge-in, credential refresh, network/time
   outage, reconnect, heap/stack, cold-boot, acoustic, thermal, and long soak
   tests.
4. Deploy the production registry/control/Agent proxy/origin/generation
   services with managed workload identity, TLS/HA, WORM audit retention,
   vulnerability/admission gates, signing, OTA rollback, and incident response.
5. Execute a monitored 10–30 device alpha fleet before hardware certification,
   privacy review, manufacturing pilot, support readiness, and market launch.
