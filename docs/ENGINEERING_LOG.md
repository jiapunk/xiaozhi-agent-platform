# XiaoZhi Agent Platform

This is a product-owned ESP-IDF application shell for combining XiaoZhi's voice
and hardware strengths with ESP-Claw's on-device Agent Runtime. It deliberately
does not merge the two complete applications.

## What is implemented

- Reproducible upstream lock file and downloader.
- ESP32-S3 N32R16V development baseline and 32MB A/B OTA partition table.
- Allocation-free request-correlated `agent_bridge` state machine.
- Barge-in cancellation and stale Agent/TTS result rejection.
- Minimal ESP-Claw runtime wrapper with a closed product capability enum,
  separate read/action visibility groups, request/session-bound one-use action
  grants and metadata-only audit. State-changing consent is requested only
  after exact typed action validation and is argument-bound; the Companion
  core and control plane implement a canonical 30-second, owner-epoch-bound,
  one-use decision contract. The backend reference store is development-only;
  production requires the durable PostgreSQL multi-replica adapter.
  A digest-locked upstream privacy patch
  removes completion/tool/reasoning/provider-body content from logs, while the
  product retains only closed, monotonic saturating counters. BOX-3 exposes
  real `device.get_status`; the development Live compile profile additionally
  binds consent-protected `device.set_indicator` to GPIO 47 display backlight.
  The Companion composition now includes a scene-aware SwiftUI gate and a
  just-in-time HTTPS exchange for device-bound action access; the matching BFF
  handler publishes a token only after selected-IdP/ownership authorization
  and durable JTI registration.
  Production-security keeps that action disabled until external release gates
  have independent evidence.
- Harmless boot-time linkage probe that retains and verifies the Agent startup
  dependency closure without creating tasks or making network requests.
- ESP-IDF minimal-build mode, so unrelated framework components are excluded.
- Host tests for the bridge's success, failure, interruption, stale-event, and
  request-id wraparound paths.
- Allocation-free, safely escaped `tts_request` and `tts_abort` wire messages.
- XiaoZhi cJSON adapter for existing STT plus request-correlated TTS lifecycle.
- Fail-closed Device Agent v1 negotiation in XiaoZhi client/server hello.
- Host tests for protocol escaping, buffer exhaustion, barge-in ordering,
  stale sessions/IDs, malformed IDs, TTS errors, and legacy server rejection.
- Dependency-free gateway reference contract and server-side conformance tests.
- Go WebSocket gateway with device authentication, private STT/TTS adapters,
  real-socket integration tests, rate limits, metrics, and graceful shutdown.
- Versioned, provider-neutral private STT/TTS contracts with strict live and
  readiness negotiation, plus fail-closed structural validation of every mono
  60 ms Opus packet before uplink forwarding or downlink emission.
- Deterministic 16 kHz STT and 24 kHz TTS Opus fixtures, independently encoded
  by libopus and decoded by a hash-pinned FFmpeg native decoder with exact
  60 ms sample-count and PCM-hash verification.
- Offline live-adapter qualification using approved corpus input, frozen
  latency/cancellation thresholds, parallel isolation probes and canonical
  Ed25519 receipts that cannot claim production readiness.
- Dedicated ESP32-S3-BOX-3 N16R8 profile with a 16 MB A/B OTA layout.
- Product-owned SKU profiles and an early fail-closed hardware-geometry guard:
  board/SKU/revision build pairing plus runtime SoC, revision, Flash and PSRAM
  validation before storage or networking. Agent capabilities are intersected
  with the selected SKU allow-list.
- Factory-authenticated, reset-stable BOX-3 SKU identity: an exact 70-byte
  `nvs_factory/prod_sku/manifest` is HMAC-verified with the unreadable and
  locked per-device identity eFuse key, then cross-checked against the compiled
  SKU/hardware revision and observed silicon revision/base MAC before reset
  recovery or networking. Factory generation is non-overwriting and receipt
  v4 binds the same subject to registry and runtime evidence.
- Per-unit factory encrypted-flash manifests bind one device/transaction to
  the approved signing request, signed bootloader/App, ordered Secure Boot
  digests, address-dependent XTS ciphertext, exact public factory NVS and five
  raw readbacks. The COMPLETE artifact is canonical and non-overwriting;
  factory receipt v4 verification now requires and cross-checks the external
  manifest instead of trusting a syntactically valid digest alone.
- Signed physical flash observations now distinguish trusted station evidence
  from copied test files. A read-only, no-stub ESP32-S3 capture freezes the
  pre-Secure-Download-lock eFuse state and five readbacks; an externally
  trusted Ed25519 authority must sign the exact transaction/release subject.
  Manifest v2 and the receipt-v4 CLI both require and cross-check that receipt.
- A pinned real `espefuse 5.3.1 --virt` lifecycle now rehearses all six BOX-3
  key slots and six irreversible security stages. It verifies logical-to-
  physical block mapping, `RD_DIS=0x38`, readable Secure Boot digests,
  protected XTS/HMAC secrets and the shared final Secure Download write lock;
  its evidence is permanently marked `VIRTUAL_TEST_ONLY`.
- A signed M58 sacrificial-board authorization contract now binds one blank
  BOX-3, transaction, attempt, release, station, fixture and two or more
  operators for at most 15 minutes. The capture is read-only, the exact
  nine-stage plan is externally Ed25519-signed, and the safety boundary is
  permanently no-inventory, quarantine-or-destroy and `executor_included=false`.
- A local M59 sacrificial-attempt ledger now gives that plan atomic one-time
  consumption. Its externally signed policy binds station/fixture and the
  actual filesystem device/inode; a completed record is published by exclusive
  hard link plus fsync. It remains single-station and explicitly invokes no
  executor or hardware operation.
- M60 removes caller-supplied time from production consumption. Ledger policy
  v2 pins an HTTPS/mTLS time endpoint, CA/client certificate and independent
  Ed25519 time key; a fresh nonce-bound receipt lasting at most ten seconds is
  embedded in consumption record v2 before the atomic link.
- M61 implements the matching Go time-authority core: exact TLS 1.3 mTLS and
  canonical request handling, atomic PostgreSQL station/fixture/certificate
  authorization plus globally unique hashed request/nonce replay rows, database
  time, and an external-only Ed25519 signer interface. No production signing
  key, service command, hardware executor or live database claim is included.
- M62 packages that core as the seventh backend service. Its provider-neutral
  remote signer accepts only canonical M60 receipts over pinned TLS 1.3 mTLS,
  locally verifies every Ed25519 result, and keeps the signing private key out
  of the process and Pod. OCI schema v3 and Kubernetes schema v3 now bind the
  exact seven-service release and 44-resource deployment graph.
- M63 implements the signer-side enforcement core: exact authority certificate
  pinning, canonical receipt-only transport, committed PostgreSQL row/time
  checks before and after the HSM/KMS call, and local verification of the
  backend signature. It contains no private key and remains outside the product
  workload trust domain.
- Product-owned BOX-3 audio lifecycle API selectively adapted from XiaoZhi:
  ES8311 output, ES7210 microphone/reference input, and 24 kHz I2S/TDM.
- Allocation-free XiaoZhi WebSocket binary audio framing for transport versions
  1, 2, and 3, with strict length and reserved-field validation.
- Request-generation playback gate with bounded four-packet queue, local
  `BEGIN`/`DRAIN`/`FLUSH`, stale-frame rejection, and barge-in invalidation.
- Transport-neutral device voice runtime that binds hello negotiation, STT,
  ESP-Claw completion, correlated TTS lifecycle, and binary audio admission.
- BOX-3 24 kHz stereo/TDM capture to 16 kHz mono/60 ms Opus uplink, plus
  24 kHz mono/60 ms Opus decode and playback. Capture and playback use separate
  workers and can run full duplex.
- Full BOX-3 audio/codec/effects/driver link-closure verification without
  touching hardware during the boot-time probe.
- WSS-only ESP transport with mandatory server verification, short-lived
  Bearer credentials, XiaoZhi identity/version headers, bounded priority TX,
  strict chunk reassembly, metadata-only failures, and no unsafe token reuse.
- Serialized device voice client that preserves JSON/audio/Agent completion
  order and fail-closes on hello timeout or fatal control overflow.
- `box3_agent_voice` composition root that owns BOX-3 audio, XiaoZhi protocol,
  ESP-Claw callbacks, copied credentials, and retry-safe shutdown ordering.
- `box3_product_runtime` as the product composition root above the session:
  deterministic base-MAC registry identity, random per-boot client identity,
  exact release-authority URL construction, identity/control/credential/
  supervisor/approximate-time/Wi-Fi/provisioning startup, strict reverse
  unwind, release-before-arm/debounced BOX-3 Boot-button ownership, one-use
  local onboarding authorization, and retry-safe aggregate stop. SNTP only
  unlocks certificate-time availability; protected proof time still requires
  the authenticated product-control response.
- Restartable process-global ESP-Claw Capability registration, allowing a
  supervisor to destroy/recreate a credentialed session without rebooting.
- Optional device session control plane with per-device HMAC bootstrap proof,
  strict registry, clock-skew bounds, nonce replay denial, issuance throttling,
  short-lived token/JTI issuance, disabled-device checks, and no-store replies.
- Purpose-bound Ed25519 device-identity snapshots with a monotonic restart
  floor, 5-minute-to-24-hour validity, atomic hot reload, rollback/equivocation
  rejection, secret-free gateway/Agent/origin access views, confidential
  control-plane proof views, fail-closed readiness/issuance, active close of
  connected revoked devices, provider-context cancellation, and firmware
  write-deadline interruption; optional M31 delivery uses dedicated-CA mTLS,
  signed conditional fetch and strict revision/ETag consistency.
- Product-owned Swift Companion App onboarding core with canonical factory-QR
  acceptance, one-use/wiped label and Wi-Fi tickets, explicit five-minute/
  lockout/cancellation states, authenticated-online-only success, and an iOS
  SoftAP/Security 2 adapter pinned to official ESPProvision 3.1.0 with logging
  disabled, bounded operations and dependency/license/privacy gates.
- Explicit ownership release/rebind lifecycle: step-up/action/device-bound
  Companion release, monotonic binding epochs, live Voice/Agent revocation,
  and XAM2 on-device memory isolation across resale.
- One-use enforcement for control-plane-issued voice tokens plus three-key
  verification rotation compatibility.
- `box3_agent_supervisor` as the sole credential/session owner: separate voice
  and Agent tokens, monotonic expiry refresh, Wi-Fi gating, teardown-before-
  recreate, bounded exponential backoff with jitter, and retry-safe cleanup.
- `box3_agent_credentials_client` as the supervisor-compatible HTTPS session
  client: canonical per-device proof, protected signer/time callbacks, strict
  bounded JSON parsing, TLS-only policy, token-audience separation, and
  credential scratch clearing.
- `agent_device_identity` backed by an unreadable/write-protected ESP32-S3
  HMAC_UP eFuse slot. It signs only current, device-bound `/v1/session` or
  `/v1/agent-token` proofs through distinct callbacks and fail-closes on
  missing, stale, rolled-back, or reboot-lost trusted time.
- Separate session and Agent proof scopes, token audiences, and signing keys;
  neither protected signer callback is an arbitrary HMAC oracle.
- `agent_control_plane_client` with same-authority HTTPS authenticated-time and
  Agent-token endpoints, strict nonce/identity binding, bounded responses,
  scoped eFuse proof signing, automatic stale-time refresh, and scratch
  clearing.
- An independently deployable control plane for authenticated time plus
  short-lived voice/Agent token issuance, with proof replay denial and
  metadata-only operations endpoints.
- A product Agent proxy that verifies Agent-only credentials, presents one
  stable ESP-Claw model alias, bounds/normalizes requests and responses, keeps
  provider keys server-side, sanitizes failures, and rate-limits per device.
- A durable OTA generation coordinator with an fsynced append-only HMAC audit
  chain, non-overwriting record commits, repairable atomic pointer, exact CAS
  publication, authenticated replica acknowledgements, bounded serving leases,
  drain fencing, and fail-closed control/origin integration.
- A daemonless deterministic OCI release builder for seven backend services and
  two Linux architectures, with scratch/non-root/static image policy, SPDX 2.3
  SBOM and in-toto/SLSA provenance subjects, an external-trust-root Ed25519
  receipt, plus independent Python and Go graph/layer/ELF validators.
- A two-person factory enrollment runbook, strict secret-free v4 receipt
  schema, and Ed25519 verifier that binds the base-MAC-derived product ID,
  all six frozen eFuse key blocks, external-signing and per-device encrypted-
  flash evidence, onboarding readback, encrypted NVS, registry, security, and
  online evidence.
- A reproducible BOX3 production-security profile with RSA-3072 Secure Boot V2,
  three rotation roots, external/HSM-only signing inputs, per-device
  XTS-AES-128 Flash Encryption release mode, real 16-step anti-rollback,
  secure-download policy, encrypted sensitive data partitions, independent
  signed-artifact verification, and a non-flashable build gate.
- A release-specific firmware SBOM gate that emits canonical SPDX 2.2 graphs
  for both App and bootloader, independently reconciles every linker-map
  archive, supplements directly linked prebuilt audio libraries omitted by the
  official minimal graph, and binds 27 exact license/notice files in a
  non-overwriting, last-`READY` release bundle.
- A product-owned ESP-IDF Wi-Fi station lifecycle with a serialized event
  worker, dedicated NVS namespace/blob, no implicit partition erase,
  WPA2-or-better credential policy, bounded jittered retry, explicit
  physical-presence onboarding state, and direct Agent-supervisor readiness
  handoff.
- A product-owned, physical-presence-gated SoftAP onboarding service using the
  official Espressif provisioning wire protocol and Security 2. It has a
  bounded window/failure lockout, per-device factory SRP material, an
  authenticated one-client WPA2 AP, and candidate validation that preserves
  prior working credentials until the replacement obtains usable IP.
- A sole product NVS initializer with a production profile that reads an
  already-provisioned, fully protected, per-device HMAC_UP key and derives
  XTS-AES keys for the credential partition. Normal firmware cannot generate
  or burn that key, identity/storage slots cannot be shared, and a missing or
  invalid key stops product startup.
- A product-owned signed A/B OTA component with an exact P-256 release
  manifest, authenticated-time/target/sequence policy, same-authority HTTPS,
  full-image SHA-256 and app-descriptor binding, explicit first-boot health
  gates, rollback/reject APIs, two-key rotation support, offline signer/verifier
  tooling, and a v2 release signature that cannot be created without an
  independently signed exact-image reset-hardware qualification receipt.
- A dedicated fleet OTA offer path with device-bound proof, strict signed
  release registry, deterministic cohort selection, and short-lived OTA-only
  tokens bound to release ID plus image SHA-256.
- An immutable firmware-origin service that rehashes exact catalog objects,
  enforces OTA-token object binding, rejects partial/conditional/redirected
  downloads, and limits concurrent streams per device and service.
- One fail-closed OTA deployment-bundle builder plus independent Python and Go
  validators. It derives both service catalogs from the signed release, binds
  their digests in a canonical receipt, writes `READY` last, and cannot produce
  an enabled rollout.
- A two-person rollout-generation chain with an external Ed25519 approver
  keyring, exact request/approval signature domain, monotonic `EXPAND`,
  zero-cohort `EMERGENCY_STOP`, explicit `RESUME`, immutable parent-receipt
  linkage, historical keyring rotation, and complete-lineage Python/Go
  validation.
- A final product market-release evidence gate with a fixed 15-domain evidence
  set, independently pinned Ed25519 authorities, exact cross-artifact subject
  binding, bounded evidence age, canonical parent-record continuity and a
  separately signed `MARKET_RELEASE_PASS` that cannot omit an external gate.
  Schema v2 also directly validates and binds the independent exact 28-day,
  seven-service backend SLO proof without adding a sixteenth evidence domain
  or an eighth workload.

## Current boundaries

- No complete XiaoZhi application is imported; this remains a selective-reuse
  product shell.
- No duplicate audio, display, Wi-Fi, filesystem, or board manager is started.
- The sample app does not store a model-provider master API key. The BOX-3 live
  composition root is implemented but opt-in: a release profile must provide
  reviewed public control/Agent-proxy authorities and a factory-provisioned
  identity key. It then obtains separate short-lived voice and Agent tokens.
- The provider-neutral speech conformance gate is implemented, but real
  speech-provider adapters and a live model-provider validation are not yet
  deployed. M27 adds a synthetic reference-decoder fixture gate and M28 adds a
  live candidate runner, but the checked-in result is deliberately only a local
  test-harness pass. Neither replaces signed primary/backup provider evidence,
  ESP decoder, real captured speech, language-quality, privacy, cost, provider-
  side cancellation/billing, or soak evidence.
- App and bootloader SBOM generation/map reconciliation are implemented, but
  SPDX license declarations intentionally remain `NOASSERTION`. Release-date
  CVE/exploitability review, legal conclusions, and separate inventories for
  assets, wake words, models, Apps, providers and factory tools remain open.
- The PCM/Opus, controller, serialized product event loop, ESP-side WSS/TLS
  client, independent voice/Agent issuance, authenticated-time and Agent-token
  ESP HTTPS clients, product Agent proxy, and reconnect/expiry supervisor are
  implemented. The Wi-Fi station/retry/persistence lifecycle, secure
  SoftAP/Security-2 onboarding transport, and production HMAC-derived NVS
  encryption path and full boot composition are implemented; physical-button
  electrical/enclosure validation, display/LED UI rendering, actual eFuse and
  factory-station execution, real phone/board provisioning, live TLS/provider
  registry push/scan/Cosign/admission, production OTA key/authority/fleet wiring, managed HA/WORM
  generation infrastructure, and the production distributed identity service
  remain. The single-leader durable CAS/convergence reference is implemented.
- BOX-3 audio is compile/link and host-contract validated; no physical board,
  microphone, speaker, acoustic echo path, or long-running duplex test has yet
  been measured.
- `VOICE_AGENT_KIT_BOX3` is a candidate profile, not a hardware identity claim.
  Runtime ESP APIs can validate SoC/Flash/PSRAM geometry but cannot prove the
  physical board, product revision, Codec/GPIO wiring or enclosure. Those need
  factory-bound identity and real-device qualification before promotion. The
  current broad silicon-revision candidate range must also be narrowed from
  qualified hardware evidence before release.
- The current M79 market-release schema v2 contract is implemented, but no
  production evidence/SLO authorities or release key are present and no
  `MARKET_RELEASE_PASS` bundle exists. Contract fixtures cannot substitute for
  live cluster, 28-day SLO, database, speech, factory, device, App, fleet,
  legal or security evidence.
- Skills, Lua, MCP and arbitrary filesystem/shell/HTTP tools remain explicitly
  disabled; they are not latent model permissions. Production eFuse execution
  and fleet operations remain later environment milestones. Bounded
  preference/profile memory is implemented; UI consent and real-device
  persistence remain external gates.

## Verified M0 results

The M0 scaffold was clean-built for ESP32-S3 with ESP-IDF 6.0.2 and the pinned
ESP-Claw revision. Its historical baseline was 547,456 bytes (about 535 KiB),
leaving 93% of each 7 MiB OTA application slot free. All current bridge,
controller, and XiaoZhi adapter host test suites pass.

These measurements include ESP-Claw Agent Core startup, Capabilities, HTTP and
TLS linkage. They do not include XiaoZhi audio/board code, live Wi-Fi traffic,
Skills, Memory, Lua, MCP, or production telemetry. See
[M0_BUILD_REPORT.md](M0_BUILD_REPORT.md) for the original baseline and
[VOICE_AGENT_PROTOCOL.md](VOICE_AGENT_PROTOCOL.md) for the implemented wire
contract. The current protocol-slice measurements are in
[M1_PROTOCOL_REPORT.md](M1_PROTOCOL_REPORT.md).
The real WebSocket boundary and its remaining deployment gates are documented
in [GATEWAY_M2_REPORT.md](GATEWAY_M2_REPORT.md) and
[gateway/README.md](gateway/README.md).

## Verified M3 BOX-3 result

The selectively adapted BOX-3 audio link closure builds as a 628,224-byte
firmware binary. Each 5.5 MiB OTA slot remains 89% free. The generic N32R16
image remains 550,864 bytes, demonstrating that the board-specific code is not
pulled into unrelated products.

ESP-IDF reports its dedicated IRAM subrange as 16,384 of 16,384 bytes used.
This was conservatively treated as a gate at M3; M10 later proved from the link
map that executable code continues into the intended shared D/IRAM region and
that total static internal headroom is not exhausted. Exact M3 evidence is in
[BOX3_M3_REPORT.md](BOX3_M3_REPORT.md).

## Verified M4 voice-stream result

The current generic image is 553,472 bytes. The BOX-3 image with the retained
24→16 kHz converter and bidirectional Opus codec closure is 827,952 bytes,
leaving 4,939,216 bytes (86%) free in each 5.5 MiB OTA slot. The generic image
only grew 2,608 bytes from M3, while the board-specific audio codec/effects
archives are absent from its linked contribution report.

All C host suites, seven Python gateway-contract tests, Go tests and vetting,
Go race tests, shell syntax checks, and both ESP-IDF builds pass. The historical
size table still shows the 16,384/16,384 dedicated subrange; its corrected
combined-memory interpretation is documented in M10. See
[M4_AUDIO_STREAM_REPORT.md](M4_AUDIO_STREAM_REPORT.md) for exact evidence and
the honest boundary between compiled integration and real-device proof.

## Verified M5 secure-device integration result

The secure generic image is 585,776 bytes and the BOX-3 image with the complete
composition root is 861,776 bytes. Their application slots remain 92% and 85%
free respectively. The WSS transport, serialized voice client, fail-closed
queue/hello policy, retry-safe lifecycle, credential ownership, and BOX-3
aggregate all compile and link under ESP-IDF 6.0.2.

Eight C host suites, seven Python contract tests, all Go tests/vetting/race
tests, shell checks, both firmware builds, and license-copy verification pass.
The dedicated 16,384/16,384 row is retained as historical output but is not the
complete ESP32-S3 internal instruction capacity. See
[M5_SECURE_DEVICE_INTEGRATION_REPORT.md](M5_SECURE_DEVICE_INTEGRATION_REPORT.md)
for the exact security policy, memory evidence, and remaining product gates.

## Verified M6 credential-lifecycle result

The optional control plane now proves a device with a per-device bootstrap
secret and issues a short-lived, one-use voice token. The BOX-3 supervisor owns
the complete credential lifecycle and never reuses a token after expiry or
disconnect. Voice and Agent credentials are distinct fields and are wiped from
supervisor scratch storage immediately after the aggregate copies them.

Nine C host suites, seven Python contract tests, Go unit/integration/vet/race
checks, shell checks, and both ESP-IDF builds pass. The generic image remains
585,776 bytes; the BOX-3 image is 866,480 bytes, leaving 85% of its application
slot free. This is still not hardware or production-identity proof. See
[M6_CREDENTIAL_LIFECYCLE_REPORT.md](M6_CREDENTIAL_LIFECYCLE_REPORT.md).

## Verified M7 device-credential client result

The BOX-3 firmware now has an HTTPS `/v1/session` client that builds the exact
gateway proof without owning the long-lived device secret, strictly validates
the bounded response, and supplies its voice credential plus a separately
scoped Agent credential to the supervisor. Both the client and supervisor
reject identical voice/Agent tokens.

Ten C host suites, seven Python contract tests, all Go tests/vetting/race
tests, shell checks, and both ESP-IDF builds pass. The generic image remains
585,776 bytes; the BOX-3 image is 870,112 bytes and retains 4,897,056 bytes
(85%) in each OTA slot. The later M10 link-map audit supersedes the earlier
full-IRAM interpretation. See
[M7_DEVICE_CREDENTIAL_CLIENT_REPORT.md](M7_DEVICE_CREDENTIAL_CLIENT_REPORT.md).

## Verified M8 factory-identity baseline

The ESP32-S3 path now verifies a factory-injected HMAC_UP key slot is
read-protected, write-protected, and purpose-protected before use. Its signer
accepts only the exact enrolled device ID, safe boot client ID, canonical
16-byte nonce, and timestamp within two seconds of the guarded current time.
The component never programs eFuse.

Twelve C host suites, seven Python gateway-contract tests, five factory-receipt
tests, all Go unit/integration/vet/race checks, shell/schema checks, and both
ESP-IDF builds pass. The generic image remains 585,776 bytes; BOX-3 is 873,200
bytes with 4,893,968 bytes (85%) free per OTA slot. The later M10 link-map audit
supersedes the earlier full-IRAM interpretation. See
[M8_FACTORY_IDENTITY_REPORT.md](M8_FACTORY_IDENTITY_REPORT.md) and the
[factory identity runbook](FACTORY_IDENTITY_RUNBOOK.md).

## Verified M9 control-plane and Agent-proxy vertical slice

The ESP32 path now obtains nonce-bound product-authenticated time, signs a
separate `/v1/agent-token` proof with the protected eFuse identity, and supplies
the resulting short-lived Agent credential to ESP-Claw. An independent control
plane and product Agent proxy preserve different voice/Agent audiences and
keys; the provider master key never reaches firmware. The Go vertical-slice
test runs from device proof through Agent-token issuance and proxy policy to a
fake provider response.

Thirteen C host suites, twelve Python contract/factory tests, all Go
unit/integration/vet/race checks, all three Go command builds, and both
ESP-IDF builds pass. The generic binary remains 585,776 bytes; BOX-3 is 877,792
bytes with 4,889,376 bytes (85%) free per OTA slot. No physical device or live
provider was exercised.
See [M9_CONTROL_PLANE_AGENT_PROXY_REPORT.md](M9_CONTROL_PLANE_AGENT_PROXY_REPORT.md).

## Verified M10 static internal-memory budget

The final link maps prove ESP-IDF's 16,384/16,384 IRAM row represents only the
dedicated subrange before shared D/IRAM, not total instruction-memory
exhaustion. The generic and BOX-3 executable spans are 50,176 and 52,224 bytes;
their exact combined static internal use is 70,272 and 72,640 of 358,144 bytes.

The new release checker requires at least 196,608 bytes of combined static
headroom and limits the executable span to 98,304 bytes. Both variants pass
with 287,872 and 285,504 bytes of headroom. Final Wi-Fi integration and
physical runtime internal/DMA heap, stack, audio, TLS, reconnect, and soak
measurements remain release gates. See
[M10_STATIC_MEMORY_BUDGET_REPORT.md](M10_STATIC_MEMORY_BUDGET_REPORT.md).

## Verified M11 product Wi-Fi lifecycle

The firmware now contains a single product-owned station lifecycle backed by
the official ESP-IDF Wi-Fi driver. ESP Wi-Fi/IP callbacks are marshalled onto
one bounded worker; usable IP is forwarded directly to the BOX-3 Agent
supervisor. Transient failures use bounded jittered retry, while repeated
authentication failures stop automatic retry and require explicit onboarding.
No open SoftAP or web portal is started automatically, and NVS errors never
erase the shared partition.

Fourteen C host suites, fifteen Python tests, all Go tests/vetting, and both
full-clean firmware builds pass. The real Wi-Fi/PHY/WPA closure raises the
generic and BOX-3 binaries to 978,816 and 1,268,704 bytes. Their exact static
internal headroom is 239,472 and 237,664 bytes, so both still pass the M10
release budget. Secure onboarding transport, production NVS encryption, and
physical RF/runtime memory tests remain mandatory. See
[M11_PRODUCT_WIFI_LIFECYCLE_REPORT.md](M11_PRODUCT_WIFI_LIFECYCLE_REPORT.md).

## Verified M12 secure onboarding transport

The product now opens a one-client WPA2 SoftAP only after a SKU-owned
physical-presence callback succeeds. It serves the standard Espressif
`proto-ver`, Security-2 `prov-session`, and `prov-config` endpoints without
instantiating the official manager or a second Wi-Fi owner. The default window
is five minutes with five security failures before lockout.

Per-device factory tooling derives separate SoftAP and Security-2 secrets from
the protected HMAC identity, emits only a salt/verifier plus authenticated
material to `nvs_factory`, and creates a confidential QR-label record. New
credentials remain candidates until usable IP is obtained; a rejected
candidate is wiped and the previous working credentials remain intact.

Fifteen C host suites, seventeen Python tests, all Go tests/vetting, and both
full-clean firmware builds pass. The generic and BOX-3 binaries are 1,041,952
and 1,332,336 bytes. Exact static internal headroom remains 239,440 and 237,648
bytes. Physical button/UI integration, real Android/CLI/board verification,
production NVS encryption, and factory execution are still release gates. See
[M12_SECURE_PROVISIONING_REPORT.md](M12_SECURE_PROVISIONING_REPORT.md).

## Verified M13 production credential-storage baseline

`product_storage` is now the only NVS initialization owner. Its production
profile verifies a factory-provisioned HMAC_UP slot and every protection bit,
derives XTS-AES keys without a key partition, secure-initializes only the home
credential `nvs`, wipes key material, and fails closed. It never calls an NVS
key generator, eFuse writer, partition erase, or repair path. The unused
`nvs_keys` partition was removed from both SKU layouts.

The reference SKU reserves slot 4 for NVS and a distinct slot 5 for device
identity, subject to the frozen SKU allocation. Factory receipt v2 binds both
protected slots, onboarding/readback evidence, a Security-2 transaction, and an
encrypted-NVS reboot round trip. Sixteen C suites, 27 Python tests, all Go tests
and vetting, and all four development/secure-storage firmware builds pass. The
secure Generic and BOX-3 binaries are 1,052,064 and 1,342,032 bytes, with
239,056 and 237,264 bytes of static internal headroom. Actual eFuse burning and
encrypted-NVS operation on hardware remain release gates. See
[M13_PRODUCTION_STORAGE_REPORT.md](M13_PRODUCTION_STORAGE_REPORT.md).

## Verified M14 signed A/B OTA vertical slice

`product_ota` now rejects unsigned, stale, wrong-target, downgraded, oversized,
or cross-authority releases before writing flash. It verifies the full HTTPS
body hash/size and ESP app descriptor before selecting the passive slot. The
new image stays pending until every compiled storage/network/control-plane/
Agent health gate passes; BOX-3 also requires audio. The sample never
auto-confirms from `app_main`.

Seventeen C suites, 40 Python tests, all Go tests/vetting, a real-build
signer/verifier smoke test, and all four firmware clean builds pass. The secure
Generic and BOX-3 binaries are 1,074,208 and 1,364,256 bytes, with 238,784 and
236,976 bytes of static internal headroom. Physical OTA/rollback, production
keys/CDN/fleet orchestration, health wiring, Secure Boot/Flash Encryption, and
hardware anti-rollback remain release gates. See
[M14_SIGNED_AB_OTA_REPORT.md](M14_SIGNED_AB_OTA_REPORT.md) and the
[OTA release runbook](OTA_RELEASE_RUNBOOK.md).

## Verified M15 fleet OTA control vertical slice

`product_ota_client` now obtains authenticated time, signs a dedicated OTA
offer proof over compiled board/channel/sequence/version state, calls the exact
HTTPS `/v1/ota/offer` route, strictly parses the fleet decision, and locally
re-verifies an available M14 manifest before exposing its short-lived download
token. The control plane verifies the registered hardware profile, strict
signed release registry, deterministic basis-point cohort, and issues an
OTA-only token bound to release ID plus image SHA-256. Disabled releases,
zero-cohort devices, replay, wrong board, cross-audience, and cross-object token
use are covered by tests.

Eighteen C suites, 40 Python tests, every Go test and vetting pass. All four
firmware profiles build; final Generic/BOX-3 secure-storage binaries are
1,079,008 and 1,369,584 bytes, with 238,784 and 236,976 bytes of static internal
headroom. Production deployment, HSM/CDN integration, audited registry reload,
distributed replay/fleet state, physical OTA/rollback, and a 10–30 device alpha
remain open gates. See
[M15_OTA_FLEET_CONTROL_REPORT.md](M15_OTA_FLEET_CONTROL_REPORT.md).

## Verified M16 immutable firmware-origin vertical slice

The independently deployable `firmwareorigin` service now consumes the M15
OTA-only token and serves only the exact catalog object whose release ID and
image SHA-256 match its claims. Its strict read-only catalog rejects duplicate
JSON, path traversal, symlink escape, size/hash drift, unsafe URL paths, and
object tampering. Downloads require one full GET with no query, body, Range,
conditional request, redirect, or duplicate security header; every object is
rehashed before status 200 and only one stream per device may be active.

The control-plane test now follows a real signed offer token into the origin
and verifies the exact returned bytes. All Go tests, race detection, and vetting
pass, and a stripped static Linux service cross-build succeeds. No container
engine is installed here, so OCI build/scan/signing remains a deployment gate.
M16 changes no ESP source or M15 firmware size. See
[M16_IMMUTABLE_FIRMWARE_ORIGIN_REPORT.md](M16_IMMUTABLE_FIRMWARE_ORIGIN_REPORT.md).

## Verified M17 fail-closed OTA deployment bundle

One release job now generates the control-plane release registry and immutable
origin catalog together from the exact signed manifest, reviewed P-256 public
key, ESP image, `sdkconfig`, and canonical lowercase authority. The fixed
read-only tree contains a digest-bound receipt and a `READY` marker written
last; existing outputs, symlink inputs, unsafe URL paths, signature/build/image
drift, manual catalog drift, writable content, and unexpected files fail
closed. Every generated registry is disabled with a zero-device cohort.

The independent Go `validateotabundle` command then loads the same bundle
through the production OTA registry and firmware-origin catalog loaders and
cross-checks the signed release against the exact object. OTA registry key and
manifest resolution was also hardened to reject absolute paths, traversal, and
symlink escape. M17 changes no ESP source or M15 firmware size. Audited rollout
promotion, live replica convergence, OCI deployment, hardware OTA/rollback,
and fleet alpha evidence remain open. See
[M17_OTA_DEPLOYMENT_BUNDLE_REPORT.md](M17_OTA_DEPLOYMENT_BUNDLE_REPORT.md).

## Verified M18 two-person rollout-generation chain

M17 staging bundles can now be activated only by producing a new immutable
schema-v2 generation. The rollout request binds its exact parent receipt,
release/image, generation sequence, old/new cohort state, approval window, and
external keyring hash. Two distinct enabled operators with cryptographically
distinct Ed25519 keys must sign the exact request before promotion can create a
new bundle. The CLI takes its own host time; request and promotion must finish
inside both the 24-hour approval limit and signed P-256 manifest validity.

`EXPAND` permits only a strictly larger active cohort, `EMERGENCY_STOP` creates
a disabled zero-cohort generation, and `RESUME` requires a new two-person
approval. Python and Go validators walk every parent back to the original M17
staging bundle, select historical keyrings by pinned digest, reject ancestor-ID
reuse, and load each generation through the production OTA/origin loaders.
M18 changes no ESP source or firmware size. HSM-backed operator signing,
append-only audit storage, atomic replica publication/convergence, live fleet
telemetry, OCI deployment, hardware rollback, and alpha evidence remain open.
See [M18_OTA_ROLLOUT_GENERATION_REPORT.md](M18_OTA_ROLLOUT_GENERATION_REPORT.md).

## Verified M19 durable generation publication and replica convergence

Approved M18 bundles now move through one authenticated, durable state machine:
`STABLE`, `PREPARING`, `DRAINING`, and `COMMITTING`. The protected publisher
reruns the complete rollout lineage validator, binds the next receipt to the
coordinator's exact active revision/generation/receipt, and performs a CAS
publication. Every required control-plane and firmware-origin replica must
load the exact new bundle and acknowledge `PREPARED` before publication can
advance.

The drain phase stops old lease renewal and waits twice the bounded state lease
plus a monotonic local minimum before the active pointer switches. Old and new
replica guards were exercised in an interleaved test: old may serve before the
drain, neither serves after its lease expires and before commit, and only new
serves after commit. OTA offer/token issuance rechecks the gate after cohort
selection and signing; the origin rechecks after complete image hashing and
before status 200. A stale or unreachable coordinator therefore becomes a
bounded OTA outage, never permission to serve an old generation.

Every transition is a canonical, SHA-linked, HMAC-authenticated record committed
without overwrite and fsynced before `CURRENT` is replaced. Crash injection
proves that a pre-commit record is discarded, a post-record/pre-pointer commit
is recovered, stale/corrupt `CURRENT` is repaired, and record tampering fails
closed. Go and independent Python validators verify the audit chain. M19 changes
no ESP source or firmware size. External HA storage/WORM export, managed
workload identity/HSM, registry signing/admission, hardware OTA/rollback, provider/App/factory
validation, and fleet alpha evidence remain open. See
[M19_ATOMIC_GENERATION_PUBLICATION_REPORT.md](M19_ATOMIC_GENERATION_PUBLICATION_REPORT.md).

## Verified M20 deterministic OCI supply-chain bundle

The five Go services now build without a container daemon as static,
shell-free, non-root `scratch` layers for both `linux/amd64` and `linux/arm64`.
Each service OCI layout contains one multi-platform image index plus subject-
attached SPDX 2.3 SBOM and in-toto Statement/SLSA Provenance v1 artifacts. A
canonical top-level receipt, authenticated by an externally trusted Ed25519
key, pins every index, platform manifest, binary, SBOM, provenance, CA bundle,
Go executable/version, and source-input digest; `READY` binds that signed receipt.

Python and independently implemented Go validators traverse the complete OCI
graph, reject orphan/missing blobs and unsafe/writable/symlink layouts, unpack
deterministic gzip/USTAR layers, require an exact non-root filesystem, and
inspect ELF headers to reject a dynamic interpreter. Fixture tests prove
byte-for-byte reproducibility and negative behavior. A real clean smoke builds
all ten platform binaries twice, compares the complete trees, then passes both
validators. This local receipt is explicitly not Cosign/transparency evidence
or a SLSA level claim. Registry push, current vulnerability scanning,
Cosign/workload identity, admission policy, and TLS/HA cluster evidence remain
environment gates. See [M20_OCI_SUPPLY_CHAIN_REPORT.md](M20_OCI_SUPPLY_CHAIN_REPORT.md)
and [OCI_DEPLOYMENT_BASELINE.md](OCI_DEPLOYMENT_BASELINE.md).

## Verified M21 bounded product Agent memory

M21 introduced the product-owned `XAM1` personalization store; the current
firmware writes `XAM2`, binding every usable snapshot to the authenticated
cloud ownership epoch and discarding all unscoped XAM1 values during migration.
The store remains in the product
`nvs` partition rather than enabling ESP-Claw's filesystem memory. It permits
only eight small `profile`/`preference` items, saves no transcript, performs no
automatic extraction, and treats every value as untrusted user data. Two NVS
slots provide interrupted-write recovery with strict canonical decode,
generation selection, divergence denial, and CRC corruption checks. The
production confidentiality boundary remains M13 encrypted NVS; development
NVS is explicitly plaintext, and logical deletion is not described as
cryptographic flash erasure.

ESP-Claw exposes root-only `memory.list`, `memory.get`, `memory.put`, and
`memory.forget`. Mutations additionally consume one-use product grants bound to
the exact request, session, and operation; user speech alone cannot grant
consent. Bulk clear stays in the trusted product/App API. Two new C suites and
six policy tests cover format, UTF-8/content bounds, power-loss slot selection,
divergence, capacity, generation exhaustion, consent replay/session mismatch,
and architectural restrictions. All four ESP profiles build and retain at
least 236,976 bytes of static internal-memory headroom. Physical power-cut,
factory-reset, App consent UX, wear/soak, and provisioned encrypted-NVS tests
remain hardware/product gates. See
[M21_BOUNDED_AGENT_MEMORY_REPORT.md](M21_BOUNDED_AGENT_MEMORY_REPORT.md) and
[AGENT_MEMORY_DATA_POLICY.md](AGENT_MEMORY_DATA_POLICY.md).

## Verified M22 product runtime orchestration

BOX-3 now has one opt-in product lifecycle owner for protected identity,
authenticated control, short-lived session credentials, Agent supervisor,
approximate certificate time, Wi-Fi, and physical-presence provisioning. It
acquires the exact dependency prefix and always unwinds in reverse; a cleanup
timeout retains the child, callback context, and aggregate handle for an exact
retry. `app_main` derives `xz-<base-mac>` as the stable registry ID and a random
per-boot client ID, while the factory receipt verifier enforces the same MAC
binding.

Cold boot uses SNTP only to make TLS certificate dates checkable. Protected
proof time remains unavailable until the product control plane's nonce-bound
`/v1/time` response is authenticated. Live startup is BOX-3-only and disabled
by default; the separate secure-storage compile gate uses `.example.invalid`
authorities and must never be flashed or shipped. Boot never opens onboarding,
and the reference runtime cannot mutate Agent memory because it supplies no
trusted UI-consent callback.

The final regression passed 22 C host suites, 7 gateway-contract tests, 12
factory tests, 66 tooling tests, 5 independent generation-state tests, all Go
package tests, and `go vet`. Four normal firmware profiles plus the Live
compile-only profile build; the lowest static internal-memory headroom is
236,800 bytes. Real button/App, eFuse factory, production service, provider,
audio, soak, regulatory, and alpha-fleet evidence remains open. See
[M22_PRODUCT_RUNTIME_ORCHESTRATION_REPORT.md](M22_PRODUCT_RUNTIME_ORCHESTRATION_REPORT.md)
and [PRODUCT_RUNTIME_RUNBOOK.md](PRODUCT_RUNTIME_RUNBOOK.md).

## Verified M23 physical-action onboarding

The BOX-3 product runtime owns its eighth resource: one polled, debounced GPIO0
active-low Boot-button input. In the original M23 contract it remained disarmed
until a stable release, accepted one continuous three-second hold per press,
and routed that action only through the aggregate's existing one-use
physical-presence grant. M39 supersedes the classification timing with
release-only 3–<10 second onboarding and >=10 second factory reset while
retaining the same release-before-arm safety invariant. A boot/reset-held
input, bounce, short press, or monotonic-clock regression cannot produce a
delayed action. The GPIO owner still has no direct erase, eFuse,
credential-clear, or restart authority; it emits a typed action to the product
aggregate.

The reference BOX-3 Live build rejects a changed GPIO or polarity unless a new
board profile is reviewed. The then-current factory v2 receipt requires a fixture to
prove that boot-held opens no window and that release plus one qualified hold
opens exactly one Security-2 window. The reference app reports metadata-only
button events but still has no display/LED renderer or companion-App proof.

The final regression passed 23 C host suites, 7 gateway-contract tests, 13
factory tests, 72 tooling tests, 5 independent generation-state tests, all Go
package tests, and `go vet`. All five firmware profiles clean-build; the Live
compile-only image is 1,392,288 bytes and the lowest static internal-memory
headroom remains 236,800 bytes. This excludes the 3,072-byte runtime task stack
and dynamic heap. Real button/electrical/enclosure, display/App, factory,
provider, soak, regulatory, and fleet evidence remains open. See
[M23_PHYSICAL_ACTION_ONBOARDING_REPORT.md](M23_PHYSICAL_ACTION_ONBOARDING_REPORT.md)
and [LOCAL_ACTION_ONBOARDING_RUNBOOK.md](LOCAL_ACTION_ONBOARDING_RUNBOOK.md).

## Verified M24 production boot-security release gate

The product now owns a reproducible BOX3 production-security profile instead
of depending on developer signing state. It emits only secure-padded unsigned
inputs, rejects private keys and non-reproducible metadata, freezes all six
ESP32-S3 key blocks, requires Secure Boot V2 RSA, Flash Encryption release mode,
secure ROM download mode, and hardware anti-rollback, and moves the partition
table to `0x10000` so the padded bootloader plus signature sector fits.
Sensitive OTA state, PHY, coredump, system, and data partitions are explicitly
Flash Encrypted; credential NVS remains on the independent HMAC-XTS path.

An independent verifier binds the exact ESP-IDF/upstream/eFuse/partition policy,
requires three ordered distinct bootloader signatures and one trusted App
signature, and emits a canonical verification receipt. Two consecutive clean
builds produced identical hashes for the application, bootloader, partition
table, OTA data, and signing request. Factory receipt v3 now binds those signing
records, the per-device encrypted-flash manifest, all six block protections,
secure-download/JTAG locks, and physical boot/encryption/anti-rollback gates.

The final regression passed 23 C host suites, 7 gateway-contract tests, 16
factory tests, 95 tooling tests, 5 independent generation-state tests, all Go
package tests, and `go vet`. All six firmware profiles build. The production-
security application is 1,441,792 padded bytes with 236,688 bytes of static
internal-memory headroom; the lowest headroom across all profiles remains
236,688 bytes. No real eFuse, HSM key, or board was used, so sacrificial-board
factory proof remains a hard release gate. See
[M24_PRODUCTION_BOOT_SECURITY_REPORT.md](M24_PRODUCTION_BOOT_SECURITY_REPORT.md),
[PRODUCTION_BOOT_SECURITY_RUNBOOK.md](PRODUCTION_BOOT_SECURITY_RUNBOOK.md), and
[FACTORY_IDENTITY_RUNBOOK.md](FACTORY_IDENTITY_RUNBOOK.md).

## Verified M25 speech-provider conformance gate

The private speech boundary now has explicit product-owned contract versions:
`xiaozhi-private-stt-v1` and `xiaozhi-private-tts-v1`. STT WebSocket upgrades,
TTS synthesis responses, and configured readiness endpoints must echo the
matching `X-Xiaozhi-Speech-Contract` value. A generic successful status can no
longer qualify a mismatched adapter generation.

A dependency-free Go Opus parser now validates packet structure, all four Opus
packet codes, frame sizes/counts/padding, the 120 ms format limit, mono policy,
and the negotiated exact 60 ms duration. Device uplink is checked before it is
sent to STT; provider downlink is checked before it enters the correlated
device stream. This is structural validation, not audio decoding, so real
decoder, provider, privacy, latency, cancellation, language, cost, and BOX3
tests remain mandatory.

The final regression passed 23 C host suites, 7 gateway-contract tests, 16
factory tests, 99 tooling tests, 5 independent generation-state tests, all Go
package tests, `go vet`, and the Go race suite. M25 changes only the backend
speech boundary, so all M24 firmware hashes and security evidence remain
unchanged. See
[M25_SPEECH_PROVIDER_CONFORMANCE_REPORT.md](M25_SPEECH_PROVIDER_CONFORMANCE_REPORT.md)
and [SPEECH_PROVIDER_ACCEPTANCE.md](SPEECH_PROVIDER_ACCEPTANCE.md).

## Verified M26 firmware SBOM and license-release gate

The BOX3 production-security candidate now emits separate canonical SPDX 2.2
graphs for the application and bootloader. Every package must be reachable
from the described project, and every archive in both linker maps must resolve
to a graph component or an explicit supplemental package. This caught two real
blind spots in the official `--rem-unused` output: the directly linked
`esp_audio_codec` and `esp_audio_effects` prebuilt archives. Both are now bound
to exact Component Manager hashes, archive hashes and Modified-MIT terms.

The release bundle contains 110 App packages, 13 bootloader packages, two
supplemental prebuilt records, 27 exact license/notice files and a canonical
receipt with `READY` written last. Two independent generations were
byte-identical. The canonical hashes are:

- App SPDX: `31573d6c2f03716bf4f2b8bfc13b57bf22bab6080b5731326f7624778d151816`
- bootloader SPDX: `ef3e0ee2a711f1f3a340aa772129b0e6fe85a8329c3d6d28ccae0cc2cee7b016`
- receipt: `1a75725497821e561e46f9642830850fcf2eebc5bddfa97b4f89e49eaeb6d10a`

The final regression passed 23 C host suites, 7 gateway-contract tests, 16
factory tests, 110 tooling tests, 5 independent generation-state tests, all Go
package tests and `go vet`; the previously completed Go race suite remains
valid because M26 changes no Go or firmware code. All M24 firmware/signing
hashes remain unchanged. M26 is inventory evidence, not a legal opinion or a
current vulnerability scan. See
[M26_FIRMWARE_SBOM_REPORT.md](M26_FIRMWARE_SBOM_REPORT.md) and
[FIRMWARE_SBOM_RELEASE_RUNBOOK.md](FIRMWARE_SBOM_RELEASE_RUNBOOK.md).

## Verified M27 reference Opus codec gate

The speech contract now includes deterministic, non-private real-codec
fixtures for both product directions. A reviewed FFmpeg 7.0 binary uses
`libopus` to encode one 16 kHz STT and one 24 kHz TTS mono packet, while
FFmpeg's independent native Opus decoder must decode each raw packet after a
minimal deterministic Ogg wrapper. The gate pins the exact qualification
binary SHA-256, packet bytes, decoded PCM hashes and exact sample counts: 960
for 16 kHz and 1,440 for 24 kHz, both exactly 60 ms. The checked-in manifest is
byte-identical across clean generations, and the same packets pass the Go
gateway's structural policy.

Run the external codec gate with an explicitly supplied reviewed binary:

```sh
XIAOZHI_FFMPEG=/path/to/reviewed/ffmpeg ./tools/run_speech_codec_gate.sh
```

The reference FFmpeg build is GPL-enabled qualification tooling and is not
copied, linked, or shipped with firmware or gateway services. M27 proves only
synthetic fixture bitstream acceptance; real provider captures, ESP codec and
BOX3 acoustic tests remain release gates. The full regression passed 23 C host
suites, 7 gateway-contract tests, 16 factory tests, 114 tooling tests, 5
independent generation-state tests, all Go package tests, `go vet`, and the Go
race suite. See [M27_REFERENCE_OPUS_CODEC_REPORT.md](M27_REFERENCE_OPUS_CODEC_REPORT.md)
and [SPEECH_PROVIDER_ACCEPTANCE.md](SPEECH_PROVIDER_ACCEPTANCE.md).

## Verified M28 speech-adapter qualification runner

Candidate private STT/TTS services can now be exercised through the same M25
clients used by the gateway and decoded packet-by-packet with the exact M27
reference decoder. The offline runner requires an approved corpus, immutable
candidate config, four actual endpoints, protected bearer-token input, explicit
latency thresholds and a controlled Ed25519 signing key. Its canonical receipt
binds config, endpoint-set, approved runner-build, transport-trust, corpus and
decoder digests while storing no URLs,
tokens, transcript, synthesis text, text hashes, raw Opus or PCM.

M28 also closes a buffered-frame cancellation race in the TTS client: context
cancellation is checked before each read and immediately after every emitted
frame. The local harness passed real FFmpeg decode, STT stop/final and abort,
parallel distinct TTS streams, one-frame cancellation, signing and independent
verification. HTTP/WS evidence is permanently `TEST_HARNESS_PASS`; even a real
HTTPS/WSS run is only `PROTOCOL_PASS`, always has `production_ready: false`, and
retains the hardware, language, privacy/legal, load/cost/soak and HA gates.
M75 later supersedes the production transport inputs with separate STT/TTS
tokens, CA trust sets and client identities; the shared input remains only for
the development harness.

The final regression passed 23 C host suites, 7 gateway-contract tests, 16
factory tests, 119 tooling tests, 5 independent generation-state tests, all Go
package tests, `go vet`, and the Go race suite. M28 changes no firmware bytes;
all M24 firmware/signing hashes remain unchanged. See
[M28_SPEECH_ADAPTER_QUALIFICATION_REPORT.md](M28_SPEECH_ADAPTER_QUALIFICATION_REPORT.md)
and [SPEECH_ADAPTER_QUALIFICATION_RUNBOOK.md](SPEECH_ADAPTER_QUALIFICATION_RUNBOOK.md).

## Verified M29 device identity and urgent revocation

Production gateway and control-plane configurations now reject the legacy
startup-only registry. They require a canonical Ed25519-signed version 2
snapshot, exact signing-key ID, positive externally approved revision floor and
bounded reload interval. The gateway accepts only a secret-free
`purpose:access` view; the independent control plane accepts only a
`purpose:proof` view with bootstrap material for every enabled device. This
keeps proof secrets out of the voice data plane.

The atomic store rejects runtime rollback and same-revision equivocation,
becomes unavailable at `valid_until`, and serializes successful token minting
against identity activation. The gateway performs a final allowed check while
registering each WebSocket, then actively closes an existing disabled or
expired connection with policy status 1008. A dedicated gate generates an
ephemeral Ed25519 key, signs and independently validates a snapshot, and proves
that tamper and broad file permissions fail.

At M29 this remained a local-file reference and did not yet invalidate Agent-
proxy or firmware-origin bearer use. M30 closes that local downstream gap;
M74 later supplies the PostgreSQL replay/session coordination software boundary,
while live cross-region convergence, audited KMS rotation and disaster recovery
remain external release gates. See
[M29_DEVICE_IDENTITY_REVOCATION_REPORT.md](M29_DEVICE_IDENTITY_REVOCATION_REPORT.md)
and [DEVICE_IDENTITY_SNAPSHOT_RUNBOOK.md](DEVICE_IDENTITY_SNAPSHOT_RUNBOOK.md).

## Verified M30 cross-service identity enforcement

The same signed secret-free `purpose:access` snapshot is now mandatory in
production at Agent Proxy and firmware origin, in addition to gateway. A
control-plane-issued Agent or OTA token that is still cryptographically valid
becomes unauthorized as soon as the consuming service activates a disabling
identity revision.

A shared request-lease tracker seals the admission/reconciliation race. Agent
revocation cancels the exact outbound provider request context and blocks the
old token from any later provider call; it also closes a slow incoming request
body and deadlines response writes. Firmware revocation sets an immediate HTTP
response write deadline, cancels a context-aware exact-byte copy and blocks the
old OTA token for both known and unknown object paths. Snapshot expiry also
fails readiness and cancels active work on the next poll.

The expanded identity gate covers provisioning, request leases, gateway,
control plane, Agent Proxy, firmware origin and the proof-to-provider vertical
slice. This proves the local single-process semantics, not multi-replica
publication convergence or a managed HA identity service. See
[M30_CROSS_SERVICE_IDENTITY_REPORT.md](M30_CROSS_SERVICE_IDENTITY_REPORT.md).

## Verified M31 remote identity-source client contract

All four services now select one common identity source: the M29/M30 atomic
local file, or a remote purpose-specific HTTPS endpoint. Remote mode always
requires a dedicated CA, workload client certificate/key, independent Ed25519
snapshot trust key, explicit production revision floor and bounded request/
poll intervals. It never falls back to HTTP, ambient proxy settings or an
unsigned response.

The client performs a synchronous startup fetch, then conditional ETag polls.
It requires no-store, exact media type and length, an uncompressed body, a
canonical revision header, a strong canonical-digest ETag and a signed body
whose purpose/revision agree with transport metadata. Redirect, weak ETag,
missing workload certificate, rollback and same-revision equivocation fail
without replacing active state.

An ephemeral-CA integration test proves three access consumers and one proof
consumer concurrently activate one higher fleet revision under the Go race
detector. This is client/protocol evidence in one test process, not managed
service, cluster, HSM or regional-HA evidence. See
[REMOTE_IDENTITY_SOURCE_RUNBOOK.md](REMOTE_IDENTITY_SOURCE_RUNBOOK.md) and
[M31_REMOTE_IDENTITY_SOURCE_REPORT.md](M31_REMOTE_IDENTITY_SOURCE_REPORT.md).

## Verified M32 Companion App onboarding core

The new Swift package owns the product QR, credential lifetime and user-visible
onboarding state instead of accepting the official library's broader defaults.
Only the compact canonical factory schema, exact `xiaozhi` username,
`XA-XXXXXX`, SoftAP and Security 2 are accepted. QR and Wi-Fi credentials are
one-use, their owned byte buffers are wiped, and 64 concurrent consumers yield
exactly one winner under Thread Sanitizer.

The reducer starts its five-minute deadline only after physical confirmation,
ignores stale flow callbacks, returns candidate failures to explicit manual
entry and clears/disconnects on session failure, cancellation, timeout or
lockout. Joining Wi-Fi is only progress; final success requires a separate
authenticated product-online observation.

The iOS adapter pins official ESPProvision 3.1.0, forces upstream logging off,
uses only SoftAP/Security 2, bounds connection/provisioning and handles task
cancellation. Exact dependency revisions, Apache-2.0 license bytes, Security 2
IV-fix ancestry and the no-sensitive-logging policy are automated. The product
Swift package now also carries an explicit privacy-manifest resource; M80 binds
it, every production source file, both clean dependency commits/licenses, SPDX
2.3 and in-toto/SLSA provenance into an independently signed source bundle. The host
gate passes Swift 6 warnings-as-errors, adapter API-subset type checking, 38
core scenarios and Thread Sanitizer. A full Xcode/iOS build, signed App, UI,
account binding, actual product-online client and iPhone/BOX-3 tests remain
external. See
[COMPANION_APP_ONBOARDING_RUNBOOK.md](COMPANION_APP_ONBOARDING_RUNBOOK.md) and
[M32_COMPANION_APP_ONBOARDING_REPORT.md](M32_COMPANION_APP_ONBOARDING_REPORT.md).

## Verified M33 authenticated device ownership

M33 replaces the abstract online-success hook with a concrete two-party claim.
Each physical window creates a fresh 256-bit claim. The App reads it only
inside the established Security 2 session, registers it with a short-lived
product-login bearer before Wi-Fi submission, and the device later confirms
the same value with a new domain-separated eFuse HMAC proof. The control plane
stores only a claim digest and atomically binds user/device only when both
sides match; another user cannot read status or overwrite an existing owner.

The firmware does not close onboarding until the device receives exact
`bound`. The Swift reducer likewise requires `bound` for the active request ID
and device ID; joining Wi-Fi remains progress. When claim mode is enabled, a
valid hardware proof from an unowned device is still denied voice/Agent token
issuance. Authenticated time and claim/OTA recovery remain available.

The reference memory store is now behind a production adapter interface and is
refused unless insecure development is explicitly enabled. A market release
still requires a durable serializable multi-replica store, managed account
issuer, App UI/signing and real phone/device evidence. M34 closes encrypted
pending Wi-Fi/claim recovery and M35 closes owner-aware downstream
authorization, but their physical and managed-service gates remain.
See [DEVICE_OWNERSHIP_CLAIM_RUNBOOK.md](DEVICE_OWNERSHIP_CLAIM_RUNBOOK.md) and
[M33_DEVICE_OWNERSHIP_CLAIM_REPORT.md](M33_DEVICE_OWNERSHIP_CLAIM_REPORT.md).

## Verified M34 power-loss-safe claim recovery

Wi-Fi and the exact pending ownership claim now share one versioned, checked
`network_state` value in the product credential NVS. Candidate IP acquisition
commits that single value; an interrupted write leaves the previous state or a
complete recoverable new state. Production's existing HMAC-derived XTS-AES NVS
boundary protects the claim at rest, and valid legacy Wi-Fi records migrate in
one commit.

After restart, the independent provisioning worker waits for Wi-Fi, repeats
the device-authenticated confirmation with a two-second minimum retry interval,
and clears only an exact matching claim after canonical `bound`. Redirects and
non-retryable 4xx responses abandon that exact claim and put the runtime in
`ONBOARDING_REQUIRED`; transport failures, 408/429, 5xx and malformed success
responses retain it. No network request runs on the Wi-Fi callback.

Host state/blob tests, ten M33/M34 policy checks, BOX-3 ESP-IDF 6.0.2 compile
and the linker-map budget pass. Physical brownout/power-cut qualification,
dual-network rollback if required by product policy, durable ownership storage,
owner-aware service tokens and real App/device evidence remain external. See
[DEVICE_CLAIM_RECOVERY_RUNBOOK.md](DEVICE_CLAIM_RECOVERY_RUNBOOK.md) and
[M34_POWER_LOSS_CLAIM_RECOVERY_REPORT.md](M34_POWER_LOSS_CLAIM_RECOVERY_REPORT.md).

## Verified M35 owner/tenant service authorization

Voice and Agent access now requires an explicit current `{tenant, owner,
device, binding ID, binding revision}` in addition to hardware proof. The
control plane refuses to
start without an ownership resolver, returns 403 for unowned devices and 503
when ownership cannot be resolved, then issues only audience-specific v3
tokens containing canonical owner, tenant, device, binding and JTI claims.
Ownerless v1 and pre-lifecycle v2 tokens fail closed; Companion tenant is an
explicit IdP input rather than an inference from the user ID.

Voice replay and Agent request admission use the opaque internal
`binding_id\0binding_revision\0device` scope. Voice retains owner/tenant only inside the
product session, while both speech and model-provider tests assert that those
identifiers are not forwarded. The standalone gateway's ownerless session
issuer is disabled; devices use the ownership-aware control plane.

M38 supersedes the original M35 v2 wire contract with the lifecycle-aware v3
contract. Market release still requires a managed IdP, live serializable
multi-replica database evidence, controlled old-token drain, workload
credentials and live provider captures. See
[OWNER_AUTHORIZATION_RUNBOOK.md](OWNER_AUTHORIZATION_RUNBOOK.md) and
[M35_OWNER_TENANT_AUTHORIZATION_REPORT.md](M35_OWNER_TENANT_AUTHORIZATION_REPORT.md).

## M36 durable ownership adapter implemented; live database gate open

The control plane now has a PostgreSQL `OwnershipStore` backed by pinned pgx
v5.10.0. Claim begin/confirm use Serializable transactions plus sorted
transaction-scoped locks for the claim digest and device, store only the
domain-separated digest, and commit owner plus append-only bind audit in one
transaction. M38 evolves the not-yet-live schema to version 3 with active/
released owner state, monotonic binding revisions and append-only bind/release
events. Database time owns expiry. The serving process does not migrate; it
verifies the exact schema contract at startup/readiness and maps database
loss to 503 instead of treating it as bad App input.

Production configuration requires `sslmode=verify-full`, bounded pool lifetime
and operation timeout. The memory store remains development-only. The code
gate and seven persistence policy checks pass, and a strict disposable-schema,
two-pool, 32-way race test is present. This workspace has no PostgreSQL runtime,
so that live gate has not executed and M36 is not yet release evidence. Managed
TLS/failover/PITR/load tests and immutable migration packaging remain open.
See
[POSTGRES_OWNERSHIP_RUNBOOK.md](POSTGRES_OWNERSHIP_RUNBOOK.md) and
[M36_DURABLE_OWNERSHIP_ADAPTER_REPORT.md](M36_DURABLE_OWNERSHIP_ADAPTER_REPORT.md).

## Verified M37 asymmetric product-account token boundary

Production Companion claim/release authorization now uses a strict Ed25519 JWT and a
verification-only control-plane interface. The token binds exact EdDSA/type,
key ID, HTTPS issuer, Companion audience, subject, explicit tenant, TTL and
JTI; canonical Base64URL plus unknown/duplicate/trailing JSON rejection closes
parser ambiguity. Claim tokens carry only `device:claim`; release tokens carry
`device:release` plus one exact device ID. Service/binding claims are forbidden.

The serving command contains only up to three rotation public keys and no
account signing key. Legacy Companion HMAC remains available in explicit
development but production rejects it even with PostgreSQL. Auth/control-plane
tests and seven account-trust policy checks pass, including valid asymmetric
claim intent and HMAC rejection under the same verifier configuration.

This is not a deployed IdP/account service: OIDC exchange, membership store,
MFA/passkey/recovery, KMS/HSM signing, hot key reload/emergency revocation,
App attestation and multi-region rollout remain release gates. See
[ACCOUNT_TOKEN_TRUST_RUNBOOK.md](ACCOUNT_TOKEN_TRUST_RUNBOOK.md) and
[M37_ASYMMETRIC_ACCOUNT_TOKEN_REPORT.md](M37_ASYMMETRIC_ACCOUNT_TOKEN_REPORT.md).

## Verified M38 ownership binding lifecycle and memory isolation

Ownership is no longer an immutable dead end. The current owner can release
one exact device only with a short-lived Ed25519 Companion token whose action
and device are fixed by the account service. The control plane performs a
Serializable release, advances revision 1 to 2, marks the device unowned and
appends a release event; replay is idempotent. A later holder must still open a
fresh physical Security 2 window and complete the existing App+device claim.
Successful rebind creates a new opaque binding ID at revision 3 and appends a
new bind event. Local factory reset alone never releases cloud ownership.

Voice/Agent v3 tokens carry the binding epoch. Both services query the live
owner row before admission; Agent rejects the old epoch on the next request,
while Gateway polls every five seconds and closes an active Voice WebSocket
with policy status 1008. Lookup failure is 503/readiness loss, not a false
revocation. Resolver workloads use the PostgreSQL read-only path.

Firmware credentials must report matching Voice and Agent binding fields.
Before ESP-Claw starts, the supervisor reconciles `product_agent_memory`:
unbound memory is locked, a higher revision atomically clears prior items,
same revision is idempotent, stale/equivocated revisions fail closed, and valid
legacy XAM1 data migrates to locked/empty before XAM2 adoption. The Companion
core now exposes the exact no-body release call, but the account service must
issue its token only after step-up reauthentication.

The lifecycle gate passes Go, 23 C host suites, Swift warnings-as-errors/core/
Thread-Sanitizer and 19 focused policy checks; BOX-3 ESP-IDF 6.0.2 also compiles
the XAM2 path. The full regression passes 167 tooling/policy tests and Go race;
the final deterministic dual-build OCI tree is
`1502f670a568d38dbdf81c6c8247df6d09355b4be208efa76880fb95b8743a59`.
This is local implementation evidence. Live PostgreSQL,
managed IdP/MFA, full App UI/signing, physical reset/resale/power-cut tests,
account deletion/support recovery and cross-region convergence remain release
gates. See [OWNERSHIP_TRANSFER_RUNBOOK.md](OWNERSHIP_TRANSFER_RUNBOOK.md) and
[M38_OWNERSHIP_BINDING_LIFECYCLE_REPORT.md](M38_OWNERSHIP_BINDING_LIFECYCLE_REPORT.md).

## Verified M39 power-loss-resumable local factory reset

The BOX-3 physical input now classifies only when the user releases it. Less
than three seconds is a no-op, three to under ten seconds opens one bounded
Security-2 onboarding window, and ten seconds or more requests local factory
reset. A boot-held or stuck-low input never triggers; release debounce is not
added to the destructive threshold. Kconfig and the build require the reset
threshold to remain strictly above onboarding.

Reset intent is a CRC-checked `XFR1` journal committed before restart. On the
next boot, recovery runs immediately after protected storage initialization and
before Agent memory, Wi-Fi, or ESP-Claw can start. It separately commits erase
of `nvs/prod_wifi`, erase of both `nvs/agent_mem` slots, and final journal
removal. Interruption before or after any commit repeats an idempotent step and
never exposes old state. The implementation has no partition-wide erase and
does not touch `nvs_factory`, eFuse identity, Secure Boot, Flash Encryption,
OTA, or anti-rollback state.

Local reset intentionally does not release cloud ownership. A normal resale
must first complete authenticated exact-device release, then local reset, then
a fresh App+device claim. The M39 gate passes 24 strict C host suites plus 19
focused physical-action/reset/ownership policy tests. BOX-3 ESP-IDF 6.0.2
compiles the live path at `0x156880` bytes with 76% App-partition free; IRAM and
internal-static use remain `81152/98304` and `121344/358144` bytes. No board was
available, so electrical, flash-remnant, brownout, App/IdP and live PostgreSQL
evidence remain mandatory. See
[FACTORY_RESET_RESALE_RUNBOOK.md](FACTORY_RESET_RESALE_RUNBOOK.md) and
[M39_FACTORY_RESET_REPORT.md](M39_FACTORY_RESET_REPORT.md).

## Verified M40 reset-hardware qualification release gate

The M39 physical acceptance matrix is now a cryptographic shipping
prerequisite rather than only prose. A strict canonical Ed25519 receipt freezes
the 2.9/3.0/9.9/10.0-second gesture boundaries, all six journal power-cut
checkpoints, at least three distinct physical devices, at least 100 reset
cycles per device and 1,000 aggregate cycles. It also requires matching
pre/post identity proof, `nvs_factory` and eFuse summaries, absence of raw
Wi-Fi/Agent-memory state, unchanged cloud binding, and preserved Secure Boot,
Flash Encryption and anti-rollback.

The P-256 OTA signer first verifies the receipt against the exact signed image,
board, project, version, secure version, trusted lab public key and key ID. It
then signs `reset_qualification_sha256` inside manifest v2. The ESP32 parser and
Go registry share the same v2 canonical payload and reject v1 or a missing
qualification digest. Existing deployment and rollout receipts transitively
bind the complete signed manifest hash.

The repository tests use only ephemeral synthetic lab receipts to validate the
contract; they are not physical evidence. No board or production lab receipt
was available, so shipment remains blocked until the runbook is executed and
its WORM evidence is independently approved. The complete local regression
passes 24 C host suites, 7 gateway-contract tests, 24 factory tests, 184
tooling/policy tests, 5 generation-state tests, Companion warnings/core/race,
all Go packages/vet and a separate Go race run. BOX-3 ESP-IDF 6.0.2 compiles
manifest v2 at `0x156910` bytes with 76% App-partition free; IRAM and internal
static remain `81152/98304` and `121344/358144` bytes. See
[RESET_HARDWARE_QUALIFICATION_RUNBOOK.md](RESET_HARDWARE_QUALIFICATION_RUNBOOK.md)
and [M40_RESET_QUALIFICATION_RELEASE_GATE_REPORT.md](M40_RESET_QUALIFICATION_RELEASE_GATE_REPORT.md).

## Verified M41 product-owned Agent capability firewall

ESP-Claw tools now pass through a closed product permission boundary rather
than a hard-coded all-visible device group. Read-only device status and
reversible device actions use different visibility groups; unknown bits,
enabled tools without adapters, state-changing tools without trusted consent,
or any tool surface without an audit callback reject startup. Every callback
then rechecks root-Agent caller, request ID, session ID, exact input and the
runtime allowlist.

State-changing `device.set_indicator` consumes a one-use grant bound to the
exact request and session. Completion, cancellation and submit failure revoke
unused capability and memory grants. All device and bounded-memory results emit
metadata-only decisions without arguments, outputs, memory values or text. The
BOX-3 Live profile intentionally exposes only `device.get_status`; indicator,
reset, OTA, ownership, arbitrary HTTP/shell/filesystem, MCP and Lua remain
unavailable to the model.

The focused gate passes 25 C host suites, 7 gateway-contract tests and 20
capability/memory/runtime policy checks. The complete regression passes 25 C
host suites, 7 gateway-contract tests, 24 factory tests, 192 tooling/policy
tests, 5 generation-state tests, Companion dependency/privacy/core/race gates,
all Go packages/vet and a separate all-package Go race run. All 26 product
shell scripts pass syntax checks and all 27 project-owned JSON files parse.

The BOX-3 Live ESP-IDF 6.0.2 composition compiles at `0x156ff0` bytes with 76%
of the smallest App partition free. Link-map policy reports IRAM
`81152/98304`, internal static `121344/358144`, and 236,800 bytes of
internal-static headroom. This is code and compile evidence;
physical UI consent, LED/display behavior, telemetry retention, penetration
testing and board-side abuse tests remain release gates. See
[AGENT_CAPABILITY_SECURITY_RUNBOOK.md](AGENT_CAPABILITY_SECURITY_RUNBOOK.md) and
[M41_AGENT_CAPABILITY_FIREWALL_REPORT.md](M41_AGENT_CAPABILITY_FIREWALL_REPORT.md).

## Verified M42 Agent content-private observability

The pinned ESP-Claw core no longer logs final response snippets, tool
arguments/results or reasoning content. It records only request state, tool
name, result enum and byte length. Non-200 provider bodies are discarded before
they can become an Agent error or device log; defining full LLM request logging
fails compilation, and the Live product profile rejects verbose stage events.

This is maintained as a SHA-256-locked product patch. `sync_upstreams.sh`
checks the digest and patch applicability after every clean checkout. The
runtime audit callback now writes no per-event log: it validates a closed
capability list and increments only monotonic saturating decision/class
counters, retaining no request/session ID, timestamp, argument, output or
error text.

The product patch is also a release artifact: SBOM policy schema v2 requires
the patch list to match `upstream.lock.json`, includes the exact patch under
`sources/esp-claw/`, binds it into the canonical receipt, and rejects patch or
bundle-file tampering. The M42 production-security candidate was rebuilt
from this source and passed its unsigned remote-signing input and ephemeral
signature-verification gates. Its padded App SHA-256 is
`d82fc62629cb80e0672552200b00f9819015c89fa0ebaefd4b59a7da6526cdc9`.

The focused gate passes 26 C host suites, 7 gateway-contract tests and 28
content-privacy/capability/memory/runtime policy checks. The complete regression
passes 26 C host suites, 7 gateway-contract tests, 24 factory tests, 201
tooling/policy tests, 5 generation-state tests, Companion
dependency/privacy/core/race gates, all Go packages/vet and a separate
all-package Go race run. All 27 product shell scripts pass syntax checks and
all 27 project-owned JSON files parse.

The BOX-3 Live ESP-IDF 6.0.2 composition compiles at `0x156e70` bytes with 76%
of the smallest App partition free. Link-map policy reports IRAM
`81152/98304`, internal static
`121392/358144`, and 236,752 bytes of internal-static headroom. Physical log
capture, crash dump/JTAG review, deployed telemetry retention, penetration and
privacy review remain release gates. See
[AGENT_CONTENT_PRIVACY_OBSERVABILITY_RUNBOOK.md](AGENT_CONTENT_PRIVACY_OBSERVABILITY_RUNBOOK.md)
and [M42_AGENT_CONTENT_PRIVACY_OBSERVABILITY_REPORT.md](M42_AGENT_CONTENT_PRIVACY_OBSERVABILITY_REPORT.md).

## Verified M43 exact-action consent software boundary

State-changing consent is no longer requested from raw voice text before the
Agent has chosen its tool arguments. `device.set_indicator` first validates
exact `{on: bool}`, then passes a typed action to the trusted consent callback
and consumes one request/session/argument-bound grant before the adapter call.

The Companion core accepts only canonical `xz-action-consent-v1` challenges
with a lifetime of at most 30 seconds. Its approve/deny body repeats the exact
device, ownership revision, session, request, capability and `on/off` argument.
The control plane requires a dedicated device-bound App action token, strict
no-store/length/JSON headers, current ownership and atomic one-use state.

The built-in backend store is an explicit development reference and production
configuration rejects it. Authenticated device challenge ingestion, decision
delivery to the waiting runtime, a durable multi-replica adapter, signed App/
physical UI and true board-side indicator evidence remain release blockers;
the BOX-3 Live profile therefore continues to expose only read-only status.

The M43 focused gate passes 26 C host suites, 7 gateway-contract tests, 16
exact-action/capability policy checks, targeted Go tests/vet, and the Companion
warnings/core/race gate with 20 scenarios. The complete regression passes 26 C
host suites, 7 gateway-contract tests, 24 factory tests, 209 tooling/policy
tests, 5 generation-state tests, the Companion gate and all Go packages/vet;
a separate all-package Go race run also passes. All 28 product shell scripts
pass syntax checks and all 27 project-owned JSON files parse.

The BOX-3 Live ESP-IDF 6.0.2 graph relinks at `0x156e50` bytes with 76% of the
smallest App partition free. Link-map policy reports IRAM `81152/98304`,
internal static `121392/358144`, and 236,752 bytes headroom. The rebuilt padded
production-security App SHA-256 is
`e956f8efa0c802e509b89a9a6973289ac5724ee138b4ce1cc9a4ddf74d49e8ac`;
it passed ephemeral 3/3 bootloader and 1/1 App verification. Two independently
generated 32-file SBOM bundles were byte-identical; the 17,915-byte receipt
SHA-256 is
`4f146c4fe8ec0316e005ffd58123a1794547db6131ba7a62155bd0f269a7a2aa`.
These used the existing configured S3 build graphs because unrelated all-target
ESP-IDF tools were unavailable; a clean isolated release build still remains
mandatory before promotion.
See [AGENT_ACTION_CONSENT_RUNBOOK.md](AGENT_ACTION_CONSENT_RUNBOOK.md) and
[M43_AGENT_ACTION_CONSENT_REPORT.md](M43_AGENT_ACTION_CONSENT_REPORT.md).

## Verified M44 durable action-consent relay boundary

The M43 in-process seam now has an authenticated, durable
challenge/decision/result software state machine.
The device registers an exact typed action through a challenge-only HMAC proof
whose canonical body SHA-256 is signed; the result path has a different proof
domain. The server enriches the challenge only from current ownership. The
Companion endpoint still chooses only approve/deny, and the device can retrieve
that stored decision exactly once. Pending returns a bounded retry response;
body, path, action, revision, nonce, decision and replay mutations fail closed.

Production `Register`, `Decide` and `Consume` now share the ownership PostgreSQL
ordering domain. Migration 0002 adds a separately versioned action-consent
schema, exact request uniqueness and decision/consume invariants. All mutations
use Serializable transactions and lock the current owner row, so release or
rebind invalidates stale consent. Production configuration requires
`ACTION_CONSENT_ENABLED=true` plus the TLS-verified ownership database; the
single-process store remains development-only.

The ESP-IDF client generates the 128-bit challenge, canonical typed JSON and
body digest, validates the canonical server response and exposes only pending,
approved or denied. Its eFuse HMAC boundary has separate challenge/result
validators, not a general signing oracle. The BOX-3 composition compiles these
seams but deliberately does not wire the consent callback, publish the App
challenge or enable `device.set_indicator`.

The focused M44 gate passes 26 C host suites, 7 gateway-contract tests, 19
action-consent/capability policy tests, targeted Gateway tests/vet and the
Companion warnings/core/race gate with 20 scenarios. The complete regression
passes 26 C host suites, 7 gateway-contract tests, 24 factory tests, 212
tooling/policy tests, 5 generation-state tests, the Companion gate and all Go
packages/vet; a separate all-package Go race run also passes. All 28 product
shell scripts pass syntax checks and all 27 project-owned JSON files parse.

The BOX-3 Live graph is 1,410,672 bytes (`0x158670`), leaving 76% of the smallest
App partition free; internal static usage remains 121,392/358,144 bytes with
236,752 bytes headroom. The padded production-security App remains 1,441,792
bytes and now has SHA-256
`a2ea533bcf50d3cb7e4f8a48d010fdbba748aa20bea628f33de5d0db1e2f276d`.
It passed unsigned security verification plus ephemeral 3/3 bootloader and 1/1
App signature verification. Two independently generated 32-file SBOM bundles
were byte-identical; their 17,915-byte receipt SHA-256 is
`af2b371bf7f37deeceaf68e37e0e0932eb26abb850a72e858f8ca68b7ba8e822`.

No PostgreSQL runtime is available in this workspace. The two-pool integration
test is implemented but skipped without `OWNERSHIP_TEST_DATABASE_URL`; this is
not live database evidence. Authenticated device-to-App delivery, signed App
UI, bounded runtime callback/cancellation, managed failover/PITR/retention and
physical indicator evidence remain release blockers. See
[ACTION_CONSENT_POSTGRES_RUNBOOK.md](ACTION_CONSENT_POSTGRES_RUNBOOK.md) and
[M44_DURABLE_ACTION_CONSENT_RELAY_REPORT.md](M44_DURABLE_ACTION_CONSENT_RELAY_REPORT.md).

## Verified M45 action-consent inbox and bounded runtime boundary

The durable M44 relay now has a product-owned delivery and waiting path. An
authenticated Companion App can fetch the oldest undecided challenge for one
exact device/current owner epoch through a no-store `200` response, or receive
an empty `204`. The serializable PostgreSQL read locks the current ownership
row, excludes expired/decided/consumed records and is stable without leasing or
consuming the challenge. The Companion core revalidates the canonical device,
revision and exact typed action before returning a pending ticket to UI code.

BOX-3 now owns the ESP-Claw consent callback. It registers and polls the exact
action for at most 20 seconds, polls at 500 ms by default and caps every HTTPS
request at 2 seconds. Network/time loss, malformed response, denial, expiry,
timeout, stop or interrupt all fail closed. ESP-Claw also places cancellation
and device-action commit on an atomic per-request boundary, so cancellation
ordered before commit cannot execute an action. Only metadata outcome counters
are retained.

The focused gate passes 26 C host suites, 7 gateway-contract tests, 22
action-consent/capability policy tests, targeted Go tests/vet and the Companion
gate with 20 scenarios. The complete regression passes 26 C host suites, 7
gateway-contract tests, 24 factory tests, 215 tooling/policy tests, 5
generation-state tests, the Companion gate and all Go packages/vet; a separate
all-package Go race run also passes. All 28 product shell scripts pass syntax
checks and all 27 project-owned JSON files parse.

The BOX-3 Live graph is 1,412,864 bytes (`0x158f00`) with SHA-256
`467a61606af241fb92e3e9df1244bc8597d3840c71d9c255886d79854563c8d2`,
leaving 76% of the smallest App partition free. Internal static usage remains
121,392/358,144 bytes with 236,752 bytes headroom. The padded
production-security App is 1,441,792 bytes with SHA-256
`1e31596f7ccc41901c9852dfe4f0de047e3cef404f98eff9d1698c96e06d467d`;
ephemeral 3/3 bootloader and 1/1 App signature verification passed. Two
independently generated 32-file SBOM bundles were byte-identical; their
17,915-byte receipt SHA-256 is
`800c438b9a5888572d43c71d847c51cc134bb7286b66675dfa36b207e117354a`.

This is a software-boundary GO, not a product-release GO. No live PostgreSQL
runtime was available, and the signed App UI/account lifecycle, managed
database failover/PITR/retention, physical consent/action matrix, privacy/
penetration review and clean HSM-backed release build remain mandatory. The
Live profile therefore still exposes only `device.get_status`; the model cannot
see or execute `device.set_indicator`. See
[M45_ACTION_CONSENT_INBOX_RUNTIME_REPORT.md](M45_ACTION_CONSENT_INBOX_RUNTIME_REPORT.md).

## Verified M46 foreground consent and online account authorization boundary

The M45 API is now wrapped by a product-owned foreground session and SwiftUI
gate. Each inbox fetch and decision obtains a fresh, exact-device account access
value and immediately discards local bearer state. Backgrounding, sign-out,
device switching, expiry and stale callbacks invalidate the ticket; submission
is serialized, and an uncertain response is never replayed. The UI displays
only the trusted device identifier, the closed indicator ON/OFF action and its
countdown, with explicit deny/approve controls and no prompt/model content.

Local Ed25519 JWT verification is no longer sufficient in production. Every
Companion claim, release or consent request must also pass the fixed
`/v1/companion-tokens/introspect` account-service contract over product-CA mTLS.
The request binds JTI, subject, tenant, action, device and JWT time. Exact active
responses repeat that binding; revoked/logout state becomes `401`, while TLS,
timeout or service failure becomes fail-closed `503`. The raw bearer is not sent
to the account service. Production configuration refuses missing/partial
introspection credentials and still forbids Companion HMAC tokens.

The focused gate now passes 25 action-consent/capability policy tests, targeted
Go tests/vet and the Companion dependency/privacy, warnings, 25-scenario and
Thread Sanitizer gate. The full regression passes 26 C host suites, 7
gateway-contract tests, 24 factory tests, 218 tooling/policy tests, 5
generation-state tests, the Companion gate and all Go packages/vet; a separate
all-package Go race run also passes. All 28 product shell scripts pass syntax
checks and all 27 project-owned JSON files parse.

M46 does not change ESP-IDF sources: the Live image remains 1,412,864 bytes
(`0x158f00`) with SHA-256
`467a61606af241fb92e3e9df1244bc8597d3840c71d9c255886d79854563c8d2`,
and the production-security image remains 1,441,792 bytes with SHA-256
`1e31596f7ccc41901c9852dfe4f0de047e3cef404f98eff9d1698c96e06d467d`.
The firmware SBOM is unchanged and explicitly does not cover App/Gateway/
account-service releases.

This remains a software-boundary GO only. The repository contains a compiled
UI component and enforced account-service protocol, not a signed App or a live
IdP/account deployment. Live account/ownership databases, mobile lifecycle and
accessibility evidence, physical action qualification and cross-service release
artifacts remain mandatory. The model still cannot see or execute
`device.set_indicator`. See
[COMPANION_ACCOUNT_AUTHORIZATION_RUNBOOK.md](COMPANION_ACCOUNT_AUTHORIZATION_RUNBOOK.md)
and
[M46_FOREGROUND_CONSENT_ACCOUNT_AUTH_REPORT.md](M46_FOREGROUND_CONSENT_ACCOUNT_AUTH_REPORT.md).

## Verified M47 durable Companion authorization core

The account-service half of M46 is no longer only a simulated wire response.
The new account-authorization core persists only exact JTI bindings—not raw
JWTs—beside a monotonic `(tenant, subject)` account revision. A selected IdP/BFF
adapter first opens an authenticated revision and may return a signed Companion
JWT only after its JTI commits at that exact revision. Logout, suspension and
resume serialize on the same account row, advance the revision and revoke old
JTIs; a concurrent flow that already acquired an older revision therefore
cannot publish a post-logout token.

The PostgreSQL adapter uses serializable transactions, database time and the
same locked account row for issuance, revocation and introspection across
replicas. Exact claim mutations, expiry, JTI revocation, logout, suspension,
revision mismatch and absence all become the existing empty `204` inactive
result. Database failure remains `503`; it never degrades to active. The
deployable `accountauthorization` reader verifies the exact schema on startup,
requires `sslmode=verify-full`, and exposes the fixed endpoint only behind a
server-side product-CA mTLS configuration. A real TLS handshake test connects
the existing control-plane client and rejects a client without a workload
certificate.

M47 deliberately does not implement passwords, passkeys, OAuth callbacks or
MFA policy. The production-selected IdP adapter must authenticate the exact
tenant/subject and call the revision-fenced issuance API; account recovery and
step-up policy remain external. The live PostgreSQL integration gate is present
but was not run without `ACCOUNT_AUTHORIZATION_TEST_DATABASE_URL`, so managed
HA/failover/PITR evidence is still open. The action capability remains disabled.

The focused gate passes 15 account-trust/ledger policy tests, targeted Go
test/vet and the account package race detector. The full regression passes 26 C
host suites, 7 gateway-contract tests, 24 factory tests, 226 tooling/policy
tests, 5 generation-state tests, the Companion 25-scenario/Thread-Sanitizer
gate and every Go package under normal test and vet; a separate all-package Go
race run also passes. All 30 product shell scripts pass syntax checks, all 27
project-owned JSON files still parse, and the new reader cross-compiles as
static Linux amd64 and arm64 executables.

M47 does not change ESP-IDF sources. The Live image remains 1,412,864 bytes with
SHA-256 `467a61606af241fb92e3e9df1244bc8597d3840c71d9c255886d79854563c8d2`;
the production-security image remains 1,441,792 bytes with SHA-256
`1e31596f7ccc41901c9852dfe4f0de047e3cef404f98eff9d1698c96e06d467d`.
See
[COMPANION_ACCOUNT_AUTHORIZATION_RUNBOOK.md](COMPANION_ACCOUNT_AUTHORIZATION_RUNBOOK.md)
and
[M47_DURABLE_ACCOUNT_AUTHORIZATION_REPORT.md](M47_DURABLE_ACCOUNT_AUTHORIZATION_REPORT.md).

## Verified M48 exact six-service OCI release contract

`accountauthorization` is now a mandatory member of the backend release rather
than a separately built binary. OCI receipt schema v2 fixes the exact order to
`gateway`, `controlplane`, `agentproxy`, `firmwareorigin`,
`generationcoordinator`, `accountauthorization`; the builder exposes no
service-subset option. Python and independent Go validators reject a missing,
duplicated or reordered service and reject schema-v1 receipts even when signed
with an otherwise valid v1-domain test key.

Each of the six services has deterministic `linux/amd64` and `linux/arm64`
static images, a subject-bound SPDX 2.3 SBOM and in-toto/SLSA provenance. The
real Go 1.26.5 smoke rebuilt the complete graph twice with identical receipts
and file trees: 44,460,151 bytes, tree SHA-256
`596cb190a040f178462c75dbe237af8d5807275f12e9d6164e4b4cb78d676ce0`.
Both validators accepted the same graph. The focused OCI suite passes all 12
tests.

The full regression now passes 26 C host suites, 7 gateway-contract tests, 24
factory tests, 229 tooling/policy tests, 5 generation-state tests, the Companion
25-scenario/Thread-Sanitizer gate, and all Go packages under normal test, vet
and a separate all-package race run. All 30 product shell scripts pass syntax
checks and the 27 project-owned JSON files parse.

M48 does not change ESP-IDF source. The Live and production-security App hashes
remain `467a61606af241fb92e3e9df1244bc8597d3840c71d9c255886d79854563c8d2`
and `1e31596f7ccc41901c9852dfe4f0de047e3cef404f98eff9d1698c96e06d467d`.
This remains an offline software-boundary GO: no registry push, current scan,
Cosign/transparency, cluster admission, managed account database, selected IdP
or signed App was exercised. The action capability remains disabled. See
[M48_SIX_SERVICE_OCI_RELEASE_REPORT.md](M48_SIX_SERVICE_OCI_RELEASE_REPORT.md)
and [OCI_DEPLOYMENT_BASELINE.md](OCI_DEPLOYMENT_BASELINE.md).

## Verified M49 signed hardened Kubernetes deployment bundle

An authenticated M48 OCI receipt can now be transformed into a deterministic,
read-only deployment bundle. The signed profile fixes the registry repository,
five purpose-isolated namespaces, exact non-overlapping speech/provider/
identity/database CIDRs, six isolated ConfigMap/environment-secret/file-secret
names and three PVCs. Every workload image is the matching six-service
image-index digest; tags, subsets, broad egress and shared service secrets are
rejected.

The generated graph contains 38 resources: six ServiceAccounts, six Services,
five single-replica `Recreate` Deployments, one single-replica `OnDelete`
StatefulSet and 20 default-deny/allow-list NetworkPolicies. Pods run as UID/GID
65532 with RuntimeDefault seccomp, no service-account token or host namespace,
drop `ALL`, no privilege escalation and a read-only root filesystem. Only the
generation state PVC is writable. `prerequisites.json` lists 27 external
objects and required keys without serializing any Secret or ConfigMap value.

The account reader now separates its product-CA mTLS API on 9444 from a narrow
HTTP probe listener on 9080. The probe exposes only health/readiness; readiness
verifies the PostgreSQL schema, while introspection and every other route remain
unavailable. The account Service still exposes only 9444 to control plane.

The real Go 1.26.5 smoke rebuilt two identical deployment bundles from the
current six-service OCI source: 96,518 bytes, tree SHA-256
`f86f5cdfc7aa19b16d4490889fc0ddbab412909b22a9ab2b33a55eaa2587e425`.
Python semantic/signature validation and checksum-verified kubectl v1.36.3
Kustomize parsing of all 38 resources passed. The focused gate passes 8 tests.

The full regression now passes 26 C host suites, 7 gateway-contract tests, 24
factory tests, 237 tooling/policy tests, 5 generation-state tests, Companion
and all Go normal/vet/race gates. All 31 product shell scripts and 30
project-owned JSON files parse. Firmware source and both App hashes are
unchanged.

This is still an offline policy-boundary GO. Kustomize parsing is not
kube-apiserver OpenAPI/defaulting/admission evidence, and no registry push,
Cosign, CNI packet test, managed secrets/database, rollout or live service was
performed. The action capability remains disabled. See
[M49_SIGNED_KUBERNETES_DEPLOYMENT_REPORT.md](M49_SIGNED_KUBERNETES_DEPLOYMENT_REPORT.md)
and [KUBERNETES_DEPLOYMENT_RUNBOOK.md](KUBERNETES_DEPLOYMENT_RUNBOOK.md).

## Verified M50 signed Kubernetes admission policy bundle

The signed M49 deployment can now be transformed into a separate immutable
admission bundle containing ten stable-v1 ValidatingAdmissionPolicies and ten
Bindings. The receipt binds the exact deployment receipt hash, deployment key,
deployment ID, namespace, admission document hash and fixed 10/10/20 inventory
under an independent Ed25519 signature domain. Validation rechecks the complete
OCI and deployment trust chain, then regenerates the policy graph byte for byte.

The policies reserve the dedicated namespace and protect Pods, Deployments,
StatefulSets, Services, ServiceAccounts, NetworkPolicies, ConfigMaps, Secrets,
PVCs and the Namespace labels. All policies fail closed and all bindings deny
and audit. Pods must preserve digest images, service identity, non-root/drop-all/
read-only hardening and exact configuration mounts; controller and network specs
cannot be changed or deleted. Config/Secret names, types and key sets are fixed
and immutable. Namespace deployment identity and Restricted Pod Security labels
cannot be removed. Pod replacement and the PVC controller's one-time volume bind
remain explicitly supported lifecycle operations.

The real Go 1.26.5 smoke rebuilt two byte-identical admission bundles after a
fresh six-service OCI and trusted deployment build: 113,372 bytes, tree SHA-256
`1c586a7396925d21b191867ab4d272f47c9996a1e34ce68e0965625b021ba73c`.
Python signature/semantic regeneration and checksum-verified kubectl v1.36.3
Kustomize parsing of all 20 resources passed. The focused gate passes 8 tests.

The full regression now passes 26 C host suites, 7 gateway-contract tests, 24
factory tests, 245 tooling/policy tests, 5 generation-state tests, Companion
and all Go normal/vet/race gates. All 32 product shell scripts and 31
project-owned JSON files parse. Firmware source and both App hashes are
unchanged.

This remains an offline policy-boundary GO. No kube-apiserver CEL type-check,
OpenAPI/defaulting, server-side dry-run, real denial, admission-resource RBAC,
CNI packet enforcement or rollout was executed. API-created Policy/Binding
objects require independent RBAC/audit protection. The action capability remains
disabled. See
[M50_SIGNED_KUBERNETES_ADMISSION_REPORT.md](M50_SIGNED_KUBERNETES_ADMISSION_REPORT.md)
and [KUBERNETES_ADMISSION_RUNBOOK.md](KUBERNETES_ADMISSION_RUNBOOK.md).

## Verified M51 live-admission qualification contract

The remaining M50 kube-apiserver gate now has an executable, signed evidence
contract. The runner revalidates the complete OCI/deployment/admission chain and
requires externally pinned API-server authority, kube-system UID, kubectl hash
and reviewed runner-source hash. Kubernetes client/server must be v1.30+, the
stable Policy/Binding APIs must exist, the ten policies must converge to their
observed generation with an empty type-check warning set, and every expected
denial must name its exact policy. A generic native-schema failure cannot be
recorded as admission evidence.

The live matrix performs an exact 20-resource admission server dry-run, creates
the ten Policies/ten Bindings and protected empty namespace, then runs the
38-resource workload, six controller-derived Pods, 22 prerequisites and a safe
PVC one-time-binding probe. Ten negative requests cover Pod, both controllers,
Service, ServiceAccount, NetworkPolicy, ConfigMap, Secret, PVC and Namespace.

Writes use create, not apply. Every temporary object has an exact qualification
ownership annotation. Cleanup removes only matching ownership in Binding →
Policy → Namespace order, refuses a raced unowned object and must prove the
entire scope absent before the Ed25519 `LIVE_API_SERVER_PASS` receipt is signed.
An independent recovery command provides the same ownership-safe cleanup after
a runner crash.

The focused contract gate passes 10 tests, including cluster/tool mismatch,
pre-existing scope, CEL warnings, missing denials, cleanup failure, create race,
crash recovery, wrong trust/domain and validly re-signed evidence tampering. The
full regression now passes 26 C host suites, 7 gateway-contract tests, 24
factory tests, 255 tooling/policy tests, 5 generation-state tests, Companion and
all Go normal/vet/race gates. All 33 product shell scripts and 33 project-owned
JSON files parse. Firmware and the action allow-list are unchanged.

No Kubernetes cluster or kubeconfig exists in this workspace, so no live runner
was executed and no M51 `LIVE_API_SERVER_PASS` receipt exists. Fixture tests are
state-machine evidence only. See
[M51_KUBERNETES_ADMISSION_LIVE_QUALIFICATION_REPORT.md](M51_KUBERNETES_ADMISSION_LIVE_QUALIFICATION_REPORT.md)
and [KUBERNETES_ADMISSION_QUALIFICATION_RUNBOOK.md](KUBERNETES_ADMISSION_QUALIFICATION_RUNBOOK.md).

## Verified M52 product market-release evidence contract

The project now has one fail-closed answer to “is this exact product release
allowed to enter the market?” A trusted policy fixes the complete subject:
SKU, product version, signed firmware digest/security version, OTA release,
  seven-service OCI release, Kubernetes deployment and live qualification. It also
fixes 14 evidence types; the set cannot be shortened or reordered.
The same policy pins the reviewed core validator source SHA-256.

M52 originally fixed 14 domains. M69 advanced the contract to 15 by adding
`push_provider_delivery`. M79 advances the current contract to schema v2 and
adds one mandatory, directly validated backend-SLO subordinate proof while
keeping the exact 15 domains. Historical v1 fixtures/reports remain milestone
records, are not current release policy and cannot parent a v2 record.

Each evidence owner signs a production HTTPS WORM object URI/digest, complete
subject, observation/expiry window and `PASS` result with a separately pinned
Ed25519 authority. Both builder and verifier also rehash an independently
retrieved local snapshot of every detailed WORM object. The release builder rejects missing/duplicate evidence,
cross-version mixing, stale evidence, non-production markers, incorrect keys,
non-contiguous sequence or parent hashes. Only then can a separate release
authority sign a canonical `MARKET_RELEASE_PASS` record. The independent
validator requires the policy and all 15 public keys from outside the bundle,
a trusted evaluation time and the exact previous record for non-genesis
releases. Under M79 it also requires the external SLO observation, canonical
policy and authority key; bundled copies and the signed summary must match
those exact independently retrieved inputs. Output is non-overwriting,
exact-file-set and last-`READY` bound.

The focused gate passes 13 adversarial tests, including a correctly re-signed
cross-release attestation and a correctly re-signed aggregate record with a
hidden evidence slot, private/ephemeral evidence URIs and a concurrent output
claim. The full regression passes 26 C host suites, 7 gateway-contract tests,
24 factory tests, 268 tooling/policy tests, 5 generation-state
tests, Companion dependency/privacy and 25 scenarios, plus all Go normal/vet/
race gates. All firmware bytes and the read-only action allow-list are
unchanged.

No production evidence/SLO keys or complete external evidence set exists in
this workspace, so no production bundle was built and no `MARKET_RELEASE_PASS`
exists. The example policy contains placeholder fingerprints. See
[M52_PRODUCT_MARKET_RELEASE_EVIDENCE_REPORT.md](M52_PRODUCT_MARKET_RELEASE_EVIDENCE_REPORT.md)
and [PRODUCT_MARKET_RELEASE_RUNBOOK.md](PRODUCT_MARKET_RELEASE_RUNBOOK.md).

## Verified M53 product-owned SKU and hardware geometry guard

The firmware now has a product-owned SKU contract instead of relying on a
BOX-3 build name. `XIAOZHI_AGENT_S3_REFERENCE` is development-only with no Live
runtime or capabilities. `VOICE_AGENT_KIT_BOX3` is a rev1 candidate fixed to
ESP32-S3 N16R8, physical GPIO0 policy, required factory/security qualification
and read-only `device.get_status`; all action capabilities remain disabled.

Kconfig and CMake reject board/SKU mismatch, non-rev1 BOX-3, Live runtime on the
reference profile and production-security geometry drift. At boot, readable
SoC revision, Flash and PSRAM are checked before storage/network initialization.
The ESP-Claw capability mask is derived through the SKU allow-list. This does
not detect the physical PCB or verify audio/GPIO wiring, so the profile remains
a candidate until factory identity and real-device qualification are bound.

The full regression passes 27 C host suites, 7 gateway-contract tests, 24
factory tests, 274 tooling/policy tests, 5 generation-state tests, Companion
dependency/privacy and 25 scenarios, plus all Go normal/vet/race gates. The
current SBOM policy now requires the `product-sku` SPDX component; two generated
bundles were byte-identical and all negative mutation checks passed.

The BOX-3 Live App is 1,414,400 bytes with SHA-256
`ea2262133706fde17539fe35c5ef44b3730f0673837f203a00e5660d6e08d318`;
the production-security padded App is 1,441,792 bytes with SHA-256
`08ac8ea4ff77324b5e9813b496af505e981c85cec8e8bc52f9d262eb6066ae19`.
Internal-static headroom is 236,752 and 236,640 bytes respectively. No board was
available, no physical qualification ran and no `MARKET_RELEASE_PASS` exists.
See [M53_PRODUCT_SKU_HARDWARE_GUARD_REPORT.md](M53_PRODUCT_SKU_HARDWARE_GUARD_REPORT.md)
and [PRODUCT_SKU_PORTING_GUIDE.md](PRODUCT_SKU_PORTING_GUIDE.md).

## Verified M54 factory-authenticated, reset-stable SKU identity

The BOX-3 candidate now requires an exact 70-byte factory manifest authenticated
by its unreadable/write-protected HMAC_UP eFuse key in block 5. The manifest
binds SKU, rev1 hardware contract, exact observed silicon revision, base MAC,
factory record version and a unique manifest ID. Startup verifies it after
secure storage but before reset recovery, Wi-Fi or the Agent runtime; missing,
malformed, unauthenticated or cross-subject data fails closed. The normal
firmware exposes no manifest sign/write/erase API.

The factory generator emits mode-0600, non-overwriting manifest/evidence files.
The onboarding CSV now carries both Security-2 and the public authenticated SKU
manifest. Signed factory receipt v4 cross-binds manifest digest/subject,
registry state and runtime verification, including a dedicated factory SKU
identity PASS.

The full regression passes 27 C host suites, 7 gateway-contract tests, 33
factory tests, 276 tooling/policy tests, 5 generation-state tests, Companion
dependency/privacy and 25 scenarios, plus all Go normal/vet/race gates. Both
ESP-IDF builds pass, as do reproducible remote-signing inputs, ephemeral 3/3
bootloader plus 1/1 App signatures and reproducible/tamper-negative firmware
SBOM gates.

The BOX-3 Live App is 1,416,320 bytes with SHA-256
`537dbd5bc2dc1e4a3b92f79d5d78355de6a91e9a91db02376a73094b92718d7e`;
the production-security padded App is 1,441,792 bytes with SHA-256
`e0fb94944718cc35f10a77e3aa7d0c0e1a835836781b0af38a5eced8663363f6`.
Internal-static headroom is 236,752 and 236,640 bytes respectively.

The manifest is authenticated and reset-stable, not physically immutable.
Cross-device replay fails through the base MAC; same-device replay is currently
bounded only by the compiled minimum record version. No real eFuse/NVS/board or
factory station was available, no v4 production receipt was issued and no
`MARKET_RELEASE_PASS` exists. See
[M54_FACTORY_AUTHENTICATED_SKU_IDENTITY_REPORT.md](M54_FACTORY_AUTHENTICATED_SKU_IDENTITY_REPORT.md)
and [FACTORY_IDENTITY_RUNBOOK.md](FACTORY_IDENTITY_RUNBOOK.md).

## Verified M55 per-unit factory encrypted-flash manifest

The factory flow now has an implemented bytes-to-unit contract rather than a
runbook-only manifest hash. Before a v4 receipt can be issued, the builder
requires one transaction/device subject, canonical signing and signed-artifact
evidence, the exact signed bootloader/App, factory SKU manifest, onboarding
material and a 24 KiB factory NVS image containing exactly two approved public
blobs. It re-runs XTS-AES-128 at offsets `0x0`, `0x10000`, `0x21000` and
`0x40000`, then compares four ciphertext and five raw-readback byte streams.
Only after every check passes is a mode-0600, non-overwriting
`complete=true` manifest published.

The signed factory-receipt CLI now requires that external manifest and
cross-checks its digest, device/serial/MAC, SKU/revision/factory record,
signing request, signed-artifact receipt, unsigned firmware, anti-rollback,
three Secure Boot digests, onboarding material and NVS readback. A correctly
re-signed cross-subject receipt/manifest pair is rejected.

The full regression passes 27 C host suites, 7 gateway-contract tests, 40
factory tests, 277 tooling/policy tests, 5 generation-state tests, Companion
dependency/privacy and 25 scenarios, plus all Go normal/vet/race gates. A real
ESP-IDF 6.0.2 flow also passes ephemeral 3/3 bootloader and 1/1 App signing,
address-dependent XTS reproduction, official NVS generation/parsing, simulated
readback, idempotent rebuild and cross-device rejection.

No firmware bytes changed: the Live App remains 1,416,320 bytes with SHA-256
`537dbd5bc2dc1e4a3b92f79d5d78355de6a91e9a91db02376a73094b92718d7e`;
the production-security padded App remains 1,441,792 bytes with SHA-256
`e0fb94944718cc35f10a77e3aa7d0c0e1a835836781b0af38a5eced8663363f6`.

The end-to-end gate uses file copies as simulated readbacks; no board, eFuse or
production station was available. No real v4 receipt or `MARKET_RELEASE_PASS`
exists. See
[M55_PER_UNIT_FACTORY_FLASH_MANIFEST_REPORT.md](M55_PER_UNIT_FACTORY_FLASH_MANIFEST_REPORT.md)
and [FACTORY_FLASH_MANIFEST_RUNBOOK.md](FACTORY_FLASH_MANIFEST_RUNBOOK.md).

## Verified M56 signed physical flash observation contract

The M55 COMPLETE path no longer accepts raw readback files without provenance.
Manifest v2 requires an externally signed `PRODUCTION_FACTORY` observation
bound to the exact transaction, attempt, device, serial, base MAC, chip
revision, signing request, signed-artifact receipt, secure version and all five
ordered readback digests. The factory receipt CLI independently receives the
observation and its readback-authority public key, verifies its Ed25519
signature, and checks its full digest and subject against the manifest.

The read-only station capture accepts only an explicit non-symlink serial
device, pins esptool/espefuse 5.3.1 and `--no-stub`, and contains no flash or
eFuse write commands. Its before/after summary must be identical and prove the
actual MAC, Flash Encryption release count, Secure Boot, disabled manual
download encryption, matching anti-rollback version and a still-pending final
Secure Download lock. An incomplete capture remains visibly `INCOMPLETE` and
cannot produce a signed request.

The full regression passes 27 C host suites, 7 gateway-contract tests, 47
factory tests, 277 tooling/policy tests, 5 generation-state tests, Companion
dependency/privacy and 25 scenarios, plus all Go normal/vet/race gates. The
ESP-IDF end-to-end flow passes with synthetic capture inputs and an ephemeral
untrusted observation key that is never persisted; all temporary evidence is
deleted. This proves the ingestion and signature chain only.

No firmware bytes changed: the Live App remains 1,416,320 bytes with SHA-256
`537dbd5bc2dc1e4a3b92f79d5d78355de6a91e9a91db02376a73094b92718d7e`;
the production-security padded App remains 1,441,792 bytes with SHA-256
`e0fb94944718cc35f10a77e3aa7d0c0e1a835836781b0af38a5eced8663363f6`.

No board or serial port was available, no production readback authority signed
an observation, and no final eFuse/v4 receipt or `MARKET_RELEASE_PASS` exists.
See
[M56_SIGNED_PHYSICAL_FLASH_OBSERVATION_REPORT.md](M56_SIGNED_PHYSICAL_FLASH_OBSERVATION_REPORT.md)
and
[FACTORY_PHYSICAL_READBACK_RUNBOOK.md](FACTORY_PHYSICAL_READBACK_RUNBOOK.md).

## Verified M57 real-tool virtual eFuse lifecycle

The production-security regression now runs the complete six-slot BOX-3 eFuse
plan through pinned `espefuse 5.3.1 --virt`. It burns and locks slots 3–5 first
as `XTS_AES_128_KEY`, `HMAC_UP` and `HMAC_UP`; burns three distinct readable
Secure Boot digests into slots 0–2; then write-protects exact `RD_DIS=0x38`.
Flash Encryption count 7, Secure Boot, secure version 1, download-cache,
manual-encryption, direct-boot and USB/pad JTAG restrictions are verified over
six official JSON summary stages.

The rehearsal also freezes a hardware-specific ordering constraint: direct
boot, Secure Download and anti-rollback share one ESP32-S3 write-protect group.
The first and third values are prepared before the boundary, while
`ENABLE_SECURITY_DOWNLOAD=1` and the shared lock are committed together in the
last espefuse batch. An independent verifier rejects wrong purposes, physical
blocks, digest readability, secret exposure, protection state, stage order,
hashes or any physical/factory/market claim.

The virtual image, XTS/HMAC secrets and public-key files are ephemeral;
Secure Boot private keys never leave memory. This proves the official tool
path and irreversible ordering only. No board, production key, physical eFuse,
factory receipt v4 or `MARKET_RELEASE_PASS` exists. See
[M57_VIRTUAL_EFUSE_REHEARSAL_REPORT.md](M57_VIRTUAL_EFUSE_REHEARSAL_REPORT.md)
and
[VIRTUAL_EFUSE_REHEARSAL_RUNBOOK.md](VIRTUAL_EFUSE_REHEARSAL_RUNBOOK.md).

The full regression passes 27 C host suites, 7 gateway-contract tests, 47
factory tests, 286 tooling/policy tests, 5 generation-state tests, Companion
dependency/privacy and 25 scenarios, plus all Go normal/vet/race gates. A clean
1,066-step ESP-IDF 6.0.2 production build, the complete remote-signing/M56/M57
flow and the reproducible/tamper-negative firmware SBOM gate also pass.

No firmware bytes changed: the BOX-3 Live App remains 1,416,320 bytes with
SHA-256
`537dbd5bc2dc1e4a3b92f79d5d78355de6a91e9a91db02376a73094b92718d7e`;
the production-security padded App remains 1,441,792 bytes with SHA-256
`e0fb94944718cc35f10a77e3aa7d0c0e1a835836781b0af38a5eced8663363f6`.

## Verified M58 sacrificial provisioning authorization contract

The remaining blank-device authorization gap is now a canonical, externally
signed one-unit/one-attempt contract. A read-only pinned-tool capture requires
an untouched ESP32-S3, exact MAC and 16 MB flash, six blank/readable/writeable
key slots and purposes, zero security/protection fuses, matching before/after
eFuse summaries and a clean coding-error result. Capture must finish within ten
minutes.

The plan binds the current signing request, signed-artifact receipt, three
ordered Secure Boot digests, station/fixture/calibration, physical serial and
two to four distinct operators. It can be issued only from a fresh capture and
expires within 15 minutes. An independent verifier rejects cross-device or
cross-release substitution, digest/order changes, private keys, inactive time,
operation reorder and any attempt to change `production_inventory_eligible`
from false, `QUARANTINE_OR_DESTROY` or `executor_included=false`.

The nine stages are declarative. No M58 program burns eFuses, erases/writes
flash or protects a block. A synthetic current-release flow using real
`espefuse 5.3.1 --virt` and an ephemeral untrusted signer passes, including a
validly re-signed cross-release negative test. No physical board, production
authorization key, station executor or market evidence was used. See
[M58_SACRIFICIAL_PROVISIONING_AUTHORIZATION_REPORT.md](M58_SACRIFICIAL_PROVISIONING_AUTHORIZATION_REPORT.md)
and
[SACRIFICIAL_PROVISIONING_AUTHORIZATION_RUNBOOK.md](SACRIFICIAL_PROVISIONING_AUTHORIZATION_RUNBOOK.md).

The full regression passes 27 C host suites, 7 gateway-contract tests, 57
factory tests, 287 tooling/policy tests, 5 generation-state tests, Companion
dependency/privacy and 25 scenarios, plus the Go test gate. The complete
remote-signing/M57/M58/M56 evidence chain also passes. Firmware bytes are
unchanged from M57. Go 1.26.5 vet and race gates also pass.

## Verified M59 atomic sacrificial-attempt consumption ledger

M59 closes the replay window between a valid M58 plan and a future separately
reviewed hardware executor. An external Ed25519 policy binds one ledger,
station, fixture/version, authorization key and the real local directory's
filesystem device/inode for at most 30 days. The policy is canonical,
non-overwriting and mode 0400; copied roots fail identity verification.

Consumption revalidates the M58 signature, active time, exact production
release, ordered Secure Boot digests and station/fixture/key binding. It writes
a completed mode-0400 temporary record, fsyncs it, then creates the
attempt-derived final name with an atomic non-overwriting hard link and fsyncs
the claims directory. Sixteen concurrent process tests produce exactly one
winner. Pre-link/post-link crash shapes, exact replay, validly re-signed
cross-device attempt reuse, unsafe modes/names/claims and record tampering all
fail closed.

The policy and record permanently state no executor, no hardware touch, no
deletion API and no production-inventory eligibility. This is a local
single-station boundary; it does not claim multi-station uniqueness, privileged
administrator resistance, network-filesystem/WORM semantics or power-cut
qualification. See
[M59_SACRIFICIAL_ATTEMPT_LEDGER_REPORT.md](M59_SACRIFICIAL_ATTEMPT_LEDGER_REPORT.md)
and
[SACRIFICIAL_ATTEMPT_LEDGER_RUNBOOK.md](SACRIFICIAL_ATTEMPT_LEDGER_RUNBOOK.md).

The full regression passes 27 C host suites, 7 gateway-contract tests, 65
factory tests, 288 tooling/policy tests, 5 generation-state tests, Companion
dependency/privacy and 25 scenarios, plus the Go test gate. The complete
remote-signing/M57/M58/M59/M56 chain passes with synthetic M58/M59 evidence and
an ephemeral untrusted key. Firmware bytes remain unchanged. Go 1.26.5 vet and
race gates also pass.

## Verified M60 online signed trusted-time consumption

The production consumer no longer accepts `--verification-time` or a cached
receipt file. It creates a random 32-byte nonce and directly calls the exact
endpoint signed into ledger policy v2. The request binds the plan/policy hashes,
attempt/device and station/fixture but contains no caller time. The authority
returns a domain-separated Ed25519 receipt with its own observation and a
maximum ten-second lifetime.

Transport requires TLS 1.3 and the policy-pinned CA/client certificate, exact
time-key fingerprint, HTTP 200, non-chunked bounded JSON, exact Content-Length,
no proxy/redirect and a five-second monotonic round trip. Consumption record v2
embeds the signed receipt and measured duration; the independent verifier
reconstructs the request and repeats the complete signature/subject check.

A local real TLS/mTLS test passes end to end through the production CLI.
Redirect, wrong content type, validly re-signed cross-attempt response and
wrong signing/TLS pins fail before a final record is created. The full
regression passes 27 C host suites, 7 gateway-contract tests, 69 factory tests,
289 tooling/policy tests, 5 generation-state tests, Companion
dependency/privacy and 25 scenarios, plus the Go normal/vet/race gates. See
[M60_SACRIFICIAL_TRUSTED_TIME_REPORT.md](M60_SACRIFICIAL_TRUSTED_TIME_REPORT.md)
and
[SACRIFICIAL_TRUSTED_TIME_RUNBOOK.md](SACRIFICIAL_TRUSTED_TIME_RUNBOOK.md).

The time server/key/CA in tests are ephemeral and untrusted. No production
endpoint, HSM/KMS signer, nonce database, hardware executor or physical board
was used. M60 proves fresh external time at ledger consumption, not the future
executor's start time. Firmware bytes remain unchanged.

## Verified M61 factory trusted-time authority core

M61 adds the matching Go server core for M60. The handler requires the exact
route and canonical body over direct verified TLS 1.3 mTLS. In one serializable
PostgreSQL transaction, it obtains database time, checks the active plan window,
locks and verifies station/fixture/version plus the leaf certificate DER hash,
then consumes globally unique request-body, request-ID and nonce hashes. Raw
nonces and signing keys are not stored.

Replay, wrong certificate/fixture, TLS or transport downgrade, duplicate JSON,
unknown/non-canonical members and signer failure all fail closed. Replay state
is committed before external signing, so a failed signer cannot revive a
nonce. A Go handler receipt passes the existing independent Python M60 verifier.
The included two-store, 16-caller live PostgreSQL gate requires exactly one
winner but was not run here because no PostgreSQL service is available. See
[M61_FACTORY_TRUSTED_TIME_AUTHORITY_REPORT.md](M61_FACTORY_TRUSTED_TIME_AUTHORITY_REPORT.md)
and
[FACTORY_TRUSTED_TIME_AUTHORITY_RUNBOOK.md](FACTORY_TRUSTED_TIME_AUTHORITY_RUNBOOK.md).

M61 intentionally stops before a provider-specific HSM/KMS adapter and service
binary. There is still no production endpoint, TLS identity, signer, database,
failover evidence, executor, physical board or market-release evidence.
The complete regression passes 27 C host suites, 7 gateway-contract tests, 70
factory tests, 296 tooling/policy tests, 5 generation-state tests, Companion
dependency/privacy and 25 scenarios, plus Go normal/vet/race gates. Firmware
bytes remain unchanged.

## Verified M62 standalone factory trusted-time service

M62 adds `factorytimeauthority` as a production-oriented standalone process and
the seventh mandatory OCI/Kubernetes workload. Startup verifies PostgreSQL,
the exact station-facing TLS 1.3 mTLS identity and the external signer before
serving. Liveness is separated from readiness; readiness rechecks both the
database schema and signer without exposing the factory API on the probe port.

The new remote signer wire contract is deliberately narrower than a generic
KMS proxy. It accepts only the fixed M60 signature domain and canonical unsigned
receipt, uses a configured key ID, direct TLS 1.3 mTLS, three reviewed pins and
no proxy/redirect, then verifies the returned Ed25519 signature locally. The
authority has no receipt-signing private key or hardware executor.

OCI receipt schema v3 fixes the exact order of seven services and Kubernetes
deployment schema v2 produces 44 resources plus 30 value-free prerequisites.
The authority exposes station mTLS on 9445, keeps HTTP probes on private 9081,
and has only database:5432 plus signer:443 egress. The real dual-architecture
Go build and kubectl Kustomize smoke passed with a reproducible 112,139-byte
deployment tree; the 10-Policy/10-Binding admission smoke also passed offline.

The complete regression passes 27 C host suites, 7 gateway-contract tests, 70
factory tests, 302 tooling/policy tests, 5 generation-state tests, Companion
dependency/privacy and 25 scenarios, plus Go normal/vet/race. No production
signer, live PostgreSQL, cluster, physical board or market-release evidence was
used. See
[M62_FACTORY_TRUSTED_TIME_SERVICE_REPORT.md](M62_FACTORY_TRUSTED_TIME_SERVICE_REPORT.md)
and
[FACTORY_TRUSTED_TIME_AUTHORITY_RUNBOOK.md](FACTORY_TRUSTED_TIME_AUTHORITY_RUNBOOK.md).

## Verified M63 factory trusted-time signer enforcement

M63 closes the server side of the M62 remote signer contract without selecting
a provider or adding a software key. The handler requires direct TLS 1.3 mTLS
and the exact authority leaf-certificate DER hash, parses only the canonical
M60 receipt-signing request and refuses generic payloads.

A separate read-only PostgreSQL authorizer proves that every receipt exactly
matches an already committed authority row and that database time is still
inside both plan and receipt windows. The check runs once before the HSM/KMS
backend and again after it; expired signatures are discarded. A returned
signature is also verified locally with the pinned Ed25519 public key.

The M62 client and M63 handler interoperate over real ephemeral TLS 1.3 mTLS.
The updated seven-service dual-architecture build and 44-resource Kubernetes
smoke remain reproducible; the complete regression passes 309 tooling/policy
tests plus all prior C, factory, Companion and Go normal/vet/race gates. No
production backend, key, PostgreSQL instance, signer image, cluster or physical
board was used. See
[M63_FACTORY_TRUSTED_TIME_SIGNER_ENFORCEMENT_REPORT.md](M63_FACTORY_TRUSTED_TIME_SIGNER_ENFORCEMENT_REPORT.md)
and
[FACTORY_TRUSTED_TIME_SIGNER_RUNBOOK.md](FACTORY_TRUSTED_TIME_SIGNER_RUNBOOK.md).

## Verified M64 BOX-3 visible Agent action adapter

M64 returns from factory infrastructure to the first visible product action.
The `VOICE_AGENT_KIT_BOX3` SKU now freezes a GPIO 47 active-high display
backlight indicator and explicitly allows `device.set_indicator`. A new
product-owned adapter drives the output inactive before use, exposes only a
boolean on/off operation, retains content-free state for `device.get_status`,
and releases the GPIO inactive.

The action remains behind the existing root-Agent, exact JSON, request/session,
owner-epoch, App decision, one-use grant, cancellation-linearization and
metadata-only audit chain. The development `.example.invalid` Live compile
profile enables the tool so the complete firmware path is compiled. The
production-security profile explicitly disables it, and CMake rejects an
attempt to combine production security with the action until signed-App, live
account/PostgreSQL, physical UX and market-release gates pass.

Both firmware gates now inspect the final ELF, not only source configuration:
the development image contains the callback and all four adapter entry points,
while the production image contains none of their symbols. The development
image is 1,417,088 bytes (SHA-256
`4eb343c8476949fdf0be66d15eefa9bd66928b1c871990128cc44a8ec770c92f`);
the unsigned Secure-Boot-padded production input is 1,441,792 bytes (SHA-256
`a636234d9c35ac48ebd66e91f33dbb24c546f4589ff466625eabaa1515171884`).
Production remote-signing and virtual-eFuse test flows pass with ephemeral
untrusted keys. The complete regression passes 27 C host suites, 7
gateway-contract tests, 70 factory tests, 314 tooling/policy tests, 5
generation-state tests, Companion gates and all Go packages/vet.

This is code and compile evidence, not board qualification. No BOX-3, signed
mobile App, production account service/database or `MARKET_RELEASE_PASS` was
available. See
[M64_BOX3_VISIBLE_AGENT_ACTION_REPORT.md](M64_BOX3_VISIBLE_AGENT_ACTION_REPORT.md),
[AGENT_ACTION_CONSENT_RUNBOOK.md](AGENT_ACTION_CONSENT_RUNBOOK.md), and
[AGENT_CAPABILITY_SECURITY_RUNBOOK.md](AGENT_CAPABILITY_SECURITY_RUNBOOK.md).

## Verified M65 Companion just-in-time consent access

M65 closes the missing App/account issuance link without pretending to have
selected an IdP. `HTTPSAgentActionConsentAccessProvider` obtains a fresh
product-login authorization for every inbox fetch or decision and exchanges it
over a fixed no-store HTTPS contract for an exact device-bound
`device:action-consent` bearer. It validates canonical response bytes, device,
owner revision and a maximum five-minute lifetime, then immediately invalidates
the login ticket and retains no bearer.

`AgentActionConsentSceneGateView` directly maps active/background scene state,
account sign-out, device changes and ownership-revision changes onto the
foreground session. A new BFF `ActionConsentAccessHandler` requires a selected
IdP/ownership authenticator, TLS 1.2+, exact canonical input and durable JTI
registration before returning the token. The handler is intentionally absent
from the private `accountauthorization` introspection reader, so it cannot
silently turn that workload into public login/issuance ingress.

The focused gate passes 27 C host suites, 7 gateway-contract tests, 27 focused
policy checks, targeted Go tests/vet, explicit SwiftUI warnings-as-errors
compilation, and 29 Companion scenarios under normal execution and Thread
Sanitizer. This remains a software integration boundary: no selected IdP,
deployed BFF, live database, signed App or physical-device evidence exists. See
[M65_COMPANION_JIT_CONSENT_ACCESS_REPORT.md](M65_COMPANION_JIT_CONSENT_ACCESS_REPORT.md)
and
[COMPANION_ACCOUNT_AUTHORIZATION_RUNBOOK.md](COMPANION_ACCOUNT_AUTHORIZATION_RUNBOOK.md).

The complete M65 regression passes 27 C host suites, 7 gateway-contract tests,
70 factory tests, 316 tooling/policy tests, 5 generation-state tests, all
Companion gates and all Go packages/vet. A separate race run covers the changed
account authorization, action consent, authentication and control-plane
packages. M65 does not change firmware, so the M64 image hashes and ELF action
isolation remain current.

## Verified M66 content-free wake-only consent notification

M66 adds a durable optional accelerator while keeping the authenticated consent
inbox authoritative. Registration writes the challenge and one wake outbox row
in the same serializable PostgreSQL transaction. Workers use database time,
`FOR UPDATE SKIP LOCKED`, bounded leases and retries; provider acceptance or a
confirmed absent installation acknowledges only the outbox row and never
decides the action.

The M66 provider-neutral sender body is exactly
`{"version":1,"kind":"action-consent-wake"}`. It contains no challenge,
device, owner, action, arguments, prompt, decision, expiry, URL or token. The
Companion parser rejects any variation, and only an active foreground session
may translate the signal into a fresh JIT-authorized inbox fetch. Background
receipt, push duplication and provider disposition cannot approve, deny or
create consent.

The focused gate passes 27 C host suites, 7 gateway-contract tests, 29 focused
policy checks, targeted Go tests/vet and action-consent race detection,
warnings-as-errors SwiftUI compilation, and 32 Companion scenarios under normal
execution and Thread Sanitizer. No APNs/FCM adapter, installation registry,
provider credential, deployed notifier, signed App or live PostgreSQL evidence
exists. See
[M66_WAKE_ONLY_NOTIFICATION_REPORT.md](M66_WAKE_ONLY_NOTIFICATION_REPORT.md),
[AGENT_ACTION_CONSENT_RUNBOOK.md](AGENT_ACTION_CONSENT_RUNBOOK.md), and
[COMPANION_ACCOUNT_AUTHORIZATION_RUNBOOK.md](COMPANION_ACCOUNT_AUTHORIZATION_RUNBOOK.md).

The complete M66 regression passes 27 C host suites, 7 gateway-contract tests,
70 factory tests, 318 tooling/policy tests, 5 generation-state tests, all
Companion gates and all Go packages/vet. A separate race run covers the changed
action-consent package. M66 changes no firmware source, so the M64 image hashes
and final-ELF action isolation remain current. This is not a claim of physical
delivery or market readiness.

## Verified M67 encrypted installation and APNs/FCM delivery software

M67 connects the content-free wake to concrete APNs HTTP/2 and FCM HTTP v1
clients. A selected-IdP BFF building block registers canonical App
installations; raw provider tokens are AES-256-GCM sealed with account/install/
platform-bound associated data before persistence, while a distinct HMAC key
produces the exact CAS digest. Logout and suspension rotate the account revision
and delete old installations in the same serializable transaction.

APNs and FCM receive only provider-required fixed envelopes containing
`version=1` and `kind=action-consent-wake`; they receive no challenge, product
device, action, arguments, decision, prompt, URL or account bearer. Typed
provider invalid-token responses remove only the exact current digest;
authentication, rate-limit, transport and 5xx failures retain the wake for
retry. `PrivateWakeHandler`/`MTLSWakeClient` preserve the existing seven-service
topology, but remain intentionally unmounted until production provider and key
sources are selected.

The Companion client refreshes/removes installations with a fresh login ticket
per request and retains neither the ticket nor provider token. Focused evidence
passes Go tests/vet/race, local TLS/HTTP2 provider exchanges, and 36 Companion
scenarios normally and under Thread Sanitizer. No live APNs/FCM credential,
signed App, mounted private dispatch or live PostgreSQL evidence exists. See
[M67_PUSH_DELIVERY_SOFTWARE_REPORT.md](M67_PUSH_DELIVERY_SOFTWARE_REPORT.md).

The complete M67 regression passes 27 C host suites, 7 gateway-contract tests,
70 factory tests, 323 tooling/policy tests, 5 generation-state tests, all
Companion gates and all Go packages/vet. A separate race run covers
`accountauth`, `pushdelivery` and `actionconsent`. M67 changes no firmware, so
the M64 image hashes and final-ELF isolation remain current.

## Verified M68 push credentials and opt-in seven-service wiring

M68 adds APNs ES256 provider-token generation and bounded rotation, plus FCM
OAuth access through either a locally verified RS256 service-account assertion
or the exact Google metadata identity protocol. Credential files and the
versioned AES-GCM/HMAC token keyring are bounded secret-mount inputs; unsafe,
partial or mismatched configuration fails startup without logging secrets.

The private wake handler is now conditionally mounted on the existing
`accountauthorization` TLS listener, while `controlplane` runs the durable
outbox worker using its existing Companion workload mTLS identity. A push wake
still contains no consent content and cannot approve an action. Kubernetes
deployment schema v3 makes provider choice an explicit profile field, derives
unique worker identity from the Pod name, adds only provider-specific
prerequisites/egress, and retains exactly seven workloads.

Local cryptographic, HTTP/TLS, configuration, worker-lifecycle and deterministic
deployment tests pass. The complete M68 regression passes 27 C host suites, 7
gateway-contract tests, 70 factory tests, 325 tooling/policy tests, 5
generation-state tests, 36 Companion scenarios normally and under Thread
Sanitizer, all Go test/vet, changed-package race tests and the signed Kubernetes
deployment gate. No production APNs/FCM credential, live PostgreSQL,
cluster admission/CNI evidence, signed App, physical device or market-release
approval exists. See
[M68_PUSH_CREDENTIAL_WIRING_REPORT.md](M68_PUSH_CREDENTIAL_WIRING_REPORT.md).

## Verified M69 signed push-provider qualification boundary

M69 adds a deliberately narrow live qualification command for the production
M68 APNs/FCM clients. It requires current and next credential acceptance, a
random permanent-invalid target classification and pre-canceled request retry,
then writes a canonical Ed25519-signed, secret-free receipt. Private config,
provider keys and valid targets must be owner-only regular files; duplicate JSON
fields, production-labelled APNs development, partial results and receipt
overwrite all fail closed.

The offline fixture can emit only `FIXTURE_PROTOCOL_PASS`; independent
validation with `--require-live` rejects it. A real run may emit
`LIVE_PROVIDER_API_PASS`, but every receipt remains `production_ready: false`
until old-credential revocation, seven-service mTLS dispatch, managed database
resilience and a signed App receipt exist. Product market release now requires
exactly 15 evidence types, including the broader `push_provider_delivery` WORM
aggregate. No live provider credentials were used here, so shipping remains
NO-GO. See
[PUSH_PROVIDER_QUALIFICATION_RUNBOOK.md](PUSH_PROVIDER_QUALIFICATION_RUNBOOK.md)
and [M69_PUSH_PROVIDER_QUALIFICATION_REPORT.md](M69_PUSH_PROVIDER_QUALIFICATION_REPORT.md).

## M70 signed-App delivery qualification boundary implemented

M70 instruments the existing Companion foreground consent session with an
optional, one-shot qualification observer. It records a background content-free
wake, later foreground entry and authenticated presentation of the exact
expected ticket. Raw challenge/device/action values never enter the observation;
per-run domain-separated hashes preserve correlation without cross-run identity.
Background receipt still performs no network request and cannot issue a
decision.

The signed chain re-verifies the exact M69 receipt, an independent Apple App
Attest/signed-artifact authority receipt, the App observation and a separate
M70 authority signature. The independent validator rebuilds the receipt from
all subordinate objects. Fixtures can emit only `FIXTURE_APP_FLOW_PASS` and are
rejected by `--require-live`; live evidence would emit
`LIVE_SIGNED_APP_FLOW_PASS` but remains `production_ready: false` while mTLS,
managed PostgreSQL and old-credential revocation gates are open. No signed App,
Apple App Attest or iPhone is available here, so market release remains NO-GO.
See [APP_DELIVERY_QUALIFICATION_RUNBOOK.md](APP_DELIVERY_QUALIFICATION_RUNBOOK.md)
and [M70_APP_DELIVERY_QUALIFICATION_REPORT.md](M70_APP_DELIVERY_QUALIFICATION_REPORT.md).

The dedicated M70 fixture gate and M69 compatibility gate pass. The complete
regression passes 27 C host suites, 7 gateway-contract tests, 70 factory tests,
334 tooling/policy tests, 5 generation-state tests, 38 Companion scenarios
normally and under Thread Sanitizer, all Go packages/vet and changed-package
race tests. Firmware remains unchanged from M64.

## M71 seven-service mTLS dispatch qualification boundary implemented

M71 qualifies the real controlplane-to-accountauthorization private wake seam
with TLS 1.3, HTTP/2, exact server-leaf binding, distinct current/next workload
certificate acceptance, and anonymous/revoked/wrong-hostname rejection. The
runner is available both as an offline operator command and as the explicit
`qualify-mtls-dispatch` mode of the signed controlplane executable, so a live
run can originate in the target Pod without adding an eighth product workload.

A deployment authority separately binds the content-minimized observation to
the exact ordered seven-service deployment, OCI/deployment IDs, live API-server
admission, mounted identity, NetworkPolicy path and WORM evidence. The final
authority re-verifies and rebuilds the complete M69/M70 chain plus the M71
deployment attestation. Fixture evidence can produce only
`FIXTURE_MTLS_DISPATCH_PASS`, retains all four earlier gates and fails
`--require-live`; only real `LIVE_MTLS_DISPATCH_PASS` removes the signed-App and
end-to-end mTLS gaps. Managed database failover and provider credential
revocation would still remain.

The M71 deployment review also fixed the accountauthorization Secret projection
so the already-required push token keyring, APNs key and FCM service account are
actually mounted in the Pod. No kube-apiserver, mounted rotation identities or
live App/provider evidence exists in this workspace, so shipping remains NO-GO.
See [MTLS_DISPATCH_QUALIFICATION_RUNBOOK.md](MTLS_DISPATCH_QUALIFICATION_RUNBOOK.md)
and [M71_MTLS_DISPATCH_QUALIFICATION_REPORT.md](M71_MTLS_DISPATCH_QUALIFICATION_REPORT.md).

The dedicated M71, M69 and M70 gates pass. The complete regression passes 27 C
host suites, 7 gateway-contract tests, 70 factory tests, 340 tooling/policy
tests, 5 generation-state tests, 38 Companion scenarios normally and under
Thread Sanitizer, all Go packages/vet and a separate all-package race run.
Firmware remains unchanged from M64.

## M72 provider credential revocation qualification boundary implemented

M72 closes the software boundary for deliberate APNs/FCM credential retirement.
The fixed live probe is active accepted, revoked explicitly rejected, then a
fresh active client accepted again. APNs accepts only 403
`InvalidProviderToken`; FCM performs a fresh Google OAuth exchange and accepts
only `invalid_grant`/`invalid_client`. Network, TLS, quota, 5xx and invalid-target
failures cannot masquerade as revocation evidence.

A separate provider-console audit authority binds the public credential IDs,
SPKI digests, change window and WORM evidence. The final builder and independent
validator consume one strict public evidence manifest and rebuild the complete
M69/M70/M71/M72 chain. Fixture evidence can emit only
`FIXTURE_PROVIDER_CREDENTIAL_REVOCATION_PASS`; only real provider/API/console
evidence can emit `LIVE_PROVIDER_CREDENTIAL_REVOCATION_PASS`.

No Apple/Google credentials or console access exists here. Even a live M72 pass
would retain `managed_database_failover`, and every receipt remains
`production_ready: false`; shipping is therefore still NO-GO. See
[PROVIDER_CREDENTIAL_REVOCATION_RUNBOOK.md](PROVIDER_CREDENTIAL_REVOCATION_RUNBOOK.md)
and [M72_PROVIDER_CREDENTIAL_REVOCATION_REPORT.md](M72_PROVIDER_CREDENTIAL_REVOCATION_REPORT.md).

The dedicated M69 through M74 gates pass. The complete M74 regression passes 27
C host suites, 7 gateway-contract tests, 70 factory tests, 358 tooling/policy
tests, 5 generation-state tests, 38 Companion scenarios normally and under
Thread Sanitizer, all Go packages/vet and a separate all-package Go race run.
Firmware remains unchanged from M64.

## M73 managed database failover and PITR qualification boundary implemented

M73 adds an append-only, idempotent canary ledger to the three exact durable
database roles: ownership/action-consent/wake outbox, account authorization and
installation registry, and factory trusted-time replay. The live runner verifies
each exact product schema and writable primary, creates a bounded database-time
restore window, publishes a secret-free ready signal and waits for an externally
initiated managed failover. Lost commit replies are retried with the same
sequence/payload and reconciled; an outage cannot pass without a new hashed node
binding and all acknowledged events remaining durable.

The PITR runner connects only to distinct isolated restore endpoints and requires
exactly `pre + restore-marker`; any restore-exclusion, heartbeat or post event is
a failure. A separate managed PostgreSQL audit authority binds real provider
failover/backup/restore operation IDs, encryption, isolation, WORM retention and
RPO/RTO values. The final builder and independent validator rebuild the entire
M69→M73 chain from strict public manifests.

Fixture evidence can emit only
`FIXTURE_MANAGED_DATABASE_FAILOVER_RESTORE_PASS` and fails `--require-live`. A
real `LIVE_MANAGED_DATABASE_FAILOVER_RESTORE_PASS` has no remaining software
qualification gates but deliberately remains `production_ready: false`; the
fixed 15-domain release, physical hardware, production App/provider/cluster,
legal evidence and `MARKET_RELEASE_PASS` are still required. No live managed
PostgreSQL or provider control plane is available here, so shipping remains
NO-GO. See
[MANAGED_DATABASE_RESILIENCE_RUNBOOK.md](MANAGED_DATABASE_RESILIENCE_RUNBOOK.md)
and [M73_MANAGED_DATABASE_RESILIENCE_REPORT.md](M73_MANAGED_DATABASE_RESILIENCE_REPORT.md).

## M74 distributed runtime coordination software boundary implemented

M74 replaces replica-local security decisions in all three online paths with a
single PostgreSQL coordination contract in the existing ownership role. Six
device-proof scopes now share nonce/cadence state; Gateway replicas share voice
token replay, per-device lease ownership and the global connection ceiling;
Agent Proxy replicas share per-device inflight/rate state and the global
concurrency ceiling. PostgreSQL time, serializable transactions and random
128-bit fencing IDs make expiry takeover and stale-release behavior explicit.

Only domain-separated SHA-256 values cross the database boundary. Production
commands verify the schema before listening, voice sessions close on lease-renew
loss, and Agent permits cover the bounded end-to-end provider request. The
signed Kubernetes generator keeps exactly seven workloads, derives a unique
worker identity from each Pod name, isolates database URLs in Secrets and adds
the exact Gateway database egress previously missing.

The focused test/race/vet/deployment gate passes. Its live-required mode rejects
missing database input. No live PostgreSQL or Kubernetes environment exists
here, so horizontal production rollout and shipping remain NO-GO. See
[RUNTIME_COORDINATION_RUNBOOK.md](RUNTIME_COORDINATION_RUNBOOK.md) and
[M74_DISTRIBUTED_RUNTIME_COORDINATION_REPORT.md](M74_DISTRIBUTED_RUNTIME_COORDINATION_REPORT.md).

## M75 private speech workload identity software boundary implemented

M75 closes the remaining Gateway-to-private-speech transport gap. STT and TTS
now use two proxy-free, redirect-free, exact TLS 1.3 mTLS clients with separate
canonical CA trust sets, client leaves and bearer tokens. Credential files are
strictly parsed, client-auth usage and validity are checked, private keys must be
mode 0600 or stricter, and reuse is detected from certificate content rather
than only filenames. Production configuration fails before listen on a missing,
partial, shared-path or plaintext speech boundary.

The M28 live qualification runner uses the same loader and binds both CA sets
and both client leaves into its signed transport-trust digest. The signed
Kubernetes generator mounts six purpose-specific files in the existing Gateway
Secret while retaining exactly seven workloads and the existing speech:443
egress scope. The focused Go test/race/vet and deployment-policy gate passes.
No live provider, rotation, Kubernetes, hardware or market evidence exists
here, so shipping remains NO-GO. See
[SPEECH_WORKLOAD_IDENTITY_RUNBOOK.md](SPEECH_WORKLOAD_IDENTITY_RUNBOOK.md) and
[M75_SPEECH_WORKLOAD_IDENTITY_REPORT.md](M75_SPEECH_WORKLOAD_IDENTITY_REPORT.md).

## M76 managed bearer-token key rotation software boundary implemented

M76 replaces raw production Voice, Agent and OTA HMAC bearer-token settings with
canonical private keyring files and externally approved positive revision
floors. New Voice/Agent tokens use `v4.<kid>...`; OTA uses `v2.<kid>...`.
Verification selects only the named key, bounds both retiring-key issuance and
verification, and permits old unkeyed tokens only through an explicit retiring
key and deadline. Voice, Agent and OTA material is checked across active and
retiring entries and against App, rollout and generation keys.

Gateway, Control Plane, Agent Proxy and Firmware Origin enforce the managed
contract outside explicit development mode. The deterministic Kubernetes graph
mounts purpose-specific 0400 keyring files at fixed paths, removes bearer-token
HMAC environment variables and remains exactly seven workloads. Firmware still
receives only opaque short-lived tokens. The focused Go test/race/vet and 18-test
deployment-policy gate passes. No live secret-manager rotation, cluster rollout,
forward-only rollback, hardware or market evidence exists here, so shipping
remains NO-GO. See
[MANAGED_TOKEN_KEY_ROTATION_RUNBOOK.md](MANAGED_TOKEN_KEY_ROTATION_RUNBOOK.md) and
[M76_MANAGED_TOKEN_KEY_ROTATION_REPORT.md](M76_MANAGED_TOKEN_KEY_ROTATION_REPORT.md).

## M77 managed-token transition preflight implemented

M77 adds an operator-facing preflight before any M76 verifier Secret rollout.
It compares the exact current issuer and proposed target verifier rings without
exporting key material. Normal rotation must add exactly one new active key;
forward recovery may reactivate only an existing non-legacy retiring key. Both
paths require a strictly higher revision, preserve every current key by ID and
constant-time material comparison, keep live legacy migration unchanged and
cover a future cutover plus the full configured TTL and skew.

`cmd/validatemanagedtokenrotation` also requires exact operator-expected
revisions, active key IDs and matching rollback floors. Its exclusive-create,
canonical 0444 receipt contains only nonsecret metadata and is explicitly
`software_only:true`; it cannot claim secret-manager or cluster evidence. See
[M77_MANAGED_TOKEN_TRANSITION_PREFLIGHT_REPORT.md](M77_MANAGED_TOKEN_TRANSITION_PREFLIGHT_REPORT.md)
and [MANAGED_TOKEN_KEY_ROTATION_RUNBOOK.md](MANAGED_TOKEN_KEY_ROTATION_RUNBOOK.md).

## M78 content-free telemetry and backend SLO boundary implemented

M78 adds one product-owned OpenTelemetry runtime to each of the exact seven
backend commands. It emits only closed operation, normalized method, status and
result-class span attributes; it records no URL, path identifier, query,
header, body, transcript, prompt, model output, credential or arbitrary error
text. Public edges reject caller-selected trace context, internal product
boundaries propagate only `traceparent`, and third-party AI/push/OAuth calls
receive no product trace ID.

OTLP/HTTP export requires a canonical HTTPS `/v1/traces` endpoint and a private
TLS 1.3 client identity. Standard `OTEL_*` overrides are forbidden. The signed
Kubernetes profile mounts isolated telemetry credentials into all seven
workloads and limits their existing egress policies to one profile-selected
collector Pod set on TCP 4318; the graph remains seven workloads and 44
resources.

The canonical 28-day SLO policy and independently signed aggregate observation
validator fail on insufficient volume, availability/p99 misses, arithmetic
drift, unknown operations/attributes or any export loss. Local tests do not
create a live SLO result. See
[CONTENT_FREE_TELEMETRY_SLO_RUNBOOK.md](CONTENT_FREE_TELEMETRY_SLO_RUNBOOK.md)
and
[M78_CONTENT_FREE_TELEMETRY_SLO_REPORT.md](M78_CONTENT_FREE_TELEMETRY_SLO_REPORT.md).

## M79 backend SLO bound into final market release

The final release contract is now schema v2. It preserves the exact 15
independent evidence domains and adds a mandatory `backend_slo` trust block
that pins the collector, authority key ID/raw-key fingerprint and canonical M78
policy digest. Both builder and independent verifier run the M78 validator
directly against an external exact 28-day observation, fixed policy and public
key. Deployment identity must equal the product-release subject; all seven
services, arithmetic, thresholds, freshness, zero export loss, zero unknown
operations and zero attribute violations are rechecked before
`MARKET_RELEASE_PASS` can exist.

The builder takes a single private snapshot of those inputs before validation,
so a local file replacement cannot make the signed summary or bundled copy
differ from what was checked. The record binds observation/policy digests,
collector, window and authority; validation also byte-compares the bundled SLO
files with independently retrieved copies. Schema/signature-domain downgrade,
v1 parent records, missing or re-signed incomplete observations, wrong
deployment/key/policy, bundle substitution and untrusted inputs fail closed.
The product release gate now runs 20 focused product/SLO tests.

No deployed collector observation, production SLO authority, final 15-domain
evidence set or release key is available here, so this is a verified contract,
not a market approval, and no `MARKET_RELEASE_PASS` was created. See
[M79_BACKEND_SLO_MARKET_RELEASE_BINDING_REPORT.md](M79_BACKEND_SLO_MARKET_RELEASE_BINDING_REPORT.md)
and [PRODUCT_MARKET_RELEASE_RUNBOOK.md](PRODUCT_MARKET_RELEASE_RUNBOOK.md).

## M80 Companion App source supply chain implemented

M80 closes the local mobile-source inventory gap. The product-owned Swift
package now processes `PrivacyInfo.xcprivacy`; its policy gate requires the
exact no-tracking/no-collection/no-Required-Reason-API package boundary. A new
fail-closed builder inventories the exact 19 production metadata/source files,
requires Package.resolved and both Swift dependency checkouts to match the
reviewed clean commits, preserves their exact Apache-2.0 license bytes and emits
deterministic SPDX 2.3 plus in-toto/SLSA provenance.

An external Ed25519 App source authority signs a canonical receipt binding all
source, privacy, dependency, license, SBOM, provenance and policy digests.
Independent validation regenerates those artifacts from a separately retrieved
source tree, rejects source/dependency/license drift, byte-compares the bundle,
checks the exact file set and verifies last-written `READY`. The receipt always
sets `production_ready:false` and explicitly excludes source review/functional
tests, distribution signing, App Store/TestFlight, App Attest/device, Android/
Play Integrity, vulnerability and legal conclusions. The focused M80 gate
passes 9 adversarial/determinism tests, and the existing Companion gate passes
38 normal plus 38 thread-sanitized scenarios with the manifest bundled.

No full Xcode distribution archive, Apple developer identity, App Store
submission, App Attest/iPhone evidence or Android implementation is available,
so M80 is only the source-supply-chain part of `companion_apps`; it does not
create market evidence or `MARKET_RELEASE_PASS`. See
[COMPANION_APP_SUPPLY_CHAIN_RUNBOOK.md](COMPANION_APP_SUPPLY_CHAIN_RUNBOOK.md)
and [M80_COMPANION_APP_SUPPLY_CHAIN_REPORT.md](M80_COMPANION_APP_SUPPLY_CHAIN_REPORT.md).

## M81 Agent usage budget implemented

M81 adds a content-free, PostgreSQL-backed Agent model cost boundary without an
eighth service. Every owned-device scope receives one cross-replica UTC daily
budget across all pricing profiles. The Agent Proxy reserves a conservative
input/output maximum before contacting the provider, requires exact prompt,
completion and total token usage, settles actual integer micro-USD cost before
delivering the response, and converts any request that may already have been
billed but cannot be verified into worst-case uncertain cost. Crash-expired
reservations are never silently refunded.

Stored subjects are purpose-specific HMAC-SHA256 values; no prompt, model
output, URL or raw device/account/binding identity enters the ledger or metric
labels. Pricing profile IDs are immutable once observed and profile rotation
cannot reset a daily budget. The current signed Kubernetes deployment contract is
v6 and preserves the Agent pricing, budget, token overhead and reservation TTL;
the isolated digest key extends the existing Agent Proxy file Secret, so the
graph remains seven workloads and 44 resources. OCI source provenance now also
binds all SQL migrations.

The example price is deliberately non-production. No live provider contract,
bill, traffic, PostgreSQL/cluster reconciliation, ASR/TTS cost or finance/legal
approval is available, so M81 is not a complete COGS result and creates no
`MARKET_RELEASE_PASS`. See
[AGENT_USAGE_BUDGET_RUNBOOK.md](AGENT_USAGE_BUDGET_RUNBOOK.md) and
[M81_AGENT_USAGE_BUDGET_REPORT.md](M81_AGENT_USAGE_BUDGET_REPORT.md).

## M82 speech usage budget implemented

M82 extends cost safety to ASR／TTS without adding an eighth service. Gateway
uses one content-free, cross-replica UTC daily subject budget across STT, TTS
and every speech pricing profile. STT reserves bounded input-audio-ms chunks
before upstream writes. TTS reserves Unicode-scalar input plus signed maximum
output-audio duration before provider contact, and the framed adapter enforces
that duration. Successful work settles exact integer micro-USD; any provider,
network, cancellation, crash or database ambiguity preserves the worst-case
reservation as uncertain cost.

The new PostgreSQL ledger stores only a purpose-specific HMAC and aggregate
units/cost—never audio, transcript, TTS text/hash, URL or raw device/account
identity. The current deployment schema/signature domain v7 preserves signed
`speech_usage` and adds
an isolated `speech-usage-digest.key` to the existing Gateway Secret. The graph
remains seven workloads, 44 resources and 30 value-free prerequisites.

Budget rejection is also product-safe on the wire and device. Gateway returns
only `type` and `code`, without identity, price, remaining-budget, text or
provider details. The ESP32 stops capture, flushes pending TTS and emits a typed
product event. A spent daily budget does not trigger reconnects; a temporarily
unavailable budget ledger follows the existing retry/backoff path. Neither
condition is counted as a protocol violation.

This model supports STT input-audio pricing and TTS Unicode-scalar,
output-audio or hybrid pricing. Providers with connection/request/minimum fees
or other billing units require a new contract and qualification. No live price,
invoice, speech traffic, PostgreSQL/cluster, hardware or finance/legal evidence
exists, so M82 remains NO-GO and creates no `MARKET_RELEASE_PASS`. See
[SPEECH_USAGE_BUDGET_RUNBOOK.md](SPEECH_USAGE_BUDGET_RUNBOOK.md) and
[M82_SPEECH_USAGE_BUDGET_REPORT.md](M82_SPEECH_USAGE_BUDGET_REPORT.md).

## M83 Voice／Agent service entitlement implemented

M83 separates authenticated accounts from current commercial service access.
The existing `accountauthorization` workload now owns an ordered, idempotent
PostgreSQL entitlement ledger with active／grace／suspended／ended states and
separate Voice／Agent flags. Control Plane performs a private mTLS authorization
before each Voice or Agent token issuance; denied access returns 402, service
failure returns 503, and an issued token can never outlive `access_until`.

Deployment schema/signature domain v6 signs separate Voice and Agent token TTL
bounds plus the fixed authorization path. The graph remains seven workloads,
44 Kubernetes resources and 30 value-free prerequisites. On ESP32, either token
endpoint's 402 becomes a typed entitlement-blocked product state: partial
credentials are erased, no session starts, and no timer-driven retry storm is
created. A reviewed App/product entitlement-change signal only triggers one
fresh backend check; it cannot locally grant access.

This is a provider-neutral software boundary, not a billing integration. No
real billing／App Store provider, IdP, managed PostgreSQL, signed App, target
cluster, ESP32 hardware cancellation/grace flow or WORM audit evidence exists,
so M83 remains NO-GO and creates no `MARKET_RELEASE_PASS`. See
[SERVICE_ENTITLEMENT_RUNBOOK.md](SERVICE_ENTITLEMENT_RUNBOOK.md) and
[M83_SERVICE_ENTITLEMENT_REPORT.md](M83_SERVICE_ENTITLEMENT_REPORT.md).

## M84 signed entitlement ingestion boundary implemented

M84 replaces direct adapter-to-database entitlement mutation with a canonical
`POST /v1/service-entitlements/apply` boundary on the existing
`accountauthorization` workload. Every write requires verified workload mTLS
and a separately trusted Ed25519 signature over an exact five-minute-or-shorter
authorization window. A rollback-fenced active/retiring public-key ring supports
rotation; re-signing the same commercial event with a fresh window remains an
idempotent replay, while stale revisions and same-ID content conflicts return
409 without overwriting newer state.

The request schema contains only tenant/subject mapping, opaque event and plan
IDs, ordered revisions, four-state Voice/Agent access and UTC expiries. It has
no provider customer, payment method, invoice, price, receipt, card or raw
webhook field. Deployment schema/signature domain v7 signs the keyring revision
floor and authorization TTL, mounts the trust file as a private regular
non-symlink file, and admits only Control Plane plus the controlled release
operator namespace to the existing 9444 Service. The graph remains seven
workloads, 44 Kubernetes resources and 30 value-free prerequisites.

This still does not select or qualify a real billing/App Store provider, IdP,
managed PostgreSQL, target cluster, signed App or ESP32 hardware flow. M84 is
therefore NO-GO for market release and creates no `MARKET_RELEASE_PASS`. See
[SIGNED_ENTITLEMENT_INGESTION_RUNBOOK.md](SIGNED_ENTITLEMENT_INGESTION_RUNBOOK.md)
and [M84_SIGNED_ENTITLEMENT_INGESTION_REPORT.md](M84_SIGNED_ENTITLEMENT_INGESTION_REPORT.md).

## M85 provider-neutral entitlement adapter SDK implemented

M85 adds the outbound half of the M84 contract without selecting a billing or
App Store provider. A narrow `EntitlementUpdateSigner` lets a production
adapter sign exact canonical bytes in an HSM/KMS without exposing private-key
material to the SDK. The HTTP client can only be constructed from an explicit
product CA and adapter mTLS identity; it has bounded timeouts, no ambient proxy,
no public root fallback, no redirects and no replaceable transport hook.

Each `Apply` signs once and sends exactly one request. The SDK deliberately has
no automatic retry: 400 enters dead-letter review, 401 disables the signer
path, 404 quarantines account mapping, 409 requires ordered reconciliation, and
a transport error or 503 may be retried only after re-reading the provider event
and current ledger. No provider customer, payment, invoice, receipt or raw
webhook field is added. Deployment remains schema v7 with seven workloads, 44
resources and 30 prerequisites.

No real provider, IdP, HSM/KMS, managed PostgreSQL, target cluster, signed App
or ESP32 flow is qualified. M85 therefore remains NO-GO for market release and
creates no `MARKET_RELEASE_PASS`. See
[ENTITLEMENT_ADAPTER_CONFORMANCE_RUNBOOK.md](ENTITLEMENT_ADAPTER_CONFORMANCE_RUNBOOK.md).

## M87 product launch-lane decision boundary implemented

M87 turns the unresolved business model into a canonical, fail-closed release
input instead of silently treating a technical demo as a market decision. The
current proposal recommends the existing `VOICE_AGENT_KIT_BOX3` as a direct
developer/system-integrator kit, but deliberately leaves target markets,
billing, IdP, SDK distribution, legal review and App channels unselected.

Three mutually exclusive lanes now define consistent sales, Companion App and
entitlement paths: organization contract/invoice, direct consumer hardware plus
cloud, or mobile-store consumer subscription. An APPROVED profile requires one
to eight ISO markets, non-placeholder authorities/providers, a policy review no
older than 30 days, and a maximum 180-day approval. Contradictory channel
combinations fail validation. The exact approved profile digest and WORM URI
must be subordinate evidence inside the existing `legal_market` domain, so the
market-release contract remains 15 domains.

The checked-in profile is only PROPOSED and `--require-approved` fails closed.
M87 therefore creates no market decision or `MARKET_RELEASE_PASS`. See
[PRODUCT_LAUNCH_LANES.md](PRODUCT_LAUNCH_LANES.md).

## M86 external-consumable entitlement adapter SDK implemented

M86 closes a packaging flaw in M85: a provider adapter in another Go module
cannot legally import `gateway/internal/accountauth`. The new public
`gateway/entitlementadapter` facade defines its own versioned Update, State,
Result, Signer and error surface without exposing any internal type. Its opaque
mTLS handle and Client delegate to the previously qualified canonical
single-delivery implementation, so adapters cannot replace transport trust or
duplicate the wire protocol.

A conformance test creates a separate temporary provider-adapter module and
compiles it using only the public import. The stable public errors hide internal
details while preserving invalid, unauthorized, not-found, conflict and
unavailable decisions. This does not claim a published public module: the final
organization/repository path and private Go proxy or signed vendor delivery
still require a product decision.

The deployment remains schema v7 with seven workloads, 44 resources and 30
prerequisites. No real provider, published module, HSM/KMS, IdP, production
database/cluster, signed App or ESP32 flow is qualified, so M86 remains NO-GO
and creates no `MARKET_RELEASE_PASS`. See
[ENTITLEMENT_ADAPTER_CONFORMANCE_RUNBOOK.md](ENTITLEMENT_ADAPTER_CONFORMANCE_RUNBOOK.md).

## M88 international individual-developer launch contract implemented

The selected customer segment is now international individual developers. That
maps to Lane B direct-consumer hardware plus cloud, not the enterprise exception:
the proposed `VOICE_AGENT_KIT_BOX3` profile uses direct web checkout, a public
free iOS companion, a public consumption-only Android companion and the web
billing adapter. Neither App may offer a purchase or outbound purchase call to
action under this proposal.

Revision 2 proposes a staged Wave 1 of AU, CA, GB, SG, TW and US. These codes are
work packages, not approvals: each market still needs its own RF/final-host,
label, merchant/tax, consumer/privacy, return/refund, App-review and legal WORM
evidence. EU/EEA, Japan and Korea stay in Wave 2. The validator now checks
lane consistency even while a profile is `PROPOSED`, so a selected web-checkout
profile cannot silently claim IAP distribution or contract-invoice entitlement.

The provider-neutral web billing contract requires native event signature
verification, provider API re-fetch, durable idempotency, ordered revisions and
explicit new-sale/renewal/failure/cancel/refund/chargeback reconciliation. Browser
return URLs and App callbacks are never entitlement authority. This adds no
backend workload and does not choose a provider.

Billing provider, merchant legal entity, IdP, HSM/KMS, SDK distribution owner,
legal reviewer and decision owner remain `UNSELECTED`; all six markets remain
NO-GO. The checked-in profile is deliberately `PROPOSED` and
`--require-approved` fails closed, so M88 creates no `MARKET_RELEASE_PASS`. See
[INTERNATIONAL_DEVELOPER_KIT_LAUNCH.md](INTERNATIONAL_DEVELOPER_KIT_LAUNCH.md)
and [WEB_BILLING_ADAPTER_CONTRACT.md](WEB_BILLING_ADAPTER_CONTRACT.md). The
qualification summary is in
[M88_INTERNATIONAL_DEVELOPER_LAUNCH_REPORT.md](M88_INTERNATIONAL_DEVELOPER_LAUNCH_REPORT.md).

## Host verification

```sh
./tools/run_all_tests.sh
```

This runs the C bridge/controller/adapter/audio/runtime/identity/SKU/Wi-Fi/
local-action/factory-reset/provisioning/storage/Agent-capability/content-privacy/OTA/fleet-offer tests, Python gateway, signed factory-receipt/per-unit-flash-manifest,
reset-hardware qualification, factory-key/onboarding-bundle, production boot-security/signing/virtual-eFuse/sacrificial-authorization/attempt-ledger/trusted-time, OTA deployment/
rollout-generation/generation-state/OCI-release/Kubernetes-deployment/
Kubernetes-admission/live-admission-qualification/product-market-release,
push-provider/App-delivery/mTLS-dispatch/provider-revocation/managed-database/runtime-coordination/speech-workload-identity/managed-token-rotation qualification,
content-free telemetry/backend-SLO qualification/Companion-App-source-supply-chain,
Agent-usage-budget/speech-usage-budget/service-entitlement/secure-storage/Agent-memory
policy, product-launch/international-developer/web-billing policy,
speech-provider/reference-codec/adapter-qualification/device-identity/
firmware-SBOM contracts, Companion App dependency/privacy/core/race gates,
ownership-binding lifecycle, memory-budget tests, and Go gateway
tests/vetting.
Go 1.26.5 and Python 3.11 with TLS 1.3-capable OpenSSL plus Python
`cryptography` are required. Native C test executables are created in a
temporary directory and removed automatically.

## Firmware build

Use ESP-IDF 6.0.2, then:

```sh
./tools/sync_upstreams.sh
./tools/build_generic.sh
```

For the isolated ESP32-S3-BOX-3 N16R8 build:

```sh
./tools/build_box3.sh
```

To prove the opt-in live composition branch compiles together with secure
storage, without using routable service endpoints:

```sh
./tools/build_box3_live_compile_gate.sh
```

This gate deliberately uses `.example.invalid`; never flash, sign, publish, or
ship that image. Real release configuration and physical-presence ownership are
defined in [PRODUCT_RUNTIME_RUNBOOK.md](PRODUCT_RUNTIME_RUNBOOK.md).

For release-candidate builds that require an already factory-provisioned slot
4 NVS HMAC key:

```sh
./tools/build_secure_storage_generic.sh
./tools/build_secure_storage_box3.sh
```

Do not flash a secure-storage image onto an unprovisioned development unit and
expect it to self-repair; it is designed to stop before network startup.

To create reproducible, unsigned external-signing inputs for the complete BOX3
production-security profile:

```sh
./tools/build_box3_production_security_gate.sh
```

This gate also runs the independent three-root signing flow with disposable
test keys, then deletes them. Its build output is still unsigned and must never
be flashed, ad-hoc signed, promoted, or shipped. The HSM, per-device encryption,
and irreversible factory sequence are defined in
[PRODUCTION_BOOT_SECURITY_RUNBOOK.md](PRODUCTION_BOOT_SECURITY_RUNBOOK.md).

To generate and independently verify the release-specific App/bootloader SBOM
bundle after the production-security build:

```sh
export FIRMWARE_SBOM_TOOL=/controlled/path/esp-idf-sbom
./tools/build_box3_firmware_sbom_gate.sh /new/immutable/sbom-output
```

The output name must not already exist. Tool/environment pinning, license
review and release-day vulnerability gates are defined in
[FIRMWARE_SBOM_RELEASE_RUNBOOK.md](FIRMWARE_SBOM_RELEASE_RUNBOOK.md).

Release signing, immutable publication, independent verification, key rotation,
health confirmation, and rollback procedures are in
[OTA_RELEASE_RUNBOOK.md](OTA_RELEASE_RUNBOOK.md).

See [XIAOZHI_INTEGRATION.md](XIAOZHI_INTEGRATION.md) for the exact pinned-source
hook points. Hardware measurements remain required before the BOX-3 audio path
can be accepted for release.

## Implemented integration seam

XiaoZhi's `type: "stt"` callback is copied by `device_voice_client` and parsed
by `device_voice_runtime`, through `xiaozhi_agent_adapter`; the controller then
invokes the bridge's serialized STT transition. The runtime's `submit_agent`
operation is bound to `esp_claw_runtime_submit()`. Agent responses are copied
back into the same bounded event queue before
`device_voice_runtime_on_agent_final()` runs.

The product voice gateway then accepts a request-correlated message such as:

```json
{
  "type": "tts_request",
  "session_id": "voice:device-id",
  "request_id": 42,
  "text": "Agent response"
}
```

Returned `tts` start/stop/error messages must carry the same `session_id` and
`request_id`. `start` opens the bounded audio generation, `stop` drains it, and
an error or interruption invalidates and flushes it. Messages and already
dequeued packets belonging to an interrupted request are rejected. The
remaining work is executing the six-block factory security plan, per-device
Flash Encryption, encrypted-NVS round trip, and anti-rollback denial on
controlled hardware,
deploying the implemented authenticated-time and Agent-token endpoints with
production certificates and secrets, qualifying primary and backup speech
adapters against the M25/M27/M28 contract, codec and hardware runbooks, live model-provider validation,
live multi-replica coordination and cross-region convergence, managed HA/WORM generation deployment, immutable
CDN token enforcement, security/fleet gates, and on-device validation. The
firmware inventory gate is present, but release-day vulnerability and legal
disposition remain mandatory. The
station lifecycle, secure onboarding transport, credential-at-rest
implementation, signed installer, and reference fleet offer boundary are now
present; factory/eFuse execution and physical Wi-Fi/onboarding/storage/OTA
testing remain.
This is not a ground-up rewrite of either upstream project.
