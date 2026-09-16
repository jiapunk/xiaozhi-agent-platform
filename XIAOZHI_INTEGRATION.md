# XiaoZhi Integration Guide

This guide targets the XiaoZhi revision pinned in `upstream.lock.json`:
`18a60b8051f5ee6a25beed6248ed84c7fcc742bf`.

The intended integration copies selected XiaoZhi voice, audio, codec, board,
and protocol pieces into the product-owned application. It does not turn the
XiaoZhi repository into the top-level product application and does not start a
second Wi-Fi, audio, display, filesystem, or lifecycle manager.

M9's preferred path is now executable in this repository: use
`box3_agent_supervisor` as the long-lived owner and `box3_agent_voice` as its
per-credential BOX-3 composition root. Together they own credential expiry,
reconnect, secure WSS, audio, and the serialized runtime, so they do not patch
or instantiate XiaoZhi's `Application` or `WebsocketProtocol`. The hook-point
instructions below remain an alternative for a product that must embed this
feature inside the original XiaoZhi application.

## Required gateway change comes first

The pinned XiaoZhi protocol already emits final `type: "stt"` events, but its
TTS lifecycle has no `request_id` and it has no `tts_request` message. Deploy a
gateway version that implements `VOICE_AGENT_PROTOCOL.md` before enabling the
firmware feature flag. The client hello/server hello negotiation keeps mixed
fleet rollout fail-closed.

Use WebSocket for the M1 Agent vertical slice. Do not enable the MQTT plus UDP
path for Agent TTS until audio-frame correlation and reordering behavior are
specified and tested.

## Ownership boundary

The product application owns:

- one serialized event loop and the overall device state machine;
- one audio capture/playback pipeline;
- Wi-Fi provisioning and reconnect policy;
- NVS initialization and production credential-at-rest policy;
- device identity, short-lived gateway credentials, OTA, and diagnostics;
- the ESP-Claw runtime and the Capability allowlist;
- `agent_bridge`, `voice_agent_controller`, `device_voice_runtime`, binary
  framing/generation policy, and protocol policy.

Selectively adapted XiaoZhi modules provide the proven BOX-3 board/codec setup,
audio behavior, and protocol semantics. Future wake-word or UI reuse must
expose narrow product interfaces rather than reach into a second global
application lifecycle. M5's WebSocket transport is product-owned and does not
import XiaoZhi's network lifecycle.

## Product-owned Wi-Fi path

Do not instantiate the pinned XiaoZhi `WifiBoard` or a second
`WifiManager`. M11 supplies `product_wifi`, which directly uses the official
ESP-IDF driver and owns station persistence, reconnect policy, and serialized
Wi-Fi/IP events. It never erases the shared NVS partition and never opens a
configuration AP automatically. M12 adds `product_provisioning` above that
single owner; it does not instantiate Espressif's full provisioning manager.

M13 supplies `product_storage` as the sole NVS initialization owner. Initialize
it before creating identity, Wi-Fi, provisioning, or Agent objects:

```c
ESP_ERROR_CHECK(product_storage_initialize());
```

In development this emits a plaintext warning. A production build made with
`sdkconfig.secure-storage.defaults` instead requires the already-provisioned,
fully protected slot 4 HMAC_UP key, derives XTS-AES keys, and secure-initializes
the credential `nvs` partition. It never generates or burns the key. Missing,
wrong-purpose, shared, or incompletely protected key state stops startup; do
not add an erase, fallback, or retry-to-plaintext path.

M14 supplies `product_ota` as the sole signed firmware-update boundary. It
accepts a strict P-256 manifest only for the compiled project/board/channel,
newer release sequence, nondecreasing secure version, authenticated time, and
exact HTTPS authority. It verifies Content-Length, the incoming app descriptor,
full byte count, and image SHA-256 before selecting the passive A/B slot. Do not
add another XiaoZhi updater, redirect-following download path, URL token, or
automatic first-boot confirmation. Production release operation is defined in
`OTA_RELEASE_RUNBOOK.md`.

M15 adds `product_ota_client` as the fleet-decision adapter above that same
installer. It signs the compiled board/channel/current-sequence/version in an
independent OTA proof domain, accepts only an exact HTTPS `/v1/ota/offer`
endpoint, strictly bounds the response, and calls `product_ota_check_manifest`
before returning an available offer. It does not install, reboot, or confirm an
image automatically.

M16 through M19 close the reference release path without adding another firmware
owner. `firmwareorigin` serves only exact, rehashed objects authorized by the
M15 OTA token. The deployment-bundle tooling derives the control registry and
origin catalog together from the signed M14 release artifacts, emits a
digest-bound read-only generation, and keeps every new release disabled at
zero rollout. A cohort can be enabled, expanded, stopped, or resumed only by a
new parent-linked generation carrying two distinct Ed25519 operator approvals
anchored in an external keyring. Neither service nor tool changes the
device-side XiaoZhi/ESP-Claw ownership boundary. M19 adds only the server-side
durable active-generation CAS, prepared/active replica acknowledgements, lease
drain fence, and fail-closed control/origin guard. It does not add an ESP task,
protocol field, partition, or firmware owner. Do not hand-author the two
catalogs, edit a verified bundle in place, or bypass the generation coordinator;
follow `OTA_RELEASE_RUNBOOK.md`.

Create it after identity and authenticated-time clients are ready. The caller
owns persistent manifest/token buffers of at least 8193 and 2049 bytes; place
them in PSRAM for the first SKU and never put the token in NVS or logs:

```c
product_ota_client_config_t fleet_config = {
    .offer_endpoint = "https://control.example/v1/ota/offer",
    .device_id = provisioned_device_id,
    .client_id = boot_client_id,
    .use_crt_bundle = true,
    .network_timeout_ms = 10000,
    .sign_ota_proof = agent_device_identity_sign_ota_offer_proof,
    .sign_ctx = identity,
    .get_authenticated_time =
        agent_control_plane_client_get_or_sync_unix_time,
    .time_ctx = control_client,
};

product_ota_client_handle_t fleet_client = NULL;
ESP_ERROR_CHECK(product_ota_client_create(&fleet_config, &fleet_client));

product_ota_offer_t offer = {
    .manifest = product_psram_manifest_buffer,
    .manifest_capacity = product_psram_manifest_capacity,
    .download_token = product_psram_token_buffer,
    .download_token_capacity = product_psram_token_capacity,
};
ESP_ERROR_CHECK(product_ota_client_fetch_offer(
    fleet_client, &ota_config, &offer));
if (offer.status == PRODUCT_OTA_FLEET_AVAILABLE) {
    ESP_ERROR_CHECK(product_ota_install(
        &ota_config, offer.manifest, offer.manifest_size,
        offer.download_token));
}
product_ota_client_clear_offer(&offer);
```

Fetch only after usable IP and product-authenticated time are available. Treat
`deferred` and `up_to_date` as normal policy results and honor the returned
retry interval. Destroy `fleet_client` before the authenticated-time client and
identity. Ordinary build profiles keep live startup disabled. The M22
`box3_product_runtime` starts the complete path only when a BOX-3 release
profile supplies reviewed public service authorities and the factory identity
slot; it never opens onboarding automatically. M23 adds the aggregate-owned
BOX-3 GPIO0 active-low local-action path. M39 classifies only on release:
3–<10 seconds issues the one-use open command, while >=10 seconds first commits
a resumable local-reset journal and then restarts.

M16 adds the separate `firmwareorigin` service at the manifest's exact image
authority. `product_ota_config_t.allowed_image_authority` must equal that
authority byte-for-byte. The device sends the M15 token only in the
Authorization header; it never sends the token to the control-plane URL as an
image credential, follows no redirect, requests no Range, and still performs
the complete M14 descriptor/size/hash verification. The origin has no XiaoZhi
or ESP-Claw dependency and must remain outside the firmware lifecycle.

## Preferred product composition root

Use `box3_product_runtime_start()` as the lifecycle owner for an actual BOX-3
product build. The product supplies the exact registry device ID, per-boot
client ID, control/Agent-proxy authorities, identity eFuse slot, and static
Agent/voice template. The aggregate creates identity, control client,
credential client, supervisor, approximate-time bootstrap, Wi-Fi, and
provisioning, then the sole local-action owner in dependency order; it unwinds
in strict reverse order and retains a timed-out child for an exact stop retry.

The reference `app_main` derives `xz-<lowercase-base-mac>` and a random
`boot-<16-hex>` client ID. It enables this composition only with
`CONFIG_PRODUCT_LIVE_RUNTIME_ENABLE=y`. Exact configuration and release gates
are in `PRODUCT_RUNTIME_RUNBOOK.md`.

The lower-level supervisor/Wi-Fi wiring below remains useful for a new board
port or focused component test. Do not start it alongside the aggregate.

Create and start the Agent supervisor first; it remains in `WAIT_NETWORK`.
Then use the supplied callback adapter when creating Wi-Fi:

```c
product_wifi_handle_t product_wifi = NULL;
product_wifi_config_t wifi_config = {
    .hostname = "agent-box-1234",
    .event = box3_agent_supervisor_product_wifi_event,
    .event_ctx = supervisor,
    .minimum_backoff_ms = 2000,
    .maximum_backoff_ms = 5 * 60 * 1000,
    .authentication_failure_limit = 3,
};
ESP_ERROR_CHECK(product_wifi_create(&wifi_config, &product_wifi));
ESP_ERROR_CHECK(product_wifi_start(product_wifi));
```

Create the onboarding service after the protected device identity shown later
in this guide. The callback named below is product code: it must atomically
claim a recent SKU-approved long press (recommended minimum three seconds),
not merely report that a GPIO is presently high.

```c
product_provisioning_handle_t provisioning = NULL;
product_provisioning_config_t provisioning_config = {
    .wifi = product_wifi,
    .physical_presence = product_claim_recent_long_press,
    .physical_presence_ctx = button_owner,
    .derive_ap_key = agent_device_identity_derive_onboarding_ap_key,
    .derive_ap_key_ctx = identity,
    .device_id = provisioned_device_id,
    .publish_claim = agent_control_plane_client_confirm_device_claim,
    .publish_claim_ctx = control_client,
    .event = product_onboarding_event,
    .event_ctx = ui_owner,
    /* Zero selects: 5-minute window, 5 security failures,
       500 ms candidate delay, and 5-second success grace. */
};
ESP_ERROR_CHECK(product_provisioning_create(
    &provisioning_config, &provisioning));

/* Call only from the product UX owner after the approved local action. */
ESP_ERROR_CHECK(product_provisioning_open(provisioning));
```

M12/M33 opens a one-client WPA2 SoftAP and serves the official `proto-ver`,
Security-2 `prov-session`, `prov-config`, plus product-owned encrypted
`xz-claim` endpoint. Wi-Fi apply is rejected until the current claim has been
read; successful onboarding is withheld until the device-authenticated control
plane returns `bound`. It does not
provide a captive portal or `prov-scan`; the product phone app must accept a
manual SSID or use the phone operating system's scan. A wrong candidate is
wiped without replacing the prior working credentials. Five security failures
lock the default session, five minutes closes it, and another verified local
action is required to reopen it.

At shutdown, stop the local-action owner before closing/destroying provisioning,
then stop Wi-Fi and the approximate-time bootstrap before consuming the
supervisor handle. Then stop the supervisor and destroy the credential,
control-plane, and identity clients in their documented order. The development
build stores the
accepted home-network credential blob without NVS-layer encryption and emits a
warning. Release candidates must use the M13 secure-storage build, frozen SKU
eFuse allocation, separate NVS/identity slots, and v2 factory receipt. Actual
key injection and an encrypted-NVS reboot round trip remain release gates.

## Alternative: exact hook points in the pinned XiaoZhi application

### 1. Advertise the Agent feature

In `main/protocols/websocket_protocol.cc`, `WebsocketProtocol::GetHelloMessage()`
creates `root`, creates `features`, adds `mcp`, and attaches `features` to
`root`. Immediately after that attachment and before JSON serialization, call:

```cpp
if (xiaozhi_agent_adapter_add_client_hello_feature(root) != AGENT_BRIDGE_OK) {
    // Log a metadata-only error and leave Agent mode disabled.
}
```

Keep the equivalent hook in `MqttProtocol::GetHelloMessage()` behind the future
MQTT/UDP Agent-mode feature flag so both transports cannot accidentally claim
support before UDP audio correlation exists.

### 2. Validate the server hello before declaring the channel ready

In `WebsocketProtocol::ParseServerHello()`, validate the acknowledgement before
`xEventGroupSetBits(..., WEBSOCKET_PROTOCOL_SERVER_HELLO_EVENT)`. Store an
`agent_protocol_ready_` boolean on the protocol object; do not make a malformed
Agent acknowledgement look like full Agent readiness.

The transport may still open in legacy voice mode if product policy permits,
but the Agent controller must remain disabled. Do not overload XiaoZhi's normal
server-hello event bit with Agent feature state.

Apply the same rule to `MqttProtocol::ParseServerHello()` only when that
transport is later supported.

### 3. Add a narrow outbound API

`Protocol::SendText()` is protected in `main/protocols/protocol.h`. Add a public,
purpose-specific method such as:

```cpp
bool Protocol::SendAgentControl(const char* json, size_t length);
```

It should reject null/empty/oversized payloads, require negotiated Agent mode,
and synchronously copy or consume the buffer before returning. Its only initial
message types are `tts_request` and `tts_abort`. Avoid exposing an unrestricted
raw-send method to unrelated components.

Wire `voice_agent_controller_ops_t::send_json` to this method. The controller's
TX scratch buffer is caller-owned and may be overwritten immediately after the
send callback returns.

### 4. Route incoming STT and TTS on the owner event loop

The pinned `Application::OnIncomingJson` callback receives a `cJSON*` that both
WebSocket and MQTT delete as soon as the callback returns. Never capture that
pointer in `Application::Schedule()`.

For `stt`, copy `session_id` and `text` into bounded product-owned values inside
the callback, then schedule a typed event. On the application event loop, call
`voice_agent_controller_on_stt_final()` or rebuild a small cJSON object and call
`xiaozhi_agent_adapter_handle_json()`.

For TTS `start`, `stop`, and `error`, copy and validate `state`, `session_id`,
and the numeric `request_id`, then schedule the typed event. Invoke the adapter
using `protocol_->session_id()` as the authoritative connection session.

Keep `sentence_start` available to the existing display handler. Before product
release, gate its UI update on the copied `request_id` matching
`voice_agent_controller_active_request_id()` so a stale caption cannot replace
the active one.

### 5. Marshal ESP-Claw callbacks back to the same event loop

The ESP-Claw completion callback may run on an Agent or network task. Copy its
final text and `request_id`, then post them to `Application::Schedule()`. Only
the scheduled handler may call:

```c
voice_agent_controller_on_agent_final(controller, request_id, text);
```

Map Agent failure/cancellation to
`voice_agent_controller_on_agent_error()`. Never call the controller
concurrently from an audio, transport, timer, and Agent task.

### 6. Connect interruption sources

Route the following through the serialized event loop:

| Source | Controller reason | Required local action |
| --- | --- | --- |
| Wake-word/new STT during output | `USER_BARGE_IN` | Stop decoder and flush queue |
| Physical stop button | `BUTTON` | Stop decoder and flush queue |
| Transport disconnect | `NETWORK_LOST` | Close session and flush queue |
| Server goodbye/user logout | `SESSION_CLOSED` | Close session and flush queue |

A new final STT already causes the controller to abort old TTS before submitting
the next Agent request. Do not send a duplicate abort from a second state
machine.

### 7. Bind the product-owned runtime and BOX-3 stream

For the low-level product-owned path, use the implemented aggregate rather than
recreating its callback graph in application code:

```c
box3_agent_voice_config_t config = {
    .websocket = {
        .uri = provisioned_wss_uri,
        .bearer_token = short_lived_device_token,
        .device_id = provisioned_device_id,
        .client_id = boot_client_id,
        .protocol_version = 3,
        .use_crt_bundle = true,
        .network_timeout_ms = 10000,
        .send_timeout_ms = 500,
        .ping_interval_seconds = 15,
        .pong_timeout_seconds = 15,
    },
    .agent = provisioned_agent_config,
    .output_volume_percent = 70,
    .hello_timeout_ms = 5000,
};

box3_agent_voice_handle_t product = NULL;
esp_err_t result = box3_agent_voice_create(&config, &product);
if (result != ESP_OK) {
    if (product) {
        (void)box3_agent_voice_stop(product, 5000);
    }
    return result;
}
result = box3_agent_voice_start(product);
if (result != ESP_OK) {
    (void)box3_agent_voice_stop(product, 5000);
    return result;
}
```

The aggregate supplies and owns these bindings:

| Runtime operation | Product target |
| --- | --- |
| `submit_agent` | `esp_claw_runtime_submit()` |
| `cancel_agent` | `esp_claw_runtime_cancel()` |
| `send_json` | `device_websocket_transport_send_text()` |
| `receive_binary` | `box3_voice_audio_push_binary()` |
| `playback_event` | forward to `box3_voice_audio_playback_event(audio_stream, ...)` |
| stream `send_binary` | `device_voice_client_send_audio()` |
| Agent final/error | copied into the serialized device voice queue |
| capture ready/not-ready | start/stop the BOX-3 capture worker |

`create` validates and creates an unstarted WSS client before it touches board
hardware, then creates the HAL, stream, and Agent runtime. `start` opens WSS;
capture begins only after TLS, authentication, and strict server-hello
negotiation succeed. Call `box3_agent_voice_stop(product, timeout_ms)` from an
owner task, never from a callback. `ESP_OK` consumes the handle; on failure,
retain it and retry because a worker and its callback context may still be
live.

Automatic socket reconnect is deliberately disabled. After disconnect or
credential expiry, use the implemented `box3_agent_supervisor`; it stops this
aggregate, obtains fresh credentials, and creates/starts a new one. The
process-global ESP-Claw Capability registry supports this sequential
recreation without rebooting.

Product capability visibility is rebuilt from a closed bitmask on each
recreation. `product_device_read` and `product_device_action` are separate;
visibility does not grant execution. Each callback rechecks root-Agent,
request/session, exact input, enabled policy and its real adapter. Actions also
consume trusted one-use consent, while every device and memory result emits a
metadata-only audit decision. The BOX-3 development Live compile composition
also binds `device.set_indicator` to the product-owned GPIO 47 display
backlight adapter; production-security keeps it disabled until external
release gates pass. Neither profile imports ESP-Claw filesystem memory, MCP,
Lua, shell or arbitrary HTTP surfaces. See
`AGENT_CAPABILITY_SECURITY_RUNBOOK.md`.

The imported ESP-Claw commit also receives one SHA-256-locked product privacy
patch during `sync_upstreams.sh`. It removes response/tool/reasoning snippets
from logs, discards provider error bodies and rejects full request logging.
Live builds require simple stage mode and the product callback retains only
saturating counters, so changing ESP-Claw revisions requires the patch to apply
cleanly plus the content-privacy policy gate. See
`AGENT_CONTENT_PRIVACY_OBSERVABILITY_RUNBOOK.md`.

The supervisor's static `product` template deliberately leaves
`websocket.uri`, `websocket.bearer_token`, and `agent.api_key` unset. Its
injected `refresh_credentials` callback fills one bounded
`box3_agent_credentials_t` with a voice WSS URI/token/TTL and a distinct Agent
token/TTL. The callback must use bounded HTTPS timeouts and must not log those
fields. On IP loss, call `set_network_available(..., false)`. The supervisor disables
readiness, destroys the complete callback graph from the owner task, discards
the old credentials, and waits. On disconnect, expiry margin, or startup
failure it uses bounded exponential backoff with jitter, fetches both fresh
tokens, and recreates the aggregate. Voice and Agent credentials are separate
audiences and must never be substituted for one another.

Use `agent_device_identity` as the protected signer/time guard,
`agent_control_plane_client` for authenticated time and Agent-token issuance,
and `box3_agent_credentials_client` as the supervisor callback adapter. The
identity component never writes eFuse and refuses to start unless the selected
HMAC_UP key is read-, write-, and purpose-protected. Its four signer callbacks
accept only the exact session-proof, Agent-token-proof, or OTA-offer-proof
domain. The Agent
client obtains a short-lived product-proxy token; it never receives a model
provider master key. Returning the voice token is rejected.

```c
agent_device_identity_handle_t identity = NULL;
agent_device_identity_config_t identity_config = {
    .device_id = provisioned_device_id,
    .hmac_key_id = product_hmac_key_slot,
    .maximum_time_age_seconds = 24 * 60 * 60,
};
ESP_ERROR_CHECK(agent_device_identity_create(&identity_config, &identity));

agent_control_plane_client_handle_t control_client = NULL;
agent_control_plane_client_config_t control_config = {
    .time_endpoint = "https://control.example/v1/time",
    .agent_token_endpoint = "https://control.example/v1/agent-token",
    .device_claim_endpoint =
        "https://control.example/v1/device-claim/device",
    .device_id = provisioned_device_id,
    .client_id = boot_client_id,
    .use_crt_bundle = true,
    .network_timeout_ms = 10000,
    .sign_agent_proof = agent_device_identity_sign_agent_token_proof,
    .sign_device_claim_proof =
        agent_device_identity_sign_device_claim_proof,
    .sign_ctx = identity,
    .get_unix_time = agent_device_identity_get_unix_time,
    .time_ctx = identity,
    .accept_authenticated_time =
        agent_device_identity_accept_authenticated_time_callback,
    .accept_time_ctx = identity,
};
ESP_ERROR_CHECK(agent_control_plane_client_create(
    &control_config, &control_client));

box3_agent_credentials_client_handle_t credential_client = NULL;
box3_agent_credentials_client_config_t credential_config = {
    .session_endpoint = "https://control.example/v1/session",
    .device_id = provisioned_device_id,
    .client_id = boot_client_id,
    .use_crt_bundle = true,
    .network_timeout_ms = 10000,
    .sign_proof = agent_device_identity_sign_proof,
    .sign_ctx = identity,
    /* Fresh guarded time is returned locally; stale time is synchronized once. */
    .get_unix_time = agent_control_plane_client_get_or_sync_unix_time,
    .time_ctx = control_client,
    .refresh_agent_token =
        agent_control_plane_client_refresh_agent_token,
    .agent_ctx = control_client,
};
ESP_ERROR_CHECK(box3_agent_credentials_client_create(
    &credential_config, &credential_client));

box3_agent_supervisor_config_t supervisor_config = {
    .product = static_product_template,
    .refresh_credentials = box3_agent_credentials_client_refresh,
    .credential_ctx = credential_client,
};

box3_agent_supervisor_handle_t supervisor = NULL;
ESP_ERROR_CHECK(box3_agent_supervisor_create(&supervisor_config,
                                              &supervisor));
ESP_ERROR_CHECK(box3_agent_supervisor_start(supervisor));

/* product_wifi forwards usable-IP changes through the callback adapter. */
```

Configure the supervisor's static Agent template for the product proxy, not
the provider endpoint. The pinned ESP-Claw OpenAI-compatible backend appends
`/chat/completions`, so the base URL ends at the exact `/v1` prefix:

```c
esp_claw_runtime_config_t product_agent_template = {
    .api_key = NULL, /* supplied per session by the supervisor */
    .backend_type = "openai-compatible",
    .model = "product-agent",
    .base_url = "https://agent.example/v1",
    .auth_type = "bearer",
    .max_tokens_field = "max_completion_tokens",
    .system_prompt = product_system_prompt,
    .timeout_ms = 35000,
    .max_tokens = 1024,
    .max_tool_iterations = 4,
    .device_ops = product_device_ops,
};
static_product_template.agent = product_agent_template;
```

The time and Agent-token endpoints must share one HTTPS authority and one
verified certificate policy; the product configuration should place the
session endpoint on that control-plane authority as shown above. `/v1/time` is
bound to a fresh 16-byte nonce plus the exact device/client identifiers before
the guarded clock accepts it. This solves the proof timestamp bootstrap; a raw
SNTP sample may help certificate-time availability but is not accepted as
product-authenticated time.

At shutdown, first stop any OTA lifecycle and destroy `product_ota_client`,
then call `box3_product_runtime_stop()` until it consumes the aggregate handle.
The aggregate stops local input, closes provisioning, stops Wi-Fi and
approximate-time bootstrap, consumes the supervisor, and destroys
credential/control/identity clients in the only safe order. A custom board
owner using the lower-level path must preserve that order and must not destroy
either client while a refresh callback is running.

## Recommended typed integration flow

```text
ESP WebSocket callback
  -> strict frame reassembly and bounded byte copy
  -> device_voice_client bounded event queue and strict JSON parse
  -> device_voice_runtime / xiaozhi_agent_adapter / voice_agent_controller
  -> ESP-Claw submit
  -> copy completion
  -> product event queue
  -> device_voice_runtime_on_agent_final
  -> Protocol::SendAgentControl(tts_request)
  -> correlated TTS lifecycle
  -> BEGIN / DRAIN / FLUSH generation gate
  -> bounded Opus decode + PCM playback
```

The implemented policy rejects the newest control event and fail-closes the
connection; binary overflow drops a bounded frame and increments a metric. No
network, audio, or Agent callback blocks indefinitely on the serialized queue.

## Build integration

1. Keep `agent_bridge`, `agent_device_identity`, `product_storage`, `product_ota`,
   `product_ota_client`, `product_wifi`,
   `product_provisioning`, `product_local_action`,
   `agent_control_plane_client`, `voice_agent_controller`,
   `xiaozhi_agent_adapter`,
   `device_voice_runtime`, `device_voice_client`,
   `device_websocket_transport`, `voice_audio_protocol`,
   `voice_audio_session`, `box3_agent_voice`, `box3_agent_supervisor`,
   `box3_agent_credentials_client`, and the selected board stream as
   product-owned ESP-IDF components.
2. Import only the selected XiaoZhi components and their explicit dependencies.
3. Retain ESP-IDF minimal-build mode and inspect every new component pulled into
   the link map.
4. Use the 32 MiB A/B partition baseline during development, but treat this as
   a module/SKU decision rather than a universal ESP32 requirement.
5. Compile XiaoZhi C++ callers against the C headers through their existing
   `extern "C"` guards.

## M1 hardware acceptance checklist

- button or wake -> STT final -> ESP-Claw -> correlated TTS works for 100 turns;
- barge-in stops audible output within the chosen product latency budget and no
  stale audio/caption resumes;
- disconnect/reconnect invalidates the old session and recovers without reboot;
- unprovisioned boot never opens a portal without a physical-presence action;
- wrong-password lockout, malformed Security-2 session, AP loss, DHCP loss,
  router reboot, credential replacement, and onboarding teardown match the
  M12 state contract;
- production image fails closed for absent/wrong/shared HMAC slots, then passes
  the M13 encrypted-NVS write/reboot/read check with distinct protected slots;
- signed OTA accepts only the intended immutable image, rejects tampered,
  expired, wrong-board/channel/authority and redirect cases, survives power
  loss, confirms only after every live health gate, and rolls back on reset or
  explicit fatal health;
- 8-hour mixed speech/tool soak has no task-stack overflow, heap trend, decoder
  deadlock, watchdog reset, or thermal violation;
- record internal heap/PSRAM minima, fragmentation, task stack high-water marks,
  first-token latency, first-audio latency, and full-turn latency;
- pass `tools/check_memory_budget.py`, compare per-component link maps against
  `M0_BUILD_REPORT.md`, and record runtime internal/DMA heap minima;
- confirm production logs contain no transcript, token, credential, or sensitive
  tool argument unless an explicit diagnostic consent mode is active.

Passing host tests and compiling the adapter are necessary but do not satisfy
this hardware gate.

The current code now supplies the bounded PCM/Opus path, secure ESP WSS transport,
serialized runtime, BOX-3 composition root, session supervisor, strict ESP
HTTPS credential adapter, same-authority authenticated time/Agent-token client,
protected eFuse signer, guarded time, product Agent proxy, independent control
plane, v2 factory receipt verifier, real product-owned Wi-Fi station lifecycle,
physical-presence-gated SoftAP/Security-2 onboarding transport, and
release-before-arm BOX-3 local-action owner, factory-keyed credential NVS path,
signed A/B OTA, explicit first-boot
health/rollback APIs, the authenticated fleet offer/token boundary, and an
independently deployable object-bound firmware origin. The
checklist remains mandatory because
this graph has not been exercised on a provisioned physical BOX-3 or over live
HTTPS/WSS/provider paths.
