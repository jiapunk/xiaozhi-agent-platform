# M21 bounded product Agent memory report

> Lifecycle update: M38 supersedes the historical XAM1 storage contract below
> with owner-binding-aware XAM2. Valid XAM1 is now migrated to locked and empty;
> unscoped values are never inherited by a later owner.

## Result

M21 adds the first product-owned persistent Agent state without enabling
ESP-Claw's broad filesystem memory or storing voice transcripts. The ESP32
firmware now has a bounded, versioned, dual-slot NVS memory component and four
selective ESP-Claw capabilities. Reads are exact and root-Agent-only. Writes
and deletes require product UI consent bound to one request, one session, and
one operation.

This is a firmware/software gate, not a market-release declaration. The host
power-loss model and four ESP-IDF builds pass. Physical power cuts, encrypted-
NVS round trips on provisioned devices, factory reset, companion App consent
UX, provider behavior, long-run flash wear, and fleet validation remain open.

## Architecture decision

The pinned ESP-Claw source contains `claw_memory` and `claw_skill`, but its
memory module expects filesystem roots and includes session/profile/long-term
providers plus optional LLM extraction. The product's FAT partitions do not
yet have a security owner and are not the encrypted credential partition.
M21 therefore does not import `claw_memory` and does not mount a memory
filesystem.

Instead, `product_agent_memory` owns one namespace inside the `nvs` partition
already initialized by `product_storage`. This preserves the architectural
rule established at the start of the project: the product shell owns security,
storage, consent, and lifecycle; ESP-Claw supplies the Agent loop and
capability interface.

## Data contract

The store contains at most 8 items. A key is 1–32 restricted lowercase ASCII
bytes, and a value is 1–160 bytes of single-line valid UTF-8. Only `profile`
and `preference` categories exist. Obvious credential, authentication, health,
biometric, payment, contact, and location labels are rejected, as are obvious
secret patterns in values.

This filter is deliberately described as a backstop rather than DLP. The fixed
ESP-Claw memory policy says that every saved value is untrusted user data and
cannot override system/security/product policy. No saved value is automatically
inserted into the prompt; the Agent must call `memory.get` for an exact key.
No code path persists user text, assistant output, tool history, or audio.

The full operating and deletion rules are in
`AGENT_MEMORY_DATA_POLICY.md`.

## Consent and capability boundary

The LLM-visible group is `product_memory`:

| Capability | Data returned/changed | Additional enforcement |
| --- | --- | --- |
| `memory.list` | key/category/revision only | manual root-caller check |
| `memory.get` | one exact value, marked untrusted | manual root-caller check |
| `memory.put` | one profile/preference | root check plus one-use PUT grant |
| `memory.forget` | one exact key | root check plus one-use FORGET grant |

The mutation grant table has four entries, matching ESP-Claw's request queue.
The product callback is invoked before submit and must consult trusted App or
physical-UI state; firmware never treats the user utterance as proof. The
grant copies and binds request ID and a session ID of at most 64 bytes. PUT and
FORGET bits are separately consumed. Duplicate request IDs, wrong sessions,
queue overflow, repeated use, and unknown flags fail closed. Submission
failure, cancellation, final response, and runtime stop revoke grants.

The upstream `RESTRICTED` flag is not used as an authorization boundary. Every
memory tool is marked `ROOT_AGENT_ONLY`, and the adapter repeats the caller
check itself. `memory.clear` is not exposed to the LLM; logical bulk clear is a
trusted product/App API.

## Storage format and interrupted-write behavior

`XAM1` schema 1 uses explicit little-endian encoding rather than a raw C
structure. The header contains magic, schema, count, generation, payload
length, reserved-zero fields, and CRC-32. Items contain category, exact key and
value lengths, revision, and bytes. Decode requires exact total length,
strictly sorted unique keys, allowed categories/content, revision not newer
than generation, valid checksum, and no trailing data.

Two NVS keys, `slot0` and `slot1`, normally contain identical current bytes.
For generation N, the implementation commits slot `N & 1` first. Only after a
successful primary commit does RAM advance; it then commits the same snapshot
to the other slot. If power fails before the primary commit, the old snapshot
remains authoritative. If it fails between commits, startup selects the valid
higher generation and reports degraded redundancy. Equal generations with
different bytes fail closed. A future successful mutation restores both slots.

CRC is corruption evidence, not keyed adversarial integrity. This does not
become an authorization weakness because all memory values remain untrusted.
Production confidentiality depends on the M13 encrypted-NVS profile. Logical
forget/clear does not claim physical or cryptographic erasure from wear-levelled
flash.

The component caps successful mutations at 128 per boot and does not write a
repair automatically at startup. Snapshot and encode buffers are dynamically
allocated; canonical decode avoids a redundant 2 KiB stack buffer so opening
from the 8 KiB main task remains bounded.

## Lifecycle integration

`app_main` opens Agent memory only after `product_storage_initialize()`. A
memory open failure logs and leaves memory disabled, preserving OTA/recovery
paths. The product shell retains ownership of the handle. BOX-3 supervisor and
voice aggregates copy the configuration but not the handle or callback
contexts; their documented lifetimes must cover the runtime.

ESP-Claw registers `product_memory` only when a memory handle is configured,
adds its fixed policy context provider, and includes the group in the root
Agent's visible catalog. Stop ordering first drains the core/response task,
then clears grants and releases synchronization objects.

## Host and negative evidence

Two new C host suites cover:

- allowed/blocked keys, secret-pattern rejection, single-line UTF-8, overlong
  and malformed UTF-8;
- sorted insertion, exact find, update revision, forget, clear, capacity, and
  generation exhaustion;
- deterministic encode/decode, CRC tamper, truncated blob, and invalid
  canonical revision;
- empty startup, identical mirrors, one corrupt slot, old/new generation
  selection, and equal-generation divergent snapshot rejection;
- consent issue/consume/revoke, request and session mismatch, operation
  separation, duplicate ID, table capacity, replacement, overlong session,
  and secure clear.

Six Python policy tests pin the bounded constants, product NVS ownership,
absence of upstream filesystem memory, request/session/root checks, absence of
LLM bulk clear or automatic context persistence, and production encryption
profile.

The final complete local regression passed 20 C host suites, 7 gateway-contract
tests, 11 factory tests, 60 tooling tests, 5 independent generation-state
tests, every Go package test, and `go vet ./...` using the pinned Go 1.26.5.

These tests model a power loss by presenting old/new/corrupt committed slot
images. They are not evidence of actual brownout timing, NVS behavior under a
cut, or flash endurance on hardware.

## Firmware evidence

All four ESP-IDF 6.0.2 profiles compile and link after M21. Each still passes
the 192 KiB minimum static internal-memory headroom gate.

| Profile | Firmware `.bin` bytes | Static internal memory | Headroom |
| --- | ---: | ---: | ---: |
| Generic development | 1,078,560 | 118,992 / 358,144 | 239,152 |
| BOX-3 development | 1,370,016 | 120,800 / 358,144 | 237,344 |
| Generic secure storage | 1,087,920 | 119,376 / 358,144 | 238,768 |
| BOX-3 secure storage | 1,378,784 | 121,168 / 358,144 | 236,976 |

The generic development build adds 8,736 bytes and the BOX-3 development build
adds 9,232 bytes versus M15. Secure builds add 8,912 and 9,200 bytes. The
small static changes come from ownership/status state; the bounded snapshots,
grant table, and mutation buffers are allocated only when their lifecycle is
active.

## Implemented artifacts

- `components/product_agent_memory`: public store, canonical core, dual-slot
  NVS persistence, mutation budget, stats, and logical clear;
- `components/esp_claw_runtime/esp_claw_memory_grant_core.c`: bounded one-use
  authorization table;
- ESP-Claw `product_memory` adapter and fixed untrusted-data policy provider;
- host recovery/format/grant tests and static product-policy tests;
- `AGENT_MEMORY_DATA_POLICY.md`, this report, README, and product blueprint
  updates.

## Gates still open

1. Execute encrypted-NVS put/get/forget/clear/reboot tests on correctly
   provisioned Generic and BOX-3 hardware.
2. Perform repeatable power cuts before primary commit and between primary and
   mirror commits; verify newest-valid selection and no boot loop.
3. Implement and test the App/physical-UI confirmation and complete memory
   management/reset experience, including accessibility and cancellation.
4. Measure heap/task stack, NVS wear, brownout recovery, and 30-day mutation
   soak under audio, Wi-Fi reconnect, Agent, and OTA load.
5. Complete threat/privacy review for the selected market and prohibit cloud
   sync or new categories until separately approved.
6. Finish the existing hardware OTA/rollback, provider, factory, registry/
   Kubernetes, TLS/HA, and 10–30 device alpha-fleet gates.
