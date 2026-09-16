# Go Device Agent Gateway

This directory contains seven independently deployable services:

- `gateway`: the Device Agent Voice Protocol WebSocket data plane;
- `controlplane`: authenticated time plus separate voice/Agent token issuance;
- `agentproxy`: the device-facing OpenAI-compatible Agent boundary;
- `firmwareorigin`: OTA-only, object-bound immutable firmware delivery.
- `generationcoordinator`: durable CAS publication, replica fencing, and
  convergence evidence for approved OTA generations.
- `accountauthorization`: private mTLS Companion-JTI introspection backed by
  the durable account-revision ledger.
- `factorytimeauthority`: TLS 1.3 mTLS factory trusted-time issuance backed by
  PostgreSQL replay state and a separately isolated external Ed25519 signer.

Two additional commands are offline operator tools, not deployable services:
`qualifyspeechadapter` runs M28 candidate STT/TTS qualification and
`validatespeechqualification` independently verifies its signed receipt. They
remain outside the M48 OCI service graph.

The voice gateway is deliberately speech-provider-neutral: private streaming
STT and TTS services sit behind small documented contracts. The Agent proxy is
model-provider-aware only at its outbound configuration boundary; devices see
one stable product model alias and never receive the provider master key.

It is not yet a production release. Transport, authentication, correlation,
limits, cancellation, health, metrics, graceful shutdown, scoped token
issuance, the Agent-proxy policy, a synthetic reference Opus decode gate and a
signed live-adapter qualification runner are implemented and tested. Real
primary/backup STT/TTS provider evidence, ESP/board codec
validation, a live model-provider validation, secrets manager, live
multi-replica coordination evidence, load tests, and a deployment environment
are still required.

## Recommended service boundary

```text
ESP32 -- WSS + voice token --> gateway -- private --> STT/TTS
  |
  +-- HTTPS + eFuse proof --> controlplane
  |                              |-- voice-audience token
  |                              |-- Agent-audience token
  |                              +-- signed fleet OTA offer + OTA token
  |
  +-- HTTPS + Agent token --> agentproxy -- provider key --> model provider
  |
  +-- HTTPS + OTA token --> immutable firmware origin/CDN

controlplane + firmwareorigin -- authenticated short lease --> generationcoordinator

signed-in App -- selected IdP/BFF adapter --> account revision + JTI ledger
controlplane -- private mTLS exact claims --> accountauthorization --> account PostgreSQL

factory station -- direct TLS 1.3 mTLS --> factorytimeauthority
factorytimeauthority -- verify-full TLS --> PostgreSQL replay ledger
factorytimeauthority -- pinned TLS 1.3 mTLS --> external receipt-only signer enforcement
external signer enforcement -- read-only exact row/time --> PostgreSQL replay ledger
external signer enforcement -- fixed receipt payload --> selected HSM/KMS backend
```

Deploy the seven serving commands separately. Voice, Agent, OTA, Companion and
factory trusted-time signing credentials must be different, and only the
corresponding verifier receives each public or verification key. The
gateway's built-in `ENABLE_SESSION_ISSUANCE` mode remains a compatibility tool
for development; disable it when the independent control plane is used.

`accountauthorization` exposes introspection only on its product-CA mTLS port
9444. M49 adds a separate credential-free probe port, default `:9080`, because
Kubernetes native HTTP probes cannot present the control-plane client
certificate. The probe surface accepts only empty `GET /healthz` and
`GET /readyz`; readiness revalidates the PostgreSQL schema, while every other
path/method is 404. Do not put 9080 in the account Service or public ingress;
allow only kubelet and isolated monitoring traffic. See
`../KUBERNETES_DEPLOYMENT_RUNBOOK.md`. M50 additionally produces a signed
deployment-receipt-bound ValidatingAdmissionPolicy bundle that locks the account
Deployment, Service, ServiceAccount, ConfigMap/Secrets, NetworkPolicies and
namespace security labels after apply; see `../KUBERNETES_ADMISSION_RUNBOOK.md`.
M51 adds the exact-cluster live qualification and signed evidence runner, but it
has not been executed because this workspace has no kube-apiserver; see
`../KUBERNETES_ADMISSION_QUALIFICATION_RUNBOOK.md`.

M63's signer-side types are an external trust-zone integration core, not an
eighth command or product OCI workload. They independently pin the authority
client leaf certificate, recheck the committed PostgreSQL receipt before and
after `ReceiptSigningBackend`, and verify the returned Ed25519 signature. A
provider implementation must be released separately and must not add a PEM
private-key fallback. See `../FACTORY_TRUSTED_TIME_SIGNER_RUNBOOK.md`.

M71 adds offline `qualifymtlsdispatch`, deployment-attestation, builder and
validator commands for the controlplane-to-accountauthorization private wake
path. The same runner is embedded as `/service qualify-mtls-dispatch` in the
existing controlplane image so live qualification can use the target Pod's
network namespace and mounted workload identities without an eighth product
workload. Fixture output cannot satisfy `--require-live`; see
`../MTLS_DISPATCH_QUALIFICATION_RUNBOOK.md`.

M72 adds offline `qualifyproviderrevocation`, provider-console attestation,
final builder and independent validator commands. It requires a fresh
active/revoked/active provider sequence, accepts only typed APNs/Google
authentication rejection, binds credential IDs plus SPKI digests, and rebuilds
the complete M69 through M71 evidence chain from a strict public manifest.
Fixture output cannot satisfy `--require-live`; a live receipt would still leave
managed PostgreSQL failover open. See
`../PROVIDER_CREDENTIAL_REVOCATION_RUNBOOK.md`.

M73 adds `qualifydatabasefailover`, `qualifydatabaserestore`, managed-provider
attestation, final builder and independent validator commands for the three
exact durable roles. It uses an append-only idempotent canary ledger to recover
ambiguous commits, requires a real primary node-binding change, reconciles every
acknowledged event, then proves an isolated PITR contains exactly the pre-marker
boundary. A separate provider/WORM authority binds control-plane operation IDs,
backup IDs, encryption and RPO/RTO evidence. Fixture output cannot satisfy
`--require-live`; see `../MANAGED_DATABASE_RESILIENCE_RUNBOOK.md`.

M74 adds `internal/runtimecoordination` and migration
`ownership/0005_runtime_coordination.sql`. Device proof replay/cadence, voice
token replay/ownership/global capacity and Agent rate/inflight/global capacity
are atomic across replicas. Stored identities are domain-separated SHA-256
values and lease IDs fence stale workers. Production Gateway, control plane and
Agent Proxy processes require a unique `RUNTIME_COORDINATION_WORKER_ID` and
verify the shared schema before listening. The offline race/deployment gate is
`../tools/run_runtime_coordination_gate.sh`; live execution and rollout rules
are in `../RUNTIME_COORDINATION_RUNBOOK.md`.

M75 adds `internal/speechidentity`. Production Gateway egress now uses separate
STT and TTS TLS 1.3 mTLS clients with different private CA trust sets, client
leaves and bearer tokens. Proxy, redirect, TLS downgrade and content-level
identity reuse fail closed. The live speech qualification command uses the same
loader and binds all four public certificate digests into its signed receipt.
The signed Kubernetes graph remains exactly seven workloads; see
`../SPEECH_WORKLOAD_IDENTITY_RUNBOOK.md`.

M76 adds `internal/auth` managed HMAC token keyrings. Production Voice, Agent
and OTA tokens now carry an explicit `kid`; verification selects only that key
and bounds old-key issuance, verification and the one-time unkeyed migration.
Canonical private files, external revision floors and material-level domain
separation replace raw production bearer-token keys in environment variables.
See `../MANAGED_TOKEN_KEY_ROTATION_RUNBOOK.md`.

M77 adds `ValidateManagedTokenTransition` and
`cmd/validatemanagedtokenrotation`. Operators can preflight an exact current
issuer/target verifier pair before rollout. Normal rotation must add one new
active key; forward recovery may reactivate only an existing non-legacy
retiring key. Both paths preserve current material, move revisions forward and
cover the future cutover plus TTL/skew. The canonical receipt is explicitly
software-only and contains no key material or file path.

M81 adds `internal/usagebudget` and ownership migration
`0006_agent_usage_budget.sql`. The existing Agent Proxy reserves a conservative
per-subject daily cost before a provider call, verifies exact prompt/completion/
total token usage, commits actual micro-USD cost before returning a response and
records the full reservation as uncertain whenever the provider may have billed
but usage cannot be proved. The ledger uses an isolated HMAC subject digest and
stores no prompt/output/raw product identity. Production requires the PostgreSQL
schema, signed pricing profile and private `usage-digest.key`; see
`../AGENT_USAGE_BUDGET_RUNBOOK.md`.

M82 adds `internal/speechbudget` and ownership migration
`0007_speech_usage_budget.sql`. Gateway reserves content-free per-owned-device
STT audio-ms chunks before upstream writes and TTS Unicode-scalar plus maximum
output-audio cost before synthesis. Exact successful units settle to integer
micro-USD; provider/network/database ambiguity becomes worst-case uncertain
cost. Production requires the signed speech profile, PostgreSQL schema and an
isolated private `speech-usage-digest.key`; see
`../SPEECH_USAGE_BUDGET_RUNBOOK.md`.

Speech budget failures use a content-free device event containing only `type`
and `code`. `speech_budget_exceeded` rejects work before provider contact and
does not count as a protocol violation or force a reconnect;
`speech_budget_unavailable` is a fail-closed transient service failure. The
device runtime stops capture, resets pending TTS and exposes a typed event to
the product UI without receiving price, remaining-budget or identity details.

M83 adds account-scoped commercial service entitlement to the existing
`accountauthorization` workload and account migration
`0004_service_entitlements.sql`. Ordered, idempotent revisions represent
active/grace/suspended/ended access with independent Voice and Agent flags.
Control Plane authorizes through the existing private mTLS listener before
token issuance and bounds token expiry by the entitlement access window. A
denial is HTTP 402; an authorization or database failure is 503. The ESP32
maps 402 to a non-retrying product state. No billing webhook or provider is
claimed; see `../SERVICE_ENTITLEMENT_RUNBOOK.md`.

M84 adds a provider-neutral signed mutation seam without adding a workload.
`POST /v1/service-entitlements/apply` accepts only canonical, minimized
commercial state through verified workload mTLS plus an independent Ed25519
signature. Its authorization window is at most five minutes; the public-key
ring is active/retiring, rollback-fenced and loaded from a private regular
non-symlink file. Freshly re-signing the same business event remains an
idempotent replay because transport timestamps are outside the ledger digest.
No raw billing webhook, receipt or payment instrument is accepted; see
`../SIGNED_ENTITLEMENT_INGESTION_RUNBOOK.md`.

M85 adds a provider-neutral adapter SDK for that mutation seam. Its signer
interface exposes only key ID plus `Sign(context, exactPayload)`, so production
implementations can keep Ed25519 material in an HSM/KMS. Its private mTLS client
uses an explicit product CA and adapter identity, never ambient proxy or public
roots. `Apply` signs and sends once with no hidden retry; 401, 404 and 409 are
terminal pending security/mapping/revision reconciliation, while transport or
503 uncertainty must be reconciled before a fresh signed attempt. See
`../ENTITLEMENT_ADAPTER_CONFORMANCE_RUNBOOK.md`.

M86 exposes that client through the public `entitlementadapter` package. Its
API defines provider-neutral product types and stable error decisions without
leaking `internal/accountauth` types. A separate temporary Go module compiles
against only this public package, while the opaque mTLS handle prevents an
external adapter from replacing the qualified transport. The module is not yet
published under a final organization/repository path; controlled vendor or a
private Go proxy remains a release decision.

## Device-facing endpoint

`GET /v1/device` upgrades to WebSocket after all of these pass:

- `Authorization: Bearer <device-token>` verifies;
- token `device_id` equals the `Device-Id` header;
- `Client-Id` is a safe bounded identifier;
- `Protocol-Version` is 1, 2, or 3 and matches the hello payload;
- no connection for that device is already active across coordinated replicas;
- client hello advertises Device Agent v1 request correlation.

The gateway replies with a XiaoZhi-compatible server hello, a random session ID,
and an exact Device Agent v1 acknowledgement. It supports XiaoZhi's raw, v2, and
v3 WebSocket Opus frame envelopes.

Production Voice tokens use this compact signed format:

```text
v4.<kid>.<base64url JSON claims>.<base64url HMAC-SHA256 signature>
```

Required claims are `device_id`, `aud`, `iat`, and `exp`; `aud` is
`xiaozhi-agent-gateway`. Control-plane-issued tokens also carry a random `jti`
and are accepted for one successful WebSocket upgrade across Gateway replicas.
Tokens are short-lived (15 minutes by default). The named key comes from a
private, revision-fenced managed ring and contains 32–128 random bytes. An old
unkeyed `v3` token is accepted only when the ring explicitly identifies one
retiring key and a future migration deadline; managed verification never tries
all keys. Legacy externally-issued tokens without `jti` retain their previous
behavior only inside that bounded migration.

## Optional device session issuance

When explicitly enabled, `POST /v1/session` exchanges a per-device bootstrap
proof for a short-lived voice token. It accepts no body or query string and
requires exactly one of each header:

```text
Device-Id: <device-id>
Client-Id: <boot/client-id>
X-Device-Timestamp: <Unix seconds>
X-Device-Nonce: <base64url 16..32 random bytes>
X-Device-Signature: <base64url HMAC-SHA256>
```

The HMAC input is the exact UTF-8 byte sequence:

```text
xiaozhi-session-proof-v1\n
POST\n
/v1/session\n
<device-id>\n
<client-id>\n
<timestamp>\n
<nonce>
```

The signature key is the device's unique 32–128 byte bootstrap secret from the
mounted registry. Proof timestamps use a bounded clock-skew window; nonces are
single-use; issuance is rate-limited per device. Unknown and disabled devices
receive the same unauthorized response. A successful response is marked
`no-store` and contains:

```json
{
  "version": 1,
  "device_id": "box3-demo-001",
  "voice": {
    "uri": "wss://voice.example/v1/device",
    "bearer_token": "v1....",
    "expires_in_seconds": 900
  }
}
```

`device-registry.example.json` is now a development-only version 1 fixture; its
secret is public test data and must never be used on a device. Production uses
the Ed25519-signed version 2 contract in
`device-identity-snapshot.schema.json`. The independent control plane consumes
a confidential `purpose:proof` snapshot, while the gateway consumes a
secret-free `purpose:access` snapshot. Revisions hot-reload atomically, expire
fail closed, reject rollback/equivocation, and actively close connected revoked
devices. M31 optionally obtains the same signed artifacts through a strict
mutually authenticated HTTPS source with conditional ETags. See
`../DEVICE_IDENTITY_SNAPSHOT_RUNBOOK.md` and
`../REMOTE_IDENTITY_SOURCE_RUNBOOK.md`.

The voice token is not an LLM/Agent token. Firmware obtains a distinct scoped
Agent token from the control plane and presents it to the product Agent proxy;
sharing either token with the other audience is forbidden. No service mints or
returns a model-provider credential to firmware.

## Independent control plane

Run `./cmd/controlplane` as the production issuance boundary. It exposes:

- `POST /v1/time`: a registered-device, nonce-bound authenticated UTC sample;
- `POST /v1/session`: the existing nested voice-credential response;
- `POST /v1/agent-token`: a flat `xiaozhi-agent-proxy` bearer-token response;
- `POST /v1/ota/offer`: an optional signed fleet decision plus a short-lived,
  release/image-bound download token;
- `/healthz`, `/readyz`, and metadata-only `/metrics`.

`/v1/session` and `/v1/agent-token` use different exact HMAC domains:

```text
xiaozhi-session-proof-v1\nPOST\n/v1/session\n...
xiaozhi-agent-token-proof-v1\nPOST\n/v1/agent-token\n...
```

A valid proof for one route fails on the other. Proof nonces are one-use per
process and issuance is throttled per device. `/v1/time` exists before the
device has trustworthy Unix time: TLS authenticates the product service, while
the response echoes an exact fresh 16-byte base64url nonce and the exact
device/client identifiers. Firmware accepts the value only after all echoes
match.

### Fleet OTA offer

When the four OTA settings below are present, `/v1/ota/offer` requires its own
proof domain and four additional signed headers:

```text
X-OTA-Board: esp32s3-box3
X-OTA-Channel: development
X-OTA-Release-Sequence: 14
X-OTA-Version: 0.14.0-dev
```

The exact proof input is:

```text
xiaozhi-ota-offer-proof-v1\n
POST\n
/v1/ota/offer\n
<device-id>\n
<client-id>\n
<timestamp>\n
<nonce>\n
<board>\n
<channel>\n
<release-sequence>\n
<version>
```

The registered device board/channel profile must match those headers. The
release registry accepts at most two P-256 public keys and 64 strict manifest
v2 documents. Every manifest carries the signed SHA-256 of an independently
verified reset-hardware qualification receipt; v1 or a missing digest fails
startup. The registry then makes a deterministic HMAC cohort decision from release ID and
device ID. An available response contains the exact signed manifest and an OTA
audience token bound to `release_id` plus `image_sha256`. Deferred, disabled,
outside-cohort, and up-to-date responses contain neither manifest nor token.

The origin/CDN must call
`VerifyAuthorizationForRelease(Authorization, release_id, image_sha256)` (or
implement that exact verification contract) before returning bytes. A valid
token for another audience, release, or image is not valid download authority.
Do not place the token in the URL, redirect it, log it, or cache the offer.

`ota-release-registry.example.json` and
`ota-release-registry.schema.json` document the fleet registry. The referenced
manifest must first pass `tools/verify_release_manifest.py` with the exact lab
receipt, trusted lab public key, and key ID. This M15 reference
loads the registry once at process startup; rollout percentage changes and
emergency `enabled:false` revocation therefore require an atomic config publish
and rolling restart of every control-plane replica. A production fleet service
should provide a versioned, audited, fail-closed reload mechanism.

Signing-key and manifest paths are canonical relative paths contained below
the registry directory. Absolute paths, noncanonical traversal, and symlinks
that escape the registry root fail startup.

Control-plane configuration:

| Variable | Required/default |
| --- | --- |
| `CONTROL_PLANE_ADDRESS` | `:8444` |
| `CONTROL_TLS_CERT_FILE`, `CONTROL_TLS_KEY_FILE` | Required outside explicit development mode |
| `ALLOW_INSECURE_DEVELOPMENT` | `false`; local tests only |
| `DEVICE_REGISTRY_FILE` | Signed local proof snapshot; mutually exclusive with `DEVICE_REGISTRY_URL`; legacy JSON is development-only |
| `DEVICE_REGISTRY_URL` | Remote alternative; exact HTTPS `/v1/device-identity/proof` endpoint |
| `DEVICE_REGISTRY_TLS_CA_FILE`, `DEVICE_REGISTRY_TLS_CERT_FILE`, `DEVICE_REGISTRY_TLS_KEY_FILE` | Required together with URL; dedicated CA and workload mTLS identity |
| `DEVICE_REGISTRY_REQUEST_TIMEOUT_SECONDS` | Remote only; `5`, range `1..30` |
| `DEVICE_REGISTRY_SIGNING_PUBLIC_KEY_FILE` | Required in production; trusted Ed25519 identity public key |
| `DEVICE_REGISTRY_SIGNING_KEY_ID` | Required in production; exact snapshot key ID |
| `DEVICE_REGISTRY_MIN_REVISION` | Required in production; approved positive restart floor |
| `DEVICE_REGISTRY_RELOAD_INTERVAL_SECONDS` | `5`; range `1..300` |
| `PUBLIC_DEVICE_WSS_URL` | Required; exact production `wss://.../v1/device` |
| `VOICE_TOKEN_HMAC_KEYRING_FILE`, `VOICE_TOKEN_HMAC_KEYRING_MIN_REVISION` | Required together in production; canonical private Voice ring and approved positive rollback floor |
| `AGENT_TOKEN_HMAC_KEYRING_FILE`, `AGENT_TOKEN_HMAC_KEYRING_MIN_REVISION` | Required together in production; canonical private Agent ring, material-isolated from Voice |
| `VOICE_TOKEN_TTL_SECONDS` | `900`; range `60..3600` |
| `AGENT_TOKEN_TTL_SECONDS` | `600`; range `60..3600` |
| `DEVICE_PROOF_MAX_SKEW_SECONDS` | `60`; range `10..300` |
| `DEVICE_PROOF_MIN_INTERVAL_SECONDS` | `5`; range `0..60` |
| `APP_TOKEN_HMAC_KEYS_B64` | Optional claim-mode keyring; current then up to two previous 32–128 byte keys; reference command permits it only in explicit development mode |
| `APP_TOKEN_MAX_TTL_SECONDS` | Claim mode; `900`, range `60..3600` |
| `DEVICE_CLAIM_TTL_SECONDS` | Claim mode; `300`, range `60..600` |
| `DEVICE_CLAIM_MAX_PENDING` | Claim mode; `4096`, range `1..100000` |
| `OTA_RELEASE_REGISTRY_FILE` | Optional; enabling OTA requires the complete OTA setting group |
| `OTA_TOKEN_HMAC_KEYRING_FILE`, `OTA_TOKEN_HMAC_KEYRING_MIN_REVISION` | Required with OTA in production; canonical private OTA ring, material-isolated from every other ring/key |
| `OTA_ROLLOUT_HMAC_KEY_B64` | Required with OTA; 32–128 decoded bytes and distinct from every other key |
| `OTA_TOKEN_TTL_SECONDS` | `300`; range `60..900` |

Claim mode exposes App-intent, device-confirm and user-scoped status routes.
The built-in command deliberately wires only the single-process reference
store and therefore rejects these settings outside
`ALLOW_INSECURE_DEVELOPMENT=true`. A production composition must inject a
durable serializable `deviceclaim.OwnershipStore`; do not weaken this startup
failure. When configured, valid session/Agent proofs are denied until an owner
exists. See the root `DEVICE_OWNERSHIP_CLAIM_RUNBOOK.md`.

## Immutable firmware origin

Run `./cmd/firmwareorigin` behind the exact HTTPS authority used by signed M14
manifest `image_url` values. The service accepts only full `GET` requests with
`Accept: application/octet-stream` and one OTA bearer token. It rejects query
strings, bodies, encoded paths, Range/conditional requests, redirects, voice or
Agent tokens, and tokens whose release ID or image SHA-256 differs from the
requested catalog object.

Production origin admission also requires the signed secret-free access
snapshot. Revocation makes an otherwise unexpired OTA token unauthorized; an
active stream receives an immediate response write deadline and context-aware
copy cancellation.

The strict catalog is documented by
`firmware-origin-catalog.example.json` and
`firmware-origin-catalog.schema.json`. Every `image_file` must be a canonical
relative path below the catalog directory; path traversal and symlink escape
fail startup. Release IDs and URL paths are unique. Size and SHA-256 are
verified at startup and rechecked before every response, before status 200 or
the first firmware byte is sent.

`FIRMWARE_ORIGIN_PUBLIC_AUTHORITY` must be the canonical lowercase authority
from every signed image URL served by this instance. A mismatched HTTP Host is
rejected before authorization or file access; use separate instances when
release authorities differ.

Mount the complete catalog directory read-only. This reference service does
not make a writable filesystem immutable and does not replace object-lock/WORM
storage. The ESP installer still verifies descriptor, byte count, and SHA-256,
so a post-verification storage race fails safely on-device, but production must
enforce immutability below the process as well.

Firmware-origin configuration:

| Variable | Required/default |
| --- | --- |
| `FIRMWARE_ORIGIN_ADDRESS` | `:8446` |
| `FIRMWARE_ORIGIN_TLS_CERT_FILE`, `FIRMWARE_ORIGIN_TLS_KEY_FILE` | Required outside explicit development mode |
| `ALLOW_INSECURE_DEVELOPMENT` | `false`; local tests only |
| `FIRMWARE_ORIGIN_CATALOG_FILE` | Required strict catalog mounted with its image tree |
| `FIRMWARE_ORIGIN_PUBLIC_AUTHORITY` | Required canonical lowercase host with optional port, exactly matching signed image URLs |
| `OTA_TOKEN_HMAC_KEYRING_FILE`, `OTA_TOKEN_HMAC_KEYRING_MIN_REVISION` | Required together in production; canonical private OTA ring and approved positive rollback floor |
| `OTA_TOKEN_MAX_TTL_SECONDS` | `900`; range `60..900` and no lower than issued token TTL |
| `FIRMWARE_ORIGIN_MAX_CONCURRENT` | `100`; range `1..10000` |
| `FIRMWARE_ORIGIN_WRITE_TIMEOUT_SECONDS` | `300`; range `30..1800` |
| `DEVICE_REGISTRY_FILE` | Signed local `purpose:access` snapshot; mutually exclusive with URL |
| `DEVICE_REGISTRY_URL` | Remote alternative; exact HTTPS `/v1/device-identity/access` endpoint |
| `DEVICE_REGISTRY_TLS_CA_FILE`, `DEVICE_REGISTRY_TLS_CERT_FILE`, `DEVICE_REGISTRY_TLS_KEY_FILE` | Required together with URL; dedicated CA and workload mTLS identity |
| `DEVICE_REGISTRY_REQUEST_TIMEOUT_SECONDS` | Remote only; `5`, range `1..30` |
| `DEVICE_REGISTRY_SIGNING_PUBLIC_KEY_FILE` | Required in production; trusted Ed25519 identity public key |
| `DEVICE_REGISTRY_SIGNING_KEY_ID` | Required in production; exact snapshot key ID |
| `DEVICE_REGISTRY_MIN_REVISION` | Required in production; approved positive restart floor |
| `DEVICE_REGISTRY_RELOAD_INTERVAL_SECONDS` | `5`; range `1..300` |

The origin and control plane use the exact approved OTA ring generation during
steady state. Rotation deploys the higher-revision verifier ring to Firmware
Origin first, then switches Control Plane issuance, and retires the old key only
after its bounded verification window.
The origin has no release-signing private key, device identity key, rollout
key, voice key, Agent key, or model-provider credential.

## Verified OTA deployment bundle

`tools/build_ota_deployment_bundle.py` derives the control registry and origin
catalog together from one signed release record; operators do not independently
copy release ID, URL path, image size, or SHA-256 into two files. The fixed
bundle also contains the exact manifest, reviewed public key, image,
`sdkconfig`, a canonical receipt, and a receipt-hash `READY` marker written
last. It refuses an existing output and makes the complete tree read-only.

Every M17 bundle is fail-closed: its only control entry has `enabled:false` and
zero rollout basis points. `ota-deployment-receipt.schema.json` documents the
receipt. `tools/validate_ota_deployment_bundle.py` re-verifies the signature,
ESP image descriptor, build policy, exact digests, canonical catalogs, layout,
and permissions. The Go command below additionally loads the generated files
through the same `ota.LoadRegistry` and `firmwareorigin.LoadCatalog` paths used
by the running services:

```sh
go run ./cmd/validateotabundle \
  -bundle /run/ota-bundle \
  -authority updates.example.com
```

The command rejects missing/invalid `READY`, missing/unknown/duplicate receipt
fields, digest drift, catalog/release disagreement, unsafe paths, unexpected
files/directories, symlinks, writable content, and any enabled rollout. Do not
edit a verified bundle in place. Audited cohort promotion, replica convergence,
and emergency generation publication remain separate deployment gates.

## Two-person rollout generations

M18 creates a new complete immutable bundle for every `EXPAND`,
`EMERGENCY_STOP`, or `RESUME` transition. A canonical request binds the parent
receipt, parent/target generation and cohort state, release/image identity,
approval window, retry policy, and exact external approver-keyring SHA-256.
Exactly two distinct enabled identities with distinct Ed25519 public keys must
approve that request. The keyring is a deployment trust root and is never
self-supplied by the bundle.

The request, approvals, approver keyring, and schema-v2 receipt are documented
by `ota-rollout-*.schema.json`; an example keyring is
`ota-rollout-approver-keyring.example.json`. `validaterolloutbundle` independently
verifies every signature and digest, then loads the active control registry and
origin catalog through their production loaders:

```sh
go run ./cmd/validaterolloutbundle \
  -bundle /run/ota-generations/current \
  -parent-bundle /run/ota-generations/previous \
  -parent-bundle /run/ota-generations/staging \
  -approver-keyring /run/release-trust/rollout-approvers-v1.json \
  -authority updates.example.com
```

Repeat parent arguments from immediate parent through original staging and
provide every historical keyring snapshot required by their pinned hashes. The
validator rejects incomplete ancestry, sequence gaps, reused ancestor IDs,
nonmonotonic expansion, wrong emergency/resume state, expired or cross-manifest
approval windows, approval replay, signer/keyring substitution, catalog drift,
and writable or unexpected content.

The online services intentionally do not hold rollout-approval private keys.
Only the protected `publishgeneration` job receives the publisher HMAC key; it
first reruns the complete M18 lineage validator and then publishes the exact
generation/receipt tuple with an active-revision compare-and-swap.

## Durable atomic generation publication

`generationcoordinator` is the M19 OTA serving authority. Its private state
directory contains canonical `state-%020d.json` records chained by SHA-256 and
authenticated with a dedicated HMAC key. Each immutable record is fsynced and
linked into place without overwrite before the repairable `CURRENT` index is
atomically replaced. Startup scans the complete contiguous chain; a missing or
stale `CURRENT` is repaired, while gaps, truncation, noncanonical JSON, wrong
HMAC, illegal transitions, unexpected files, or a second writer fail closed.

The exact state machine is:

```text
STABLE --publish CAS--> PREPARING --all PREPARED--> DRAINING
   ^                         |                         |
   +------timeout/abort------+                         |
   |                                                   |
   +--all ACTIVE-- COMMITTING <--lease drain + CAS-----+
```

During `PREPARING`, old replicas may continue serving while new replicas load
the complete read-only bundle and acknowledge its exact receipt. `DRAINING`
stops renewal of old leases and permits neither generation to start new OTA
work. The coordinator waits twice the five-second state lease and also requires
a local monotonic minimum interval before atomically switching active. New
replicas serve only when their locally hashed receipt equals active; old
replicas fail immediately or at lease expiry. A `COMMITTING` timeout never
rolls back because some replicas may already have served the new generation.

Initialize a new state directory once, using a fully validated staging or
rollout bundle and the exact required replica set:

```sh
GENERATION_STATE_HMAC_KEY_B64='<dedicated random key>' \
go run ./cmd/initgenerationstate \
  -state-directory /var/lib/xiaozhi-generation \
  -bundle /run/ota-generations/staging \
  -authority updates.example.com \
  -replica-registry /run/secrets/generation-replicas.json
```

For a schema-v2 initial generation, also repeat `-parent-bundle` through
staging and provide every historical `-approver-keyring`. Initialization never
opens or overwrites an existing directory. The replica registry is canonical,
uniquely sorted, private mode, contains at least one `controlplane` and one
`firmwareorigin`, and uses a distinct 32–128 byte key for every stable replica
ID. See `generation-replica-registry.schema.json`; the example keys are public
test data and are never production secrets.

Coordinator configuration:

| Variable | Required/default |
| --- | --- |
| `GENERATION_COORDINATOR_ADDRESS` | `:8447` |
| `GENERATION_COORDINATOR_TLS_CERT_FILE`, `GENERATION_COORDINATOR_TLS_KEY_FILE` | Required outside explicit development mode |
| `GENERATION_STATE_DIRECTORY` | Required initialized private writable volume |
| `GENERATION_STATE_HMAC_KEY_B64` | Required dedicated 32–128 byte key |
| `GENERATION_PUBLISHER_ID`, `GENERATION_PUBLISHER_HMAC_KEY_B64` | Required protected publisher identity/key |
| `GENERATION_REPLICA_REGISTRY_FILE` | Required private canonical registry |
| `GENERATION_PREPARE_TIMEOUT_SECONDS` | `600`; range `30..86400` |
| `GENERATION_COMMIT_TIMEOUT_SECONDS` | `600`; range `30..86400` |
| `GENERATION_MAX_CLOCK_SKEW_SECONDS` | `60`; range `5..300` |

Each OTA-enabled control/origin replica additionally requires
`GENERATION_COORDINATOR_URL`, its stable `GENERATION_REPLICA_ID`, its unique
`GENERATION_REPLICA_HMAC_KEY_B64`, and `OTA_DEPLOYMENT_BUNDLE_ROOT`. Production
requires HTTPS. The configured registry/catalog path must be the exact path
inside that root. At startup, control replicas rehash the receipt, registry,
manifest, and P-256 public key; origin replicas rehash the receipt and catalog,
whose loader rehashes the image. Writable files, symlinks, aliases, digest
drift, or coordinator mismatch fail readiness and OTA serving.

Publish only with the lineage-validating client:

```sh
GENERATION_PUBLISHER_HMAC_KEY_B64='<publisher key>' \
go run ./cmd/publishgeneration \
  -coordinator https://generation.example.com \
  -publisher-id release-publisher \
  -bundle /release/g0002.bundle \
  -parent-bundle /release/g0001.bundle \
  -parent-bundle /release/staging.bundle \
  -approver-keyring /release-trust/rollout-approvers-v1.json \
  -authority updates.example.com
```

Before active flip, the publisher may run `abortgeneration`; prepare timeout
also aborts to the old stable generation. After active flip there is no
automatic rollback: restore missing replicas or publish a separately approved
forward emergency generation after convergence. `validate_generation_state.py`
independently verifies every record, HMAC, transition, permission, and CURRENT:

```sh
GENERATION_STATE_HMAC_KEY_B64='<state key>' \
../tools/validate_generation_state.py \
  --state-directory /var/lib/xiaozhi-generation
```

## Product Agent proxy

Run `./cmd/agentproxy` at the device-facing base URL, for example
`https://agent.example/v1`. The pinned ESP-Claw OpenAI-compatible adapter adds
`/chat/completions`, yielding the proxy's exact endpoint:
`POST /v1/chat/completions`.

The proxy:

- accepts only Agent-audience bearer tokens and rejects voice tokens;
- requires the signed secret-free access snapshot in production, rejects old
  tokens after device revocation, and cancels active provider contexts;
- accepts the public model alias `product-agent` and replaces it with the
  private provider model;
- permits only `model`, `messages`, `tools`, `max_tokens`,
  `max_completion_tokens`, and non-streaming `stream`;
- applies request, response, message, tool, output-token, timeout, per-device,
  and global-concurrency bounds;
- normalizes output tokens to `max_completion_tokens` and forces `store:false`;
- adds the provider key only on the outbound hop and sanitizes provider errors;
- validates that a successful provider response contains an assistant message.

Agent-proxy configuration:

| Variable | Required/default |
| --- | --- |
| `AGENT_PROXY_ADDRESS` | `:8445` |
| `AGENT_PROXY_TLS_CERT_FILE`, `AGENT_PROXY_TLS_KEY_FILE` | Required outside explicit development mode |
| `ALLOW_INSECURE_DEVELOPMENT` | `false`; local tests only |
| `AGENT_TOKEN_HMAC_KEYRING_FILE`, `AGENT_TOKEN_HMAC_KEYRING_MIN_REVISION` | Required together in production; canonical private Agent ring and approved positive rollback floor |
| `AGENT_TOKEN_MAX_TTL_SECONDS` | `600`; verifier ceiling, range `60..3600` |
| `DEVICE_REGISTRY_FILE` | Signed local `purpose:access` snapshot; mutually exclusive with URL |
| `DEVICE_REGISTRY_URL` | Remote alternative; exact HTTPS `/v1/device-identity/access` endpoint |
| `DEVICE_REGISTRY_TLS_CA_FILE`, `DEVICE_REGISTRY_TLS_CERT_FILE`, `DEVICE_REGISTRY_TLS_KEY_FILE` | Required together with URL; dedicated CA and workload mTLS identity |
| `DEVICE_REGISTRY_REQUEST_TIMEOUT_SECONDS` | Remote only; `5`, range `1..30` |
| `DEVICE_REGISTRY_SIGNING_PUBLIC_KEY_FILE` | Required in production; trusted Ed25519 identity public key |
| `DEVICE_REGISTRY_SIGNING_KEY_ID` | Required in production; exact snapshot key ID |
| `DEVICE_REGISTRY_MIN_REVISION` | Required in production; approved positive restart floor |
| `DEVICE_REGISTRY_RELOAD_INTERVAL_SECONDS` | `5`; range `1..300` |
| `AGENT_PROVIDER_URL` | Required exact HTTPS `/v1/chat/completions` URL |
| `AGENT_PROVIDER_API_KEY` | Required server-side secret |
| `AGENT_PROVIDER_MODEL` | Required private provider model |
| `AGENT_PUBLIC_MODEL` | `product-agent` |
| `OPENAI_ORGANIZATION`, `OPENAI_PROJECT` | Optional bounded header-safe identifiers |
| `AGENT_MAX_OUTPUT_TOKENS` | `1024`; range `1..8192` |
| `AGENT_MAX_REQUEST_KIB`, `AGENT_MAX_RESPONSE_KIB` | `256`, `1024` |
| `AGENT_REQUEST_TIMEOUT_SECONDS` | `35`; range `5..120` |
| `AGENT_MAX_CONCURRENT` | `100` per process |
| `AGENT_MAX_REQUESTS_PER_MINUTE` | `30` per device, per process |

This compatibility path uses Chat Completions because the pinned ESP-Claw
backend speaks that contract. A later migration to another provider API should
be implemented behind the proxy or an ESP-Claw adapter, not by exposing a new
provider contract directly to products.

## Private STT contract

The gateway opens `STT_UPSTREAM_URL` with WSS and sends:

```json
{
  "type": "start",
  "contract": "xiaozhi-private-stt-v1",
  "session_id": "voice:...",
  "format": "opus",
  "sample_rate": 16000,
  "frame_duration_ms": 60
}
```

Both the upgrade request and successful upgrade response must carry
`X-Xiaozhi-Speech-Contract: xiaozhi-private-stt-v1`. If `STT_HEALTH_URL` is
configured, its successful response must carry the same header; an arbitrary
2xx is not readiness evidence.

It then sends raw Opus packets as binary WebSocket messages and forwards only
XiaoZhi `listen` and `abort` controls. The STT service returns:

```json
{"type":"stt","text":"turn on the lamp","final":true}
```

Only final STT text reaches the device. The gateway does not allow the STT
service to emit TTS or arbitrary device control messages, which preserves the
on-device ESP-Claw Agent's ownership of reasoning and tools. Before forwarding
audio, the production gateway parses the complete Opus packet layout and
requires mono audio with the exact negotiated 60 ms packet duration. A wrong
TOC, stereo bit, frame count, CBR/VBR length, padding, or duration fails the
session at the private boundary rather than at the ESP32 decoder.

## Private TTS contract

The gateway POSTs JSON to `TTS_UPSTREAM_URL`:

```json
{
  "contract": "xiaozhi-private-tts-v1",
  "device_id": "device-1",
  "session_id": "voice:...",
  "request_id": 42,
  "text": "The lamp is on.",
  "format": "opus",
  "sample_rate": 24000,
  "frame_duration_ms": 60
}
```

It sends `Idempotency-Key: <session_id>:<request_id>` plus
`X-Xiaozhi-Speech-Contract: xiaozhi-private-tts-v1`, and expects both the same
contract response header and `Content-Type: application/x-opus-frames`. If
`TTS_HEALTH_URL` is configured, its response must also carry that contract
header. The response body is a stream of:

```text
4-byte big-endian frame length | one raw Opus packet | repeat
```

Each framed payload is limited to 4 KiB and each synthesis to 4 MiB. Every Opus
packet must be structurally valid mono audio totaling exactly 60 ms; individual
Opus frames are limited to the format maximum of 1,275 bytes, and code 0/1/2/3,
CBR, VBR, and padding layouts are checked before emission. This validator does
not decode speech content. M27 adds deterministic 16 kHz/24 kHz, mono, 60 ms
golden packets that are encoded with libopus and decoded by an exact
hash-pinned FFmpeg native decoder; run `../tools/run_speech_codec_gate.sh` with
`XIAOZHI_FFMPEG` set to that reviewed binary. A candidate adapter must still
pass decode over captured output, duration, language, ESP codec, and acoustic
tests. Cancelling a request cancels
the upstream HTTP context and invalidates the request before any later frame
can be written to the device.

The framed client also checks cancellation before each buffered read and
immediately after each emitted packet. Its caller therefore sees at most the
frame whose callback initiated cancellation, even if later upstream frames
already arrived in the HTTP receive buffer.

## Offline speech-adapter qualification

`go run ./cmd/qualifyspeechadapter` applies the live M25 contract and M27 codec
gates to approved corpus input. It tests readiness, STT stop/final and abort,
parallel distinct TTS outputs, real decode of every packet, explicit latency
thresholds and cancellation after one frame. Output is a canonical Ed25519
receipt bound to the candidate config, tested endpoint set, corpus, exact
reference decoder, approved runner-build digest and transport-trust digest.

The receipt contains no endpoint URL, token, transcript, synthesis text, text
hash, raw Opus or PCM. It always says `production_ready: false`. Local HTTP/WS
runs can produce only `TEST_HARNESS_PASS`; HTTPS/WSS runs can produce only
`PROTOCOL_PASS`. The independent verifier accepts externally supplied trust
expectations and can reject all development-transport evidence. See
`../SPEECH_ADAPTER_QUALIFICATION_RUNBOOK.md` for the complete command and
evidence policy.

## Operational endpoints

- `/healthz`: process health only.
- `/readyz`: checks ownership/runtime-coordination/speech-budget schema plus
  configured STT and TTS dependencies.
- `/metrics`: metadata-only Prometheus text counters.

Logs contain device/session identifiers and error classes, but not transcript
text, provider tokens, or tool arguments.

## Configuration

| Variable | Required/default |
| --- | --- |
| `GATEWAY_ADDRESS` | `:8443` |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | Required outside explicit development mode |
| `ALLOW_INSECURE_DEVELOPMENT` | `false`; permits HTTP/WS only for local tests |
| `VOICE_TOKEN_HMAC_KEYRING_FILE`, `VOICE_TOKEN_HMAC_KEYRING_MIN_REVISION` | Required together in production; canonical private Voice ring and approved positive rollback floor |
| `DEVICE_TOKEN_MAX_TTL_SECONDS` | `900`, maximum `3600` |
| `ENABLE_SESSION_ISSUANCE` | `false`; development-only embedded `/v1/session`; production uses the independent control plane |
| `DEVICE_REGISTRY_FILE` | Signed local `purpose:access` snapshot; legacy file is only for development embedded issuance; mutually exclusive with URL |
| `DEVICE_REGISTRY_URL` | Remote alternative; exact HTTPS `/v1/device-identity/access` endpoint |
| `DEVICE_REGISTRY_TLS_CA_FILE`, `DEVICE_REGISTRY_TLS_CERT_FILE`, `DEVICE_REGISTRY_TLS_KEY_FILE` | Required together with URL; dedicated CA and workload mTLS identity |
| `DEVICE_REGISTRY_REQUEST_TIMEOUT_SECONDS` | Remote only; `5`, range `1..30` |
| `DEVICE_REGISTRY_SIGNING_PUBLIC_KEY_FILE` | Required in production; trusted Ed25519 identity public key |
| `DEVICE_REGISTRY_SIGNING_KEY_ID` | Required in production; exact snapshot key ID |
| `DEVICE_REGISTRY_MIN_REVISION` | Required in production; approved positive restart floor |
| `DEVICE_REGISTRY_RELOAD_INTERVAL_SECONDS` | `5`; range `1..300` |
| `PUBLIC_DEVICE_WSS_URL` | Required when issuance is enabled; production `wss://.../v1/device` |
| `SESSION_TOKEN_TTL_SECONDS` | `900`; `60..DEVICE_TOKEN_MAX_TTL_SECONDS` |
| `SESSION_PROOF_MAX_SKEW_SECONDS` | `60`; range `10..300` |
| `SESSION_MIN_INTERVAL_SECONDS` | `5`; range `0..60` |
| `STT_UPSTREAM_URL`, `STT_UPSTREAM_TOKEN` | Required |
| `STT_HEALTH_URL` | Optional |
| `STT_TLS_CA_FILE`, `STT_TLS_CLIENT_CERT_FILE`, `STT_TLS_CLIENT_KEY_FILE` | Required together in production; dedicated STT CA set and client identity |
| `TTS_UPSTREAM_URL`, `TTS_UPSTREAM_TOKEN` | Required |
| `TTS_HEALTH_URL` | Optional |
| `TTS_TLS_CA_FILE`, `TTS_TLS_CLIENT_CERT_FILE`, `TTS_TLS_CLIENT_KEY_FILE` | Required together in production; content-isolated from STT |
| `SPEECH_PRICING_PROFILE_ID` | Required in production; immutable once its three rates are observed |
| `SPEECH_STT_MICROUSD_PER_MILLION_AUDIO_MS` | Required in production; positive integer |
| `SPEECH_TTS_MICROUSD_PER_MILLION_CHARACTERS` | Required in production; Unicode-scalar rate, may be `0` only when output-audio rate is positive |
| `SPEECH_TTS_MICROUSD_PER_MILLION_OUTPUT_AUDIO_MS` | Required in production; may be `0` only when character rate is positive |
| `SPEECH_DAILY_BUDGET_MICROUSD` | Required in production; one cross-STT/TTS/profile UTC daily subject budget |
| `SPEECH_STT_RESERVATION_CHUNK_AUDIO_MS` | Required in production; `1000..60000` |
| `SPEECH_TTS_MAX_OUTPUT_AUDIO_MS` | Required in production; `1000..600000`, also enforced by the framed adapter |
| `SPEECH_USAGE_RESERVATION_TTL_SECONDS` | Required in production; `60..600` and at least synthesis timeout plus 15 seconds |
| `SPEECH_USAGE_DIGEST_KEY_FILE` | Required in production; canonical private 32-byte base64url key, isolated from every token/usage domain |
| `OUTPUT_SAMPLE_RATE` | `24000` |
| `OUTPUT_FRAME_MILLIS` | `60` |
| `MAX_CONNECTIONS` | `1000`; global across coordinated Gateway replicas |
| `OWNERSHIP_DATABASE_URL` | Required; `sslmode=verify-full` outside development |
| `OWNERSHIP_DATABASE_MAX_CONNECTIONS`, `OWNERSHIP_DATABASE_IDLE_CONNECTIONS` | `20`, `5` |
| `OWNERSHIP_DATABASE_CONNECTION_TTL_SECONDS` | `300`; range `30..3600` |
| `OWNERSHIP_DATABASE_OPERATION_TIMEOUT_MS` | `2000`; range `100..30000` |
| `RUNTIME_COORDINATION_WORKER_ID` | Required unique Pod/process identifier; Kubernetes uses Pod name |
| `MAX_MESSAGES_PER_MINUTE` | `120` control messages per connection |
| `MAX_AUDIO_PACKETS_PER_MINUTE` | `4000` audio packets per connection |

The device-facing production listener has a TLS 1.2 minimum to remain compatible
with ESP32-class clients. Private speech egress is exact TLS 1.3 mTLS. Put
distinct upstream tokens, client keys and the managed Voice keyring in a secrets
manager or mounted secret, never in images, source, logs, or device firmware.

## Verification

Use Go 1.26.5:

```sh
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/gateway
go build ./cmd/controlplane
go build ./cmd/agentproxy
go build ./cmd/firmwareorigin
go build ./cmd/generationcoordinator
go build ./cmd/accountauthorization
go build ./cmd/factorytimeauthority
go build ./cmd/initgenerationstate
go build ./cmd/publishgeneration
go build ./cmd/abortgeneration
go build ./cmd/validateocirelease
go build ./cmd/generateidentitykey
go build ./cmd/signidentitysnapshot
go build ./cmd/validateidentitysnapshot
```

The integration tests open real WebSockets and cover authentication, hello
negotiation, raw Opus upload, final STT, correlated TTS lifecycle/audio, barge-in
stale-audio suppression, versioned private speech contracts, Opus TOC/CBR/VBR/
padding/duration rejection, buffered cancellation, signed adapter qualification,
proof issuance, signed identity expiry/rollback/equivocation, active
disabled-device revocation, proof and
voice-token replay denial, signed fleet OTA selection, rollout/revocation,
OTA proof replay denial, object-bound token verification, exact immutable image
streaming, storage-tamper denial, expiry, readiness/metrics, and graceful
shutdown.

The authoritative release path is the daemonless OCI builder, not a mutable
local Docker tag. Schema v3 always builds the exact ordered seven-service set
(`gateway`, `controlplane`, `agentproxy`, `firmwareorigin`,
`generationcoordinator`, `accountauthorization`, `factorytimeauthority`) for
both supported Linux architectures, attaches subject-bound SPDX/provenance artifacts, signs a
top-level receipt in the v3 signature domain, and writes an immutable exact
layout. Partial service releases, reordered records and older receipts are rejected:

```sh
../tools/build_oci_release_bundle.py \
  --go /opt/pinned/go1.26.5/bin/go \
  --ca-bundle /release-inputs/ca-certificates.crt \
  --signing-private-key /run/release-secrets/oci-release-ed25519.pem \
  --signing-key-id oci-release-2026-q3 \
  --release-id backend-2026-08-09-01 \
  --version 0.62.0 \
  --source-date-epoch 1786276800 \
  --output /release-output/backend-2026-08-09-01.oci

../tools/validate_oci_release_bundle.py \
  --bundle /release-output/backend-2026-08-09-01.oci \
  --trusted-public-key /release-trust/oci-release-2026-q3.pub.pem \
  --expected-signing-key-id oci-release-2026-q3

go run ./cmd/validateocirelease \
  -bundle /release-output/backend-2026-08-09-01.oci \
  -public-key /release-trust/oci-release-2026-q3.pub.pem \
  -key-id oci-release-2026-q3
```

The included `Dockerfile` remains a local-development convenience and does not
produce production release evidence. See `../OCI_DEPLOYMENT_BASELINE.md` for registry
push, referrer, current scanner, Cosign, transparency, and admission gates.
M48 proves deterministic offline construction and validation of the account
reader together with the other five services; it is not evidence that any image
was pushed, signed in a registry, admitted by a cluster, or deployed.

## Remaining production gates

- Connect primary and backup STT/TTS adapters that each produce a signed M28
  `PROTOCOL_PASS` receipt through the exact deployed M75 mTLS bindings against
  approved captured speech, prove token/client/CA rotation and rollback, then run provider-
  side cancellation/billing, ESP/BOX3 codec, language-quality, privacy,
  failure, quota, cost and soak gates. A protocol receipt is not production
  approval.
- Reconcile M82 STT audio-ms and TTS Unicode-scalar/output-audio-ms aggregates
  against the selected providers' production usage exports and invoices. Prove
  that no connection/request/minimum fee or unsupported billing unit exists;
  otherwise extend the contract before release. The local signed example rate
  is not a commercial COGS claim.
- Validate the Agent proxy with the selected live provider and measure tool
  calls, latency, quota failures, retry behavior, and cost ceilings. Reconcile
  the M81 committed plus uncertain ledger against provider usage exports and
  invoices; the local pricing fixture is not a commercial cost claim.
- Execute the M74 gate against a disposable live PostgreSQL qualification
  database, then prove cross-Pod admission, crash/expiry takeover, outage
  fail-closed behavior and global limits in the selected cluster before
  horizontal production scaling.
- Deploy M31 against a selected managed HA identity source and prove bounded
  convergence across every real replica. The reference client already enforces
  mTLS, signed conditional fetch, revision floors and four-consumer convergence;
  it does not prove the external source, cluster or regional failure modes.
- Execute M76 verifier-first Voice, Agent and OTA key rotation in the selected
  secret manager and exact seven-service cluster, including forward-only
  rollback and final retirement. Preserve each M77 preflight as subordinate
  evidence, but do not treat the local managed-keyring gate or software-only
  receipt as live rollout evidence.
- Deploy the M78 TLS 1.3 mTLS OTLP path and independently prove zero unknown
  attributes/export loss plus every seven-service target over one complete
  signed 28-day SLO window. The local gate and synthetic collector test are not
  live availability, latency, privacy or retention evidence.
- Run fuzzing, connection/load/soak tests, failover drills, and an external
  security review.
- Push the verified OCI graph to the selected registry, run current scanning,
  Cosign/transparency verification, install and server-validate the M50 signed
  admission bundle, execute M51 against the selected qualification cluster and
  independently verify its receipt, enforce digest-only registry admission, and execute the
  TLS/HA Kubernetes smoke in `OCI_DEPLOYMENT_BASELINE.md`. Offline Kustomize
  parsing is not CEL type-check or live denial evidence.
- Sign the resulting backend supply-chain and live-cluster WORM objects with
  their independent M52 evidence authorities. They are only two of the fixed
  15 evidence domains, including `push_provider_delivery`; backend tests cannot
  by themselves create a product `MARKET_RELEASE_PASS`. M79 schema v2 also
  requires the final builder and independent verifier to directly validate and
  bind the external signed M78 28-day SLO observation, policy and authority
  key; this subordinate proof does not add an eighth service or a sixteenth
  domain. See `../PRODUCT_MARKET_RELEASE_RUNBOOK.md`.
