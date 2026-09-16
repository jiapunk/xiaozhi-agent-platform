# M28 speech-adapter qualification report

Date: 2026-08-09

## Result

M28 adds the offline qualification runner needed to apply M25 and M27 to a real
private STT/TTS adapter. It uses the production gateway's WebSocket STT and
framed-HTTP TTS clients, the exact M27 reference decoder, approved corpus input
and explicit latency thresholds. A successful run emits a new Ed25519-signed,
canonical receipt; a failed run emits no receipt.

The result intentionally cannot claim a product release. Insecure local runs
are fixed to `TEST_HARNESS_PASS`, production HTTPS/WSS runs can reach only
`PROTOCOL_PASS`, and every receipt has `production_ready: false` plus five
mandatory unresolved production gates.

## Protocol and codec coverage

The runner verifies:

- strict readiness and live contract versions for both private services;
- real decode of every 16 kHz STT input packet and every 24 kHz TTS output
  packet with the hash-pinned M27 FFmpeg native Opus decoder;
- exact 60 ms sample counts: 960 uplink and 1,440 per downlink frame;
- exact STT transcript match and single-final enforcement after stop without
  writing text or text hashes to the receipt;
- a separate STT abort observation;
- parallel TTS cases with distinct packet and PCM aggregate evidence;
- frozen first-frame, completion, final and cancellation latency thresholds;
- TTS cancellation after one decoded frame with no buffered second-frame
  emission.

The TTS client itself was hardened to check `ctx.Err()` before reading each
framed packet and immediately after callback emission. This closes a real
buffering race: cancellation no longer depends on the next network read
failing before stale audio reaches the caller.

## Evidence boundary

The signed receipt binds:

- immutable run and candidate IDs;
- SHA-256 of the candidate config;
- a domain-separated digest of the four actual tested endpoints;
- the externally approved qualification-runner source/image digest;
- a domain-separated digest of the exact private CA or system-trust policy;
- corpus SHA-256 and consent class;
- M27 fixture-manifest, FFmpeg binary and version identity;
- frozen thresholds, measured metadata-only results and timestamps;
- exact Ed25519 signing-key ID and signature domain.

It stores no bearer token, endpoint URL, transcript, synthesis text, text hash,
raw Opus or PCM. Output creation is exclusive and refuses overwrite. The
independent verifier requires external expectations for candidate, run,
config, endpoint set, runner build, transport trust, corpus/consent, M27
manifest, FFmpeg, all four thresholds and trusted public key; it can explicitly
reject development-transport evidence.

The two qualification commands are offline operator tools and are not added to
the five-service M20 backend OCI release graph. The separately supplied,
GPL-enabled FFmpeg qualification binary remains outside all firmware and
backend release artifacts.

## Verification

The controlled harness passed with the exact M27 FFmpeg 7.0 binary
`326895b16940f238d76e902fc71150f10c388c281985756f9850ff800a2f1499`.
It exercised real reference decode, STT stop/final, STT abort, two parallel TTS
streams, one-frame cancellation, ephemeral Ed25519 signing and independent
verification. Ordinary tests use an injected decoder only to keep the default
suite portable; the dedicated gate proves the real decoder path separately.

Negative tests reject noncanonical or unapproved corpus input, receipt tamper,
wrong endpoint/trust/threshold expectations, development-to-production
promotion, over-permissive private-key permissions, output overwrite,
query-string endpoints, invalid CA
data, malformed streams and buffered post-cancel frames.

The final regression passed 23 C host suites, 7 gateway-contract tests, 16
factory tests, 119 tooling tests, 5 independent generation-state tests, all Go
package tests, `go vet`, and the Go race suite. Both the M27 codec gate and M28
live harness gate passed again. M28 changes no firmware code or binary, so the
M24 firmware and signing hashes remain unchanged.

## Honest boundary

The checked-in synthetic corpus and controlled adapter are harness evidence,
not provider evidence. No commercial STT/TTS endpoint, real speech corpus,
provider cancellation/billing telemetry, human language-quality score or BOX3
hardware was used. A primary and backup adapter must each produce a separately
signed `PROTOCOL_PASS` receipt against approved captured speech, then complete
privacy/legal, language, cost, load/soak, failure, workload-identity and real
ESP/BOX3 canary gates before selection.
