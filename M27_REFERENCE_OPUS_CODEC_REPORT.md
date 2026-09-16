# M27 reference Opus codec gate report

Date: 2026-08-09

## Result

M27 closes the narrow gap between M25 packet-layout validation and a real
codec. It adds two deterministic, non-private Opus fixtures matching the exact
product contract:

- STT uplink: 16 kHz, mono, 60 ms, 960 decoded samples;
- TTS downlink: 24 kHz, mono, 60 ms, 1,440 decoded samples.

The fixtures are encoded with `libopus` and then decoded through FFmpeg's
independent native Opus decoder. Each raw packet is placed in a minimal,
deterministic Ogg Opus stream with zero pre-skip and an exact 60 ms granule.
Verification rejects a wrong decoder binary, changed packet, changed duration,
duplicate profile, wrong sample count, decode error, silent output, or changed
decoded PCM hash.

## Frozen evidence

The reviewed qualification binary is FFmpeg 7.0 with SHA-256:

`326895b16940f238d76e902fc71150f10c388c281985756f9850ff800a2f1499`

The canonical fixture manifest is
`gateway/testdata/speech/opus-codec-fixtures.json`. Two clean generations were
byte-identical at 2,716 bytes, with SHA-256
`5303039b7e261ccd3ff21e2226ed8a8c6021d45b908a91d0b5da825a242eb5f7`.
The fixture evidence is:

| Direction | Packet bytes | Packet SHA-256 | Samples | Decoded PCM SHA-256 |
| --- | ---: | --- | ---: | --- |
| STT 16 kHz | 180 | `4fd29fa6857f33155530184649aec98217344c25ca46df6e0d46ea22b6825da2` | 960 | `5ecca2a2c0492a9eadc9dfd28f86f51cbc2d61b5ecfe0d97a00cf7d1d36e722b` |
| TTS 24 kHz | 180 | `c6da4bba20cfb2e4828673b026d386f5a81bbdfa3c1d658e0e458c28ce22b145` | 1,440 | `7a2cabf0ad1d61bd4e25131f68bc1489d7c7bf9434638d09657d4257714adf5a` |

The Go `opuspacket` tests consume the same checked-in manifest and require both
packets to satisfy mono and exact 60 ms gateway policy. This prevents the
reference fixtures and production packet admission rules from drifting apart.

## Verification

The dedicated M27 flow passed deterministic regeneration, exact decoder and
PCM verification, plus negative packet-tamper, duration-drift,
decoder-identity and duplicate-profile cases. Four new dependency-free policy
tests validate the Ogg wrapper, checksum/lacing boundaries, product rates and
canonical fixture manifest.

The final full regression passed 23 C host suites, 7 gateway-contract tests,
16 factory tests, 114 tooling tests, 5 independent generation-state tests, all
Go package tests, `go vet`, and the Go race suite. M27 changes qualification
fixtures, tests and documentation only; firmware and M24 signing hashes remain
unchanged.

## Honest boundary

This is a qualification fixture gate, not a production media service. The
hash-pinned FFmpeg build is GPL-enabled and is neither redistributed nor
linked into firmware or Go services. A different qualification binary must be
reviewed and the manifest deliberately regenerated; silently accepting a
decoder mismatch is prohibited.

The synthetic sine fixtures do not prove that a candidate STT/TTS adapter emits
correct audio, that ESP32's managed codec produces equivalent output, or that
the BOX3 microphone, speaker, AEC/half-duplex policy and acoustic path work.
Captured provider packets, privacy/consent controls, Mandarin and code-switching
quality, latency/cancellation/failure/cost/soak tests, and real-board canaries
remain mandatory under `SPEECH_PROVIDER_ACCEPTANCE.md`.
