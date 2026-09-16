#!/usr/bin/env python3
"""Deterministic Ogg/Opus helpers for the M27 reference-codec gate."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable


SCHEMA = "xiaozhi-opus-codec-fixtures-v1"
SERIAL = 0x5849414F
EXPECTED_FIXTURES = {
    "stt-16k-mono-60ms": ("stt_uplink", 16000, 960),
    "tts-24k-mono-60ms": ("tts_downlink", 24000, 1440),
}


class CodecFixtureError(RuntimeError):
    """Fail-closed fixture or reference-codec validation error."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def ffmpeg_identity(ffmpeg: Path) -> tuple[str, str]:
    if not ffmpeg.is_file():
        raise CodecFixtureError(f"FFmpeg binary does not exist: {ffmpeg}")
    try:
        result = subprocess.run(
            [str(ffmpeg), "-version"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CodecFixtureError(f"cannot identify FFmpeg: {error}") from error
    first_line = result.stdout.decode("utf-8", "replace").splitlines()[0]
    return first_line, sha256_file(ffmpeg)


def _ogg_crc(data: bytes) -> int:
    crc = 0
    for value in data:
        crc ^= value << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if crc & 0x80000000 else (crc << 1) & 0xFFFFFFFF
    return crc


def _lacing(packet: bytes) -> bytes:
    if not packet:
        return b"\x00"
    segments = [255] * (len(packet) // 255)
    remainder = len(packet) % 255
    if remainder or not segments:
        segments.append(remainder)
    else:
        segments.append(0)
    if len(segments) > 255:
        raise CodecFixtureError("Opus packet requires more than one Ogg page")
    return bytes(segments)


def _ogg_page(packet: bytes, header_type: int, granule: int, sequence: int) -> bytes:
    segments = _lacing(packet)
    header = bytearray(
        b"OggS"
        + bytes([0, header_type])
        + struct.pack("<QII", granule, SERIAL, sequence)
        + b"\x00\x00\x00\x00"
        + bytes([len(segments)])
        + segments
    )
    page = header + packet
    struct.pack_into("<I", page, 22, _ogg_crc(page))
    return bytes(page)


def wrap_raw_opus(packet: bytes, input_sample_rate: int, duration_ms: int = 60) -> bytes:
    if not packet:
        raise CodecFixtureError("cannot wrap an empty Opus packet")
    if input_sample_rate not in (16000, 24000):
        raise CodecFixtureError("product fixtures permit only 16 kHz or 24 kHz")
    if duration_ms != 60:
        raise CodecFixtureError("product fixtures require exactly 60 ms")
    opus_head = b"OpusHead" + bytes([1, 1]) + struct.pack("<HIhB", 0, input_sample_rate, 0, 0)
    vendor = b"xiaozhi-agent-platform M27"
    opus_tags = b"OpusTags" + struct.pack("<I", len(vendor)) + vendor + struct.pack("<I", 0)
    granule = duration_ms * 48
    return b"".join(
        (
            _ogg_page(opus_head, 0x02, 0, 0),
            _ogg_page(opus_tags, 0x00, 0, 1),
            _ogg_page(packet, 0x04, granule, 2),
        )
    )


def parse_ogg_packets(data: bytes) -> list[bytes]:
    packets: list[bytes] = []
    current = bytearray()
    offset = 0
    while offset < len(data):
        if offset + 27 > len(data) or data[offset : offset + 4] != b"OggS":
            raise CodecFixtureError("invalid or truncated Ogg page")
        segment_count = data[offset + 26]
        header_end = offset + 27 + segment_count
        if header_end > len(data):
            raise CodecFixtureError("truncated Ogg lacing table")
        lengths = data[offset + 27 : header_end]
        page_end = header_end + sum(lengths)
        if page_end > len(data):
            raise CodecFixtureError("truncated Ogg page payload")
        page = bytearray(data[offset:page_end])
        expected_crc = struct.unpack_from("<I", page, 22)[0]
        page[22:26] = b"\x00\x00\x00\x00"
        if _ogg_crc(page) != expected_crc:
            raise CodecFixtureError("Ogg page checksum mismatch")
        body_offset = header_end
        for length in lengths:
            current.extend(data[body_offset : body_offset + length])
            body_offset += length
            if length < 255:
                packets.append(bytes(current))
                current.clear()
        offset = page_end
    if current:
        raise CodecFixtureError("unterminated Ogg packet")
    return packets


def decode_packet(ffmpeg: Path, packet: bytes, sample_rate: int) -> bytes:
    ogg = wrap_raw_opus(packet, sample_rate)
    try:
        result = subprocess.run(
            [
                str(ffmpeg), "-nostdin", "-hide_banner", "-loglevel", "error",
                "-c:a", "opus", "-f", "ogg", "-i", "pipe:0", "-map", "0:a:0", "-ac", "1",
                "-ar", str(sample_rate), "-c:a", "pcm_s16le", "-f", "s16le", "pipe:1",
            ],
            input=ogg,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CodecFixtureError(f"reference decode could not run: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise CodecFixtureError(f"reference decoder rejected packet: {detail}")
    return result.stdout


def generate_encoded_packets(ffmpeg: Path, sample_rate: int, frequency: int) -> list[bytes]:
    with tempfile.TemporaryDirectory(prefix="xiaozhi-opus-") as temporary:
        output = Path(temporary) / "fixture.opus"
        command = [
            str(ffmpeg), "-nostdin", "-hide_banner", "-loglevel", "error", "-y",
            "-f", "lavfi", "-i",
            f"sine=frequency={frequency}:sample_rate={sample_rate}:duration=0.18",
            "-ac", "1", "-c:a", "libopus", "-application", "voip",
            "-frame_duration", "60", "-vbr", "off", "-b:a", "24000",
            "-f", "opus", str(output),
        ]
        try:
            result = subprocess.run(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise CodecFixtureError(f"fixture encoding could not run: {error}") from error
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", "replace").strip()
            raise CodecFixtureError(f"fixture encoder failed: {detail}")
        packets = parse_ogg_packets(output.read_bytes())
    if len(packets) < 5 or packets[0][:8] != b"OpusHead" or packets[1][:8] != b"OpusTags":
        raise CodecFixtureError("encoder did not produce expected Ogg Opus headers and data")
    return packets[2:]


def load_manifest(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CodecFixtureError(f"cannot read fixture manifest: {error}") from error
    if not isinstance(value, dict):
        raise CodecFixtureError("fixture manifest root must be an object")
    return value


def _decode_base64(value: object) -> bytes:
    if not isinstance(value, str):
        raise CodecFixtureError("packet_base64 must be a string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise CodecFixtureError("packet_base64 is not canonical base64") from error
    if base64.b64encode(decoded).decode("ascii") != value:
        raise CodecFixtureError("packet_base64 is not canonical base64")
    return decoded


def verify_manifest(manifest: dict, ffmpeg: Path) -> list[dict]:
    if manifest.get("schema") != SCHEMA:
        raise CodecFixtureError("unsupported fixture-manifest schema")
    if manifest.get("qualification_only") is not True:
        raise CodecFixtureError("manifest must preserve the qualification-only boundary")
    toolchain = manifest.get("reference_toolchain")
    if not isinstance(toolchain, dict):
        raise CodecFixtureError("reference_toolchain is missing")
    version, binary_hash = ffmpeg_identity(ffmpeg)
    if toolchain.get("ffmpeg_version") != version:
        raise CodecFixtureError("FFmpeg version does not match the reviewed fixture toolchain")
    if toolchain.get("ffmpeg_sha256") != binary_hash:
        raise CodecFixtureError("FFmpeg binary hash does not match the reviewed fixture toolchain")
    if toolchain.get("encoder_backend") != "libopus" or toolchain.get("decoder_backend") != "ffmpeg-native-opus":
        raise CodecFixtureError("fixture toolchain must preserve independent libopus encode/native decode")
    fixtures = manifest.get("fixtures")
    if not isinstance(fixtures, list) or len(fixtures) != len(EXPECTED_FIXTURES):
        raise CodecFixtureError("manifest must contain exactly the two product fixtures")

    results: list[dict] = []
    seen: set[str] = set()
    for fixture in fixtures:
        if not isinstance(fixture, dict):
            raise CodecFixtureError("fixture entry must be an object")
        name = fixture.get("name")
        if name not in EXPECTED_FIXTURES or name in seen:
            raise CodecFixtureError("fixture names must be unique and product-defined")
        seen.add(name)
        direction, sample_rate, expected_samples = EXPECTED_FIXTURES[name]
        if fixture.get("direction") != direction:
            raise CodecFixtureError(f"{name}: wrong direction")
        if fixture.get("sample_rate_hz") != sample_rate or fixture.get("channels") != 1:
            raise CodecFixtureError(f"{name}: wrong rate or channel count")
        if fixture.get("duration_ms") != 60 or fixture.get("decoded_sample_count") != expected_samples:
            raise CodecFixtureError(f"{name}: wrong duration or sample count")
        packet = _decode_base64(fixture.get("packet_base64"))
        if not 2 <= len(packet) <= 1276:
            raise CodecFixtureError(f"{name}: packet size is outside the product fixture limit")
        if fixture.get("packet_bytes") != len(packet) or fixture.get("packet_sha256") != sha256_bytes(packet):
            raise CodecFixtureError(f"{name}: packet length or hash mismatch")
        pcm = decode_packet(ffmpeg, packet, sample_rate)
        if len(pcm) != expected_samples * 2:
            raise CodecFixtureError(
                f"{name}: decoder emitted {len(pcm) // 2} samples; expected {expected_samples}"
            )
        pcm_hash = sha256_bytes(pcm)
        if fixture.get("decoded_pcm_s16le_sha256") != pcm_hash:
            raise CodecFixtureError(f"{name}: decoded PCM hash differs from reviewed reference")
        if not any(pcm):
            raise CodecFixtureError(f"{name}: decoded PCM is silent")
        results.append(
            {
                "name": name,
                "packet_bytes": len(packet),
                "packet_sha256": sha256_bytes(packet),
                "decoded_samples": expected_samples,
                "decoded_pcm_s16le_sha256": pcm_hash,
            }
        )
    if seen != set(EXPECTED_FIXTURES):
        raise CodecFixtureError("required product fixture is missing")
    return sorted(results, key=lambda item: item["name"])


def make_manifest(ffmpeg: Path) -> dict:
    version, binary_hash = ffmpeg_identity(ffmpeg)
    profiles: Iterable[tuple[str, str, int, int, int]] = (
        ("stt-16k-mono-60ms", "stt_uplink", 16000, 997, 960),
        ("tts-24k-mono-60ms", "tts_downlink", 24000, 1301, 1440),
    )
    fixtures = []
    for name, direction, sample_rate, frequency, expected_samples in profiles:
        packets = generate_encoded_packets(ffmpeg, sample_rate, frequency)
        if len(packets) < 3:
            raise CodecFixtureError(f"{name}: encoder produced too few data packets")
        packet = packets[1]
        pcm = decode_packet(ffmpeg, packet, sample_rate)
        if len(pcm) != expected_samples * 2:
            raise CodecFixtureError(f"{name}: reference decode emitted the wrong sample count")
        fixtures.append(
            {
                "name": name,
                "direction": direction,
                "sample_rate_hz": sample_rate,
                "channels": 1,
                "duration_ms": 60,
                "source": {
                    "kind": "lavfi_sine",
                    "frequency_hz": frequency,
                    "source_duration_ms": 180,
                    "selected_data_packet_index": 1,
                },
                "encoder": {
                    "codec": "libopus",
                    "application": "voip",
                    "bit_rate": 24000,
                    "vbr": "off",
                    "frame_duration_ms": 60,
                },
                "packet_bytes": len(packet),
                "packet_base64": base64.b64encode(packet).decode("ascii"),
                "packet_sha256": sha256_bytes(packet),
                "decoded_sample_count": expected_samples,
                "decoded_pcm_s16le_sha256": sha256_bytes(pcm),
            }
        )
    return {
        "schema": SCHEMA,
        "qualification_only": True,
        "boundary": (
            "Reference decode proves fixture bitstream acceptance and exact sample count; "
            "it does not qualify an ESP codec, board audio path, or speech provider."
        ),
        "reference_toolchain": {
            "ffmpeg_version": version,
            "ffmpeg_sha256": binary_hash,
            "encoder_backend": "libopus",
            "decoder_backend": "ffmpeg-native-opus",
            "license_boundary": (
                "Reviewed GPL-enabled qualification binary; it is not linked, copied, or shipped "
                "with firmware or gateway services."
            ),
        },
        "fixtures": fixtures,
    }
