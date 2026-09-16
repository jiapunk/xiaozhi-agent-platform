#!/usr/bin/env python3
"""Canonical factory-authenticated product SKU manifest helpers."""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any


DOMAIN = b"XIAOZHI-PRODUCT-SKU-MANIFEST-V1\x00"
DOMAIN_NAME = "XIAOZHI-PRODUCT-SKU-MANIFEST-V1"
MAGIC = b"XSKU"
SCHEMA_VERSION = 1
AUTHENTICATED_BYTES = 38
TAG_BYTES = 32
MANIFEST_BYTES = AUTHENTICATED_BYTES + TAG_BYTES
MANIFEST_ID_BYTES = 16
MAC = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
MANIFEST_ID = re.compile(r"^[0-9a-f]{32}$")

PROFILES: dict[str, dict[str, Any]] = {
    "VOICE_AGENT_KIT_BOX3": {
        "sku_id": 2,
        "board": "esp32s3-box3",
        "hardware_revision": 1,
        "identity_hmac_key_slot": 5,
    }
}


class FactorySKUManifestError(ValueError):
    pass


def _base_mac(value: str) -> tuple[bytes, str]:
    if not isinstance(value, str) or not MAC.fullmatch(value):
        raise FactorySKUManifestError(
            "base MAC must use six colon-separated hexadecimal octets"
        )
    raw = bytes.fromhex(value.replace(":", ""))
    if raw == bytes(6) or raw == bytes([0xFF]) * 6 or raw[0] & 1:
        raise FactorySKUManifestError("base MAC must be a non-multicast device MAC")
    return raw, ":".join(f"{byte:02X}" for byte in raw)


def _manifest_id(value: str) -> bytes:
    if not isinstance(value, str) or not MANIFEST_ID.fullmatch(value):
        raise FactorySKUManifestError("manifest ID must be 32 lowercase hex characters")
    raw = bytes.fromhex(value)
    if raw == bytes(MANIFEST_ID_BYTES) or raw == bytes([0xFF]) * MANIFEST_ID_BYTES:
        raise FactorySKUManifestError("manifest ID cannot be all-zero or all-ff")
    return raw


def _profile(sku: str, board: str, hardware_revision: int) -> dict[str, Any]:
    profile = PROFILES.get(sku)
    if profile is None:
        raise FactorySKUManifestError("SKU has no factory manifest profile")
    if board != profile["board"]:
        raise FactorySKUManifestError("board does not match the frozen SKU profile")
    if isinstance(hardware_revision, bool) or hardware_revision != profile["hardware_revision"]:
        raise FactorySKUManifestError(
            "hardware revision does not match the frozen SKU profile"
        )
    return profile


def build_manifest(
    device_hmac_key: bytes,
    *,
    base_mac: str,
    sku: str,
    board: str,
    hardware_revision: int,
    chip_revision: int,
    factory_record_version: int,
    manifest_id: str,
) -> tuple[bytes, dict[str, Any]]:
    if not isinstance(device_hmac_key, bytes) or len(device_hmac_key) != 32:
        raise FactorySKUManifestError("device HMAC key must be exactly 32 raw bytes")
    profile = _profile(sku, board, hardware_revision)
    mac_raw, mac_text = _base_mac(base_mac)
    if isinstance(chip_revision, bool) or not 0 <= chip_revision <= 999:
        raise FactorySKUManifestError("chip revision must be in 0..999")
    if (
        isinstance(factory_record_version, bool)
        or not 1 <= factory_record_version <= 0xFFFFFFFF
    ):
        raise FactorySKUManifestError("factory record version must be in 1..2^32-1")
    manifest_id_raw = _manifest_id(manifest_id)

    authenticated = bytearray(AUTHENTICATED_BYTES)
    authenticated[0:4] = MAGIC
    authenticated[4] = SCHEMA_VERSION
    authenticated[5] = profile["sku_id"]
    authenticated[6:8] = hardware_revision.to_bytes(2, "little")
    authenticated[8:10] = chip_revision.to_bytes(2, "little")
    authenticated[12:18] = mac_raw
    authenticated[18:22] = factory_record_version.to_bytes(4, "little")
    authenticated[22:38] = manifest_id_raw
    tag = hmac.new(device_hmac_key, DOMAIN + authenticated, hashlib.sha256).digest()
    blob = bytes(authenticated) + tag
    if len(blob) != MANIFEST_BYTES:
        raise AssertionError("internal factory SKU manifest size mismatch")
    evidence = {
        "schema": "xz-factory-sku-manifest-v1",
        "manifest_schema": SCHEMA_VERSION,
        "manifest_id": manifest_id,
        "sku": sku,
        "board": board,
        "hardware_revision": hardware_revision,
        "chip_revision": chip_revision,
        "base_mac": mac_text,
        "factory_record_version": factory_record_version,
        "identity_hmac_key_slot": profile["identity_hmac_key_slot"],
        "authentication_domain": DOMAIN_NAME,
        "nvs_namespace": "prod_sku",
        "nvs_key": "manifest",
        "manifest_size": len(blob),
        "manifest_sha256": hashlib.sha256(blob).hexdigest(),
    }
    return blob, evidence


def parse_and_verify_manifest(
    device_hmac_key: bytes, blob: bytes
) -> dict[str, Any]:
    if not isinstance(device_hmac_key, bytes) or len(device_hmac_key) != 32:
        raise FactorySKUManifestError("device HMAC key must be exactly 32 raw bytes")
    if not isinstance(blob, bytes) or len(blob) != MANIFEST_BYTES:
        raise FactorySKUManifestError("factory SKU manifest has the wrong size")
    if blob[:4] != MAGIC or blob[4] != SCHEMA_VERSION or blob[10:12] != b"\x00\x00":
        raise FactorySKUManifestError("factory SKU manifest header is invalid")
    expected = hmac.new(
        device_hmac_key, DOMAIN + blob[:AUTHENTICATED_BYTES], hashlib.sha256
    ).digest()
    if not hmac.compare_digest(blob[AUTHENTICATED_BYTES:], expected):
        raise FactorySKUManifestError("factory SKU manifest authentication failed")
    sku_id = blob[5]
    matches = [
        (sku, profile)
        for sku, profile in PROFILES.items()
        if profile["sku_id"] == sku_id
    ]
    if len(matches) != 1:
        raise FactorySKUManifestError("factory SKU manifest uses an unknown SKU ID")
    sku, profile = matches[0]
    hardware_revision = int.from_bytes(blob[6:8], "little")
    if hardware_revision != profile["hardware_revision"]:
        raise FactorySKUManifestError("factory SKU manifest hardware revision mismatch")
    chip_revision = int.from_bytes(blob[8:10], "little")
    if chip_revision > 999:
        raise FactorySKUManifestError("factory SKU manifest chip revision is invalid")
    base_mac_raw = blob[12:18]
    base_mac_text = ":".join(f"{byte:02X}" for byte in base_mac_raw)
    _base_mac(base_mac_text)
    record_version = int.from_bytes(blob[18:22], "little")
    if record_version == 0:
        raise FactorySKUManifestError("factory SKU manifest record version is invalid")
    manifest_id_raw = blob[22:38]
    manifest_id = manifest_id_raw.hex()
    _manifest_id(manifest_id)
    return {
        "schema": "xz-factory-sku-manifest-v1",
        "manifest_schema": SCHEMA_VERSION,
        "manifest_id": manifest_id,
        "sku": sku,
        "board": profile["board"],
        "hardware_revision": hardware_revision,
        "chip_revision": chip_revision,
        "base_mac": base_mac_text,
        "factory_record_version": record_version,
        "identity_hmac_key_slot": profile["identity_hmac_key_slot"],
        "authentication_domain": DOMAIN_NAME,
        "nvs_namespace": "prod_sku",
        "nvs_key": "manifest",
        "manifest_size": len(blob),
        "manifest_sha256": hashlib.sha256(blob).hexdigest(),
    }
