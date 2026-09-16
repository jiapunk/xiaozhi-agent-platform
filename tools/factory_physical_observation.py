#!/usr/bin/env python3
"""Canonical externally-signed physical factory flash observation contract."""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import re
from datetime import datetime, timedelta
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


SCHEMA = "xz-factory-physical-flash-observation-v1"
ENVIRONMENT = "PRODUCTION_FACTORY"
PHASE = "PRE_SECURE_DOWNLOAD_LOCK"
RESULT = "PHYSICAL_FLASH_READBACK_PASS"
ESPTOOL_VERSION = "5.3.1"
MAX_JSON_BYTES = 128 * 1024
MAX_PUBLIC_KEY_BYTES = 16 * 1024
IDENTIFIER = re.compile(r"^[A-Za-z0-9:_.-]{1,128}$")
DEVICE_ID = re.compile(r"^xz-[0-9a-f]{12}$")
MAC_ADDRESS = re.compile(r"^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$")
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")

REGIONS = (
    ("bootloader", 0x00000),
    ("partition_table", 0x10000),
    ("nvs_factory", 0x11000),
    ("ota_data_initial", 0x21000),
    ("application", 0x40000),
)


class PhysicalObservationError(ValueError):
    pass


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PhysicalObservationError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def parse_canonical(data: bytes, *, signed: bool) -> dict[str, Any]:
    label = "physical observation receipt" if signed else "physical observation request"
    if not data or len(data) > MAX_JSON_BYTES:
        raise PhysicalObservationError(f"{label} size is invalid")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PhysicalObservationError(f"{label} is invalid JSON") from error
    if not isinstance(value, dict) or canonical_json(value) != data:
        raise PhysicalObservationError(f"{label} is not canonical JSON")
    validate(value, signed=signed)
    return value


def _exact(value: Any, members: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PhysicalObservationError(f"{label} must be an object")
    if set(value) != members:
        missing = sorted(members - set(value))
        extra = sorted(set(value) - members)
        raise PhysicalObservationError(
            f"{label} members differ: missing={missing}, extra={extra}"
        )
    return value


def _string(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise PhysicalObservationError(f"{label} has invalid format")
    return value


def _integer(value: Any, minimum: int, maximum: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PhysicalObservationError(f"{label} must be an integer")
    if value < minimum or value > maximum:
        raise PhysicalObservationError(f"{label} is outside the allowed range")
    return value


def _true(value: Any, label: str) -> None:
    if value is not True:
        raise PhysicalObservationError(f"{label} must be true")


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value
    ):
        raise PhysicalObservationError(f"{label} must be whole-second RFC3339 UTC")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise PhysicalObservationError(f"{label} is not a valid timestamp") from error


def _signature(value: Any) -> bytes:
    if not isinstance(value, str) or "=" in value:
        raise PhysicalObservationError("signature must be unpadded base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except (ValueError, binascii.Error) as error:
        raise PhysicalObservationError("signature is invalid base64url") from error
    if (
        len(decoded) != 64
        or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value
    ):
        raise PhysicalObservationError("signature is non-canonical or not 64 bytes")
    return decoded


def _efuse_field(lines: list[str], name: str) -> str:
    for index, line in enumerate(lines):
        if line.startswith(name + " "):
            combined = line
            if "=" not in combined and index + 1 < len(lines):
                combined += " " + lines[index + 1]
            return " ".join(combined.split())
    raise PhysicalObservationError(f"eFuse summary is missing {name}")


def validate_efuse_summary(data: bytes, *, base_mac: str, secure_version: int) -> None:
    if not data or len(data) > 2 * 1024 * 1024:
        raise PhysicalObservationError("eFuse summary size is invalid")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PhysicalObservationError("eFuse summary is not UTF-8") from error
    if "espefuse v5.3.1" not in text:
        raise PhysicalObservationError("eFuse summary is not from espefuse 5.3.1")
    lines = text.splitlines()
    checks = {
        "DIS_DOWNLOAD_MODE": "= False",
        "DIS_DOWNLOAD_MANUAL_ENCRYPT": "= True",
        "SPI_BOOT_CRYPT_CNT": "= Enable",
        "SECURE_BOOT_EN": "= True",
        "ENABLE_SECURITY_DOWNLOAD": "= False",
    }
    for name, expected in checks.items():
        if expected not in _efuse_field(lines, name):
            raise PhysicalObservationError(f"eFuse summary {name} state differs")
    if "(0b111)" not in _efuse_field(lines, "SPI_BOOT_CRYPT_CNT"):
        raise PhysicalObservationError("eFuse summary flash-encryption count is not release")
    mac_line = _efuse_field(lines, "MAC")
    if f"= {base_mac}" not in mac_line or "(OK)" not in mac_line:
        raise PhysicalObservationError("eFuse summary base MAC differs")
    version_line = _efuse_field(lines, "SECURE_VERSION")
    if (
        f"= {secure_version} " not in version_line
        and f"= {secure_version}(" not in version_line
    ):
        raise PhysicalObservationError("eFuse summary anti-rollback version differs")


def validate(value: dict[str, Any], *, signed: bool) -> None:
    members = {
        "schema",
        "observation_id",
        "environment",
        "phase",
        "transaction",
        "product",
        "release",
        "station",
        "capture",
        "started_at",
        "finished_at",
        "result",
        "signature_algorithm",
    }
    if signed:
        members.add("signature_b64url")
    root = _exact(value, members, "physical observation")
    if root["schema"] != SCHEMA:
        raise PhysicalObservationError("physical observation schema differs")
    _string(root["observation_id"], IDENTIFIER, "observation ID")
    if root["environment"] != ENVIRONMENT:
        raise PhysicalObservationError("physical observation is not production-factory evidence")
    if root["phase"] != PHASE:
        raise PhysicalObservationError("physical observation phase differs")
    if root["result"] != RESULT:
        raise PhysicalObservationError("physical observation result is not PASS")
    if root["signature_algorithm"] != "Ed25519":
        raise PhysicalObservationError("signature algorithm must be Ed25519")
    if signed:
        _signature(root["signature_b64url"])

    transaction = _exact(
        root["transaction"],
        {"transaction_id", "attempt_id", "device_id", "serial_number", "base_mac"},
        "observation transaction",
    )
    for name in ("transaction_id", "attempt_id", "serial_number"):
        _string(transaction[name], IDENTIFIER, name)
    _string(transaction["device_id"], DEVICE_ID, "device ID")
    _string(transaction["base_mac"], MAC_ADDRESS, "base MAC")
    if transaction["device_id"] != "xz-" + transaction["base_mac"].replace(
        ":", ""
    ).lower():
        raise PhysicalObservationError("device ID does not derive from base MAC")

    product = _exact(
        root["product"],
        {"sku", "board", "hardware_revision", "chip_model", "chip_revision"},
        "observation product",
    )
    if (
        product["sku"] != "VOICE_AGENT_KIT_BOX3"
        or product["board"] != "esp32s3-box3"
        or product["hardware_revision"] != 1
        or product["chip_model"] != "ESP32-S3"
    ):
        raise PhysicalObservationError("physical observation product differs")
    _integer(product["chip_revision"], 0, 999, "chip revision")

    release = _exact(
        root["release"],
        {
            "signing_request_sha256",
            "signed_artifact_verification_sha256",
            "anti_rollback_secure_version",
        },
        "observation release",
    )
    _string(release["signing_request_sha256"], SHA256_HEX, "signing request hash")
    _string(
        release["signed_artifact_verification_sha256"],
        SHA256_HEX,
        "signed-artifact receipt hash",
    )
    _integer(
        release["anti_rollback_secure_version"], 1, 16, "anti-rollback secure version"
    )

    station = _exact(
        root["station"],
        {
            "id",
            "operators",
            "fixture_id",
            "fixture_version",
            "fixture_calibration_sha256",
            "signing_key_id",
            "esptool_version",
        },
        "observation station",
    )
    for name in ("id", "fixture_id", "fixture_version", "signing_key_id"):
        _string(station[name], IDENTIFIER, f"station {name}")
    operators = station["operators"]
    if (
        not isinstance(operators, list)
        or not 2 <= len(operators) <= 4
        or len(set(operators)) != len(operators)
    ):
        raise PhysicalObservationError("station needs two to four distinct operators")
    for index, operator in enumerate(operators):
        _string(operator, IDENTIFIER, f"operator {index}")
    _string(
        station["fixture_calibration_sha256"], SHA256_HEX, "fixture calibration hash"
    )
    if station["esptool_version"] != ESPTOOL_VERSION:
        raise PhysicalObservationError("esptool version differs from frozen profile")

    capture = _exact(
        root["capture"],
        {
            "transport",
            "port_fingerprint_sha256",
            "chip_probe_log_sha256",
            "efuse_summary_before_sha256",
            "efuse_summary_after_sha256",
            "flash_encryption_enabled",
            "download_manual_encrypt_disabled",
            "secure_download_lock_pending",
            "raw_readback_pass",
            "regions",
        },
        "physical capture",
    )
    if capture["transport"] != "UART_ROM_DOWNLOAD":
        raise PhysicalObservationError("capture transport differs")
    for name in (
        "port_fingerprint_sha256",
        "chip_probe_log_sha256",
        "efuse_summary_before_sha256",
        "efuse_summary_after_sha256",
    ):
        _string(capture[name], SHA256_HEX, name)
    if (
        capture["efuse_summary_before_sha256"]
        != capture["efuse_summary_after_sha256"]
    ):
        raise PhysicalObservationError("eFuse state changed during readback capture")
    for name in (
        "flash_encryption_enabled",
        "download_manual_encrypt_disabled",
        "secure_download_lock_pending",
        "raw_readback_pass",
    ):
        _true(capture[name], name)
    regions = capture["regions"]
    if not isinstance(regions, list) or len(regions) != len(REGIONS):
        raise PhysicalObservationError("physical readback region set differs")
    for index, (name, offset) in enumerate(REGIONS):
        region = _exact(
            regions[index],
            {"name", "offset", "size", "readback_sha256"},
            f"physical readback region {index}",
        )
        if region["name"] != name or region["offset"] != offset:
            raise PhysicalObservationError("physical readback region order differs")
        _integer(region["size"], 1, 0x581000, "physical readback size")
        _string(region["readback_sha256"], SHA256_HEX, "physical readback hash")

    started = _timestamp(root["started_at"], "started_at")
    finished = _timestamp(root["finished_at"], "finished_at")
    if finished <= started or finished - started > timedelta(hours=1):
        raise PhysicalObservationError("physical observation time window is invalid")


def signature_payload(receipt: Mapping[str, Any]) -> bytes:
    unsigned = copy.deepcopy(dict(receipt))
    unsigned.pop("signature_b64url", None)
    validate(unsigned, signed=False)
    return canonical_json(unsigned)


def verify_receipt(receipt: dict[str, Any], public_key_pem: bytes) -> None:
    validate(receipt, signed=True)
    if (
        not 1 <= len(public_key_pem) <= MAX_PUBLIC_KEY_BYTES
        or b"PRIVATE KEY" in public_key_pem
    ):
        raise PhysicalObservationError("observation verifier requires a bounded public key")
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
    except (TypeError, ValueError) as error:
        raise PhysicalObservationError("observation public key is invalid") from error
    if not isinstance(public_key, Ed25519PublicKey):
        raise PhysicalObservationError("observation public key must be Ed25519")
    try:
        public_key.verify(_signature(receipt["signature_b64url"]), signature_payload(receipt))
    except InvalidSignature as error:
        raise PhysicalObservationError("physical observation signature is invalid") from error


def build_request(
    *,
    observation_id: str,
    transaction_id: str,
    attempt_id: str,
    device_id: str,
    serial_number: str,
    base_mac: str,
    chip_revision: int,
    signing_request_sha256: str,
    signed_artifact_verification_sha256: str,
    anti_rollback_secure_version: int,
    station_id: str,
    operators: list[str],
    fixture_id: str,
    fixture_version: str,
    fixture_calibration_sha256: str,
    signing_key_id: str,
    port_fingerprint_sha256: str,
    chip_probe_log_sha256: str,
    efuse_summary_before: bytes,
    efuse_summary_after: bytes,
    readbacks: Mapping[str, bytes],
    started_at: str,
    finished_at: str,
) -> dict[str, Any]:
    if set(readbacks) != {name for name, _ in REGIONS}:
        raise PhysicalObservationError("readback input set differs")
    if efuse_summary_before != efuse_summary_after:
        raise PhysicalObservationError("eFuse state changed during readback capture")
    validate_efuse_summary(
        efuse_summary_before,
        base_mac=base_mac,
        secure_version=anti_rollback_secure_version,
    )
    result = {
        "schema": SCHEMA,
        "observation_id": observation_id,
        "environment": ENVIRONMENT,
        "phase": PHASE,
        "transaction": {
            "transaction_id": transaction_id,
            "attempt_id": attempt_id,
            "device_id": device_id,
            "serial_number": serial_number,
            "base_mac": base_mac,
        },
        "product": {
            "sku": "VOICE_AGENT_KIT_BOX3",
            "board": "esp32s3-box3",
            "hardware_revision": 1,
            "chip_model": "ESP32-S3",
            "chip_revision": chip_revision,
        },
        "release": {
            "signing_request_sha256": signing_request_sha256,
            "signed_artifact_verification_sha256": signed_artifact_verification_sha256,
            "anti_rollback_secure_version": anti_rollback_secure_version,
        },
        "station": {
            "id": station_id,
            "operators": operators,
            "fixture_id": fixture_id,
            "fixture_version": fixture_version,
            "fixture_calibration_sha256": fixture_calibration_sha256,
            "signing_key_id": signing_key_id,
            "esptool_version": ESPTOOL_VERSION,
        },
        "capture": {
            "transport": "UART_ROM_DOWNLOAD",
            "port_fingerprint_sha256": port_fingerprint_sha256,
            "chip_probe_log_sha256": chip_probe_log_sha256,
            "efuse_summary_before_sha256": hashlib.sha256(
                efuse_summary_before
            ).hexdigest(),
            "efuse_summary_after_sha256": hashlib.sha256(
                efuse_summary_after
            ).hexdigest(),
            "flash_encryption_enabled": True,
            "download_manual_encrypt_disabled": True,
            "secure_download_lock_pending": True,
            "raw_readback_pass": True,
            "regions": [
                {
                    "name": name,
                    "offset": offset,
                    "size": len(readbacks[name]),
                    "readback_sha256": hashlib.sha256(readbacks[name]).hexdigest(),
                }
                for name, offset in REGIONS
            ],
        },
        "started_at": started_at,
        "finished_at": finished_at,
        "result": RESULT,
        "signature_algorithm": "Ed25519",
    }
    validate(result, signed=False)
    return result


def bind_receipt(
    *,
    receipt: dict[str, Any],
    transaction_id: str,
    attempt_id: str,
    device_id: str,
    serial_number: str,
    base_mac: str,
    chip_revision: int,
    signing_request_sha256: str,
    signed_artifact_verification_sha256: str,
    anti_rollback_secure_version: int,
    readbacks: Mapping[str, bytes],
) -> None:
    expected_transaction = {
        "transaction_id": transaction_id,
        "attempt_id": attempt_id,
        "device_id": device_id,
        "serial_number": serial_number,
        "base_mac": base_mac,
    }
    if receipt["transaction"] != expected_transaction:
        raise PhysicalObservationError("physical observation transaction differs")
    if receipt["product"]["chip_revision"] != chip_revision:
        raise PhysicalObservationError("physical observation chip revision differs")
    if receipt["release"] != {
        "signing_request_sha256": signing_request_sha256,
        "signed_artifact_verification_sha256": signed_artifact_verification_sha256,
        "anti_rollback_secure_version": anti_rollback_secure_version,
    }:
        raise PhysicalObservationError("physical observation release differs")
    if set(readbacks) != {name for name, _ in REGIONS}:
        raise PhysicalObservationError("physical observation readback set differs")
    for item, (name, offset) in zip(receipt["capture"]["regions"], REGIONS):
        data = readbacks[name]
        if (
            item["name"] != name
            or item["offset"] != offset
            or item["size"] != len(data)
            or item["readback_sha256"] != hashlib.sha256(data).hexdigest()
        ):
            raise PhysicalObservationError(f"physical observation {name} readback differs")
