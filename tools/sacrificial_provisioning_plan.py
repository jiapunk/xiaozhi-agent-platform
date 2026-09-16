#!/usr/bin/env python3
"""M58 signed, non-executing sacrificial-board provisioning plan contract."""

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


SCHEMA = "xz-sacrificial-provisioning-plan-v1"
ENVIRONMENT = "SACRIFICIAL_HARDWARE_AUTHORIZATION"
SCOPE = "ONE_UNIT_ONE_ATTEMPT_DESTRUCTIVE_QUALIFICATION"
RESULT = "SACRIFICIAL_EXECUTION_AUTHORIZED"
PROFILE = "box3-production-security-v1"
ESPTOOL_VERSION = "5.3.1"
MAX_JSON_BYTES = 512 * 1024
MAX_CAPTURE_BYTES = 2 * 1024 * 1024
MAX_PUBLIC_KEY_BYTES = 16 * 1024
IDENTIFIER = re.compile(r"^[A-Za-z0-9:_.-]{1,128}$")
DEVICE_ID = re.compile(r"^xz-[0-9a-f]{12}$")
MAC_ADDRESS = re.compile(r"^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$")
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")
ZERO_KEY = "0x" + "0" * 64

KEY_PURPOSES = (
    "SECURE_BOOT_DIGEST0",
    "SECURE_BOOT_DIGEST1",
    "SECURE_BOOT_DIGEST2",
    "XTS_AES_128_KEY",
    "HMAC_UP",
    "HMAC_UP",
)
KEY_ROLES = (
    "SECURE_BOOT_AUTHORITY_0",
    "SECURE_BOOT_AUTHORITY_1",
    "SECURE_BOOT_AUTHORITY_2",
    "PER_DEVICE_FLASH_ENCRYPTION",
    "PER_DEVICE_CREDENTIAL_NVS",
    "PER_DEVICE_IDENTITY",
)

OPERATION_PLAN = (
    {
        "sequence": 1,
        "phase": "PREFLIGHT_BOUND",
        "irreversible": False,
        "required_evidence": "SIGNED_PLAN_AND_UNCHANGED_BLANK_SUMMARY",
    },
    {
        "sequence": 2,
        "phase": "SECRET_SLOTS_3_TO_5",
        "irreversible": True,
        "required_evidence": "THREE_UNIQUE_EPHEMERAL_SECRETS_AND_PROTECTION_CONFIRMATION",
    },
    {
        "sequence": 3,
        "phase": "SECURE_BOOT_DIGEST_SLOTS_0_TO_2",
        "irreversible": True,
        "required_evidence": "THREE_ORDERED_RELEASE_DIGESTS_REMAIN_READABLE",
    },
    {
        "sequence": 4,
        "phase": "RD_DIS_WRITE_LOCK",
        "irreversible": True,
        "required_evidence": "RD_DIS_EXACTLY_0X38_BEFORE_LOCK",
    },
    {
        "sequence": 5,
        "phase": "PRE_DOWNLOAD_SECURITY_POLICY",
        "irreversible": True,
        "required_evidence": "M57_SHARED_LOCK_ORDER_AND_SECURE_VERSION",
    },
    {
        "sequence": 6,
        "phase": "SIGNED_THEN_ENCRYPTED_FLASH",
        "irreversible": True,
        "required_evidence": "PER_DEVICE_XTS_AND_EXACT_PARTITION_OFFSETS",
    },
    {
        "sequence": 7,
        "phase": "M56_PRE_LOCK_PHYSICAL_READBACK",
        "irreversible": False,
        "required_evidence": "SIGNED_PHYSICAL_OBSERVATION_AND_MANIFEST_V2",
    },
    {
        "sequence": 8,
        "phase": "FINAL_SECURE_DOWNLOAD_SHARED_LOCK",
        "irreversible": True,
        "required_evidence": "ENABLE_SECURITY_DOWNLOAD_AND_WR_DIS_GROUP_18_ONE_BATCH",
    },
    {
        "sequence": 9,
        "phase": "POST_LOCK_QUALIFICATION",
        "irreversible": False,
        "required_evidence": "ALL_V4_TESTS_OR_QUARANTINE_NO_INVENTORY",
    },
)

SUMMARY_BOOL_FIELDS = (
    "DIS_DOWNLOAD_ICACHE",
    "DIS_DOWNLOAD_DCACHE",
    "DIS_PAD_JTAG",
    "DIS_DOWNLOAD_MANUAL_ENCRYPT",
    "DIS_USB_JTAG",
    "DIS_DIRECT_BOOT",
    "SECURE_BOOT_EN",
    "ENABLE_SECURITY_DOWNLOAD",
    "DIS_DOWNLOAD_MODE",
    "SECURE_BOOT_AGGRESSIVE_REVOKE",
    "SECURE_BOOT_KEY_REVOKE0",
    "SECURE_BOOT_KEY_REVOKE1",
    "SECURE_BOOT_KEY_REVOKE2",
)


class SacrificialPlanError(ValueError):
    pass


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SacrificialPlanError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _parse_json(data: bytes, label: str, maximum: int) -> dict[str, Any]:
    if not data or len(data) > maximum:
        raise SacrificialPlanError(f"{label} size is invalid")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SacrificialPlanError(f"{label} is invalid JSON") from error
    if not isinstance(value, dict):
        raise SacrificialPlanError(f"{label} must contain one object")
    return value


def _exact(value: Any, members: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SacrificialPlanError(f"{label} must be an object")
    if set(value) != members:
        raise SacrificialPlanError(
            f"{label} members differ: missing={sorted(members - set(value))}, "
            f"extra={sorted(set(value) - members)}"
        )
    return value


def _string(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise SacrificialPlanError(f"{label} has invalid format")
    return value


def _integer(value: Any, minimum: int, maximum: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise SacrificialPlanError(f"{label} is outside policy")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value
    ):
        raise SacrificialPlanError(f"{label} must be whole-second UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise SacrificialPlanError(f"{label} is invalid") from error


def _field(summary: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    field = summary.get(name)
    if not isinstance(field, dict):
        raise SacrificialPlanError(f"preflight summary is missing {name}")
    for member in ("block", "bit_len", "raw_value", "readable", "writeable", "value"):
        if member not in field:
            raise SacrificialPlanError(f"preflight summary {name} lacks {member}")
    return field


def validate_blank_summary(data: bytes, *, base_mac: str) -> dict[str, Any]:
    summary = _parse_json(data, "preflight eFuse summary", MAX_CAPTURE_BYTES)
    mac = _field(summary, "MAC")
    if (
        mac["block"] != 1
        or mac["bit_len"] != 48
        or not mac["readable"]
        or not isinstance(mac["value"], str)
        or not mac["value"].startswith(base_mac + " (OK)")
    ):
        raise SacrificialPlanError("preflight base MAC differs or has invalid CRC")

    for name, raw, value, bits in (
        ("WR_DIS", "0x00000000", 0, 32),
        ("RD_DIS", "0x00", 0, 7),
        ("SPI_BOOT_CRYPT_CNT", "0x0", "Disable", 3),
        ("SECURE_VERSION", "0x0000", 0, 16),
    ):
        field = _field(summary, name)
        if (
            field["block"] != 0
            or field["bit_len"] != bits
            or field["raw_value"] != raw
            or field["value"] != value
            or field["readable"] is not True
            or field["writeable"] is not True
        ):
            raise SacrificialPlanError(f"preflight {name} is not blank and writable")

    for name in SUMMARY_BOOL_FIELDS:
        field = _field(summary, name)
        if (
            field["block"] != 0
            or field["bit_len"] != 1
            or field["raw_value"] != "0x0"
            or field["value"] is not False
            or field["readable"] is not True
            or field["writeable"] is not True
        ):
            raise SacrificialPlanError(f"preflight {name} is not blank and writable")

    for slot in range(6):
        block = _field(summary, f"BLOCK_KEY{slot}")
        purpose = _field(summary, f"KEY_PURPOSE_{slot}")
        if (
            block["block"] != 4 + slot
            or block["bit_len"] != 256
            or block["raw_value"] != ZERO_KEY
            or block["readable"] is not True
            or block["writeable"] is not True
        ):
            raise SacrificialPlanError(f"preflight BLOCK_KEY{slot} is not blank")
        if (
            purpose["block"] != 0
            or purpose["bit_len"] != 4
            or purpose["raw_value"] != "0x0"
            or purpose["value"] != "USER"
            or purpose["readable"] is not True
            or purpose["writeable"] is not True
        ):
            raise SacrificialPlanError(f"preflight KEY_PURPOSE_{slot} is not blank")
    return summary


def validate_capture_logs(
    *,
    tool_versions: bytes,
    chip_probe: bytes,
    flash_probe: bytes,
    efuse_check_error: bytes,
    base_mac: str,
) -> None:
    if tool_versions != b"esptool=5.3.1\nespefuse=5.3.1\n":
        raise SacrificialPlanError("preflight tools are not pinned to 5.3.1")
    for data, label in (
        (chip_probe, "chip probe"),
        (flash_probe, "flash probe"),
        (efuse_check_error, "eFuse check-error"),
    ):
        if not data or len(data) > MAX_CAPTURE_BYTES:
            raise SacrificialPlanError(f"preflight {label} size is invalid")
        try:
            data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise SacrificialPlanError(f"preflight {label} is not UTF-8") from error
    chip_text = chip_probe.decode("utf-8")
    if "esptool v5.3.1" not in chip_text or "ESP32-S3" not in chip_text:
        raise SacrificialPlanError("chip probe does not prove ESP32-S3 with esptool 5.3.1")
    normalized_mac = base_mac.lower()
    if normalized_mac not in chip_text.lower():
        raise SacrificialPlanError("chip probe base MAC differs")
    flash_text = flash_probe.decode("utf-8")
    if "esptool v5.3.1" not in flash_text or "Detected flash size: 16MB" not in flash_text:
        raise SacrificialPlanError("flash probe does not prove 16MB Flash")
    error_text = efuse_check_error.decode("utf-8")
    if "espefuse v5.3.1" not in error_text or "No errors detected." not in error_text:
        raise SacrificialPlanError("eFuse coding-error check did not pass")


def load_release_evidence(
    signing_request_data: bytes, signed_artifact_data: bytes
) -> dict[str, Any]:
    request = _parse_json(signing_request_data, "signing request", MAX_JSON_BYTES)
    receipt = _parse_json(
        signed_artifact_data, "signed-artifact verification", MAX_JSON_BYTES
    )
    if canonical_json(request) != signing_request_data:
        raise SacrificialPlanError("signing request is not canonical JSON")
    if canonical_json(receipt) != signed_artifact_data:
        raise SacrificialPlanError("signed-artifact verification is not canonical JSON")
    _exact(
        request,
        {
            "version",
            "profile",
            "target",
            "idf_version",
            "upstream_commits",
            "secure_boot",
            "efuse_key_block_map",
            "flash_encryption",
            "anti_rollback_secure_version",
            "partition_table_offset",
            "artifacts",
        },
        "signing request",
    )
    if (
        request.get("version") != 1
        or request.get("profile") != PROFILE
        or request.get("target") != "esp32s3"
        or request.get("idf_version") != "6.0.2"
        or request.get("secure_boot")
        != {
            "scheme": "RSA-3072",
            "bootloader_required_signatures": 3,
            "application_required_signatures": 1,
            "trusted_digest_key_blocks": [0, 1, 2],
        }
        or request.get("flash_encryption")
        != {"mode": "release", "scheme": "XTS-AES-128"}
        or request.get("partition_table_offset") != 0x10000
        or request.get("upstream_commits")
        != {
            "esp-claw": "9ba07d013329df480e34a1a59d1513ab783d8a52",
            "xiaozhi-esp32": "18a60b8051f5ee6a25beed6248ed84c7fcc742bf",
        }
    ):
        raise SacrificialPlanError("signing request policy differs")
    expected_map = [
        {"block": 0, "purpose": "SECURE_BOOT_DIGEST0"},
        {"block": 1, "purpose": "SECURE_BOOT_DIGEST1"},
        {"block": 2, "purpose": "SECURE_BOOT_DIGEST2"},
        {"block": 3, "purpose": "XTS_AES_128_KEY"},
        {"block": 4, "purpose": "HMAC_UP_NVS"},
        {"block": 5, "purpose": "HMAC_UP_IDENTITY"},
    ]
    if request.get("efuse_key_block_map") != expected_map:
        raise SacrificialPlanError("signing request key allocation differs")
    secure_version = request.get("anti_rollback_secure_version")
    _integer(secure_version, 1, 16, "release secure version")
    artifacts = request.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != {
        "application",
        "bootloader",
        "ota_data_initial",
        "partition_table",
    }:
        raise SacrificialPlanError("signing request artifacts differ")
    for name in artifacts:
        metadata = artifacts[name]
        if not isinstance(metadata, dict):
            raise SacrificialPlanError(f"signing request {name} metadata differs")
        _string(metadata.get("sha256"), SHA256_HEX, f"{name} hash")
        _integer(metadata.get("size"), 1, 0x580000, f"{name} size")
    if set(artifacts["application"]) != {
        "project",
        "project_version",
        "secure_version",
        "sha256",
        "size",
    } or (
        artifacts["application"]["project"] != "xiaozhi_agent_platform"
        or artifacts["application"]["project_version"] != "0.24.0-security-gate"
        or artifacts["application"]["secure_version"] != secure_version
    ):
        raise SacrificialPlanError("signing request application metadata differs")
    for name in ("bootloader", "ota_data_initial", "partition_table"):
        if set(artifacts[name]) != {"sha256", "size"}:
            raise SacrificialPlanError(f"signing request {name} metadata shape differs")
    if (
        artifacts["ota_data_initial"]["size"] != 0x2000
        or artifacts["partition_table"]["size"] != 0xC00
    ):
        raise SacrificialPlanError("signing request fixed artifact sizes differ")

    _exact(
        receipt,
        {
            "version",
            "profile",
            "signing_request_sha256",
            "anti_rollback_secure_version",
            "bootloader",
            "application",
            "secure_boot_digests",
            "application_signing_slot",
        },
        "signed-artifact verification",
    )
    request_hash = sha256(signing_request_data)
    if (
        receipt["version"] != 1
        or receipt["profile"] != PROFILE
        or receipt["signing_request_sha256"] != request_hash
        or receipt["anti_rollback_secure_version"] != secure_version
    ):
        raise SacrificialPlanError("signed-artifact verification subject differs")
    for name in ("bootloader", "application"):
        metadata = _exact(receipt[name], {"size", "sha256"}, f"signed {name}")
        _integer(metadata["size"], 1, 0x581000, f"signed {name} size")
        _string(metadata["sha256"], SHA256_HEX, f"signed {name} hash")
    digests = receipt["secure_boot_digests"]
    if not isinstance(digests, list) or len(digests) != 3:
        raise SacrificialPlanError("signed-artifact verification needs three digests")
    normalized: list[dict[str, Any]] = []
    values: list[str] = []
    for slot, entry in enumerate(digests):
        item = _exact(entry, {"slot", "digest_sha256"}, f"digest {slot}")
        if item["slot"] != slot:
            raise SacrificialPlanError("Secure Boot digest order differs")
        digest = _string(item["digest_sha256"], SHA256_HEX, f"digest {slot}")
        values.append(digest)
        normalized.append(
            {
                "slot": slot,
                "purpose": f"SECURE_BOOT_DIGEST{slot}",
                "digest_sha256": digest,
            }
        )
    if len(set(values)) != 3:
        raise SacrificialPlanError("Secure Boot digests must be distinct")
    if receipt["application_signing_slot"] not in (0, 1, 2):
        raise SacrificialPlanError("application signing slot differs")
    return {
        "profile": PROFILE,
        "signing_request_sha256": request_hash,
        "signed_artifact_verification_sha256": sha256(signed_artifact_data),
        "anti_rollback_secure_version": secure_version,
        "signed_bootloader_sha256": receipt["bootloader"]["sha256"],
        "signed_application_sha256": receipt["application"]["sha256"],
        "partition_table_sha256": artifacts["partition_table"]["sha256"],
        "ota_data_initial_sha256": artifacts["ota_data_initial"]["sha256"],
        "secure_boot_digests": normalized,
    }


def key_allocation() -> list[dict[str, Any]]:
    return [
        {
            "logical_slot": slot,
            "physical_block": 4 + slot,
            "block_name": f"BLOCK_KEY{slot}",
            "purpose": KEY_PURPOSES[slot],
            "product_role": KEY_ROLES[slot],
            "read_policy": "READABLE" if slot < 3 else "READ_PROTECTED",
            "write_protected": True,
        }
        for slot in range(6)
    ]


def build_request(
    *,
    plan_id: str,
    transaction_id: str,
    attempt_id: str,
    device_id: str,
    serial_number: str,
    base_mac: str,
    chip_revision: int,
    release: dict[str, Any],
    station_id: str,
    operators: list[str],
    fixture_id: str,
    fixture_version: str,
    fixture_calibration_sha256: str,
    authorization_key_id: str,
    port_fingerprint_sha256: str,
    chip_probe: bytes,
    flash_probe: bytes,
    tool_versions: bytes,
    efuse_summary_before: bytes,
    efuse_summary_after: bytes,
    efuse_check_error: bytes,
    capture_started_at: str,
    capture_finished_at: str,
    issued_at: str,
    expires_at: str,
) -> dict[str, Any]:
    if efuse_summary_before != efuse_summary_after:
        raise SacrificialPlanError("preflight eFuse summary changed during capture")
    validate_blank_summary(efuse_summary_before, base_mac=base_mac)
    validate_capture_logs(
        tool_versions=tool_versions,
        chip_probe=chip_probe,
        flash_probe=flash_probe,
        efuse_check_error=efuse_check_error,
        base_mac=base_mac,
    )
    request = {
        "schema": SCHEMA,
        "plan_id": plan_id,
        "environment": ENVIRONMENT,
        "scope": SCOPE,
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
            "flash_bytes": 16 * 1024 * 1024,
        },
        "release": copy.deepcopy(release),
        "preflight": {
            "capture_format": "xz-sacrificial-blank-preflight-v1",
            "transport": "UART_ROM_DOWNLOAD",
            "esptool_version": ESPTOOL_VERSION,
            "espefuse_version": ESPTOOL_VERSION,
            "port_fingerprint_sha256": port_fingerprint_sha256,
            "chip_probe_sha256": sha256(chip_probe),
            "flash_probe_sha256": sha256(flash_probe),
            "efuse_summary_before_sha256": sha256(efuse_summary_before),
            "efuse_summary_after_sha256": sha256(efuse_summary_after),
            "efuse_check_error_sha256": sha256(efuse_check_error),
            "blank_key_slots_pass": True,
            "blank_security_fuses_pass": True,
            "coding_error_check_pass": True,
            "started_at": capture_started_at,
            "finished_at": capture_finished_at,
        },
        "station": {
            "id": station_id,
            "operators": list(operators),
            "fixture_id": fixture_id,
            "fixture_version": fixture_version,
            "fixture_calibration_sha256": fixture_calibration_sha256,
        },
        "key_allocation": key_allocation(),
        "operation_plan": [dict(item) for item in OPERATION_PLAN],
        "authorization": {
            "key_id": authorization_key_id,
            "issued_at": issued_at,
            "expires_at": expires_at,
            "two_person_approval": True,
            "production_inventory_eligible": False,
            "failure_disposition": "QUARANTINE_OR_DESTROY",
            "executor_included": False,
        },
        "result": RESULT,
        "signature_algorithm": "Ed25519",
    }
    validate(request, signed=False)
    return request


def validate(value: dict[str, Any], *, signed: bool) -> None:
    members = {
        "schema",
        "plan_id",
        "environment",
        "scope",
        "transaction",
        "product",
        "release",
        "preflight",
        "station",
        "key_allocation",
        "operation_plan",
        "authorization",
        "result",
        "signature_algorithm",
    }
    if signed:
        members.add("signature_b64url")
    root = _exact(value, members, "sacrificial provisioning plan")
    if (
        root["schema"] != SCHEMA
        or root["environment"] != ENVIRONMENT
        or root["scope"] != SCOPE
        or root["result"] != RESULT
        or root["signature_algorithm"] != "Ed25519"
    ):
        raise SacrificialPlanError("sacrificial plan frozen constants differ")
    _string(root["plan_id"], IDENTIFIER, "plan ID")
    if signed:
        _string(root["signature_b64url"], SIGNATURE, "plan signature")

    transaction = _exact(
        root["transaction"],
        {"transaction_id", "attempt_id", "device_id", "serial_number", "base_mac"},
        "plan transaction",
    )
    for name in ("transaction_id", "attempt_id", "serial_number"):
        _string(transaction[name], IDENTIFIER, name)
    _string(transaction["device_id"], DEVICE_ID, "device ID")
    _string(transaction["base_mac"], MAC_ADDRESS, "base MAC")
    if transaction["device_id"] != "xz-" + transaction["base_mac"].replace(
        ":", ""
    ).lower():
        raise SacrificialPlanError("device ID does not derive from base MAC")

    product = _exact(
        root["product"],
        {"sku", "board", "hardware_revision", "chip_model", "chip_revision", "flash_bytes"},
        "plan product",
    )
    if product != {
        "sku": "VOICE_AGENT_KIT_BOX3",
        "board": "esp32s3-box3",
        "hardware_revision": 1,
        "chip_model": "ESP32-S3",
        "chip_revision": product["chip_revision"],
        "flash_bytes": 16 * 1024 * 1024,
    }:
        raise SacrificialPlanError("plan product differs")
    _integer(product["chip_revision"], 0, 999, "chip revision")

    release = _exact(
        root["release"],
        {
            "profile",
            "signing_request_sha256",
            "signed_artifact_verification_sha256",
            "anti_rollback_secure_version",
            "signed_bootloader_sha256",
            "signed_application_sha256",
            "partition_table_sha256",
            "ota_data_initial_sha256",
            "secure_boot_digests",
        },
        "plan release",
    )
    if release["profile"] != PROFILE:
        raise SacrificialPlanError("plan release profile differs")
    for name in (
        "signing_request_sha256",
        "signed_artifact_verification_sha256",
        "signed_bootloader_sha256",
        "signed_application_sha256",
        "partition_table_sha256",
        "ota_data_initial_sha256",
    ):
        _string(release[name], SHA256_HEX, f"release {name}")
    _integer(release["anti_rollback_secure_version"], 1, 16, "secure version")
    digests = release["secure_boot_digests"]
    if not isinstance(digests, list) or len(digests) != 3:
        raise SacrificialPlanError("plan release needs three Secure Boot digests")
    digest_values: list[str] = []
    for slot, item in enumerate(digests):
        entry = _exact(item, {"slot", "purpose", "digest_sha256"}, f"release digest {slot}")
        if entry["slot"] != slot or entry["purpose"] != f"SECURE_BOOT_DIGEST{slot}":
            raise SacrificialPlanError("plan release digest order differs")
        digest_values.append(
            _string(entry["digest_sha256"], SHA256_HEX, f"release digest {slot}")
        )
    if len(set(digest_values)) != 3:
        raise SacrificialPlanError("plan release digests are not distinct")

    preflight = _exact(
        root["preflight"],
        {
            "capture_format",
            "transport",
            "esptool_version",
            "espefuse_version",
            "port_fingerprint_sha256",
            "chip_probe_sha256",
            "flash_probe_sha256",
            "efuse_summary_before_sha256",
            "efuse_summary_after_sha256",
            "efuse_check_error_sha256",
            "blank_key_slots_pass",
            "blank_security_fuses_pass",
            "coding_error_check_pass",
            "started_at",
            "finished_at",
        },
        "plan preflight",
    )
    if (
        preflight["capture_format"] != "xz-sacrificial-blank-preflight-v1"
        or preflight["transport"] != "UART_ROM_DOWNLOAD"
        or preflight["esptool_version"] != ESPTOOL_VERSION
        or preflight["espefuse_version"] != ESPTOOL_VERSION
        or preflight["blank_key_slots_pass"] is not True
        or preflight["blank_security_fuses_pass"] is not True
        or preflight["coding_error_check_pass"] is not True
    ):
        raise SacrificialPlanError("plan preflight assertions differ")
    for name in (
        "port_fingerprint_sha256",
        "chip_probe_sha256",
        "flash_probe_sha256",
        "efuse_summary_before_sha256",
        "efuse_summary_after_sha256",
        "efuse_check_error_sha256",
    ):
        _string(preflight[name], SHA256_HEX, f"preflight {name}")
    if preflight["efuse_summary_before_sha256"] != preflight["efuse_summary_after_sha256"]:
        raise SacrificialPlanError("plan preflight eFuse hashes differ")
    started = _timestamp(preflight["started_at"], "preflight start")
    finished = _timestamp(preflight["finished_at"], "preflight finish")
    if not started <= finished <= started + timedelta(minutes=10):
        raise SacrificialPlanError("preflight capture window exceeds ten minutes")

    station = _exact(
        root["station"],
        {"id", "operators", "fixture_id", "fixture_version", "fixture_calibration_sha256"},
        "plan station",
    )
    for name in ("id", "fixture_id", "fixture_version"):
        _string(station[name], IDENTIFIER, f"station {name}")
    _string(station["fixture_calibration_sha256"], SHA256_HEX, "fixture calibration hash")
    operators = station["operators"]
    if (
        not isinstance(operators, list)
        or not 2 <= len(operators) <= 4
        or len(set(operators)) != len(operators)
    ):
        raise SacrificialPlanError("plan needs two to four distinct operators")
    for index, operator in enumerate(operators):
        _string(operator, IDENTIFIER, f"operator {index}")

    if root["key_allocation"] != key_allocation():
        raise SacrificialPlanError("plan key allocation differs")
    if root["operation_plan"] != [dict(item) for item in OPERATION_PLAN]:
        raise SacrificialPlanError("plan irreversible operation order differs")

    authorization = _exact(
        root["authorization"],
        {
            "key_id",
            "issued_at",
            "expires_at",
            "two_person_approval",
            "production_inventory_eligible",
            "failure_disposition",
            "executor_included",
        },
        "plan authorization",
    )
    _string(authorization["key_id"], IDENTIFIER, "authorization key ID")
    if authorization != {
        "key_id": authorization["key_id"],
        "issued_at": authorization["issued_at"],
        "expires_at": authorization["expires_at"],
        "two_person_approval": True,
        "production_inventory_eligible": False,
        "failure_disposition": "QUARANTINE_OR_DESTROY",
        "executor_included": False,
    }:
        raise SacrificialPlanError("plan authorization safety boundary differs")
    issued = _timestamp(authorization["issued_at"], "authorization issue time")
    expires = _timestamp(authorization["expires_at"], "authorization expiry")
    if not finished <= issued <= finished + timedelta(minutes=15):
        raise SacrificialPlanError("authorization was not issued from a fresh preflight")
    if not issued < expires <= issued + timedelta(minutes=15):
        raise SacrificialPlanError("authorization lifetime exceeds fifteen minutes")


def parse_canonical(data: bytes, *, signed: bool) -> dict[str, Any]:
    value = _parse_json(data, "sacrificial provisioning plan", MAX_JSON_BYTES)
    if canonical_json(value) != data:
        raise SacrificialPlanError("sacrificial provisioning plan is not canonical JSON")
    validate(value, signed=signed)
    return value


def _public_key(data: bytes) -> Ed25519PublicKey:
    if not data or len(data) > MAX_PUBLIC_KEY_BYTES or b"PRIVATE KEY" in data:
        raise SacrificialPlanError("authorization public key input is invalid")
    try:
        key = serialization.load_pem_public_key(data)
    except (TypeError, ValueError) as error:
        raise SacrificialPlanError("authorization public key is invalid") from error
    if not isinstance(key, Ed25519PublicKey):
        raise SacrificialPlanError("authorization public key must be Ed25519")
    return key


def verify_receipt(receipt: dict[str, Any], public_key_data: bytes) -> None:
    validate(receipt, signed=True)
    unsigned = dict(receipt)
    encoded = unsigned.pop("signature_b64url")
    try:
        signature = base64.urlsafe_b64decode(encoded + "==")
    except (ValueError, binascii.Error) as error:
        raise SacrificialPlanError("plan signature encoding is invalid") from error
    if len(signature) != 64:
        raise SacrificialPlanError("plan signature length is invalid")
    try:
        _public_key(public_key_data).verify(signature, canonical_json(unsigned))
    except InvalidSignature as error:
        raise SacrificialPlanError("plan signature verification failed") from error


def bind_release(
    receipt: dict[str, Any], signing_request_data: bytes, signed_artifact_data: bytes
) -> None:
    expected = load_release_evidence(signing_request_data, signed_artifact_data)
    if receipt["release"] != expected:
        raise SacrificialPlanError("plan release evidence binding differs")


def require_active(receipt: dict[str, Any], verification_time: str) -> None:
    now = _timestamp(verification_time, "verification time")
    issued = _timestamp(receipt["authorization"]["issued_at"], "authorization issue time")
    expires = _timestamp(receipt["authorization"]["expires_at"], "authorization expiry")
    if not issued <= now <= expires:
        raise SacrificialPlanError("sacrificial authorization is not active")
