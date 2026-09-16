#!/usr/bin/env python3
"""Strict M57 ESP32-S3 virtual-eFuse rehearsal evidence policy."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any


FORMAT = "xz-box3-virtual-efuse-rehearsal-v1"
VERSION = 1
ENVIRONMENT = "VIRTUAL_TEST_ONLY"
RESULT = "VIRTUAL_EFUSE_REHEARSAL_PASS"
PROFILE = "box3-production-security-v1"
TARGET = "esp32s3"
IDF_VERSION = "6.0.2"
ESPEFUSE_VERSION = "5.3.1"
SECURE_VERSION = 1

STAGE_NAMES = (
    "BLANK",
    "SECRETS_LOCKED",
    "DIGESTS_LOCKED",
    "RD_DIS_LOCKED",
    "SECURITY_POLICY_PRE_DOWNLOAD_LOCK",
    "FINAL_SECURE_DOWNLOAD_LOCKED",
)

KEY_PURPOSES = (
    "SECURE_BOOT_DIGEST0",
    "SECURE_BOOT_DIGEST1",
    "SECURE_BOOT_DIGEST2",
    "XTS_AES_128_KEY",
    "HMAC_UP",
    "HMAC_UP",
)

PRODUCT_ROLES = (
    "SECURE_BOOT_DIGEST0",
    "SECURE_BOOT_DIGEST1",
    "SECURE_BOOT_DIGEST2",
    "FLASH_ENCRYPTION",
    "CREDENTIAL_NVS",
    "DEVICE_IDENTITY",
)

BOOL_FUSES = (
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

FIELD_NAMES = (
    "RD_DIS",
    "SPI_BOOT_CRYPT_CNT",
    "SECURE_VERSION",
    *BOOL_FUSES,
    *(f"KEY_PURPOSE_{slot}" for slot in range(6)),
    *(f"BLOCK_KEY{slot}" for slot in range(6)),
)

FIELD_KEYS = {
    "bit_len",
    "block",
    "raw_value",
    "readable",
    "value",
    "writeable",
}

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ZERO_KEY = "0x" + "0" * 64
SIGNING_REQUEST_KEYS = {
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
}


class RehearsalError(ValueError):
    pass


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _exact_keys(value: dict[str, Any], expected: set[str], path: str) -> None:
    if not isinstance(value, dict):
        raise RehearsalError(f"{path} must be an object")
    actual = set(value)
    if actual != expected:
        raise RehearsalError(
            f"{path} keys differ: missing={sorted(expected - actual)} "
            f"extra={sorted(actual - expected)}"
        )


def _hash(value: Any, path: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise RehearsalError(f"{path} must be a lowercase SHA-256")
    return value


def _field(fields: dict[str, Any], name: str) -> dict[str, Any]:
    value = fields.get(name)
    _exact_keys(value, FIELD_KEYS, f"fields.{name}")
    if not isinstance(value["block"], int) or isinstance(value["block"], bool):
        raise RehearsalError(f"fields.{name}.block must be an integer")
    if not isinstance(value["bit_len"], int) or isinstance(value["bit_len"], bool):
        raise RehearsalError(f"fields.{name}.bit_len must be an integer")
    for key in ("readable", "writeable"):
        if not isinstance(value[key], bool):
            raise RehearsalError(f"fields.{name}.{key} must be boolean")
    if not isinstance(value["raw_value"], str):
        raise RehearsalError(f"fields.{name}.raw_value must be a string")
    return value


def select_fields(summary: dict[str, Any]) -> dict[str, Any]:
    """Select only security-policy fields from official espefuse JSON output."""
    if not isinstance(summary, dict):
        raise RehearsalError("espefuse summary must be an object")
    selected: dict[str, Any] = {}
    for name in FIELD_NAMES:
        source = summary.get(name)
        if not isinstance(source, dict):
            raise RehearsalError(f"espefuse summary is missing {name}")
        missing = FIELD_KEYS - set(source)
        if missing:
            raise RehearsalError(f"espefuse summary {name} is missing {sorted(missing)}")
        selected[name] = {key: source[key] for key in sorted(FIELD_KEYS)}
    return selected


def _require_field(
    fields: dict[str, Any],
    name: str,
    *,
    value: Any | None = None,
    readable: bool | None = None,
    writeable: bool | None = None,
    raw_value: str | None = None,
    block: int | None = None,
    bit_len: int | None = None,
) -> dict[str, Any]:
    field = _field(fields, name)
    expected = {
        "value": value,
        "readable": readable,
        "writeable": writeable,
        "raw_value": raw_value,
        "block": block,
        "bit_len": bit_len,
    }
    for key, wanted in expected.items():
        if wanted is not None and field[key] != wanted:
            raise RehearsalError(
                f"{name}.{key} must be {wanted!r}, got {field[key]!r}"
            )
    return field


def _validate_keys(fields: dict[str, Any], stage_index: int) -> None:
    digest_values: list[str] = []
    for slot in range(6):
        block_name = f"BLOCK_KEY{slot}"
        purpose_name = f"KEY_PURPOSE_{slot}"
        block = _field(fields, block_name)
        purpose = _field(fields, purpose_name)
        if block["block"] != 4 + slot or block["bit_len"] != 256:
            raise RehearsalError(f"{block_name} physical mapping differs")
        if purpose["block"] != 0 or purpose["bit_len"] != 4:
            raise RehearsalError(f"{purpose_name} physical mapping differs")

        provisioned = (slot >= 3 and stage_index >= 1) or (
            slot <= 2 and stage_index >= 2
        )
        if not provisioned:
            _require_field(
                fields,
                block_name,
                readable=True,
                writeable=True,
                raw_value=ZERO_KEY,
            )
            _require_field(
                fields, purpose_name, value="USER", readable=True, writeable=True
            )
            continue

        _require_field(
            fields,
            purpose_name,
            value=KEY_PURPOSES[slot],
            readable=True,
            writeable=False,
        )
        if slot <= 2:
            block = _require_field(
                fields, block_name, readable=True, writeable=False
            )
            raw = block["raw_value"]
            if not re.fullmatch(r"0x[0-9a-f]{64}", raw) or raw == ZERO_KEY:
                raise RehearsalError(f"{block_name} must contain a readable digest")
            digest_values.append(raw)
        else:
            _require_field(
                fields, block_name, readable=False, writeable=False
            )
    if stage_index >= 2 and len(set(digest_values)) != 3:
        raise RehearsalError("Secure Boot digests must be three distinct values")


def _validate_security_fuses(fields: dict[str, Any], stage_index: int) -> None:
    policy_active = stage_index >= 4
    final = stage_index >= 5
    enabled_before_final = {
        "DIS_DOWNLOAD_ICACHE",
        "DIS_DOWNLOAD_DCACHE",
        "DIS_PAD_JTAG",
        "DIS_DOWNLOAD_MANUAL_ENCRYPT",
        "DIS_USB_JTAG",
        "DIS_DIRECT_BOOT",
        "SECURE_BOOT_EN",
    }
    group2 = {
        "DIS_DOWNLOAD_ICACHE",
        "DIS_DOWNLOAD_DCACHE",
        "DIS_PAD_JTAG",
        "DIS_DOWNLOAD_MANUAL_ENCRYPT",
        "DIS_USB_JTAG",
    }
    group18 = {
        "DIS_DIRECT_BOOT",
        "ENABLE_SECURITY_DOWNLOAD",
        "DIS_DOWNLOAD_MODE",
    }

    for name in BOOL_FUSES:
        wanted = policy_active and name in enabled_before_final
        if name == "ENABLE_SECURITY_DOWNLOAD":
            wanted = final
        if name in {
            "DIS_DOWNLOAD_MODE",
            "SECURE_BOOT_AGGRESSIVE_REVOKE",
            "SECURE_BOOT_KEY_REVOKE0",
            "SECURE_BOOT_KEY_REVOKE1",
            "SECURE_BOOT_KEY_REVOKE2",
        }:
            wanted = False

        if not policy_active:
            writeable = True
        elif name in group2 or name == "SECURE_BOOT_EN":
            writeable = False
        elif name in group18:
            writeable = not final
        else:
            writeable = True
        _require_field(
            fields,
            name,
            value=wanted,
            readable=True,
            writeable=writeable,
            block=0,
            bit_len=1,
        )

    crypt_value = "Enable" if policy_active else "Disable"
    crypt_raw = "0x7" if policy_active else "0x0"
    _require_field(
        fields,
        "SPI_BOOT_CRYPT_CNT",
        value=crypt_value,
        raw_value=crypt_raw,
        readable=True,
        writeable=not policy_active,
        block=0,
        bit_len=3,
    )
    _require_field(
        fields,
        "SECURE_VERSION",
        value=SECURE_VERSION if policy_active else 0,
        raw_value="0x0001" if policy_active else "0x0000",
        readable=True,
        writeable=not final,
        block=0,
        bit_len=16,
    )


def _validate_stage(stage: dict[str, Any], index: int) -> None:
    _exact_keys(
        stage,
        {"name", "official_summary_sha256", "selected_fields_sha256", "fields"},
        f"stages[{index}]",
    )
    if stage["name"] != STAGE_NAMES[index]:
        raise RehearsalError(f"stages[{index}].name differs")
    _hash(stage["official_summary_sha256"], f"stages[{index}].official_summary_sha256")
    fields = stage["fields"]
    _exact_keys(fields, set(FIELD_NAMES), f"stages[{index}].fields")
    if stage["selected_fields_sha256"] != sha256(canonical_json(fields)):
        raise RehearsalError(f"stages[{index}] selected-fields hash differs")
    _validate_keys(fields, index)

    rd_value = 56 if index >= 1 else 0
    _require_field(
        fields,
        "RD_DIS",
        value=rd_value,
        raw_value=f"0x{rd_value:02x}",
        readable=True,
        writeable=index < 3,
        block=0,
        bit_len=7,
    )
    _validate_security_fuses(fields, index)


def validate_evidence(value: dict[str, Any]) -> dict[str, Any]:
    _exact_keys(
        value,
        {
            "schema",
            "version",
            "environment",
            "result",
            "subject",
            "tool",
            "key_allocation",
            "stages",
            "final_virtual_efuse_image_sha256",
            "secret_handling",
            "boundary",
        },
        "evidence",
    )
    constants = {
        "schema": FORMAT,
        "version": VERSION,
        "environment": ENVIRONMENT,
        "result": RESULT,
    }
    for key, expected in constants.items():
        if value[key] != expected:
            raise RehearsalError(f"{key} must be {expected!r}")

    subject = value["subject"]
    _exact_keys(
        subject,
        {
            "profile",
            "target",
            "idf_version",
            "secure_version",
            "signing_request_sha256",
        },
        "subject",
    )
    if subject != {
        "profile": PROFILE,
        "target": TARGET,
        "idf_version": IDF_VERSION,
        "secure_version": SECURE_VERSION,
        "signing_request_sha256": subject["signing_request_sha256"],
    }:
        raise RehearsalError("subject differs from frozen profile")
    _hash(subject["signing_request_sha256"], "subject.signing_request_sha256")

    tool = value["tool"]
    expected_tool = {
        "name": "espefuse",
        "version": ESPEFUSE_VERSION,
        "mode": "--virt",
        "chip": TARGET,
    }
    if tool != expected_tool:
        raise RehearsalError("tool identity differs from pinned virtual tool")

    allocation = value["key_allocation"]
    if not isinstance(allocation, list) or len(allocation) != 6:
        raise RehearsalError("key_allocation must contain six slots")
    for slot, entry in enumerate(allocation):
        expected = {
            "logical_slot": slot,
            "physical_block": 4 + slot,
            "block_name": f"BLOCK_KEY{slot}",
            "purpose": KEY_PURPOSES[slot],
            "product_role": PRODUCT_ROLES[slot],
        }
        if entry != expected:
            raise RehearsalError(f"key_allocation[{slot}] differs")

    stages = value["stages"]
    if not isinstance(stages, list) or len(stages) != len(STAGE_NAMES):
        raise RehearsalError("stages must contain the six frozen transitions")
    for index, stage in enumerate(stages):
        _validate_stage(stage, index)

    _hash(value["final_virtual_efuse_image_sha256"], "final virtual image hash")
    if value["secret_handling"] != {
        "test_only_ephemeral": True,
        "secure_boot_private_keys_persisted": False,
        "raw_secret_values_recorded": False,
    }:
        raise RehearsalError("secret_handling boundary differs")
    if value["boundary"] != {
        "physical_device_touched": False,
        "factory_evidence": False,
        "market_release_evidence": False,
    }:
        raise RehearsalError("virtual-only boundary differs")
    return value


def load_evidence(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise RehearsalError("evidence must be a regular non-symlink file")
    if path.stat().st_size > 2 * 1024 * 1024:
        raise RehearsalError("evidence is too large")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RehearsalError(f"cannot read evidence: {exc}") from exc
    if not isinstance(value, dict):
        raise RehearsalError("evidence root must be an object")
    return validate_evidence(value)


def validate_signing_request_binding(
    evidence: dict[str, Any], path: Path
) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise RehearsalError("signing request must be a regular non-symlink file")
    if path.stat().st_size > 2 * 1024 * 1024:
        raise RehearsalError("signing request is too large")
    data = path.read_bytes()
    try:
        request = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RehearsalError(f"invalid signing request: {exc}") from exc
    _exact_keys(request, SIGNING_REQUEST_KEYS, "signing request")
    if canonical_json(request) != data:
        raise RehearsalError("signing request is not canonical JSON")
    if sha256(data) != evidence["subject"]["signing_request_sha256"]:
        raise RehearsalError("signing request hash differs from evidence")
    if (
        request["version"] != 1
        or request["profile"] != PROFILE
        or request["target"] != TARGET
        or request["idf_version"] != IDF_VERSION
        or request["anti_rollback_secure_version"] != SECURE_VERSION
    ):
        raise RehearsalError("signing request does not match frozen subject")
    expected_map = [
        {"block": 0, "purpose": "SECURE_BOOT_DIGEST0"},
        {"block": 1, "purpose": "SECURE_BOOT_DIGEST1"},
        {"block": 2, "purpose": "SECURE_BOOT_DIGEST2"},
        {"block": 3, "purpose": "XTS_AES_128_KEY"},
        {"block": 4, "purpose": "HMAC_UP_NVS"},
        {"block": 5, "purpose": "HMAC_UP_IDENTITY"},
    ]
    if request["efuse_key_block_map"] != expected_map:
        raise RehearsalError("signing request six-slot allocation differs")
    if request["secure_boot"] != {
        "scheme": "RSA-3072",
        "bootloader_required_signatures": 3,
        "application_required_signatures": 1,
        "trusted_digest_key_blocks": [0, 1, 2],
    }:
        raise RehearsalError("signing request Secure Boot policy differs")
    if request["flash_encryption"] != {
        "mode": "release",
        "scheme": "XTS-AES-128",
    }:
        raise RehearsalError("signing request Flash Encryption policy differs")
    return request
