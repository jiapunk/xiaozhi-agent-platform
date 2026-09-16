#!/usr/bin/env python3
"""Strict factory per-unit encrypted-flash manifest contract."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import stat
import struct
import sys
from pathlib import Path
from typing import Any, Mapping

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from factory_physical_observation import (
    PhysicalObservationError,
    bind_receipt as bind_physical_observation,
    verify_receipt as verify_physical_observation,
)

FORMAT = "xz-factory-encrypted-flash-manifest-v2"
PROFILE = "box3-production-security-v1"
ESPSECURE_VERSION = "5.3.1"
MAX_JSON_BYTES = 256 * 1024
MAX_ARTIFACT_BYTES = 0x580000 + 0x1000
SIGNATURE_SECTOR_BYTES = 0x1000
NVS_FACTORY_BYTES = 0x6000
ONBOARDING_MATERIAL_BYTES = 460
FACTORY_SKU_MANIFEST_BYTES = 70
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9:_.-]{1,128}$")
DEVICE_ID = re.compile(r"^xz-[0-9a-f]{12}$")
MAC_ADDRESS = re.compile(r"^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$")
MANIFEST_ID = re.compile(r"^[0-9a-f]{32}$")

PARTITIONS = [
    {
        "name": "nvs_factory",
        "offset": 0x11000,
        "size": 0x6000,
        "initial_state": "PROGRAMMED_PLAINTEXT_AUTHENTICATED_PUBLIC_NVS",
    },
    {
        "name": "nvs",
        "offset": 0x17000,
        "size": 0xA000,
        "initial_state": "BLANK_THEN_PRODUCT_HMAC_XTS_AES",
    },
    {
        "name": "otadata",
        "offset": 0x21000,
        "size": 0x2000,
        "initial_state": "PROGRAMMED_FLASH_ENCRYPTED",
    },
    {
        "name": "phy_init",
        "offset": 0x23000,
        "size": 0x1000,
        "initial_state": "BLANK_FLASH_ENCRYPTED",
    },
    {
        "name": "coredump",
        "offset": 0x24000,
        "size": 0x13000,
        "initial_state": "BLANK_FLASH_ENCRYPTED",
    },
    {
        "name": "ota_0",
        "offset": 0x40000,
        "size": 0x580000,
        "initial_state": "PROGRAMMED_FLASH_ENCRYPTED",
    },
    {
        "name": "ota_1",
        "offset": 0x5C0000,
        "size": 0x580000,
        "initial_state": "BLANK_FLASH_ENCRYPTED",
    },
    {
        "name": "system",
        "offset": 0xB40000,
        "size": 0x200000,
        "initial_state": "BLANK_FLASH_ENCRYPTED",
    },
    {
        "name": "data",
        "offset": 0xD40000,
        "size": 0x2C0000,
        "initial_state": "BLANK_FLASH_ENCRYPTED",
    },
]

EXPECTED_PARTITIONS = {
    "nvs_factory": (0x01, 0x02, 0x11000, 0x6000, 0),
    "nvs": (0x01, 0x02, 0x17000, 0xA000, 0),
    "otadata": (0x01, 0x00, 0x21000, 0x2000, 1),
    "phy_init": (0x01, 0x01, 0x23000, 0x1000, 1),
    "coredump": (0x01, 0x03, 0x24000, 0x13000, 1),
    "ota_0": (0x00, 0x10, 0x40000, 0x580000, 0),
    "ota_1": (0x00, 0x11, 0x5C0000, 0x580000, 0),
    "system": (0x01, 0x81, 0xB40000, 0x200000, 1),
    "data": (0x01, 0x81, 0xD40000, 0x2C0000, 1),
}

REGION_POLICY = [
    (
        "bootloader",
        0x00000,
        "SECURE_BOOT_V2_SIGNED_3_OF_3",
        "FLASH_ENCRYPTION_XTS_AES_128",
    ),
    (
        "partition_table",
        0x10000,
        "FROZEN_PRODUCTION_PARTITION_TABLE",
        "FLASH_ENCRYPTION_XTS_AES_128",
    ),
    (
        "nvs_factory",
        0x11000,
        "AUTHENTICATED_PUBLIC_FACTORY_NVS",
        "PLAINTEXT_AUTHENTICATED_PUBLIC_NVS",
    ),
    (
        "ota_data_initial",
        0x21000,
        "FROZEN_OTA_DATA_INITIAL",
        "FLASH_ENCRYPTION_XTS_AES_128",
    ),
    (
        "application",
        0x40000,
        "SECURE_BOOT_V2_SIGNED_1_OF_3",
        "FLASH_ENCRYPTION_XTS_AES_128",
    ),
]


class FactoryFlashManifestError(ValueError):
    pass


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FactoryFlashManifestError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def load_canonical_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    data = read_regular(path, MAX_JSON_BYTES, label)
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FactoryFlashManifestError(f"{label} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict) or canonical_json(value) != data:
        raise FactoryFlashManifestError(f"{label} is not canonical JSON")
    return value, data


def parse_manifest_bytes(data: bytes) -> dict[str, Any]:
    if not data or len(data) > MAX_JSON_BYTES:
        raise FactoryFlashManifestError("encrypted-flash manifest size is invalid")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FactoryFlashManifestError("encrypted-flash manifest is invalid JSON") from error
    if not isinstance(value, dict) or canonical_json(value) != data:
        raise FactoryFlashManifestError("encrypted-flash manifest is not canonical JSON")
    validate_manifest(value)
    return value


def read_regular(path: Path, maximum: int, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise FactoryFlashManifestError(f"cannot stat {label}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise FactoryFlashManifestError(f"{label} must be a regular non-symlink file")
    if metadata.st_size < 1 or metadata.st_size > maximum:
        raise FactoryFlashManifestError(f"{label} size is invalid")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
        ):
            raise FactoryFlashManifestError(f"{label} changed while opening")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise FactoryFlashManifestError(f"{label} was truncated while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        final = os.fstat(descriptor)
        if (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        ):
            raise FactoryFlashManifestError(f"{label} changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def write_new(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise FactoryFlashManifestError("manifest output must not be a symlink")
    if path.exists():
        if path.read_bytes() != payload:
            raise FactoryFlashManifestError("existing manifest output differs")
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _exact(value: Any, members: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FactoryFlashManifestError(f"{label} must be an object")
    if set(value) != members:
        raise FactoryFlashManifestError(f"{label} members differ")
    return value


def _string(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise FactoryFlashManifestError(f"{label} has invalid format")
    return value


def _integer(value: Any, minimum: int, maximum: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise FactoryFlashManifestError(f"{label} must be an integer")
    if value < minimum or value > maximum:
        raise FactoryFlashManifestError(f"{label} is outside the allowed range")
    return value


def _decode_b64(value: Any, label: str) -> bytes:
    if not isinstance(value, str):
        raise FactoryFlashManifestError(f"{label} must be base64 text")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise FactoryFlashManifestError(f"{label} is invalid base64") from error
    if base64.b64encode(decoded).decode("ascii") != value:
        raise FactoryFlashManifestError(f"{label} is not canonical base64")
    return decoded


def validate_partition_table(data: bytes) -> None:
    if len(data) != 0xC00:
        raise FactoryFlashManifestError("partition table must be exactly 0xC00 bytes")
    result: dict[str, tuple[int, int, int, int, int]] = {}
    for offset in range(0, len(data), 32):
        magic = struct.unpack_from("<H", data, offset)[0]
        if magic in (0xFFFF, 0xEBEB):
            break
        if magic != 0x50AA:
            raise FactoryFlashManifestError("partition table entry magic is invalid")
        _, kind, subtype, address, size, raw_label, flags = struct.unpack_from(
            "<HBBII16sI", data, offset
        )
        try:
            label = raw_label.split(b"\0", 1)[0].decode("ascii")
        except UnicodeDecodeError as error:
            raise FactoryFlashManifestError("partition label is not ASCII") from error
        if not label or label in result:
            raise FactoryFlashManifestError("partition label is empty or duplicated")
        result[label] = (kind, subtype, address, size, flags)
    if result != EXPECTED_PARTITIONS:
        raise FactoryFlashManifestError("partition table differs from frozen BOX-3 layout")


def validate_signed_artifact_receipt(
    receipt: dict[str, Any],
    request: dict[str, Any],
    request_sha256: str,
    signed_bootloader: bytes,
    signed_application: bytes,
) -> None:
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
        "signed-artifact receipt",
    )
    if receipt["version"] != 1 or receipt["profile"] != PROFILE:
        raise FactoryFlashManifestError("signed-artifact receipt profile differs")
    if receipt["signing_request_sha256"] != request_sha256:
        raise FactoryFlashManifestError("signed-artifact receipt uses another signing request")
    if receipt["anti_rollback_secure_version"] != request["anti_rollback_secure_version"]:
        raise FactoryFlashManifestError("signed-artifact secure version differs")
    for name, data in (
        ("bootloader", signed_bootloader),
        ("application", signed_application),
    ):
        info = _exact(receipt[name], {"size", "sha256"}, f"signed {name}")
        if info["size"] != len(data) or info["sha256"] != _sha(data):
            raise FactoryFlashManifestError(f"signed {name} differs from verification receipt")
        unsigned = request["artifacts"][name]
        if len(data) != unsigned["size"] + SIGNATURE_SECTOR_BYTES:
            raise FactoryFlashManifestError(f"signed {name} has the wrong signature size")
        if _sha(data[: unsigned["size"]]) != unsigned["sha256"]:
            raise FactoryFlashManifestError(f"signed {name} prefix differs from release")
        if data[unsigned["size"]] != 0xE7:
            raise FactoryFlashManifestError(f"signed {name} has no Secure Boot V2 block")
    digests = receipt["secure_boot_digests"]
    if not isinstance(digests, list) or len(digests) != 3:
        raise FactoryFlashManifestError("signed-artifact receipt needs three boot digests")
    values: list[str] = []
    for slot, item in enumerate(digests):
        _exact(item, {"slot", "digest_sha256"}, f"boot digest {slot}")
        if item["slot"] != slot:
            raise FactoryFlashManifestError("boot digest slots are not ordered")
        values.append(_string(item["digest_sha256"], SHA256_HEX, "boot digest"))
    if len(set(values)) != 3:
        raise FactoryFlashManifestError("boot digests are not distinct")
    _integer(receipt["application_signing_slot"], 0, 2, "application signing slot")


def validate_factory_sku_evidence(
    evidence: dict[str, Any], blob: bytes, base_mac: str, chip_revision: int
) -> None:
    _exact(
        evidence,
        {
            "schema",
            "manifest_schema",
            "manifest_id",
            "sku",
            "board",
            "hardware_revision",
            "chip_revision",
            "base_mac",
            "factory_record_version",
            "identity_hmac_key_slot",
            "authentication_domain",
            "nvs_namespace",
            "nvs_key",
            "manifest_size",
            "manifest_sha256",
        },
        "factory SKU evidence",
    )
    if (
        evidence["schema"] != "xz-factory-sku-manifest-v1"
        or evidence["manifest_schema"] != 1
        or evidence["sku"] != "VOICE_AGENT_KIT_BOX3"
        or evidence["board"] != "esp32s3-box3"
        or evidence["hardware_revision"] != 1
        or evidence["chip_revision"] != chip_revision
        or evidence["base_mac"] != base_mac
        or evidence["identity_hmac_key_slot"] != 5
        or evidence["authentication_domain"] != "XIAOZHI-PRODUCT-SKU-MANIFEST-V1"
        or evidence["nvs_namespace"] != "prod_sku"
        or evidence["nvs_key"] != "manifest"
        or evidence["manifest_size"] != FACTORY_SKU_MANIFEST_BYTES
        or evidence["manifest_sha256"] != _sha(blob)
    ):
        raise FactoryFlashManifestError("factory SKU evidence subject differs")
    _string(evidence["manifest_id"], MANIFEST_ID, "factory manifest ID")
    _integer(evidence["factory_record_version"], 1, 0x7FFFFFFF, "record version")
    if len(blob) != FACTORY_SKU_MANIFEST_BYTES:
        raise FactoryFlashManifestError("factory SKU manifest size differs")
    mac = bytes.fromhex(base_mac.replace(":", ""))
    if (
        blob[:4] != b"XSKU"
        or blob[4] != 1
        or blob[5] != 2
        or int.from_bytes(blob[6:8], "little") != 1
        or int.from_bytes(blob[8:10], "little") != chip_revision
        or blob[10:12] != b"\0\0"
        or blob[12:18] != mac
        or int.from_bytes(blob[18:22], "little")
        != evidence["factory_record_version"]
        or blob[22:38].hex() != evidence["manifest_id"]
    ):
        raise FactoryFlashManifestError("factory SKU manifest cleartext subject differs")


def validate_nvs_entries(
    entries: Any, onboarding_material: bytes, factory_sku_manifest: bytes
) -> None:
    if not isinstance(entries, list):
        raise FactoryFlashManifestError("NVS parser output must be a list")
    observed: dict[tuple[str, str], bytes] = {}
    for index, value in enumerate(entries):
        entry = _exact(
            value,
            {"namespace", "key", "encoding", "data", "state", "is_empty"},
            f"NVS entry {index}",
        )
        pair = (entry["namespace"], entry["key"])
        if pair not in {("prod_prov", "sec2"), ("prod_sku", "manifest")}:
            raise FactoryFlashManifestError("nvs_factory contains an unexpected entry")
        if entry["encoding"] not in {"blob", "blob_data"}:
            raise FactoryFlashManifestError("nvs_factory entry is not a blob")
        if entry["state"] != "Written" or entry["is_empty"] is not False:
            raise FactoryFlashManifestError("nvs_factory entry is not written")
        observed[pair] = observed.get(pair, b"") + _decode_b64(
            entry["data"], f"NVS entry {index}"
        )
    expected = {
        ("prod_prov", "sec2"): onboarding_material,
        ("prod_sku", "manifest"): factory_sku_manifest,
    }
    if observed != expected:
        raise FactoryFlashManifestError("nvs_factory exact public contents differ")


def _region(
    name: str,
    offset: int,
    source_treatment: str,
    flash_treatment: str,
    source: bytes,
    programmed: bytes,
    readback: bytes,
) -> dict[str, Any]:
    if len(source) != len(programmed) or programmed != readback:
        raise FactoryFlashManifestError(f"{name} ciphertext/readback differs")
    if flash_treatment.startswith("FLASH_ENCRYPTION") and programmed == source:
        raise FactoryFlashManifestError(f"{name} was not encrypted")
    if flash_treatment.startswith("PLAINTEXT") and programmed != source:
        raise FactoryFlashManifestError(f"{name} plaintext readback differs")
    return {
        "name": name,
        "offset": offset,
        "size": len(source),
        "source_treatment": source_treatment,
        "flash_treatment": flash_treatment,
        "source_sha256": _sha(source),
        "programmed_sha256": _sha(programmed),
        "readback_sha256": _sha(readback),
    }


def build_manifest(
    *,
    transaction_id: str,
    attempt_id: str,
    device_id: str,
    serial_number: str,
    base_mac: str,
    chip_revision: int,
    request: dict[str, Any],
    request_sha256: str,
    signed_artifact_receipt: dict[str, Any],
    signed_artifact_receipt_raw: bytes,
    factory_sku_evidence: dict[str, Any],
    signed_bootloader: bytes,
    signed_application: bytes,
    partition_table: bytes,
    ota_data_initial: bytes,
    factory_sku_manifest: bytes,
    onboarding_material: bytes,
    nvs_csv: bytes,
    nvs_factory_image: bytes,
    nvs_entries: Any,
    encrypted: Mapping[str, bytes],
    encryption_reference: Mapping[str, bytes],
    readback: Mapping[str, bytes],
    physical_observation_receipt: dict[str, Any],
    physical_observation_receipt_raw: bytes,
    physical_observation_public_key_pem: bytes,
    espsecure_version: str,
    nvs_tool_bundle_sha256: str,
    builder_tool_bundle_sha256: str,
) -> dict[str, Any]:
    _string(transaction_id, IDENTIFIER, "transaction ID")
    _string(attempt_id, IDENTIFIER, "attempt ID")
    _string(serial_number, IDENTIFIER, "serial number")
    _string(device_id, DEVICE_ID, "device ID")
    _string(base_mac, MAC_ADDRESS, "base MAC")
    _integer(chip_revision, 0, 999, "chip revision")
    if device_id != "xz-" + base_mac.replace(":", "").lower():
        raise FactoryFlashManifestError("device ID does not derive from base MAC")
    if request.get("profile") != PROFILE:
        raise FactoryFlashManifestError("signing request profile differs")
    _string(request_sha256, SHA256_HEX, "signing request SHA-256")
    validate_signed_artifact_receipt(
        signed_artifact_receipt,
        request,
        request_sha256,
        signed_bootloader,
        signed_application,
    )
    validate_factory_sku_evidence(
        factory_sku_evidence, factory_sku_manifest, base_mac, chip_revision
    )
    validate_partition_table(partition_table)
    for name, data in (
        ("partition_table", partition_table),
        ("ota_data_initial", ota_data_initial),
    ):
        metadata = request["artifacts"][name]
        if len(data) != metadata["size"] or _sha(data) != metadata["sha256"]:
            raise FactoryFlashManifestError(f"{name} differs from signing request")
    if len(onboarding_material) != ONBOARDING_MATERIAL_BYTES:
        raise FactoryFlashManifestError("onboarding material size differs")
    expected_csv = (
        "key,type,encoding,value\n"
        "prod_prov,namespace,,\n"
        f"sec2,data,base64,{base64.b64encode(onboarding_material).decode('ascii')}\n"
        "prod_sku,namespace,,\n"
        f"manifest,data,base64,{base64.b64encode(factory_sku_manifest).decode('ascii')}\n"
    ).encode("ascii")
    if nvs_csv != expected_csv:
        raise FactoryFlashManifestError("factory NVS CSV differs from exact material")
    if len(nvs_factory_image) != NVS_FACTORY_BYTES:
        raise FactoryFlashManifestError("nvs_factory image must be exactly 24 KiB")
    validate_nvs_entries(nvs_entries, onboarding_material, factory_sku_manifest)

    source = {
        "bootloader": signed_bootloader,
        "partition_table": partition_table,
        "ota_data_initial": ota_data_initial,
        "application": signed_application,
    }
    expected_names = set(source)
    if (
        set(encrypted) != expected_names
        or set(encryption_reference) != expected_names
        or set(readback) != expected_names | {"nvs_factory"}
    ):
        raise FactoryFlashManifestError("programmed region input set differs")
    for name in expected_names:
        if encryption_reference[name] != encrypted[name]:
            raise FactoryFlashManifestError(f"{name} ciphertext is not reproducible")
    try:
        verify_physical_observation(
            physical_observation_receipt, physical_observation_public_key_pem
        )
        bind_physical_observation(
            receipt=physical_observation_receipt,
            transaction_id=transaction_id,
            attempt_id=attempt_id,
            device_id=device_id,
            serial_number=serial_number,
            base_mac=base_mac,
            chip_revision=chip_revision,
            signing_request_sha256=request_sha256,
            signed_artifact_verification_sha256=_sha(signed_artifact_receipt_raw),
            anti_rollback_secure_version=request["anti_rollback_secure_version"],
            readbacks=readback,
        )
    except PhysicalObservationError as error:
        raise FactoryFlashManifestError(str(error)) from error

    regions = [
        _region(
            "bootloader",
            0x00000,
            "SECURE_BOOT_V2_SIGNED_3_OF_3",
            "FLASH_ENCRYPTION_XTS_AES_128",
            signed_bootloader,
            encrypted["bootloader"],
            readback["bootloader"],
        ),
        _region(
            "partition_table",
            0x10000,
            "FROZEN_PRODUCTION_PARTITION_TABLE",
            "FLASH_ENCRYPTION_XTS_AES_128",
            partition_table,
            encrypted["partition_table"],
            readback["partition_table"],
        ),
        _region(
            "nvs_factory",
            0x11000,
            "AUTHENTICATED_PUBLIC_FACTORY_NVS",
            "PLAINTEXT_AUTHENTICATED_PUBLIC_NVS",
            nvs_factory_image,
            nvs_factory_image,
            readback["nvs_factory"],
        ),
        _region(
            "ota_data_initial",
            0x21000,
            "FROZEN_OTA_DATA_INITIAL",
            "FLASH_ENCRYPTION_XTS_AES_128",
            ota_data_initial,
            encrypted["ota_data_initial"],
            readback["ota_data_initial"],
        ),
        _region(
            "application",
            0x40000,
            "SECURE_BOOT_V2_SIGNED_1_OF_3",
            "FLASH_ENCRYPTION_XTS_AES_128",
            signed_application,
            encrypted["application"],
            readback["application"],
        ),
    ]
    if espsecure_version != ESPSECURE_VERSION:
        raise FactoryFlashManifestError("espsecure version differs from frozen profile")
    _string(nvs_tool_bundle_sha256, SHA256_HEX, "NVS tool bundle SHA-256")
    _string(builder_tool_bundle_sha256, SHA256_HEX, "builder tool bundle SHA-256")

    manifest = {
        "version": 2,
        "format": FORMAT,
        "profile": PROFILE,
        "complete": True,
        "transaction": {
            "transaction_id": transaction_id,
            "attempt_id": attempt_id,
            "device_id": device_id,
            "serial_number": serial_number,
            "base_mac": base_mac,
            "sku": "VOICE_AGENT_KIT_BOX3",
            "board": "esp32s3-box3",
            "hardware_revision": 1,
            "chip_revision": chip_revision,
            "factory_record_version": factory_sku_evidence[
                "factory_record_version"
            ],
            "factory_manifest_id": factory_sku_evidence["manifest_id"],
            "factory_manifest_sha256": factory_sku_evidence["manifest_sha256"],
        },
        "release": {
            "signing_request_sha256": request_sha256,
            "signed_artifact_verification_sha256": _sha(
                signed_artifact_receipt_raw
            ),
            "anti_rollback_secure_version": request[
                "anti_rollback_secure_version"
            ],
            "application_unsigned_sha256": request["artifacts"]["application"][
                "sha256"
            ],
            "application_signed_sha256": _sha(signed_application),
            "bootloader_signed_sha256": _sha(signed_bootloader),
            "secure_boot_digests": signed_artifact_receipt[
                "secure_boot_digests"
            ],
            "application_signing_slot": signed_artifact_receipt[
                "application_signing_slot"
            ],
        },
        "factory_material": {
            "onboarding_material_sha256": _sha(onboarding_material),
            "factory_sku_manifest_sha256": _sha(factory_sku_manifest),
            "nvs_factory_image_sha256": _sha(nvs_factory_image),
            "nvs_factory_readback_sha256": _sha(readback["nvs_factory"]),
            "nvs_factory_size": len(nvs_factory_image),
            "exact_public_entries": ["prod_prov/sec2", "prod_sku/manifest"],
        },
        "physical_flash_observation": {
            "schema": physical_observation_receipt["schema"],
            "observation_id": physical_observation_receipt["observation_id"],
            "environment": physical_observation_receipt["environment"],
            "phase": physical_observation_receipt["phase"],
            "station_id": physical_observation_receipt["station"]["id"],
            "signing_key_id": physical_observation_receipt["station"]["signing_key_id"],
            "receipt_sha256": _sha(physical_observation_receipt_raw),
        },
        "programmed_regions": regions,
        "partition_initial_state": PARTITIONS,
        "tools": {
            "espsecure_version": espsecure_version,
            "nvs_partition_tool_bundle_sha256": nvs_tool_bundle_sha256,
            "factory_manifest_builder_bundle_sha256": builder_tool_bundle_sha256,
        },
    }
    validate_manifest(manifest)
    return manifest


def validate_manifest(manifest: dict[str, Any]) -> None:
    root = _exact(
        manifest,
        {
            "version",
            "format",
            "profile",
            "complete",
            "transaction",
            "release",
            "factory_material",
            "physical_flash_observation",
            "programmed_regions",
            "partition_initial_state",
            "tools",
        },
        "manifest",
    )
    if (
        root["version"] != 2
        or root["format"] != FORMAT
        or root["profile"] != PROFILE
        or root["complete"] is not True
    ):
        raise FactoryFlashManifestError("manifest header or completion state differs")
    transaction = _exact(
        root["transaction"],
        {
            "transaction_id",
            "attempt_id",
            "device_id",
            "serial_number",
            "base_mac",
            "sku",
            "board",
            "hardware_revision",
            "chip_revision",
            "factory_record_version",
            "factory_manifest_id",
            "factory_manifest_sha256",
        },
        "manifest transaction",
    )
    _string(transaction["transaction_id"], IDENTIFIER, "transaction ID")
    _string(transaction["attempt_id"], IDENTIFIER, "attempt ID")
    _string(transaction["device_id"], DEVICE_ID, "device ID")
    _string(transaction["serial_number"], IDENTIFIER, "serial number")
    _string(transaction["base_mac"], MAC_ADDRESS, "base MAC")
    if (
        transaction["device_id"]
        != "xz-" + transaction["base_mac"].replace(":", "").lower()
        or transaction["sku"] != "VOICE_AGENT_KIT_BOX3"
        or transaction["board"] != "esp32s3-box3"
        or transaction["hardware_revision"] != 1
    ):
        raise FactoryFlashManifestError("manifest transaction subject differs")
    _integer(transaction["chip_revision"], 0, 999, "chip revision")
    _integer(transaction["factory_record_version"], 1, 0x7FFFFFFF, "record version")
    _string(transaction["factory_manifest_id"], MANIFEST_ID, "manifest ID")
    _string(transaction["factory_manifest_sha256"], SHA256_HEX, "manifest SHA-256")

    release = _exact(
        root["release"],
        {
            "signing_request_sha256",
            "signed_artifact_verification_sha256",
            "anti_rollback_secure_version",
            "application_unsigned_sha256",
            "application_signed_sha256",
            "bootloader_signed_sha256",
            "secure_boot_digests",
            "application_signing_slot",
        },
        "manifest release",
    )
    for name in (
        "signing_request_sha256",
        "signed_artifact_verification_sha256",
        "application_unsigned_sha256",
        "application_signed_sha256",
        "bootloader_signed_sha256",
    ):
        _string(release[name], SHA256_HEX, name)
    _integer(release["anti_rollback_secure_version"], 1, 16, "secure version")
    _integer(release["application_signing_slot"], 0, 2, "application signing slot")
    digests = release["secure_boot_digests"]
    if not isinstance(digests, list) or len(digests) != 3:
        raise FactoryFlashManifestError("manifest release needs three boot digests")
    digest_values = []
    for slot, item in enumerate(digests):
        _exact(item, {"slot", "digest_sha256"}, f"manifest boot digest {slot}")
        if item["slot"] != slot:
            raise FactoryFlashManifestError("manifest boot digest order differs")
        digest_values.append(_string(item["digest_sha256"], SHA256_HEX, "boot digest"))
    if len(set(digest_values)) != 3:
        raise FactoryFlashManifestError("manifest boot digests are not distinct")

    material = _exact(
        root["factory_material"],
        {
            "onboarding_material_sha256",
            "factory_sku_manifest_sha256",
            "nvs_factory_image_sha256",
            "nvs_factory_readback_sha256",
            "nvs_factory_size",
            "exact_public_entries",
        },
        "factory material",
    )
    for name in (
        "onboarding_material_sha256",
        "factory_sku_manifest_sha256",
        "nvs_factory_image_sha256",
        "nvs_factory_readback_sha256",
    ):
        _string(material[name], SHA256_HEX, name)
    if (
        material["nvs_factory_size"] != NVS_FACTORY_BYTES
        or material["nvs_factory_image_sha256"]
        != material["nvs_factory_readback_sha256"]
        or material["factory_sku_manifest_sha256"]
        != transaction["factory_manifest_sha256"]
        or material["exact_public_entries"]
        != ["prod_prov/sec2", "prod_sku/manifest"]
    ):
        raise FactoryFlashManifestError("factory material binding differs")

    observation = _exact(
        root["physical_flash_observation"],
        {
            "schema",
            "observation_id",
            "environment",
            "phase",
            "station_id",
            "signing_key_id",
            "receipt_sha256",
        },
        "physical flash observation",
    )
    if (
        observation["schema"] != "xz-factory-physical-flash-observation-v1"
        or observation["environment"] != "PRODUCTION_FACTORY"
        or observation["phase"] != "PRE_SECURE_DOWNLOAD_LOCK"
    ):
        raise FactoryFlashManifestError("physical flash observation provenance differs")
    for name in ("observation_id", "station_id", "signing_key_id"):
        _string(observation[name], IDENTIFIER, f"physical observation {name}")
    _string(observation["receipt_sha256"], SHA256_HEX, "physical observation hash")

    regions = root["programmed_regions"]
    if not isinstance(regions, list) or len(regions) != len(REGION_POLICY):
        raise FactoryFlashManifestError("programmed region set differs")
    for index, policy in enumerate(REGION_POLICY):
        region = _exact(
            regions[index],
            {
                "name",
                "offset",
                "size",
                "source_treatment",
                "flash_treatment",
                "source_sha256",
                "programmed_sha256",
                "readback_sha256",
            },
            f"programmed region {index}",
        )
        if tuple(region[name] for name in (
            "name", "offset", "source_treatment", "flash_treatment"
        )) != policy:
            raise FactoryFlashManifestError("programmed region policy differs")
        _integer(region["size"], 1, MAX_ARTIFACT_BYTES, "programmed region size")
        for name in ("source_sha256", "programmed_sha256", "readback_sha256"):
            _string(region[name], SHA256_HEX, name)
        if region["programmed_sha256"] != region["readback_sha256"]:
            raise FactoryFlashManifestError("programmed region readback differs")
        if region["flash_treatment"].startswith("FLASH_ENCRYPTION"):
            if region["source_sha256"] == region["programmed_sha256"]:
                raise FactoryFlashManifestError("encrypted region equals plaintext")
        elif region["source_sha256"] != region["programmed_sha256"]:
            raise FactoryFlashManifestError("plaintext factory region differs")
    nvs_region = regions[2]
    if (
        nvs_region["size"] != NVS_FACTORY_BYTES
        or nvs_region["source_sha256"] != material["nvs_factory_image_sha256"]
        or regions[0]["source_sha256"] != release["bootloader_signed_sha256"]
        or regions[4]["source_sha256"] != release["application_signed_sha256"]
    ):
        raise FactoryFlashManifestError("programmed source binding differs")
    if root["partition_initial_state"] != PARTITIONS:
        raise FactoryFlashManifestError("partition initial-state contract differs")
    tools = _exact(
        root["tools"],
        {
            "espsecure_version",
            "nvs_partition_tool_bundle_sha256",
            "factory_manifest_builder_bundle_sha256",
        },
        "manifest tools",
    )
    if tools["espsecure_version"] != ESPSECURE_VERSION:
        raise FactoryFlashManifestError("manifest espsecure version differs")
    _string(tools["nvs_partition_tool_bundle_sha256"], SHA256_HEX, "NVS tool hash")
    _string(tools["factory_manifest_builder_bundle_sha256"], SHA256_HEX, "builder hash")


def tool_bundle_sha256(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths, key=lambda item: item.name):
        data = read_regular(path, 2 * 1024 * 1024, f"tool {path.name}")
        digest.update(path.name.encode("utf-8") + b"\0")
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()
