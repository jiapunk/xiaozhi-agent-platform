#!/usr/bin/env python3
"""Verify M24 unsigned production-security inputs and emit a signing request."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
from pathlib import Path
from typing import Any


PROJECT = Path(__file__).resolve().parents[1]
APP_DESCRIPTION_MAGIC = 0xABCD5432
PARTITION_MAGIC = 0x50AA
PARTITION_MD5_MAGIC = 0xEBEB
PARTITION_TABLE_OFFSET = 0x10000
APP_SLOT_BYTES = 0x580000
SIGNATURE_SECTOR_BYTES = 0x1000

REQUIRED_TRUE = {
    "CONFIG_IDF_TARGET_ESP32S3",
    "CONFIG_PRODUCT_BOARD_ESP_BOX_3",
    "CONFIG_PRODUCT_LIVE_RUNTIME_ENABLE",
    "CONFIG_PRODUCT_STORAGE_REQUIRE_HMAC_NVS_ENCRYPTION",
    "CONFIG_PRODUCT_PRODUCTION_SECURITY_PROFILE",
    "CONFIG_APP_REPRODUCIBLE_BUILD",
    "CONFIG_SECURE_BOOT",
    "CONFIG_SECURE_BOOT_V2_ENABLED",
    "CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME",
    "CONFIG_SECURE_FLASH_ENC_ENABLED",
    "CONFIG_SECURE_FLASH_ENCRYPTION_KEY_SOURCE_EFUSES",
    "CONFIG_SECURE_FLASH_ENCRYPTION_AES128",
    "CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE",
    "CONFIG_SECURE_ENABLE_SECURE_ROM_DL_MODE",
    "CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE",
    "CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK",
}

REQUIRED_FALSE = {
    "CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES",
    "CONFIG_SECURE_BOOT_INSECURE",
    "CONFIG_SECURE_BOOT_ENABLE_AGGRESSIVE_KEY_REVOKE",
    "CONFIG_SECURE_BOOT_V2_ALLOW_EFUSE_RD_DIS",
    "CONFIG_SECURE_BOOT_FLASH_BOOTLOADER_DEFAULT",
    "CONFIG_SECURE_DISABLE_ROM_DL_MODE",
    "CONFIG_SECURE_INSECURE_ALLOW_DL_MODE",
    "CONFIG_BOOTLOADER_EFUSE_SECURE_VERSION_EMULATE",
}

EXPECTED_CONFIG = {
    "CONFIG_IDF_TARGET": '"esp32s3"',
    "CONFIG_PARTITION_TABLE_CUSTOM_FILENAME":
        '"partitions_16MB_box3_production.csv"',
    "CONFIG_PARTITION_TABLE_OFFSET": "0x10000",
    "CONFIG_PRODUCT_STORAGE_NVS_HMAC_KEY_ID": "4",
    "CONFIG_PRODUCT_IDENTITY_HMAC_KEY_ID": "5",
    "CONFIG_BOOTLOADER_APP_SEC_VER_SIZE_EFUSE_FIELD": "16",
    "CONFIG_PRODUCT_OTA_CHANNEL": '"production"',
}

EXPECTED_PARTITIONS = {
    "nvs_factory": (0x01, 0x02, 0x11000, 0x6000, 0),
    "nvs": (0x01, 0x02, 0x17000, 0xA000, 0),
    "otadata": (0x01, 0x00, 0x21000, 0x2000, 1),
    "phy_init": (0x01, 0x01, 0x23000, 0x1000, 1),
    "coredump": (0x01, 0x03, 0x24000, 0x13000, 1),
    "ota_0": (0x00, 0x10, 0x40000, APP_SLOT_BYTES, 0),
    "ota_1": (0x00, 0x11, 0x5C0000, APP_SLOT_BYTES, 0),
    "system": (0x01, 0x81, 0xB40000, 0x200000, 1),
    "data": (0x01, 0x81, 0xD40000, 0x2C0000, 1),
}


class VerificationError(ValueError):
    pass


def parse_sdkconfig(path: Path) -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("CONFIG_") and "=" in line:
            name, value = line.split("=", 1)
            if name in result:
                raise VerificationError(f"duplicate sdkconfig symbol: {name}")
            result[name] = value
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            name = line[2 : -len(" is not set")]
            if name in result:
                raise VerificationError(f"duplicate sdkconfig symbol: {name}")
            result[name] = None
    return result


def verify_config(config: dict[str, str | None]) -> int:
    for name in sorted(REQUIRED_TRUE):
        if config.get(name) != "y":
            raise VerificationError(f"{name} must be enabled")
    for name in sorted(REQUIRED_FALSE):
        if name not in config or config[name] is not None:
            raise VerificationError(f"{name} must be explicitly disabled")
    for name, expected in EXPECTED_CONFIG.items():
        if config.get(name) != expected:
            raise VerificationError(f"{name} must equal {expected}")
    raw_version = config.get("CONFIG_BOOTLOADER_APP_SECURE_VERSION")
    try:
        secure_version = int(raw_version or "", 10)
    except ValueError as error:
        raise VerificationError("invalid app secure version") from error
    if not 1 <= secure_version <= 16:
        raise VerificationError("app secure version must be in 1..16")
    return secure_version


def parse_partition_table(path: Path) -> dict[str, tuple[int, int, int, int, int]]:
    data = path.read_bytes()
    if len(data) != 0xC00:
        raise VerificationError("partition table binary must be exactly 0xC00 bytes")
    result: dict[str, tuple[int, int, int, int, int]] = {}
    for offset in range(0, len(data), 32):
        magic = struct.unpack_from("<H", data, offset)[0]
        if magic in (0xFFFF, PARTITION_MD5_MAGIC):
            break
        if magic != PARTITION_MAGIC:
            raise VerificationError("invalid partition entry magic")
        _, part_type, subtype, address, size, raw_label, flags = struct.unpack_from(
            "<HBBII16sI", data, offset
        )
        label = raw_label.split(b"\0", 1)[0].decode("ascii")
        if not label or label in result:
            raise VerificationError("empty or duplicate partition label")
        result[label] = (part_type, subtype, address, size, flags)
    return result


def verify_partitions(path: Path) -> None:
    partitions = parse_partition_table(path)
    if partitions != EXPECTED_PARTITIONS:
        raise VerificationError("production partition table differs from frozen layout")
    for name in ("ota_0", "ota_1"):
        _, _, offset, size, _ = partitions[name]
        if offset % 0x10000 or size % 0x10000:
            raise VerificationError(f"{name} is not 64 KiB aligned")


def _c_string(data: bytes) -> str:
    try:
        return data.split(b"\0", 1)[0].decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError("application descriptor string is not UTF-8") from error


def verify_application(path: Path, secure_version: int,
                       expected_version: str) -> dict[str, Any]:
    data = path.read_bytes()
    if len(data) < 288 or data[0] != 0xE9:
        raise VerificationError("invalid ESP application image")
    if len(data) % 0x10000 != 0:
        raise VerificationError("unsigned app is not Secure Boot 64 KiB padded")
    if len(data) + SIGNATURE_SECTOR_BYTES > APP_SLOT_BYTES:
        raise VerificationError("signed app would not fit the OTA slot")
    magic, image_secure_version = struct.unpack_from("<II", data, 32)
    if magic != APP_DESCRIPTION_MAGIC:
        raise VerificationError("missing ESP application descriptor")
    if image_secure_version != secure_version:
        raise VerificationError("application secure version differs from sdkconfig")
    version = _c_string(data[48:80])
    project_name = _c_string(data[80:112])
    build_time = _c_string(data[112:128])
    build_date = _c_string(data[128:144])
    if version != expected_version or project_name != "xiaozhi_agent_platform":
        raise VerificationError("application identity differs from release config")
    if build_time or build_date:
        raise VerificationError("reproducible app still contains time/date")
    return {
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "project": project_name,
        "project_version": version,
        "secure_version": image_secure_version,
    }


def verify_bootloader(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    if not data or data[0] != 0xE9 or len(data) % 0x1000:
        raise VerificationError("invalid or unpadded bootloader image")
    if len(data) + SIGNATURE_SECTOR_BYTES > PARTITION_TABLE_OFFSET:
        raise VerificationError("signed bootloader would overlap partition table")
    return {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def artifact(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    return {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def reject_private_keys(build_dir: Path) -> None:
    for path in build_dir.rglob("*"):
        if not path.is_file() or path.stat().st_size > 128 * 1024:
            continue
        if path.suffix.lower() not in {".pem", ".key"} and "signing_key" not in path.name:
            continue
        if b"PRIVATE KEY" in path.read_bytes():
            raise VerificationError(f"private key present in build output: {path.name}")


def make_request(build_dir: Path, config: dict[str, str | None]) -> dict[str, Any]:
    secure_version = verify_config(config)
    partition_path = build_dir / "partition_table" / "partition-table.bin"
    app_path = build_dir / "xiaozhi_agent_platform.bin"
    bootloader_path = build_dir / "bootloader" / "bootloader.bin"
    ota_data_path = build_dir / "ota_data_initial.bin"
    for path in (partition_path, app_path, bootloader_path, ota_data_path):
        if not path.is_file():
            raise VerificationError(f"missing build artifact: {path.name}")
    verify_partitions(partition_path)
    expected_version = (config.get("CONFIG_APP_PROJECT_VER") or "").strip('"')
    if not expected_version:
        raise VerificationError("CONFIG_APP_PROJECT_VER is required")
    app_info = verify_application(app_path, secure_version, expected_version)
    bootloader_info = verify_bootloader(bootloader_path)
    reject_private_keys(build_dir)

    lock = json.loads((PROJECT / "upstream.lock.json").read_text(encoding="utf-8"))
    commits = {
        name: details["commit"]
        for name, details in sorted(lock["upstreams"].items())
    }
    return {
        "version": 1,
        "profile": "box3-production-security-v1",
        "target": "esp32s3",
        "idf_version": "6.0.2",
        "upstream_commits": commits,
        "secure_boot": {
            "scheme": "RSA-3072",
            "bootloader_required_signatures": 3,
            "application_required_signatures": 1,
            "trusted_digest_key_blocks": [0, 1, 2],
        },
        "efuse_key_block_map": [
            {"block": 0, "purpose": "SECURE_BOOT_DIGEST0"},
            {"block": 1, "purpose": "SECURE_BOOT_DIGEST1"},
            {"block": 2, "purpose": "SECURE_BOOT_DIGEST2"},
            {"block": 3, "purpose": "XTS_AES_128_KEY"},
            {"block": 4, "purpose": "HMAC_UP_NVS"},
            {"block": 5, "purpose": "HMAC_UP_IDENTITY"},
        ],
        "flash_encryption": {"mode": "release", "scheme": "XTS-AES-128"},
        "anti_rollback_secure_version": secure_version,
        "partition_table_offset": PARTITION_TABLE_OFFSET,
        "artifacts": {
            "application": app_info,
            "bootloader": bootloader_info,
            "ota_data_initial": artifact(ota_data_path),
            "partition_table": artifact(partition_path),
        },
    }


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def write_request(path: Path, request: dict[str, Any]) -> None:
    payload = canonical_json(request)
    if path.is_symlink():
        raise VerificationError("signing request path must not be a symlink")
    if path.exists():
        if path.read_bytes() != payload:
            raise VerificationError("existing signing request differs")
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o644)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--write-signing-request", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        build_dir = args.build_dir.resolve()
        config = parse_sdkconfig(build_dir / "sdkconfig")
        request = make_request(build_dir, config)
        if args.write_signing_request:
            write_request(args.write_signing_request.resolve(), request)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"production security verification FAILED: {error}", file=sys.stderr)
        return 1
    if args.json:
        print(canonical_json(request).decode("utf-8"), end="")
    else:
        print(
            "production security verification PASS: unsigned reproducible "
            "RSA-3072 remote-signing inputs; three boot digests; "
            f"secure version {request['anti_rollback_secure_version']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
