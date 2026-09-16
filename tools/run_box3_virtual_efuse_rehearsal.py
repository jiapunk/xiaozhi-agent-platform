#!/usr/bin/env python3
"""Run the M57 ESP32-S3 eFuse lifecycle only against espefuse --virt."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from virtual_efuse_rehearsal import (
    ESPEFUSE_VERSION,
    ENVIRONMENT,
    FORMAT,
    IDF_VERSION,
    KEY_PURPOSES,
    PRODUCT_ROLES,
    PROFILE,
    RESULT,
    SECURE_VERSION,
    STAGE_NAMES,
    TARGET,
    VERSION,
    RehearsalError,
    canonical_json,
    select_fields,
    sha256,
    validate_evidence,
    validate_signing_request_binding,
)


EXPECTED_REQUEST_KEYS = {
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


def read_request(path: Path) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink() or not path.is_file():
        raise RehearsalError("signing request must be a regular non-symlink file")
    if path.stat().st_size > 2 * 1024 * 1024:
        raise RehearsalError("signing request is too large")
    data = path.read_bytes()
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RehearsalError(f"invalid signing request: {exc}") from exc
    if not isinstance(value, dict) or set(value) != EXPECTED_REQUEST_KEYS:
        raise RehearsalError("signing request shape differs")
    if canonical_json(value) != data:
        raise RehearsalError("signing request is not canonical JSON")
    if (
        value["version"] != 1
        or value["profile"] != PROFILE
        or value["target"] != TARGET
        or value["idf_version"] != IDF_VERSION
        or value["anti_rollback_secure_version"] != SECURE_VERSION
    ):
        raise RehearsalError("signing request does not match frozen M57 subject")
    expected_map = [
        {"block": 0, "purpose": "SECURE_BOOT_DIGEST0"},
        {"block": 1, "purpose": "SECURE_BOOT_DIGEST1"},
        {"block": 2, "purpose": "SECURE_BOOT_DIGEST2"},
        {"block": 3, "purpose": "XTS_AES_128_KEY"},
        {"block": 4, "purpose": "HMAC_UP_NVS"},
        {"block": 5, "purpose": "HMAC_UP_IDENTITY"},
    ]
    if value["efuse_key_block_map"] != expected_map:
        raise RehearsalError("signing request six-slot allocation differs")
    if value["secure_boot"] != {
        "scheme": "RSA-3072",
        "bootloader_required_signatures": 3,
        "application_required_signatures": 1,
        "trusted_digest_key_blocks": [0, 1, 2],
    }:
        raise RehearsalError("signing request Secure Boot policy differs")
    if value["flash_encryption"] != {
        "mode": "release",
        "scheme": "XTS-AES-128",
    }:
        raise RehearsalError("signing request Flash Encryption policy differs")
    return value, data


def write_private_file(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def write_evidence(path: Path, data: bytes) -> None:
    if path.is_symlink() or path.exists():
        raise RehearsalError("evidence output already exists or is a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


class VirtualEfuse:
    def __init__(self, directory: Path):
        self.directory = directory
        self.image = directory / "virtual-efuse.bin"
        self.prefix = [
            sys.executable,
            "-m",
            "espefuse",
            "--chip",
            TARGET,
            "--virt",
            "--path-efuse-file",
            str(self.image),
            "--do-not-confirm",
        ]

    def run(self, *arguments: str) -> str:
        command = [*self.prefix, *arguments]
        if "--port" in command or "-p" in command:
            raise RehearsalError("virtual rehearsal refuses every serial-port argument")
        result = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            raise RehearsalError(
                f"virtual espefuse command failed ({arguments[0]}): {result.stdout[-2000:]}"
            )
        return result.stdout

    def summary(self, index: int) -> tuple[dict[str, Any], str]:
        path = self.directory / f"stage-{index}.json"
        self.run("summary", "--format", "json", "--file", str(path))
        data = path.read_bytes()
        try:
            value = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RehearsalError(f"official summary is invalid: {exc}") from exc
        if not isinstance(value, dict):
            raise RehearsalError("official summary root must be an object")
        return value, sha256(data)


def public_key_bytes() -> bytes:
    private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def verify_tool_version() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "espefuse", "--version"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=15,
    )
    if result.returncode != 0 or f"espefuse v{ESPEFUSE_VERSION}" not in result.stdout:
        raise RehearsalError(f"espefuse must be exactly {ESPEFUSE_VERSION}")


def run_rehearsal(request_data: bytes) -> dict[str, Any]:
    verify_tool_version()
    with tempfile.TemporaryDirectory(prefix="xz-virtual-efuse-") as name:
        directory = Path(name)
        flash_key = directory / "flash-xts.bin"
        nvs_key = directory / "nvs-hmac.bin"
        identity_key = directory / "identity-hmac.bin"
        for path in (flash_key, nvs_key, identity_key):
            write_private_file(path, secrets.token_bytes(32))

        public_keys: list[Path] = []
        for slot in range(3):
            path = directory / f"secure-boot-{slot}-public.pem"
            write_private_file(path, public_key_bytes())
            public_keys.append(path)

        efuse = VirtualEfuse(directory)
        stages: list[dict[str, Any]] = []

        def capture(index: int) -> None:
            summary, official_hash = efuse.summary(index)
            fields = select_fields(summary)
            stages.append(
                {
                    "name": STAGE_NAMES[index],
                    "official_summary_sha256": official_hash,
                    "selected_fields_sha256": sha256(canonical_json(fields)),
                    "fields": fields,
                }
            )

        capture(0)
        efuse.run(
            "burn-key",
            "BLOCK_KEY3",
            str(flash_key),
            "XTS_AES_128_KEY",
            "BLOCK_KEY4",
            str(nvs_key),
            "HMAC_UP",
            "BLOCK_KEY5",
            str(identity_key),
            "HMAC_UP",
        )
        capture(1)
        efuse.run(
            "burn-key-digest",
            "--no-read-protect",
            "BLOCK_KEY0",
            str(public_keys[0]),
            "SECURE_BOOT_DIGEST0",
            "BLOCK_KEY1",
            str(public_keys[1]),
            "SECURE_BOOT_DIGEST1",
            "BLOCK_KEY2",
            str(public_keys[2]),
            "SECURE_BOOT_DIGEST2",
        )
        capture(2)

        efuse.run("write-protect-efuse", "RD_DIS")
        capture(3)

        efuse.run(
            "burn-efuse",
            "DIS_DOWNLOAD_ICACHE",
            "1",
            "DIS_DOWNLOAD_DCACHE",
            "1",
            "DIS_PAD_JTAG",
            "1",
            "DIS_DOWNLOAD_MANUAL_ENCRYPT",
            "1",
            "SPI_BOOT_CRYPT_CNT",
            "7",
            "DIS_USB_JTAG",
            "1",
            "DIS_DIRECT_BOOT",
            "1",
            "SECURE_VERSION",
            str(SECURE_VERSION),
            "SECURE_BOOT_EN",
            "1",
        )
        efuse.run(
            "write-protect-efuse",
            "DIS_DOWNLOAD_ICACHE",
            "SPI_BOOT_CRYPT_CNT",
            "SECURE_BOOT_EN",
        )
        capture(4)

        # ENABLE_SECURITY_DOWNLOAD and its shared WR_DIS group must be committed
        # in one final batch. Reconnecting after this boundary is not assumed.
        efuse.run(
            "burn-efuse",
            "ENABLE_SECURITY_DOWNLOAD",
            "1",
            "write-protect-efuse",
            "ENABLE_SECURITY_DOWNLOAD",
        )
        capture(5)

        image_data = efuse.image.read_bytes()
        evidence = {
            "schema": FORMAT,
            "version": VERSION,
            "environment": ENVIRONMENT,
            "result": RESULT,
            "subject": {
                "profile": PROFILE,
                "target": TARGET,
                "idf_version": IDF_VERSION,
                "secure_version": SECURE_VERSION,
                "signing_request_sha256": sha256(request_data),
            },
            "tool": {
                "name": "espefuse",
                "version": ESPEFUSE_VERSION,
                "mode": "--virt",
                "chip": TARGET,
            },
            "key_allocation": [
                {
                    "logical_slot": slot,
                    "physical_block": 4 + slot,
                    "block_name": f"BLOCK_KEY{slot}",
                    "purpose": KEY_PURPOSES[slot],
                    "product_role": PRODUCT_ROLES[slot],
                }
                for slot in range(6)
            ],
            "stages": stages,
            "final_virtual_efuse_image_sha256": sha256(image_data),
            "secret_handling": {
                "test_only_ephemeral": True,
                "secure_boot_private_keys_persisted": False,
                "raw_secret_values_recorded": False,
            },
            "boundary": {
                "physical_device_touched": False,
                "factory_evidence": False,
                "market_release_evidence": False,
            },
        }
        return validate_evidence(evidence)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--signing-request", required=True, type=Path)
    parser.add_argument("--write-evidence", required=True, type=Path)
    args = parser.parse_args()
    try:
        _, request_data = read_request(args.signing_request)
        evidence = run_rehearsal(request_data)
        validate_signing_request_binding(evidence, args.signing_request)
        write_evidence(args.write_evidence, canonical_json(evidence))
    except (OSError, RehearsalError, subprocess.SubprocessError) as exc:
        parser.error(str(exc))
    print("box3 virtual-eFuse rehearsal PASS")
    print("VIRTUAL_TEST_ONLY: no physical device, factory, or market-release evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
