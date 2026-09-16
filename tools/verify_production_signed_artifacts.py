#!/usr/bin/env python3
"""Verify externally signed M24 bootloader/application artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


MAX_REQUEST_BYTES = 64 * 1024
SIGNATURE_SECTOR_BYTES = 0x1000
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
VALID_BLOCK = re.compile(r"^Signature block ([0-2]) is valid \(RSA\)\.$")
BLOCK_DIGEST = re.compile(
    r"^Public key digest for block ([0-2]): ((?:[0-9a-f]{2} ){31}[0-9a-f]{2})$"
)


class VerificationError(ValueError):
    pass


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
EXPECTED_UPSTREAMS = {
    "esp-claw": "9ba07d013329df480e34a1a59d1513ab783d8a52",
    "xiaozhi-esp32": "18a60b8051f5ee6a25beed6248ed84c7fcc742bf",
}
EXPECTED_SECURE_BOOT = {
    "scheme": "RSA-3072",
    "bootloader_required_signatures": 3,
    "application_required_signatures": 1,
    "trusted_digest_key_blocks": [0, 1, 2],
}
EXPECTED_KEY_BLOCK_MAP = [
    {"block": 0, "purpose": "SECURE_BOOT_DIGEST0"},
    {"block": 1, "purpose": "SECURE_BOOT_DIGEST1"},
    {"block": 2, "purpose": "SECURE_BOOT_DIGEST2"},
    {"block": 3, "purpose": "XTS_AES_128_KEY"},
    {"block": 4, "purpose": "HMAC_UP_NVS"},
    {"block": 5, "purpose": "HMAC_UP_IDENTITY"},
]


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def load_request(path: Path) -> tuple[dict[str, Any], str]:
    data = path.read_bytes()
    if not data or len(data) > MAX_REQUEST_BYTES:
        raise VerificationError("invalid signing request size")
    try:
        request = json.loads(data.decode("utf-8"), object_pairs_hook=_object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError("invalid signing request JSON") from error
    if not isinstance(request, dict) or canonical_json(request) != data:
        raise VerificationError("signing request is not canonical JSON")
    if (
        set(request) != EXPECTED_REQUEST_KEYS
        or request.get("version") != 1
        or request.get("profile") != "box3-production-security-v1"
        or request.get("target") != "esp32s3"
        or request.get("idf_version") != "6.0.2"
        or request.get("upstream_commits") != EXPECTED_UPSTREAMS
        or request.get("secure_boot") != EXPECTED_SECURE_BOOT
        or request.get("efuse_key_block_map") != EXPECTED_KEY_BLOCK_MAP
        or request.get("flash_encryption")
        != {"mode": "release", "scheme": "XTS-AES-128"}
        or request.get("partition_table_offset") != 0x10000
    ):
        raise VerificationError("signing request policy differs from M24")
    secure_version = request.get("anti_rollback_secure_version")
    if (
        isinstance(secure_version, bool)
        or not isinstance(secure_version, int)
        or not 1 <= secure_version <= 16
    ):
        raise VerificationError("invalid anti-rollback secure version")
    artifacts = request.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != {
        "application", "bootloader", "ota_data_initial", "partition_table"
    } or not all(isinstance(value, dict) for value in artifacts.values()):
        raise VerificationError("signing request artifacts are missing")
    if set(artifacts["bootloader"]) != {"size", "sha256"}:
        raise VerificationError("invalid bootloader metadata shape")
    if set(artifacts["application"]) != {
        "size", "sha256", "project", "project_version", "secure_version"
    }:
        raise VerificationError("invalid application metadata shape")
    if artifacts["application"].get("project") != "xiaozhi_agent_platform":
        raise VerificationError("invalid application project")
    if artifacts["application"].get("project_version") != "0.24.0-security-gate":
        raise VerificationError("invalid application version")
    if artifacts["application"].get("secure_version") != secure_version:
        raise VerificationError("application/request secure versions differ")
    for name in ("ota_data_initial", "partition_table"):
        if set(artifacts[name]) != {"size", "sha256"}:
            raise VerificationError(f"invalid {name} metadata shape")
    if artifacts["ota_data_initial"].get("size") != 0x2000 or artifacts[
        "partition_table"
    ].get("size") != 0xC00:
        raise VerificationError("fixed auxiliary artifact sizes differ")
    for name, metadata in artifacts.items():
        size = metadata.get("size")
        digest = metadata.get("sha256")
        if (
            isinstance(size, bool)
            or not isinstance(size, int)
            or size <= 0
            or not isinstance(digest, str)
            or not SHA256_HEX.fullmatch(digest)
        ):
            raise VerificationError(f"invalid {name} hash/size")
    app_size = artifacts["application"]["size"]
    boot_size = artifacts["bootloader"]["size"]
    if app_size % 0x10000 or app_size + SIGNATURE_SECTOR_BYTES > 0x580000:
        raise VerificationError("invalid secure-padded application size")
    if boot_size % 0x1000 or boot_size + SIGNATURE_SECTOR_BYTES > 0x10000:
        raise VerificationError("invalid secure-padded bootloader size")
    return request, hashlib.sha256(data).hexdigest()


def verify_signed_prefix(path: Path, expected: dict[str, Any], name: str) -> dict[str, Any]:
    unsigned_size = expected.get("size")
    unsigned_sha256 = expected.get("sha256")
    if (
        isinstance(unsigned_size, bool)
        or not isinstance(unsigned_size, int)
        or unsigned_size <= 0
        or not isinstance(unsigned_sha256, str)
        or not SHA256_HEX.fullmatch(unsigned_sha256)
    ):
        raise VerificationError(f"invalid unsigned {name} metadata")
    if path.stat().st_size != unsigned_size + SIGNATURE_SECTOR_BYTES:
        raise VerificationError(f"signed {name} must add one signature sector")
    data = path.read_bytes()
    if len(data) != unsigned_size + SIGNATURE_SECTOR_BYTES:
        raise VerificationError(f"signed {name} changed while being verified")
    if hashlib.sha256(data[:unsigned_size]).hexdigest() != unsigned_sha256:
        raise VerificationError(f"signed {name} prefix differs from approved input")
    if data[unsigned_size] != 0xE7:
        raise VerificationError(f"signed {name} has no Secure Boot V2 signature magic")
    return {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def run_espsecure(python: Path, arguments: list[str]) -> str:
    result = subprocess.run(
        [str(python), "-m", "espsecure", *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=60,
    )
    if result.returncode != 0:
        detail = " ".join(result.stdout.strip().split())[:500]
        raise VerificationError(
            f"espsecure {arguments[0]} rejected verification: {detail}"
        )
    return result.stdout


def parse_signature_info(output: str, expected_count: int) -> list[str]:
    valid: dict[int, bool] = {}
    digests: dict[int, str] = {}
    for line in output.splitlines():
        valid_match = VALID_BLOCK.fullmatch(line.strip())
        if valid_match:
            slot = int(valid_match.group(1))
            if slot in valid:
                raise VerificationError("duplicate valid-signature block output")
            valid[slot] = True
        digest_match = BLOCK_DIGEST.fullmatch(line.strip())
        if digest_match:
            slot = int(digest_match.group(1))
            if slot in digests:
                raise VerificationError("duplicate public-key digest output")
            digests[slot] = digest_match.group(2).replace(" ", "")
    expected_slots = list(range(expected_count))
    if sorted(valid) != expected_slots or sorted(digests) != expected_slots:
        raise VerificationError(
            f"expected exactly {expected_count} valid RSA signature blocks"
        )
    values = [digests[index] for index in expected_slots]
    if len(set(values)) != expected_count:
        raise VerificationError("signature blocks must use distinct public keys")
    return values


def public_key_digests(python: Path, keys: list[Path]) -> list[str]:
    if len(keys) != 3:
        raise VerificationError("exactly three ordered public keys are required")
    values: list[str] = []
    with tempfile.TemporaryDirectory(prefix="xz-public-digests-") as directory:
        root = Path(directory)
        for index, key in enumerate(keys):
            if key.stat().st_size > 16 * 1024:
                raise VerificationError("public key PEM is too large")
            key_data = key.read_bytes()
            if len(key_data) > 16 * 1024:
                raise VerificationError("public key PEM changed while being verified")
            if b"PRIVATE KEY" in key_data or b"BEGIN PUBLIC KEY" not in key_data:
                raise VerificationError("only PEM public keys are accepted")
            output = root / f"digest-{index}.bin"
            run_espsecure(
                python,
                [
                    "digest-sbv2-public-key",
                    "--keyfile",
                    str(key),
                    "--output",
                    str(output),
                ],
            )
            digest = output.read_bytes()
            if len(digest) != 32:
                raise VerificationError("invalid Secure Boot public-key digest")
            values.append(digest.hex())
    if len(set(values)) != 3:
        raise VerificationError("public keys must be distinct")
    return values


def verify_artifacts(
    python: Path,
    request_path: Path,
    signed_bootloader: Path,
    signed_application: Path,
    public_keys: list[Path],
) -> dict[str, Any]:
    request, request_sha256 = load_request(request_path)
    boot_info = verify_signed_prefix(
        signed_bootloader, request["artifacts"]["bootloader"], "bootloader"
    )
    app_info = verify_signed_prefix(
        signed_application, request["artifacts"]["application"], "application"
    )
    key_digests = public_key_digests(python, public_keys)
    boot_digests = parse_signature_info(
        run_espsecure(python, ["signature-info-v2", str(signed_bootloader)]), 3
    )
    app_digests = parse_signature_info(
        run_espsecure(python, ["signature-info-v2", str(signed_application)]), 1
    )
    if boot_digests != key_digests:
        raise VerificationError("ordered public keys do not match boot signature slots")
    if app_digests[0] not in key_digests:
        raise VerificationError("application is not signed by a trusted boot key")
    for key in public_keys:
        run_espsecure(
            python,
            [
                "verify-signature",
                "--version",
                "2",
                "--keyfile",
                str(key),
                str(signed_bootloader),
            ],
        )
    active_key_index = key_digests.index(app_digests[0])
    run_espsecure(
        python,
        [
            "verify-signature",
            "--version",
            "2",
            "--keyfile",
            str(public_keys[active_key_index]),
            str(signed_application),
        ],
    )
    return {
        "version": 1,
        "profile": request["profile"],
        "signing_request_sha256": request_sha256,
        "anti_rollback_secure_version": request["anti_rollback_secure_version"],
        "bootloader": boot_info,
        "application": app_info,
        "secure_boot_digests": [
            {"slot": index, "digest_sha256": digest}
            for index, digest in enumerate(boot_digests)
        ],
        "application_signing_slot": active_key_index,
    }


def write_receipt(path: Path, receipt: dict[str, Any]) -> None:
    payload = canonical_json(receipt)
    if path.is_symlink():
        raise VerificationError("signed-artifact receipt path must not be a symlink")
    if path.exists():
        if path.read_bytes() != payload:
            raise VerificationError("existing signed-artifact receipt differs")
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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--signing-request", type=Path, required=True)
    parser.add_argument("--signed-bootloader", type=Path, required=True)
    parser.add_argument("--signed-application", type=Path, required=True)
    parser.add_argument(
        "--public-key", type=Path, action="append", required=True,
        help="ordered key for SECURE_BOOT_DIGEST0, 1, then 2",
    )
    parser.add_argument("--espsecure-python", type=Path, default=Path(sys.executable))
    parser.add_argument("--write-verification-receipt", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        receipt = verify_artifacts(
            Path(os.path.abspath(args.espsecure_python)),
            args.signing_request.resolve(),
            args.signed_bootloader.resolve(),
            args.signed_application.resolve(),
            [path.resolve() for path in args.public_key],
        )
        if args.write_verification_receipt:
            write_receipt(args.write_verification_receipt.resolve(), receipt)
    except (OSError, KeyError, TypeError, ValueError, subprocess.SubprocessError) as error:
        print(f"signed production artifact verification FAILED: {error}", file=sys.stderr)
        return 1
    if args.json:
        print(canonical_json(receipt).decode("utf-8"), end="")
    else:
        print(
            "signed production artifact verification PASS: bootloader 3/3 RSA; "
            f"application slot {receipt['application_signing_slot']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
