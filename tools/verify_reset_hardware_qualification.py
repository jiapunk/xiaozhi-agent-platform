#!/usr/bin/env python3
"""Strict verification for signed physical reset/power-cut qualification."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


MAX_RECEIPT_BYTES = 128 * 1024
MAX_PUBLIC_KEY_BYTES = 16 * 1024
SCHEMA = "xz-reset-hardware-qualification-v1"
PROFILE = "box3-reset-v1"
IDENTIFIER = re.compile(r"^[A-Za-z0-9:_.-]{1,64}$")
LONG_IDENTIFIER = re.compile(r"^[A-Za-z0-9:_.-]{1,128}$")
VERSION = re.compile(r"^[A-Za-z0-9._+-]{1,32}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAC = re.compile(r"^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$")
DEVICE_ID = re.compile(r"^xz-[0-9a-f]{12}$")

ROOT_FIELDS = {
    "schema", "qualification_id", "profile", "board", "hardware_revision",
    "firmware", "lab", "fixture", "gesture", "power_cut", "samples",
    "started_at", "finished_at", "result", "signature_algorithm",
    "signature_b64url",
}
FIRMWARE_FIELDS = {"project", "version", "secure_version", "image_sha256"}
LAB_FIELDS = {"id", "operators", "signing_key_id"}
FIXTURE_FIELDS = {"id", "version", "tool_sha256", "evidence_bundle_sha256"}
GESTURE_FIELDS = {
    "boot_held_ms", "boot_held_no_action_pass", "short_press_ms",
    "short_press_no_action_pass", "onboarding_min_ms", "onboarding_max_ms",
    "onboarding_window_pass", "reset_min_ms", "reset_pass", "stuck_hold_ms",
    "stuck_hold_no_action_until_release_pass",
}
POWER_CUT_FIELDS = {
    "after_intent_commit", "after_wifi_erase", "after_wifi_phase_commit",
    "after_memory_erase", "after_memory_phase_commit", "after_journal_erase",
}
SAMPLE_FIELDS = {
    "device_id", "serial_number", "base_mac", "reset_cycles",
    "pre_identity_proof_sha256", "post_identity_proof_sha256",
    "pre_nvs_factory_sha256", "post_nvs_factory_sha256",
    "pre_efuse_summary_sha256", "post_efuse_summary_sha256",
    "wifi_raw_keys_absent_pass", "agent_memory_raw_slots_absent_pass",
    "cloud_binding_unchanged_pass", "secure_boot_preserved_pass",
    "flash_encryption_preserved_pass", "anti_rollback_preserved_pass",
}


class QualificationError(ValueError):
    pass


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise QualificationError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def _exact_object(value: Any, fields: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise QualificationError(f"{path} fields do not match the contract")
    return value


def _string(value: Any, pattern: re.Pattern[str], path: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise QualificationError(f"{path} has invalid format")
    return value


def _integer(value: Any, minimum: int, maximum: int, path: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise QualificationError(f"{path} is outside {minimum}..{maximum}")
    return value


def _true(value: Any, path: str) -> None:
    if value is not True:
        raise QualificationError(f"{path} must be true")


def _timestamp(value: Any, path: str) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value
    ):
        raise QualificationError(f"{path} must be whole-second RFC3339 UTC")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise QualificationError(f"{path} is invalid") from error


def _base64url(value: Any, size: int, path: str) -> bytes:
    if not isinstance(value, str) or "=" in value:
        raise QualificationError(f"{path} must be unpadded base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except (ValueError, binascii.Error) as error:
        raise QualificationError(f"{path} is invalid base64url") from error
    if len(decoded) != size or (
        base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value
    ):
        raise QualificationError(f"{path} is non-canonical or wrong-sized")
    return decoded


def signature_payload(receipt: dict[str, Any]) -> bytes:
    unsigned = dict(receipt)
    unsigned.pop("signature_b64url", None)
    return b"XIAOZHI-RESET-HARDWARE-QUALIFICATION-V1\n" + canonical_json(unsigned)


def parse_receipt(data: bytes) -> dict[str, Any]:
    if not 1 <= len(data) <= MAX_RECEIPT_BYTES:
        raise QualificationError("qualification receipt size is invalid")
    try:
        receipt = json.loads(data.decode("utf-8"), object_pairs_hook=_object_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationError("qualification receipt is not strict UTF-8 JSON") from error
    if not isinstance(receipt, dict) or canonical_json(receipt) != data:
        raise QualificationError("qualification receipt is not canonical JSON")
    return receipt


def validate_receipt(
    receipt: dict[str, Any],
    *,
    expected_board: str,
    expected_project: str,
    expected_version: str,
    expected_secure_version: int,
    expected_image_sha256: str,
    expected_signing_key_id: str,
) -> None:
    root = _exact_object(receipt, ROOT_FIELDS, "receipt")
    if root["schema"] != SCHEMA or root["profile"] != PROFILE:
        raise QualificationError("qualification schema/profile is unsupported")
    _string(root["qualification_id"], LONG_IDENTIFIER, "qualification_id")
    _string(root["hardware_revision"], IDENTIFIER, "hardware_revision")
    if (
        root["board"] != expected_board
        or expected_board != "esp32s3-box3"
        or expected_project != "xiaozhi_agent_platform"
    ):
        raise QualificationError("qualification board does not match release")
    if root["result"] != "PASS" or root["signature_algorithm"] != "Ed25519":
        raise QualificationError("qualification is not an Ed25519 PASS receipt")

    firmware = _exact_object(root["firmware"], FIRMWARE_FIELDS, "firmware")
    _string(firmware["project"], IDENTIFIER, "firmware.project")
    _string(firmware["version"], VERSION, "firmware.version")
    _integer(firmware["secure_version"], 1, 16, "firmware.secure_version")
    _string(firmware["image_sha256"], SHA256, "firmware.image_sha256")
    if firmware != {
        "project": expected_project,
        "version": expected_version,
        "secure_version": expected_secure_version,
        "image_sha256": expected_image_sha256,
    }:
        raise QualificationError("qualification firmware does not match release bytes")

    lab = _exact_object(root["lab"], LAB_FIELDS, "lab")
    _string(lab["id"], IDENTIFIER, "lab.id")
    _string(lab["signing_key_id"], IDENTIFIER, "lab.signing_key_id")
    if lab["signing_key_id"] != expected_signing_key_id:
        raise QualificationError("qualification signing key ID is not trusted")
    operators = lab["operators"]
    if not isinstance(operators, list) or not 2 <= len(operators) <= 4:
        raise QualificationError("lab.operators must contain 2..4 IDs")
    checked_operators = [_string(item, IDENTIFIER, "lab.operators[]") for item in operators]
    if len(set(checked_operators)) != len(checked_operators):
        raise QualificationError("lab operators must be distinct")

    fixture = _exact_object(root["fixture"], FIXTURE_FIELDS, "fixture")
    _string(fixture["id"], IDENTIFIER, "fixture.id")
    _string(fixture["version"], IDENTIFIER, "fixture.version")
    _string(fixture["tool_sha256"], SHA256, "fixture.tool_sha256")
    _string(fixture["evidence_bundle_sha256"], SHA256,
            "fixture.evidence_bundle_sha256")

    gesture = _exact_object(root["gesture"], GESTURE_FIELDS, "gesture")
    exact_gesture = {
        "boot_held_ms": 30000,
        "boot_held_no_action_pass": True,
        "short_press_ms": 2900,
        "short_press_no_action_pass": True,
        "onboarding_min_ms": 3000,
        "onboarding_max_ms": 9900,
        "onboarding_window_pass": True,
        "reset_min_ms": 10000,
        "reset_pass": True,
        "stuck_hold_ms": 30000,
        "stuck_hold_no_action_until_release_pass": True,
    }
    if gesture != exact_gesture:
        raise QualificationError("gesture matrix differs from the frozen release policy")

    power_cut = _exact_object(root["power_cut"], POWER_CUT_FIELDS, "power_cut")
    for boundary, value in power_cut.items():
        item = _exact_object(value, {"attempts", "pass"}, f"power_cut.{boundary}")
        _integer(item["attempts"], 10, 1000, f"power_cut.{boundary}.attempts")
        _true(item["pass"], f"power_cut.{boundary}.pass")

    samples = root["samples"]
    if not isinstance(samples, list) or not 3 <= len(samples) <= 32:
        raise QualificationError("samples must contain 3..32 physical devices")
    device_ids: set[str] = set()
    serials: set[str] = set()
    macs: set[str] = set()
    total_cycles = 0
    for index, value in enumerate(samples):
        path = f"samples[{index}]"
        sample = _exact_object(value, SAMPLE_FIELDS, path)
        device_id = _string(sample["device_id"], DEVICE_ID, f"{path}.device_id")
        serial = _string(sample["serial_number"], IDENTIFIER, f"{path}.serial_number")
        mac = _string(sample["base_mac"], MAC, f"{path}.base_mac")
        if device_id != "xz-" + mac.replace(":", "").lower():
            raise QualificationError(f"{path} device ID does not match base MAC")
        if device_id in device_ids or serial in serials or mac in macs:
            raise QualificationError("physical qualification samples must be distinct")
        device_ids.add(device_id)
        serials.add(serial)
        macs.add(mac)
        total_cycles += _integer(sample["reset_cycles"], 100, 100000,
                                 f"{path}.reset_cycles")
        for name in (
            "pre_identity_proof_sha256", "post_identity_proof_sha256",
            "pre_nvs_factory_sha256", "post_nvs_factory_sha256",
            "pre_efuse_summary_sha256", "post_efuse_summary_sha256",
        ):
            _string(sample[name], SHA256, f"{path}.{name}")
        for prefix in ("identity_proof", "nvs_factory", "efuse_summary"):
            if sample[f"pre_{prefix}_sha256"] != sample[f"post_{prefix}_sha256"]:
                raise QualificationError(f"{path} {prefix} changed across reset")
        for name in SAMPLE_FIELDS - {
            "device_id", "serial_number", "base_mac", "reset_cycles",
            "pre_identity_proof_sha256", "post_identity_proof_sha256",
            "pre_nvs_factory_sha256", "post_nvs_factory_sha256",
            "pre_efuse_summary_sha256", "post_efuse_summary_sha256",
        }:
            _true(sample[name], f"{path}.{name}")
    if total_cycles < 1000:
        raise QualificationError("physical reset wear evidence must total at least 1000 cycles")

    started = _timestamp(root["started_at"], "started_at")
    finished = _timestamp(root["finished_at"], "finished_at")
    if finished <= started or finished - started > timedelta(days=7):
        raise QualificationError("qualification time window is invalid or too long")
    _base64url(root["signature_b64url"], 64, "signature_b64url")


def verify_receipt_bytes(
    receipt_bytes: bytes,
    public_key_pem: bytes,
    *,
    expected_board: str,
    expected_project: str,
    expected_version: str,
    expected_secure_version: int,
    expected_image_sha256: str,
    expected_signing_key_id: str,
) -> dict[str, Any]:
    receipt = parse_receipt(receipt_bytes)
    validate_receipt(
        receipt,
        expected_board=expected_board,
        expected_project=expected_project,
        expected_version=expected_version,
        expected_secure_version=expected_secure_version,
        expected_image_sha256=expected_image_sha256,
        expected_signing_key_id=expected_signing_key_id,
    )
    if not 1 <= len(public_key_pem) <= MAX_PUBLIC_KEY_BYTES or b"PRIVATE KEY" in public_key_pem:
        raise QualificationError("qualification verifier requires a bounded public key")
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
    except (TypeError, ValueError) as error:
        raise QualificationError("qualification public key PEM is invalid") from error
    if not isinstance(public_key, Ed25519PublicKey):
        raise QualificationError("qualification public key must be Ed25519")
    signature = _base64url(receipt["signature_b64url"], 64, "signature_b64url")
    try:
        public_key.verify(signature, signature_payload(receipt))
    except InvalidSignature as error:
        raise QualificationError("qualification signature is invalid") from error
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--expected-board", required=True)
    parser.add_argument("--expected-project", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-secure-version", required=True, type=int)
    parser.add_argument("--expected-image-sha256", required=True)
    parser.add_argument("--expected-signing-key-id", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        receipt_bytes = args.receipt.read_bytes()
        receipt = verify_receipt_bytes(
            receipt_bytes,
            args.public_key.read_bytes(),
            expected_board=args.expected_board,
            expected_project=args.expected_project,
            expected_version=args.expected_version,
            expected_secure_version=args.expected_secure_version,
            expected_image_sha256=args.expected_image_sha256,
            expected_signing_key_id=args.expected_signing_key_id,
        )
    except (OSError, QualificationError) as error:
        print(f"reset hardware qualification FAILED: {error}", file=sys.stderr)
        return 1
    if args.json:
        print(canonical_json(receipt).decode("utf-8"), end="")
    else:
        print(
            "reset hardware qualification PASS: "
            f"{receipt['qualification_id']} receipt_sha256="
            f"{hashlib.sha256(receipt_bytes).hexdigest()}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
