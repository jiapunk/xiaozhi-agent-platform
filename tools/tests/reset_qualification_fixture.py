from __future__ import annotations

import base64
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools import verify_reset_hardware_qualification as QUALIFICATION


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def resign(receipt: dict[str, object], private_key: Ed25519PrivateKey) -> bytes:
    receipt["signature_b64url"] = base64.urlsafe_b64encode(
        private_key.sign(QUALIFICATION.signature_payload(receipt))
    ).rstrip(b"=").decode("ascii")
    return QUALIFICATION.canonical_json(receipt)


def signed_reset_qualification(
    *,
    image_sha256: str,
    version: str,
    secure_version: int,
    project: str = "xiaozhi_agent_platform",
    board: str = "esp32s3-box3",
) -> tuple[bytes, bytes, Ed25519PrivateKey]:
    private_key = Ed25519PrivateKey.generate()
    power_cut = {
        boundary: {"attempts": 10, "pass": True}
        for boundary in QUALIFICATION.POWER_CUT_FIELDS
    }
    samples = []
    for index in range(1, 4):
        mac = f"02:00:00:00:00:{index:02X}"
        identity = _digest(f"identity-{index}")
        factory = _digest(f"factory-{index}")
        efuse = _digest(f"efuse-{index}")
        samples.append(
            {
                "device_id": "xz-" + mac.replace(":", "").lower(),
                "serial_number": f"BOX3-M40-{index:04d}",
                "base_mac": mac,
                "reset_cycles": 334,
                "pre_identity_proof_sha256": identity,
                "post_identity_proof_sha256": identity,
                "pre_nvs_factory_sha256": factory,
                "post_nvs_factory_sha256": factory,
                "pre_efuse_summary_sha256": efuse,
                "post_efuse_summary_sha256": efuse,
                "wifi_raw_keys_absent_pass": True,
                "agent_memory_raw_slots_absent_pass": True,
                "cloud_binding_unchanged_pass": True,
                "secure_boot_preserved_pass": True,
                "flash_encryption_preserved_pass": True,
                "anti_rollback_preserved_pass": True,
            }
        )
    receipt: dict[str, object] = {
        "schema": QUALIFICATION.SCHEMA,
        "qualification_id": "box3-m40-synthetic-contract-fixture",
        "profile": QUALIFICATION.PROFILE,
        "board": board,
        "hardware_revision": "box3-rev-a",
        "firmware": {
            "project": project,
            "version": version,
            "secure_version": secure_version,
            "image_sha256": image_sha256,
        },
        "lab": {
            "id": "synthetic-test-lab",
            "operators": ["test-operator-a", "test-operator-b"],
            "signing_key_id": "synthetic-ed25519-key",
        },
        "fixture": {
            "id": "synthetic-reset-fixture",
            "version": "1.0.0",
            "tool_sha256": _digest("fixture-tool"),
            "evidence_bundle_sha256": _digest("evidence-bundle"),
        },
        "gesture": {
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
        },
        "power_cut": power_cut,
        "samples": samples,
        "started_at": "2026-08-09T08:00:00Z",
        "finished_at": "2026-08-10T08:00:00Z",
        "result": "PASS",
        "signature_algorithm": "Ed25519",
        "signature_b64url": "",
    }
    receipt_bytes = resign(receipt, private_key)
    public_key_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return receipt_bytes, public_key_pem, private_key
