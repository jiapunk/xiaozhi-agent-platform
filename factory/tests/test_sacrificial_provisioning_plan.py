import base64
import copy
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


PROJECT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = PROJECT / "tools" / "sacrificial_provisioning_plan.py"
SPEC = importlib.util.spec_from_file_location("sacrificial_plan_test", MODULE_PATH)
PLAN = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(PLAN)


def field(block, bit_len, raw_value, value, readable=True, writeable=True):
    return {
        "block": block,
        "bit_len": bit_len,
        "raw_value": raw_value,
        "value": value,
        "readable": readable,
        "writeable": writeable,
    }


def blank_summary():
    value = {
        "MAC": field(1, 48, "0x020000000001", "02:00:00:00:00:01 (OK)"),
        "WR_DIS": field(0, 32, "0x00000000", 0),
        "RD_DIS": field(0, 7, "0x00", 0),
        "SPI_BOOT_CRYPT_CNT": field(0, 3, "0x0", "Disable"),
        "SECURE_VERSION": field(0, 16, "0x0000", 0),
    }
    for name in PLAN.SUMMARY_BOOL_FIELDS:
        value[name] = field(0, 1, "0x0", False)
    for slot in range(6):
        value[f"BLOCK_KEY{slot}"] = field(4 + slot, 256, PLAN.ZERO_KEY, "00 " * 31 + "00")
        value[f"KEY_PURPOSE_{slot}"] = field(0, 4, "0x0", "USER")
    return value


def signing_request():
    return {
        "version": 1,
        "profile": "box3-production-security-v1",
        "target": "esp32s3",
        "idf_version": "6.0.2",
        "upstream_commits": {
            "esp-claw": "9ba07d013329df480e34a1a59d1513ab783d8a52",
            "xiaozhi-esp32": "18a60b8051f5ee6a25beed6248ed84c7fcc742bf",
        },
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
        "anti_rollback_secure_version": 1,
        "partition_table_offset": 0x10000,
        "artifacts": {
            "application": {
                "project": "xiaozhi_agent_platform",
                "project_version": "0.24.0-security-gate",
                "secure_version": 1,
                "sha256": "10" * 32,
                "size": 0x160000,
            },
            "bootloader": {"sha256": "11" * 32, "size": 0xB000},
            "ota_data_initial": {"sha256": "12" * 32, "size": 0x2000},
            "partition_table": {"sha256": "13" * 32, "size": 0xC00},
        },
    }


def release_files():
    request_raw = PLAN.canonical_json(signing_request())
    receipt = {
        "version": 1,
        "profile": "box3-production-security-v1",
        "signing_request_sha256": PLAN.sha256(request_raw),
        "anti_rollback_secure_version": 1,
        "bootloader": {"size": 0xC000, "sha256": "20" * 32},
        "application": {"size": 0x161000, "sha256": "21" * 32},
        "secure_boot_digests": [
            {"slot": slot, "digest_sha256": f"{0x30 + slot:02x}" * 32}
            for slot in range(3)
        ],
        "application_signing_slot": 0,
    }
    return request_raw, PLAN.canonical_json(receipt)


def request():
    signing_raw, artifact_raw = release_files()
    summary = json.dumps(blank_summary(), sort_keys=True).encode("utf-8")
    return PLAN.build_request(
        plan_id="sacrificial-plan-0001",
        transaction_id="sacrificial-tx-0001",
        attempt_id="attempt-0001",
        device_id="xz-020000000001",
        serial_number="SACRIFICIAL-0001",
        base_mac="02:00:00:00:00:01",
        chip_revision=1,
        release=PLAN.load_release_evidence(signing_raw, artifact_raw),
        station_id="lab-station-01",
        operators=["operator-a", "operator-b"],
        fixture_id="fixture-01",
        fixture_version="1.0.0",
        fixture_calibration_sha256="40" * 32,
        authorization_key_id="sacrificial-authority-2026",
        port_fingerprint_sha256="41" * 32,
        chip_probe=(
            b"esptool v5.3.1\nChip is ESP32-S3 (revision v0.2)\n"
            b"MAC: 02:00:00:00:00:01\n"
        ),
        flash_probe=b"esptool v5.3.1\nDetected flash size: 16MB\n",
        tool_versions=b"esptool=5.3.1\nespefuse=5.3.1\n",
        efuse_summary_before=summary,
        efuse_summary_after=summary,
        efuse_check_error=b"espefuse v5.3.1\nNo errors detected.\n",
        capture_started_at="2026-08-10T10:00:00Z",
        capture_finished_at="2026-08-10T10:05:00Z",
        issued_at="2026-08-10T10:06:00Z",
        expires_at="2026-08-10T10:16:00Z",
    )


def signed():
    private = Ed25519PrivateKey.generate()
    value = request()
    value["signature_b64url"] = base64.urlsafe_b64encode(
        private.sign(PLAN.canonical_json(value))
    ).rstrip(b"=").decode("ascii")
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return value, public, private


class SacrificialProvisioningPlanTests(unittest.TestCase):
    @unittest.skipUnless(
        importlib.util.find_spec("espefuse") is not None,
        "pinned ESP-IDF Python environment is unavailable",
    )
    def test_real_espefuse_virtual_blank_summary_matches_preflight_parser(self):
        with tempfile.TemporaryDirectory(prefix="xz-m58-virt-") as name:
            root = pathlib.Path(name)
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "espefuse",
                    "--chip",
                    "esp32s3",
                    "--virt",
                    "--path-efuse-file",
                    str(root / "efuse.bin"),
                    "summary",
                    "--format",
                    "json",
                    "--file",
                    str(root / "summary.json"),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            PLAN.validate_blank_summary(
                (root / "summary.json").read_bytes(),
                base_mac="00:00:00:00:00:00",
            )

    def test_signed_plan_verifies_and_binds_release(self):
        value, public, _ = signed()
        PLAN.verify_receipt(value, public)
        signing_raw, artifact_raw = release_files()
        PLAN.bind_release(value, signing_raw, artifact_raw)
        PLAN.require_active(value, "2026-08-10T10:10:00Z")
        self.assertEqual(len(value["key_allocation"]), 6)
        self.assertEqual(len(value["operation_plan"]), 9)
        self.assertFalse(value["authorization"]["executor_included"])

    def test_nonblank_or_locked_key_slot_is_rejected(self):
        for mutate, message in (
            (
                lambda value: value["BLOCK_KEY3"].update({"raw_value": "0x" + "1" * 64}),
                "BLOCK_KEY3",
            ),
            (
                lambda value: value["BLOCK_KEY3"].update({"writeable": False}),
                "BLOCK_KEY3",
            ),
            (
                lambda value: value["KEY_PURPOSE_4"].update({"value": "HMAC_UP"}),
                "KEY_PURPOSE_4",
            ),
        ):
            value = blank_summary()
            mutate(value)
            with self.assertRaisesRegex(PLAN.SacrificialPlanError, message):
                PLAN.validate_blank_summary(
                    json.dumps(value).encode(), base_mac="02:00:00:00:00:01"
                )

    def test_nonblank_security_or_protection_fuse_is_rejected(self):
        for name, change in (
            ("WR_DIS", {"raw_value": "0x00000001", "value": 1}),
            ("RD_DIS", {"raw_value": "0x01", "value": 1}),
            ("SECURE_BOOT_EN", {"raw_value": "0x1", "value": True}),
            ("SECURE_VERSION", {"raw_value": "0x0001", "value": 1}),
        ):
            value = blank_summary()
            value[name].update(change)
            with self.assertRaisesRegex(PLAN.SacrificialPlanError, name):
                PLAN.validate_blank_summary(
                    json.dumps(value).encode(), base_mac="02:00:00:00:00:01"
                )

    def test_mac_flash_tool_and_coding_error_checks_fail_closed(self):
        arguments = {
            "tool_versions": b"esptool=5.3.1\nespefuse=5.3.1\n",
            "chip_probe": b"esptool v5.3.1\nESP32-S3\nMAC: 02:00:00:00:00:01\n",
            "flash_probe": b"esptool v5.3.1\nDetected flash size: 16MB\n",
            "efuse_check_error": b"espefuse v5.3.1\nNo errors detected.\n",
            "base_mac": "02:00:00:00:00:01",
        }
        PLAN.validate_capture_logs(**arguments)
        for key, value, message in (
            ("tool_versions", b"esptool=5.3.2\nespefuse=5.3.1\n", "pinned"),
            ("chip_probe", b"esptool v5.3.1\nESP32-S2\n", "ESP32-S3"),
            ("flash_probe", b"esptool v5.3.1\nDetected flash size: 8MB\n", "16MB"),
            ("efuse_check_error", b"espefuse v5.3.1\nErrors detected.\n", "did not pass"),
        ):
            changed = dict(arguments)
            changed[key] = value
            with self.assertRaisesRegex(PLAN.SacrificialPlanError, message):
                PLAN.validate_capture_logs(**changed)

    def test_cross_release_and_digest_reordering_are_rejected(self):
        signing_raw, artifact_raw = release_files()
        receipt = json.loads(artifact_raw)
        receipt["secure_boot_digests"].reverse()
        with self.assertRaisesRegex(PLAN.SacrificialPlanError, "order"):
            PLAN.load_release_evidence(signing_raw, PLAN.canonical_json(receipt))
        changed = json.loads(signing_raw)
        changed["artifacts"]["partition_table"]["sha256"] = "99" * 32
        with self.assertRaisesRegex(PLAN.SacrificialPlanError, "subject"):
            PLAN.load_release_evidence(PLAN.canonical_json(changed), artifact_raw)

    def test_signature_tamper_and_private_key_input_are_rejected(self):
        value, public, private = signed()
        value["transaction"]["serial_number"] = "OTHER"
        with self.assertRaisesRegex(PLAN.SacrificialPlanError, "signature"):
            PLAN.verify_receipt(value, public)
        value, _, _ = signed()
        private_pem = private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        with self.assertRaisesRegex(PLAN.SacrificialPlanError, "public key"):
            PLAN.verify_receipt(value, private_pem)

    def test_expiry_single_operator_executor_and_inventory_claim_are_rejected(self):
        value = request()
        with self.assertRaisesRegex(PLAN.SacrificialPlanError, "not active"):
            PLAN.require_active(value, "2026-08-10T10:16:01Z")
        for mutate, message in (
            (lambda item: item["station"].update({"operators": ["operator-a"]}), "operators"),
            (lambda item: item["authorization"].update({"executor_included": True}), "boundary"),
            (
                lambda item: item["authorization"].update({"production_inventory_eligible": True}),
                "boundary",
            ),
        ):
            changed = copy.deepcopy(value)
            mutate(changed)
            with self.assertRaisesRegex(PLAN.SacrificialPlanError, message):
                PLAN.validate(changed, signed=False)

    def test_operation_reordering_and_cross_device_subject_are_rejected(self):
        value = request()
        value["operation_plan"][3], value["operation_plan"][4] = (
            value["operation_plan"][4],
            value["operation_plan"][3],
        )
        with self.assertRaisesRegex(PLAN.SacrificialPlanError, "operation order"):
            PLAN.validate(value, signed=False)
        value = request()
        value["transaction"]["base_mac"] = "02:00:00:00:00:02"
        with self.assertRaisesRegex(PLAN.SacrificialPlanError, "derive"):
            PLAN.validate(value, signed=False)

    def test_cli_request_sign_finalize_and_verify_flow(self):
        with tempfile.TemporaryDirectory(prefix="xz-m58-cli-") as name:
            root = pathlib.Path(name)
            signing_raw, artifact_raw = release_files()
            summary = json.dumps(blank_summary(), sort_keys=True).encode()
            files = {
                "signing.json": signing_raw,
                "artifact.json": artifact_raw,
                "summary-before.json": summary,
                "summary-after.json": summary,
                "chip.log": b"esptool v5.3.1\nESP32-S3\nMAC: 02:00:00:00:00:01\n",
                "flash.log": b"esptool v5.3.1\nDetected flash size: 16MB\n",
                "tools.txt": b"esptool=5.3.1\nespefuse=5.3.1\n",
                "error.log": b"espefuse v5.3.1\nNo errors detected.\n",
                "fixture.txt": b"fixture calibration",
                "port.txt": b"port fingerprint",
            }
            for relative, data in files.items():
                (root / relative).write_bytes(data)
            request_path = root / "plan-request.json"
            signature_path = root / "signature.bin"
            public_path = root / "public.pem"
            receipt_path = root / "plan-receipt.json"

            def run(arguments):
                result = subprocess.run(
                    [sys.executable, *map(str, arguments)],
                    cwd=PROJECT,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stdout)
                return result.stdout

            run(
                [
                    PROJECT / "tools/build_sacrificial_provisioning_plan_request.py",
                    "--plan-id", "sacrificial-plan-cli",
                    "--transaction-id", "sacrificial-tx-cli",
                    "--attempt-id", "attempt-cli",
                    "--device-id", "xz-020000000001",
                    "--serial-number", "SACRIFICIAL-CLI",
                    "--base-mac", "02:00:00:00:00:01",
                    "--chip-revision", "1",
                    "--signing-request", root / "signing.json",
                    "--signed-artifact-verification", root / "artifact.json",
                    "--station-id", "lab-station-01",
                    "--operator", "operator-a",
                    "--operator", "operator-b",
                    "--fixture-id", "fixture-01",
                    "--fixture-version", "1.0.0",
                    "--fixture-calibration", root / "fixture.txt",
                    "--authorization-key-id", "sacrificial-authority-test",
                    "--port-fingerprint", root / "port.txt",
                    "--chip-probe", root / "chip.log",
                    "--flash-probe", root / "flash.log",
                    "--tool-versions", root / "tools.txt",
                    "--efuse-summary-before", root / "summary-before.json",
                    "--efuse-summary-after", root / "summary-after.json",
                    "--efuse-check-error", root / "error.log",
                    "--capture-started-at", "2026-08-10T10:00:00Z",
                    "--capture-finished-at", "2026-08-10T10:05:00Z",
                    "--issued-at", "2026-08-10T10:06:00Z",
                    "--expires-at", "2026-08-10T10:16:00Z",
                    "--output", request_path,
                ]
            )
            signer_output = run(
                [
                    PROJECT / "tools/tests/sign_sacrificial_provisioning_plan_fixture.py",
                    "--request", request_path,
                    "--signature-output", signature_path,
                    "--public-key-output", public_path,
                ]
            )
            self.assertIn("TEST ONLY", signer_output)
            run(
                [
                    PROJECT / "tools/finalize_sacrificial_provisioning_plan.py",
                    "--request", request_path,
                    "--signature", signature_path,
                    "--public-key", public_path,
                    "--verification-time", "2026-08-10T10:10:00Z",
                    "--output", receipt_path,
                ]
            )
            output = run(
                [
                    PROJECT / "tools/verify_sacrificial_provisioning_plan.py",
                    "--receipt", receipt_path,
                    "--public-key", public_path,
                    "--signing-request", root / "signing.json",
                    "--signed-artifact-verification", root / "artifact.json",
                    "--verification-time", "2026-08-10T10:10:00Z",
                ]
            )
            self.assertIn("SACRIFICIAL ONLY", output)


if __name__ == "__main__":
    unittest.main()
