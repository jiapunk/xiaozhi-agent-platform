import copy
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = PROJECT / "tools"
sys.path.insert(0, str(TOOLS))

import virtual_efuse_rehearsal as POLICY  # noqa: E402


def signing_request():
    return {
        "version": 1,
        "profile": "box3-production-security-v1",
        "target": "esp32s3",
        "idf_version": "6.0.2",
        "upstream_commits": {},
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
        "partition_table_offset": 65536,
        "artifacts": {},
    }


@unittest.skipUnless(
    importlib.util.find_spec("espefuse") is not None,
    "pinned ESP-IDF Python environment is unavailable",
)
class VirtualEfuseRehearsalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="xz-m57-test-")
        cls.directory = pathlib.Path(cls.temp.name)
        cls.request = cls.directory / "request.json"
        cls.evidence = cls.directory / "evidence.json"
        cls.request.write_bytes(POLICY.canonical_json(signing_request()))
        result = subprocess.run(
            [
                sys.executable,
                str(TOOLS / "run_box3_virtual_efuse_rehearsal.py"),
                "--signing-request",
                str(cls.request),
                "--write-evidence",
                str(cls.evidence),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            raise AssertionError(result.stdout)
        cls.value = json.loads(cls.evidence.read_text())

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_real_espefuse_virtual_lifecycle_passes_independent_verifier(self):
        self.assertEqual(POLICY.validate_evidence(copy.deepcopy(self.value)), self.value)
        result = subprocess.run(
            [
                sys.executable,
                str(TOOLS / "verify_box3_virtual_efuse_rehearsal.py"),
                "--evidence",
                str(self.evidence),
                "--signing-request",
                str(self.request),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("VIRTUAL_TEST_ONLY", result.stdout)

    def test_cross_request_evidence_is_rejected(self):
        other = self.directory / "other-request.json"
        request = signing_request()
        request["partition_table_offset"] = 131072
        other.write_bytes(POLICY.canonical_json(request))
        with self.assertRaisesRegex(POLICY.RehearsalError, "hash differs"):
            POLICY.validate_signing_request_binding(self.value, other)

    def test_read_protection_covers_only_three_secret_slots(self):
        final = self.value["stages"][-1]["fields"]
        self.assertEqual(final["RD_DIS"]["raw_value"], "0x38")
        for slot in range(3):
            self.assertTrue(final[f"BLOCK_KEY{slot}"]["readable"])
        for slot in range(3, 6):
            self.assertFalse(final[f"BLOCK_KEY{slot}"]["readable"])

    def test_tampered_digest_readability_is_rejected(self):
        value = copy.deepcopy(self.value)
        value["stages"][-1]["fields"]["BLOCK_KEY0"]["readable"] = False
        value["stages"][-1]["selected_fields_sha256"] = POLICY.sha256(
            POLICY.canonical_json(value["stages"][-1]["fields"])
        )
        with self.assertRaisesRegex(POLICY.RehearsalError, "BLOCK_KEY0.readable"):
            POLICY.validate_evidence(value)

    def test_tampered_shared_write_lock_is_rejected(self):
        value = copy.deepcopy(self.value)
        value["stages"][-1]["fields"]["SECURE_VERSION"]["writeable"] = True
        value["stages"][-1]["selected_fields_sha256"] = POLICY.sha256(
            POLICY.canonical_json(value["stages"][-1]["fields"])
        )
        with self.assertRaisesRegex(POLICY.RehearsalError, "SECURE_VERSION.writeable"):
            POLICY.validate_evidence(value)

    def test_stage_reordering_is_rejected(self):
        value = copy.deepcopy(self.value)
        value["stages"][3], value["stages"][4] = value["stages"][4], value["stages"][3]
        with self.assertRaisesRegex(POLICY.RehearsalError, "name differs"):
            POLICY.validate_evidence(value)

    def test_physical_or_factory_claim_is_rejected(self):
        for key in ("physical_device_touched", "factory_evidence"):
            value = copy.deepcopy(self.value)
            value["boundary"][key] = True
            with self.assertRaisesRegex(POLICY.RehearsalError, "boundary differs"):
                POLICY.validate_evidence(value)

    def test_selected_field_hash_tampering_is_rejected(self):
        value = copy.deepcopy(self.value)
        value["stages"][0]["selected_fields_sha256"] = "0" * 64
        with self.assertRaisesRegex(POLICY.RehearsalError, "hash differs"):
            POLICY.validate_evidence(value)


if __name__ == "__main__":
    unittest.main()
