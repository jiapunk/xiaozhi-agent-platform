from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


PROJECT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT))

from tools import verify_reset_hardware_qualification as VERIFY
from tools.tests.reset_qualification_fixture import (
    resign,
    signed_reset_qualification,
)


IMAGE_SHA256 = hashlib.sha256(b"exact-release-image").hexdigest()


class ResetHardwareQualificationTests(unittest.TestCase):
    def setUp(self):
        self.data, self.public_key, self.private_key = signed_reset_qualification(
            image_sha256=IMAGE_SHA256,
            version="0.40.0-dev",
            secure_version=4,
        )

    def verify(self, data: bytes | None = None, public_key: bytes | None = None):
        return VERIFY.verify_receipt_bytes(
            data if data is not None else self.data,
            public_key if public_key is not None else self.public_key,
            expected_board="esp32s3-box3",
            expected_project="xiaozhi_agent_platform",
            expected_version="0.40.0-dev",
            expected_secure_version=4,
            expected_image_sha256=IMAGE_SHA256,
            expected_signing_key_id="synthetic-ed25519-key",
        )

    def mutate_and_resign(self, callback) -> bytes:
        receipt = json.loads(self.data)
        callback(receipt)
        return resign(receipt, self.private_key)

    def test_valid_signed_receipt_is_accepted(self):
        receipt = self.verify()
        self.assertEqual(receipt["result"], "PASS")
        self.assertEqual(len(receipt["samples"]), 3)

    def test_noncanonical_duplicate_and_unknown_json_fail_closed(self):
        receipt = json.loads(self.data)
        pretty = (json.dumps(receipt, indent=2) + "\n").encode()
        with self.assertRaisesRegex(VERIFY.QualificationError, "canonical"):
            self.verify(pretty)
        duplicate = self.data[:-2] + b',"schema":"duplicate"}\n'
        with self.assertRaisesRegex(VERIFY.QualificationError, "duplicate"):
            self.verify(duplicate)
        unknown = self.mutate_and_resign(lambda value: value.update({"extra": True}))
        with self.assertRaisesRegex(VERIFY.QualificationError, "fields"):
            self.verify(unknown)

    def test_signature_key_and_release_bytes_are_bound(self):
        tampered = bytearray(self.data)
        location = tampered.index(b"synthetic-test-lab")
        tampered[location] = ord("S")
        with self.assertRaisesRegex(VERIFY.QualificationError, "signature"):
            self.verify(bytes(tampered))
        _, wrong_public, _ = signed_reset_qualification(
            image_sha256=IMAGE_SHA256, version="0.40.0-dev", secure_version=4
        )
        with self.assertRaisesRegex(VERIFY.QualificationError, "signature"):
            self.verify(public_key=wrong_public)
        with self.assertRaisesRegex(VERIFY.QualificationError, "firmware"):
            VERIFY.verify_receipt_bytes(
                self.data,
                self.public_key,
                expected_board="esp32s3-box3",
                expected_project="xiaozhi_agent_platform",
                expected_version="0.40.0-dev",
                expected_secure_version=4,
                expected_image_sha256="0" * 64,
                expected_signing_key_id="synthetic-ed25519-key",
            )

    def test_untrusted_signing_key_id_is_rejected(self):
        with self.assertRaisesRegex(VERIFY.QualificationError, "not trusted"):
            VERIFY.verify_receipt_bytes(
                self.data,
                self.public_key,
                expected_board="esp32s3-box3",
                expected_project="xiaozhi_agent_platform",
                expected_version="0.40.0-dev",
                expected_secure_version=4,
                expected_image_sha256=IMAGE_SHA256,
                expected_signing_key_id="different-lab-key",
            )

    def test_identity_and_security_preservation_are_mandatory(self):
        for field, value in (
            ("post_identity_proof_sha256", "0" * 64),
            ("post_nvs_factory_sha256", "0" * 64),
            ("post_efuse_summary_sha256", "0" * 64),
            ("secure_boot_preserved_pass", False),
            ("flash_encryption_preserved_pass", False),
            ("anti_rollback_preserved_pass", False),
            ("wifi_raw_keys_absent_pass", False),
            ("agent_memory_raw_slots_absent_pass", False),
        ):
            with self.subTest(field=field):
                data = self.mutate_and_resign(
                    lambda receipt, f=field, v=value: receipt["samples"][0].update(
                        {f: v}
                    )
                )
                with self.assertRaises(VERIFY.QualificationError):
                    self.verify(data)

    def test_sample_count_uniqueness_and_wear_floor_are_mandatory(self):
        too_few = self.mutate_and_resign(
            lambda receipt: receipt.update({"samples": receipt["samples"][:2]})
        )
        with self.assertRaisesRegex(VERIFY.QualificationError, "3..32"):
            self.verify(too_few)
        duplicate = self.mutate_and_resign(
            lambda receipt: receipt["samples"].__setitem__(
                1, dict(receipt["samples"][0])
            )
        )
        with self.assertRaisesRegex(VERIFY.QualificationError, "distinct"):
            self.verify(duplicate)
        wear = self.mutate_and_resign(
            lambda receipt: [sample.update({"reset_cycles": 100}) for sample in receipt["samples"]]
        )
        with self.assertRaisesRegex(VERIFY.QualificationError, "1000"):
            self.verify(wear)

    def test_every_power_cut_boundary_and_gesture_policy_are_frozen(self):
        for boundary in VERIFY.POWER_CUT_FIELDS:
            with self.subTest(boundary=boundary):
                data = self.mutate_and_resign(
                    lambda receipt, b=boundary: receipt["power_cut"][b].update(
                        {"pass": False}
                    )
                )
                with self.assertRaises(VERIFY.QualificationError):
                    self.verify(data)
        gesture = self.mutate_and_resign(
            lambda receipt: receipt["gesture"].update({"reset_min_ms": 9999})
        )
        with self.assertRaisesRegex(VERIFY.QualificationError, "gesture"):
            self.verify(gesture)

    def test_private_key_input_and_invalid_time_window_are_rejected(self):
        private_pem = self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        with self.assertRaises(VERIFY.QualificationError):
            self.verify(public_key=private_pem)
        invalid_time = self.mutate_and_resign(
            lambda receipt: receipt.update(
                {"finished_at": "2026-08-20T08:00:00Z"}
            )
        )
        with self.assertRaisesRegex(VERIFY.QualificationError, "time window"):
            self.verify(invalid_time)


if __name__ == "__main__":
    unittest.main()
