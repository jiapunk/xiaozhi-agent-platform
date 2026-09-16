import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = PROJECT / "tools" / "verify_production_signed_artifacts.py"
SPEC = importlib.util.spec_from_file_location(
    "verify_production_signed_artifacts", MODULE_PATH
)
VERIFY = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(VERIFY)


def request_template():
    return {
        "version": 1,
        "profile": "box3-production-security-v1",
        "target": "esp32s3",
        "idf_version": "6.0.2",
        "upstream_commits": VERIFY.EXPECTED_UPSTREAMS,
        "secure_boot": VERIFY.EXPECTED_SECURE_BOOT,
        "efuse_key_block_map": VERIFY.EXPECTED_KEY_BLOCK_MAP,
        "flash_encryption": {"mode": "release", "scheme": "XTS-AES-128"},
        "anti_rollback_secure_version": 1,
        "partition_table_offset": 0x10000,
        "artifacts": {
            "bootloader": {
                "size": 0x2000,
                "sha256": hashlib.sha256(b"boot").hexdigest(),
            },
            "application": {
                "size": 0x10000,
                "sha256": hashlib.sha256(b"app").hexdigest(),
                "project": "xiaozhi_agent_platform",
                "project_version": "0.24.0-security-gate",
                "secure_version": 1,
            },
            "ota_data_initial": {
                "size": 0x2000,
                "sha256": "01" * 32,
            },
            "partition_table": {"size": 0xC00, "sha256": "02" * 32},
        },
    }


def signature_info(count):
    lines = []
    for slot in range(count):
        octets = " ".join(f"{(slot + 1):02x}" for _ in range(32))
        lines.extend(
            [
                f"Signature block {slot} is valid (RSA).",
                f"Public key digest for block {slot}: {octets}",
            ]
        )
    return "\n".join(lines)


class SignedArtifactVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def write_request(self, request=None, name="request.json"):
        path = self.root / name
        path.write_bytes(VERIFY.canonical_json(request or request_template()))
        return path

    def test_canonical_request_and_policy_are_required(self):
        request, digest = VERIFY.load_request(self.write_request())
        self.assertEqual(request["profile"], "box3-production-security-v1")
        self.assertEqual(len(digest), 64)

        path = self.root / "noncanonical.json"
        path.write_text(json.dumps(request_template(), indent=2) + "\n")
        with self.assertRaisesRegex(VERIFY.VerificationError, "canonical"):
            VERIFY.load_request(path)

        request["secure_boot"] = []
        with self.assertRaisesRegex(VERIFY.VerificationError, "policy"):
            VERIFY.load_request(self.write_request(request, "wrong-policy.json"))

    def test_entire_build_and_efuse_contract_is_frozen(self):
        mutations = (
            ("idf_version", "6.1"),
            ("upstream_commits", {}),
            ("efuse_key_block_map", []),
            ("flash_encryption", {"mode": "development", "scheme": "XTS-AES-128"}),
            ("partition_table_offset", 0x8000),
            ("anti_rollback_secure_version", 17),
        )
        for index, (field, value) in enumerate(mutations):
            request = request_template()
            request[field] = value
            with self.assertRaises(VERIFY.VerificationError):
                VERIFY.load_request(self.write_request(request, f"mutation-{index}.json"))

    def test_duplicate_json_member_is_rejected(self):
        path = self.root / "duplicate.json"
        path.write_text('{"version":1,"version":1}\n')
        with self.assertRaisesRegex(VERIFY.VerificationError, "duplicate"):
            VERIFY.load_request(path)

    def test_signed_prefix_must_be_exact_and_unchanged(self):
        unsigned = b"boot"
        expected = {
            "size": len(unsigned),
            "sha256": hashlib.sha256(unsigned).hexdigest(),
        }
        path = self.root / "signed.bin"
        path.write_bytes(unsigned + bytes([0xE7]) + bytes(0xFFF))
        info = VERIFY.verify_signed_prefix(path, expected, "bootloader")
        self.assertEqual(info["size"], len(unsigned) + 0x1000)

        path.write_bytes(b"BOOT" + bytes([0xE7]) + bytes(0xFFF))
        with self.assertRaisesRegex(VERIFY.VerificationError, "prefix"):
            VERIFY.verify_signed_prefix(path, expected, "bootloader")
        path.write_bytes(unsigned + bytes(0x1000))
        with self.assertRaisesRegex(VERIFY.VerificationError, "magic"):
            VERIFY.verify_signed_prefix(path, expected, "bootloader")

    def test_signature_info_requires_exact_distinct_blocks(self):
        values = VERIFY.parse_signature_info(signature_info(3), 3)
        self.assertEqual(values, ["01" * 32, "02" * 32, "03" * 32])
        with self.assertRaisesRegex(VERIFY.VerificationError, "exactly 3"):
            VERIFY.parse_signature_info(signature_info(2), 3)
        duplicate = signature_info(3) + "\nSignature block 1 is valid (RSA)."
        with self.assertRaisesRegex(VERIFY.VerificationError, "duplicate"):
            VERIFY.parse_signature_info(duplicate, 3)
        repeated = signature_info(2).replace("02 02", "01 01").replace(
            "02 02", "01 01"
        )
        repeated = repeated.replace("02 ", "01 ").replace("02\n", "01\n")
        with self.assertRaisesRegex(VERIFY.VerificationError, "distinct"):
            VERIFY.parse_signature_info(repeated, 2)

    def test_private_or_wrong_key_count_is_rejected_without_tool_call(self):
        key = self.root / "key.pem"
        key.write_text("-----BEGIN PRIVATE KEY-----\nsecret\n")
        with self.assertRaisesRegex(VERIFY.VerificationError, "three"):
            VERIFY.public_key_digests(pathlib.Path("python"), [key])
        with self.assertRaisesRegex(VERIFY.VerificationError, "public keys"):
            VERIFY.public_key_digests(pathlib.Path("python"), [key, key, key])

    def test_receipt_write_is_idempotent_and_not_overwritable(self):
        receipt = {"version": 1, "value": "bound"}
        path = self.root / "receipt.json"
        VERIFY.write_receipt(path, receipt)
        VERIFY.write_receipt(path, receipt)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        path.write_text("{}\n")
        with self.assertRaisesRegex(VERIFY.VerificationError, "differs"):
            VERIFY.write_receipt(path, receipt)
        target = self.root / "target.json"
        target.write_bytes(VERIFY.canonical_json(receipt))
        link = self.root / "receipt-link.json"
        link.symlink_to(target)
        with self.assertRaisesRegex(VERIFY.VerificationError, "symlink"):
            VERIFY.write_receipt(link, receipt)


if __name__ == "__main__":
    unittest.main()
