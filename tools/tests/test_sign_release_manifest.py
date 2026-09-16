import importlib.util
import hashlib
import json
import pathlib
import struct
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from tools.tests.reset_qualification_fixture import signed_reset_qualification


PROJECT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = PROJECT / "tools" / "sign_release_manifest.py"
SPEC = importlib.util.spec_from_file_location("sign_release_manifest", MODULE_PATH)
SIGNER = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(SIGNER)


def test_image() -> bytes:
    image = bytearray(2048)
    struct.pack_into("<II", image, 32, 0xABCD5432, 2)
    image[48 : 48 + len(b"0.14.0-dev")] = b"0.14.0-dev"
    image[80 : 80 + len(b"xiaozhi_agent_platform")] = b"xiaozhi_agent_platform"
    return bytes(image)


def sdkconfig() -> str:
    return (
        "CONFIG_PRODUCT_BOARD_ESP_BOX_3=y\n"
        'CONFIG_PRODUCT_OTA_CHANNEL="stable"\n'
        "CONFIG_PRODUCT_OTA_RELEASE_SEQUENCE=14\n"
    )


class ReleaseManifestTests(unittest.TestCase):
    def setUp(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.private_pem = self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self.public_pem = self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.qualification, self.qualification_public, _ = (
            signed_reset_qualification(
                image_sha256=hashlib.sha256(test_image()).hexdigest(),
                version="0.14.0-dev",
                secure_version=2,
            )
        )

    def build(self):
        return SIGNER.build_manifest(
            test_image(),
            sdkconfig(),
            self.private_pem,
            self.qualification,
            self.qualification_public,
            "synthetic-ed25519-key",
            release_id="release-0014",
            image_url="https://updates.example.com/firmware/r14.bin",
            not_before=1786276800,
            expires_at=1786881600,
            signing_key_id="release-key-2026",
        )

    def test_manifest_is_bound_to_image_and_build_policy(self):
        manifest = self.build()
        self.assertEqual(manifest["project"], "xiaozhi_agent_platform")
        self.assertEqual(manifest["version"], "0.14.0-dev")
        self.assertEqual(manifest["secure_version"], 2)
        self.assertEqual(manifest["board"], "esp32s3-box3")
        self.assertEqual(manifest["channel"], "stable")
        self.assertEqual(manifest["release_sequence"], 14)
        self.assertEqual(
            manifest["reset_qualification_sha256"],
            hashlib.sha256(self.qualification).hexdigest(),
        )
        SIGNER.verify_manifest_signature(manifest, self.public_pem)

    def test_tampering_breaks_signature(self):
        manifest = self.build()
        manifest["image_url"] = "https://updates.example.com/firmware/evil.bin"
        with self.assertRaisesRegex(SIGNER.ManifestError, "signature"):
            SIGNER.verify_manifest_signature(manifest, self.public_pem)

    def test_release_verifier_binds_exact_artifacts_and_authority(self):
        manifest = self.build()
        SIGNER.verify_release_artifacts(
            manifest,
            self.public_pem,
            test_image(),
            sdkconfig(),
            expected_authority="updates.example.com",
            reset_qualification_receipt=self.qualification,
            reset_qualification_public_key_pem=self.qualification_public,
            reset_qualification_signing_key_id="synthetic-ed25519-key",
        )
        altered = bytearray(test_image())
        altered[-1] = 1
        with self.assertRaisesRegex(SIGNER.ManifestError, "image_sha256"):
            SIGNER.verify_release_artifacts(
                manifest,
                self.public_pem,
                bytes(altered),
                sdkconfig(),
                expected_authority="updates.example.com",
                reset_qualification_receipt=self.qualification,
                reset_qualification_public_key_pem=self.qualification_public,
                reset_qualification_signing_key_id="synthetic-ed25519-key",
            )

    def test_manifest_loader_rejects_duplicate_and_unknown_fields(self):
        manifest = self.build()
        encoded = json.dumps(manifest).encode()
        self.assertEqual(
            SIGNER.load_manifest_json(encoded)["release_id"], "release-0014"
        )
        duplicate = encoded[:-1] + b',"schema":1}'
        with self.assertRaisesRegex(SIGNER.ManifestError, "duplicate"):
            SIGNER.load_manifest_json(duplicate)
        manifest["unexpected"] = True
        with self.assertRaisesRegex(SIGNER.ManifestError, "fields"):
            SIGNER.load_manifest_json(json.dumps(manifest).encode())

    def test_url_and_validity_policy_fail_closed(self):
        with self.assertRaises(SIGNER.ManifestError):
            SIGNER.validate_image_url("https://updates.example.com/r.bin?secret=x")
        with self.assertRaises(SIGNER.ManifestError):
            SIGNER.validate_image_url("http://updates.example.com/r.bin")
        for authority in (
            "updates..example.com",
            "-updates.example.com",
            "updates.example.com:",
            "updates.example.com:0",
            "updates.example.com:65536",
            "updates.example.com:443:9",
        ):
            with self.subTest(authority=authority):
                with self.assertRaises(SIGNER.ManifestError):
                    SIGNER.validate_image_url(f"https://{authority}/r.bin")
        with self.assertRaisesRegex(SIGNER.ManifestError, "validity"):
            SIGNER.build_manifest(
                test_image(),
                sdkconfig(),
                self.private_pem,
                self.qualification,
                self.qualification_public,
                "synthetic-ed25519-key",
                release_id="release-0014",
                image_url="https://updates.example.com/r.bin",
                not_before=1786276800,
                expires_at=1786276800,
                signing_key_id="release-key-2026",
            )

    def test_wrong_curve_is_rejected(self):
        wrong_key = ec.generate_private_key(ec.SECP384R1()).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        with self.assertRaisesRegex(SIGNER.ManifestError, "P-256"):
            SIGNER.build_manifest(
                test_image(),
                sdkconfig(),
                wrong_key,
                self.qualification,
                self.qualification_public,
                "synthetic-ed25519-key",
                release_id="release-0014",
                image_url="https://updates.example.com/r.bin",
                not_before=1786276800,
                expires_at=1786881600,
                signing_key_id="release-key-2026",
            )

    def test_missing_mismatched_or_tampered_qualification_blocks_signing(self):
        with self.assertRaisesRegex(SIGNER.ManifestError, "qualification"):
            SIGNER.build_manifest(
                test_image(), sdkconfig(), self.private_pem, b"", b"",
                "synthetic-ed25519-key",
                release_id="release-0014",
                image_url="https://updates.example.com/r.bin",
                not_before=1786276800,
                expires_at=1786881600,
                signing_key_id="release-key-2026",
            )
        tampered = bytearray(self.qualification)
        location = tampered.index(b"synthetic-test-lab")
        tampered[location] = ord("S")
        with self.assertRaisesRegex(SIGNER.ManifestError, "qualification"):
            SIGNER.build_manifest(
                test_image(), sdkconfig(), self.private_pem, bytes(tampered),
                self.qualification_public,
                "synthetic-ed25519-key",
                release_id="release-0014",
                image_url="https://updates.example.com/r.bin",
                not_before=1786276800,
                expires_at=1786881600,
                signing_key_id="release-key-2026",
            )

    def test_manifest_v1_and_unbound_qualification_are_rejected(self):
        manifest = self.build()
        manifest["schema"] = 1
        with self.assertRaises(SIGNER.ManifestError):
            SIGNER.validate_manifest_shape(manifest)
        manifest = self.build()
        del manifest["reset_qualification_sha256"]
        with self.assertRaisesRegex(SIGNER.ManifestError, "schema v2"):
            SIGNER.validate_manifest_shape(manifest)


if __name__ == "__main__":
    unittest.main()
