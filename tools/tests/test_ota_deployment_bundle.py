import importlib.util
import hashlib
import json
import os
import pathlib
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


PROJECT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = PROJECT / "tools"
sys.path.insert(0, str(TOOLS))
import sign_release_manifest as SIGNER
from tools.tests.reset_qualification_fixture import signed_reset_qualification

MODULE_PATH = TOOLS / "build_ota_deployment_bundle.py"
SPEC = importlib.util.spec_from_file_location("build_ota_deployment_bundle", MODULE_PATH)
BUNDLE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(BUNDLE)


def test_image() -> bytes:
    image = bytearray(2048)
    struct.pack_into("<II", image, 32, 0xABCD5432, 2)
    image[48 : 48 + len(b"0.17.0-dev")] = b"0.17.0-dev"
    image[80 : 80 + len(b"xiaozhi_agent_platform")] = b"xiaozhi_agent_platform"
    return bytes(image)


def sdkconfig() -> bytes:
    return (
        "CONFIG_PRODUCT_BOARD_ESP_BOX_3=y\n"
        'CONFIG_PRODUCT_OTA_CHANNEL="stable"\n'
        "CONFIG_PRODUCT_OTA_RELEASE_SEQUENCE=17\n"
    ).encode("utf-8")


def unlock_tree(root: pathlib.Path) -> None:
    if not root.exists():
        return
    os.chmod(root, 0o700)
    for path in root.rglob("*"):
        os.chmod(path, 0o700 if path.is_dir() else 0o600)


class OTADeploymentBundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = pathlib.Path(tempfile.mkdtemp())
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_pem = self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.private_pem = self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self.image = test_image()
        self.sdkconfig = sdkconfig()
        self.qualification, self.qualification_public, _ = (
            signed_reset_qualification(
                image_sha256=hashlib.sha256(self.image).hexdigest(),
                version="0.17.0-dev",
                secure_version=2,
            )
        )
        self.manifest_path = self.temporary / "manifest.json"
        self.public_path = self.temporary / "public.pem"
        self.image_path = self.temporary / "image.bin"
        self.sdkconfig_path = self.temporary / "sdkconfig"
        self.qualification_path = self.temporary / "reset-qualification.json"
        self.qualification_public_path = self.temporary / "reset-lab-public.pem"
        self.output_path = self.temporary / "deployment-bundle"
        self._write_inputs("https://updates.example.com/firmware/r17.bin")
        self.qualification_path.write_bytes(self.qualification)
        self.qualification_public_path.write_bytes(self.qualification_public)

    def tearDown(self):
        unlock_tree(self.output_path)
        unlock_tree(self.temporary / "cli-bundle")
        shutil.rmtree(self.temporary)

    def _write_inputs(self, image_url: str) -> None:
        manifest = SIGNER.build_manifest(
            self.image,
            self.sdkconfig.decode("utf-8"),
            self.private_pem,
            self.qualification,
            self.qualification_public,
            "synthetic-ed25519-key",
            release_id="release-0017",
            image_url=image_url,
            not_before=1786276800,
            expires_at=1786881600,
            signing_key_id="release-key-2026",
        )
        self.manifest_path.write_bytes(BUNDLE._json_bytes(manifest))
        self.public_path.write_bytes(self.public_pem)
        self.image_path.write_bytes(self.image)
        self.sdkconfig_path.write_bytes(self.sdkconfig)

    def _build(self):
        return BUNDLE.build_deployment_bundle(
            manifest_path=self.manifest_path,
            public_key_path=self.public_path,
            image_path=self.image_path,
            sdkconfig_path=self.sdkconfig_path,
            reset_qualification_receipt_path=self.qualification_path,
            reset_qualification_public_key_path=self.qualification_public_path,
            reset_qualification_signing_key_id="synthetic-ed25519-key",
            expected_authority="updates.example.com",
            retry_after_seconds=900,
            output_path=self.output_path,
        )

    def test_builds_exact_read_only_fail_closed_bundle(self):
        receipt = self._build()
        verified = BUNDLE.validate_deployment_bundle(
            self.output_path, expected_authority="updates.example.com"
        )
        self.assertEqual(verified, receipt)
        registry = json.loads(
            (self.output_path / "control/ota-release-registry.json").read_text()
        )
        self.assertFalse(registry["releases"][0]["enabled"])
        self.assertEqual(registry["releases"][0]["rollout_basis_points"], 0)
        catalog = json.loads(
            (self.output_path / "origin/firmware-origin-catalog.json").read_text()
        )
        self.assertEqual(catalog["objects"][0]["url_path"], "/firmware/r17.bin")
        self.assertEqual(
            catalog["objects"][0]["image_file"], "objects/firmware/r17.bin"
        )
        for path in [self.output_path, *self.output_path.rglob("*")]:
            self.assertEqual(path.stat().st_mode & 0o222, 0)

    def test_refuses_existing_output_without_modifying_it(self):
        self.output_path.mkdir()
        sentinel = self.output_path / "owner-data"
        sentinel.write_text("keep")
        with self.assertRaisesRegex(BUNDLE.DeploymentBundleError, "already exists"):
            self._build()
        self.assertEqual(sentinel.read_text(), "keep")

    def test_rejects_noncanonical_authority_and_origin_unsafe_signed_path(self):
        with self.assertRaisesRegex(BUNDLE.DeploymentBundleError, "lowercase"):
            BUNDLE.build_deployment_bundle(
                manifest_path=self.manifest_path,
                public_key_path=self.public_path,
                image_path=self.image_path,
                sdkconfig_path=self.sdkconfig_path,
                reset_qualification_receipt_path=self.qualification_path,
                reset_qualification_public_key_path=self.qualification_public_path,
                reset_qualification_signing_key_id="synthetic-ed25519-key",
                expected_authority="Updates.Example.com",
                retry_after_seconds=900,
                output_path=self.output_path,
            )
        self._write_inputs("https://updates.example.com/firmware/%72.bin")
        with self.assertRaisesRegex(BUNDLE.DeploymentBundleError, "origin-safe"):
            self._build()

    def test_rejects_artifact_tampering_and_wrong_key(self):
        self.image_path.write_bytes(self.image[:-1] + b"x")
        with self.assertRaisesRegex(BUNDLE.ManifestError, "image_sha256"):
            self._build()
        self.image_path.write_bytes(self.image)
        other_key = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.public_path.write_bytes(other_key)
        with self.assertRaisesRegex(BUNDLE.ManifestError, "signature"):
            self._build()

    def test_rejects_input_symlink_and_invalid_retry_policy(self):
        real_image = self.temporary / "real-image.bin"
        self.image_path.rename(real_image)
        self.image_path.symlink_to(real_image)
        with self.assertRaises(BUNDLE.DeploymentBundleError):
            self._build()
        self.image_path.unlink()
        real_image.rename(self.image_path)
        with self.assertRaisesRegex(BUNDLE.DeploymentBundleError, "retry-after"):
            BUNDLE.build_deployment_bundle(
                manifest_path=self.manifest_path,
                public_key_path=self.public_path,
                image_path=self.image_path,
                sdkconfig_path=self.sdkconfig_path,
                reset_qualification_receipt_path=self.qualification_path,
                reset_qualification_public_key_path=self.qualification_public_path,
                reset_qualification_signing_key_id="synthetic-ed25519-key",
                expected_authority="updates.example.com",
                retry_after_seconds=59,
                output_path=self.output_path,
            )

    def test_validator_detects_catalog_tamper(self):
        self._build()
        catalog = self.output_path / "origin/firmware-origin-catalog.json"
        os.chmod(self.output_path, 0o700)
        os.chmod(catalog.parent, 0o700)
        os.chmod(catalog, 0o600)
        catalog.write_text('{"version":1,"objects":[]}\n')
        os.chmod(catalog, 0o444)
        os.chmod(catalog.parent, 0o555)
        os.chmod(self.output_path, 0o555)
        with self.assertRaisesRegex(BUNDLE.DeploymentBundleError, "catalogs"):
            BUNDLE.validate_deployment_bundle(
                self.output_path, expected_authority="updates.example.com"
            )

    def test_validator_detects_extra_file_and_bad_ready(self):
        self._build()
        os.chmod(self.output_path, 0o700)
        extra = self.output_path / "unexpected"
        extra.write_text("not part of the bundle")
        os.chmod(extra, 0o444)
        os.chmod(self.output_path, 0o555)
        with self.assertRaisesRegex(BUNDLE.DeploymentBundleError, "layout"):
            BUNDLE.validate_deployment_bundle(
                self.output_path, expected_authority="updates.example.com"
            )
        os.chmod(self.output_path, 0o700)
        os.chmod(extra, 0o600)
        extra.unlink()
        ready = self.output_path / "READY"
        os.chmod(ready, 0o600)
        ready.write_text("0" * 64 + "\n")
        os.chmod(ready, 0o444)
        os.chmod(self.output_path, 0o555)
        with self.assertRaisesRegex(BUNDLE.DeploymentBundleError, "READY"):
            BUNDLE.validate_deployment_bundle(
                self.output_path, expected_authority="updates.example.com"
            )

    def test_validator_rejects_noncanonical_receipt_bytes(self):
        self._build()
        receipt = self.output_path / "deployment-receipt.json"
        value = json.loads(receipt.read_text())
        os.chmod(self.output_path, 0o700)
        os.chmod(receipt, 0o600)
        receipt.write_text(json.dumps(value, separators=(",", ":")) + "\n")
        os.chmod(receipt, 0o444)
        os.chmod(self.output_path, 0o555)
        with self.assertRaisesRegex(BUNDLE.DeploymentBundleError, "receipt"):
            BUNDLE.validate_deployment_bundle(
                self.output_path, expected_authority="updates.example.com"
            )

    def test_go_production_loaders_accept_generated_bundle(self):
        go = shutil.which("go")
        if go is None:
            self.skipTest("Go is not available in PATH")
        self._build()
        completed = subprocess.run(
            [
                go,
                "run",
                "./cmd/validateotabundle",
                "-bundle",
                str(self.output_path),
                "-authority",
                "updates.example.com",
            ],
            cwd=PROJECT / "gateway",
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("rollout=disabled", completed.stdout)

    def test_builder_and_validator_cli_smoke(self):
        cli_bundle = self.temporary / "cli-bundle"
        build = subprocess.run(
            [
                sys.executable,
                str(TOOLS / "build_ota_deployment_bundle.py"),
                "--manifest",
                str(self.manifest_path),
                "--public-key",
                str(self.public_path),
                "--image",
                str(self.image_path),
                "--sdkconfig",
                str(self.sdkconfig_path),
                "--reset-qualification-receipt",
                str(self.qualification_path),
                "--reset-qualification-public-key",
                str(self.qualification_public_path),
                "--reset-qualification-signing-key-id",
                "synthetic-ed25519-key",
                "--expected-authority",
                "updates.example.com",
                "--output",
                str(cli_bundle),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(build.returncode, 0, build.stderr)
        self.assertIn("rollout=disabled", build.stdout)
        verify = subprocess.run(
            [
                sys.executable,
                str(TOOLS / "validate_ota_deployment_bundle.py"),
                "--bundle",
                str(cli_bundle),
                "--expected-authority",
                "updates.example.com",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(verify.returncode, 0, verify.stderr)
        self.assertIn("rollout=disabled", verify.stdout)


if __name__ == "__main__":
    unittest.main()
