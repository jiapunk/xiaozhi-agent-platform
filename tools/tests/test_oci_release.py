from __future__ import annotations

import gzip
import hashlib
import io
import os
import pathlib
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


PROJECT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = PROJECT / "tools"
sys.path.insert(0, str(TOOLS))
import oci_release as OCI


SOURCE_DATE_EPOCH = 1786276800


def fake_elf(architecture: str, *, interpreter: bool = False) -> bytes:
    data = bytearray(256)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<H", data, 16, 2)
    struct.pack_into("<H", data, 18, OCI.GO_MACHINES[architecture])
    struct.pack_into("<I", data, 20, 1)
    struct.pack_into("<Q", data, 32, 64)
    struct.pack_into("<H", data, 52, 64)
    struct.pack_into("<H", data, 54, 56)
    struct.pack_into("<H", data, 56, 1 if interpreter else 0)
    if interpreter:
        struct.pack_into("<I", data, 64, 3)
    data[192:] = ("fixture-" + architecture).encode() * 4
    return bytes(data)


def unlock_tree(root: pathlib.Path) -> None:
    if not root.exists() or root.is_symlink():
        return
    os.chmod(root, 0o700)
    for path in root.rglob("*"):
        if not path.is_symlink():
            os.chmod(path, 0o700 if path.is_dir() else 0o600)


def tree_digest(root: pathlib.Path) -> str:
    digest = hashlib.sha256()
    for path in sorted((item for item in root.rglob("*") if item.is_file())):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


class OCIReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = pathlib.Path(tempfile.mkdtemp())
        go = shutil.which("go")
        if go is None:
            self.skipTest("Go 1.26.5 is not available")
        self.go = pathlib.Path(go).resolve()
        if OCI._go_version(self.go) != "go1.26.5":
            self.skipTest("tests require the pinned Go 1.26.5 toolchain")
        self.private = Ed25519PrivateKey.generate()
        self.private_path = self.temporary / "release-private.pem"
        self.public_path = self.temporary / "release-public.pem"
        self.private_path.write_bytes(
            self.private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self.public_path.write_bytes(
            self.private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        self.ca_path = self.temporary / "ca.pem"
        self.ca_path.write_bytes(
            b"-----BEGIN CERTIFICATE-----\nZmFrZS1jYS1mb3ItdGVzdHM=\n-----END CERTIFICATE-----\n"
        )
        self.bundle = self.temporary / "release"

    def tearDown(self) -> None:
        for path in (self.bundle, self.temporary / "release-2"):
            unlock_tree(path)
        shutil.rmtree(self.temporary, ignore_errors=True)

    @staticmethod
    def compile_fixture(
        project_root: pathlib.Path,
        go_binary: pathlib.Path,
        service: str,
        architecture: str,
        output: pathlib.Path,
    ) -> None:
        output.write_bytes(fake_elf(architecture) + service.encode())

    def build(self, output: pathlib.Path | None = None) -> dict[str, object]:
        return OCI.build_release_bundle(
            project_root=PROJECT,
            go_binary=self.go,
            ca_bundle_path=self.ca_path,
            signing_private_key_path=self.private_path,
            signing_key_id="oci-release-2026",
            release_id="gateway-r48",
            version="0.48.0",
            source_date_epoch=SOURCE_DATE_EPOCH,
            output_path=output or self.bundle,
            compile_callback=self.compile_fixture,
        )

    def validate(self, public_key: pathlib.Path | None = None) -> dict[str, object]:
        return OCI.validate_release_bundle(
            self.bundle,
            trusted_public_key_path=public_key or self.public_path,
            expected_signing_key_id="oci-release-2026",
            expected_release_id="gateway-r48",
        )

    def resign_receipt(self, receipt: dict[str, object], domain: bytes | None = None) -> None:
        unsigned = dict(receipt)
        unsigned.pop("signature_b64url", None)
        payload = (domain or OCI.SIGNATURE_DOMAIN) + OCI._compact_bytes(unsigned)
        receipt["signature_b64url"] = OCI._b64url(self.private.sign(payload))
        receipt_data = OCI._json_bytes(receipt)
        (self.bundle / "release-receipt.json").write_bytes(receipt_data)
        (self.bundle / "READY").write_text(hashlib.sha256(receipt_data).hexdigest() + "\n")

    def go_validate(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                str(self.go),
                "run",
                "./cmd/validateocirelease",
                "-bundle",
                str(self.bundle),
                "-public-key",
                str(self.public_path),
                "-key-id",
                "oci-release-2026",
                "-release-id",
                "gateway-r48",
            ],
            cwd=PROJECT / "gateway",
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def test_builds_exact_signed_multiarch_read_only_bundle(self) -> None:
        receipt = self.build()
        self.assertEqual(self.validate(), receipt)
        self.assertEqual(receipt["schema"], 3)
        self.assertEqual([item["name"] for item in receipt["services"]], list(OCI.SERVICES))
        self.assertEqual(len(receipt["services"]), 7)
        source = OCI._strict_json(
            (self.bundle / "source-inputs.json").read_bytes(), "source inputs"
        )
        self.assertIn(
            "project:gateway/cmd/accountauthorization/main.go",
            [item["name"] for item in source["inputs"]],
        )
        self.assertIn(
            "project:gateway/cmd/factorytimeauthority/main.go",
            [item["name"] for item in source["inputs"]],
        )
        for service in receipt["services"]:
            self.assertEqual(
                [item["architecture"] for item in service["platforms"]],
                list(OCI.ARCHITECTURES),
            )
        for path in [self.bundle, *self.bundle.rglob("*")]:
            self.assertEqual(path.stat().st_mode & 0o222, 0)

    def test_same_inputs_produce_identical_bundle(self) -> None:
        self.build()
        second = self.temporary / "release-2"
        self.build(second)
        self.assertEqual(tree_digest(self.bundle), tree_digest(second))

    def test_independent_go_validator_accepts_generated_bundle(self) -> None:
        self.build()
        completed = self.go_validate()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("signature=Ed25519", completed.stdout)

    def test_builder_and_schema_require_exact_seven_service_v3_contract(self) -> None:
        for services in (OCI.SERVICES[:-1], tuple(reversed(OCI.SERVICES))):
            with self.assertRaisesRegex(OCI.OCIReleaseError, "exact ordered seven-service"):
                OCI.build_release_bundle(
                    project_root=PROJECT,
                    go_binary=self.go,
                    ca_bundle_path=self.ca_path,
                    signing_private_key_path=self.private_path,
                    signing_key_id="oci-release-2026",
                    release_id="gateway-r48",
                    version="0.48.0",
                    source_date_epoch=SOURCE_DATE_EPOCH,
                    output_path=self.bundle,
                    services=services,
                    compile_callback=self.compile_fixture,
                )
        schema = OCI._strict_json(
            (PROJECT / "gateway/oci-release-receipt.schema.json").read_bytes(),
            "receipt schema",
        )
        self.assertTrue(schema["$id"].endswith("oci-release-receipt-v3.json"))
        self.assertEqual(schema["properties"]["schema"]["const"], 3)
        service_schema = schema["properties"]["services"]
        self.assertEqual(service_schema["minItems"], 7)
        self.assertEqual(service_schema["maxItems"], 7)
        self.assertTrue(service_schema["uniqueItems"])
        self.assertIn(
            "accountauthorization",
            service_schema["items"]["properties"]["name"]["enum"],
        )
        self.assertIn(
            "factorytimeauthority",
            service_schema["items"]["properties"]["name"]["enum"],
        )

    def test_both_validators_reject_signed_missing_or_reordered_service(self) -> None:
        for mutation in ("missing", "reordered"):
            with self.subTest(mutation=mutation):
                self.build()
                unlock_tree(self.bundle)
                receipt = OCI._strict_json(
                    (self.bundle / "release-receipt.json").read_bytes(), "receipt"
                )
                if mutation == "missing":
                    removed = receipt["services"].pop()
                    self.assertEqual(removed["name"], "factorytimeauthority")
                    shutil.rmtree(self.bundle / "services/factorytimeauthority")
                else:
                    receipt["services"][-1], receipt["services"][-2] = (
                        receipt["services"][-2],
                        receipt["services"][-1],
                    )
                self.resign_receipt(receipt)
                OCI._lock_tree(self.bundle)
                with self.assertRaisesRegex(OCI.OCIReleaseError, "exact ordered seven-service"):
                    self.validate()
                completed = self.go_validate()
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(
                    "seven-service" if mutation == "missing" else "ordering",
                    completed.stderr,
                )
                unlock_tree(self.bundle)
                shutil.rmtree(self.bundle)

    def test_both_validators_reject_authentic_v1_downgrade(self) -> None:
        self.build()
        unlock_tree(self.bundle)
        receipt = OCI._strict_json(
            (self.bundle / "release-receipt.json").read_bytes(), "receipt"
        )
        receipt["schema"] = 1
        self.resign_receipt(receipt, b"XIAOZHI-AGENT-OCI-RELEASE-V1\x00")
        OCI._lock_tree(self.bundle)
        with self.assertRaisesRegex(OCI.OCIReleaseError, "schema is unsupported"):
            self.validate()
        completed = self.go_validate()
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("trust policy", completed.stderr)

    def test_refuses_existing_output_without_modifying_it(self) -> None:
        self.bundle.mkdir()
        sentinel = self.bundle / "owner-data"
        sentinel.write_text("keep")
        with self.assertRaisesRegex(OCI.OCIReleaseError, "already exists"):
            self.build()
        self.assertEqual(sentinel.read_text(), "keep")

    def test_wrong_external_key_and_tampered_blob_fail(self) -> None:
        self.build()
        other = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        other_path = self.temporary / "other.pem"
        other_path.write_bytes(other)
        with self.assertRaisesRegex(OCI.OCIReleaseError, "signature"):
            self.validate(other_path)

        unlock_tree(self.bundle)
        service = self.bundle / "services/gateway"
        index = OCI._strict_json((service / "index.json").read_bytes(), "index")
        digest = index["manifests"][0]["digest"].split(":", 1)[1]
        blob = service / "blobs/sha256" / digest
        blob.write_bytes(blob.read_bytes()[:-1] + b"x")
        OCI._lock_tree(self.bundle)
        with self.assertRaisesRegex(OCI.OCIReleaseError, "descriptor"):
            self.validate()

    def test_extra_file_writable_file_and_symlink_fail_closed(self) -> None:
        self.build()
        unlock_tree(self.bundle)
        extra = self.bundle / "unexpected"
        extra.write_text("extra")
        OCI._lock_tree(self.bundle)
        with self.assertRaisesRegex(OCI.OCIReleaseError, "layout"):
            self.validate()
        unlock_tree(self.bundle)
        extra.unlink()
        receipt = self.bundle / "release-receipt.json"
        os.chmod(receipt, 0o600)
        with self.assertRaisesRegex(OCI.OCIReleaseError, "read-only"):
            self.validate()
        os.chmod(receipt, 0o444)
        link = self.bundle / "link"
        link.symlink_to("READY")
        with self.assertRaisesRegex(OCI.OCIReleaseError, "symlink"):
            OCI.validate_release_bundle(
                self.bundle,
                trusted_public_key_path=self.public_path,
                expected_signing_key_id="oci-release-2026",
                expected_release_id="gateway-r48",
                require_read_only=False,
            )

    def test_noncanonical_receipt_and_ready_tamper_fail(self) -> None:
        self.build()
        unlock_tree(self.bundle)
        receipt_path = self.bundle / "release-receipt.json"
        receipt = OCI._strict_json(receipt_path.read_bytes(), "receipt")
        receipt_path.write_text(json_compact(receipt) + "\n")
        OCI._lock_tree(self.bundle)
        with self.assertRaisesRegex(OCI.OCIReleaseError, "canonical"):
            self.validate()

    def test_static_elf_policy_rejects_dynamic_interpreter(self) -> None:
        self.assertTrue(OCI._static_elf(fake_elf("amd64"), "amd64"))
        self.assertFalse(OCI._static_elf(fake_elf("amd64", interpreter=True), "amd64"))
        with self.assertRaisesRegex(OCI.OCIReleaseError, "static ELF"):
            OCI._make_layer(
                fake_elf("arm64", interpreter=True),
                "arm64",
                self.ca_path.read_bytes(),
                b"license",
                b"notices",
                SOURCE_DATE_EPOCH,
            )

    def test_layer_validator_rejects_duplicate_path_and_wrong_timestamp(self) -> None:
        binary = fake_elf("amd64")
        layer, _ = OCI._make_layer(
            binary,
            "amd64",
            self.ca_path.read_bytes(),
            b"license",
            b"notices",
            SOURCE_DATE_EPOCH,
        )
        tampered = bytearray(layer)
        struct.pack_into("<I", tampered, 4, SOURCE_DATE_EPOCH + 1)
        with self.assertRaisesRegex(OCI.OCIReleaseError, "timestamp"):
            OCI._validate_layer(
                bytes(tampered),
                "amd64",
                SOURCE_DATE_EPOCH,
                hashlib.sha256(binary).hexdigest(),
                len(binary),
                hashlib.sha256(self.ca_path.read_bytes()).hexdigest(),
            )

        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for _ in range(2):
                info = tarfile.TarInfo("service")
                info.mode = 0o555
                info.uid = info.gid = 65532
                info.mtime = SOURCE_DATE_EPOCH
                info.size = len(binary)
                archive.addfile(info, io.BytesIO(binary))
        compressed = io.BytesIO()
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=compressed, mtime=SOURCE_DATE_EPOCH
        ) as stream:
            stream.write(raw.getvalue())
        with self.assertRaisesRegex(OCI.OCIReleaseError, "unsafe or duplicate"):
            OCI._validate_layer(
                compressed.getvalue(),
                "amd64",
                SOURCE_DATE_EPOCH,
                hashlib.sha256(binary).hexdigest(),
                len(binary),
                hashlib.sha256(self.ca_path.read_bytes()).hexdigest(),
            )


def json_compact(value: object) -> str:
    import json

    return json.dumps(value, separators=(",", ":"), sort_keys=True)


if __name__ == "__main__":
    unittest.main()
