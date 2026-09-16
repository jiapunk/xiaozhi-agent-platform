from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
import plistlib
import shutil
import subprocess
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


PROJECT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = PROJECT / "tools"
sys.path.insert(0, str(TOOLS))
import companion_app_supply_chain as SUPPLY


def unlock_tree(root: pathlib.Path) -> None:
    if not root.exists() or root.is_symlink():
        return
    os.chmod(root, 0o700)
    for path in root.rglob("*"):
        if not path.is_symlink():
            os.chmod(path, 0o700 if path.is_dir() else 0o600)


class CompanionAppSupplyChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = pathlib.Path(tempfile.mkdtemp())
        self.project = self.temporary / "project"
        self.app = self.project / "companion-app"
        self.app.mkdir(parents=True)
        self.key = Ed25519PrivateKey.generate()
        self.private_key = self.temporary / "authority.private.pem"
        self.public_key = self.temporary / "authority.public.pem"
        self.private_key.write_bytes(
            self.key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self.public_key.write_bytes(
            self.key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        self.dependencies = [
            self.make_checkout(
                "esp-idf-provisioning-ios",
                "LICENSE",
                b"Apache License for ESP provisioning fixture\n",
                "https://github.com/espressif/esp-idf-provisioning-ios.git",
                "3.1.0",
                "ios-provisioning-transport",
                "licenses/esp-idf-provisioning-ios-LICENSE.txt",
            ),
            self.make_checkout(
                "swift-protobuf",
                "LICENSE.txt",
                b"Apache License for Swift protobuf fixture\n",
                "https://github.com/apple/swift-protobuf.git",
                "1.38.1",
                "protobuf-runtime",
                "licenses/swift-protobuf-LICENSE.txt",
            ),
        ]
        self.write_sources()
        self.policy = self.make_policy()
        self.policy_path = self.temporary / "policy.json"
        self.policy_path.write_bytes(SUPPLY._json_bytes(self.policy))
        self.bundle = self.temporary / "bundle"

    def tearDown(self) -> None:
        unlock_tree(self.temporary)
        shutil.rmtree(self.temporary, ignore_errors=True)

    @staticmethod
    def fingerprint(key: Ed25519PrivateKey) -> str:
        raw = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return hashlib.sha256(raw).hexdigest()

    def git(self, checkout: pathlib.Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment.update(
            {
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_AUTHOR_DATE": "2026-08-11T00:00:00Z",
                "GIT_COMMITTER_DATE": "2026-08-11T00:00:00Z",
            }
        )
        return subprocess.run(
            ["git", "-C", str(checkout), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
            env=environment,
        )

    def make_checkout(
        self,
        identity: str,
        license_name: str,
        license_raw: bytes,
        url: str,
        version: str,
        role: str,
        bundle_path: str,
    ) -> dict[str, object]:
        checkout = self.app / ".build/checkouts" / identity
        checkout.mkdir(parents=True)
        self.git(checkout, "init", "-q")
        self.git(checkout, "config", "user.name", "Supply Chain Test")
        self.git(checkout, "config", "user.email", "supply-chain@invalid.example")
        (checkout / license_name).write_bytes(license_raw)
        (checkout / "Source.swift").write_text("public let version = 1\n")
        self.git(checkout, "add", license_name, "Source.swift")
        self.git(checkout, "commit", "-q", "-m", "fixture dependency")
        revision = self.git(checkout, "rev-parse", "HEAD").stdout.strip()
        return {
            "bundle_path": bundle_path,
            "checkout_path": f".build/checkouts/{identity}",
            "identity": identity,
            "license": "Apache-2.0",
            "license_path": license_name,
            "license_sha256": hashlib.sha256(license_raw).hexdigest(),
            "revision": revision,
            "role": role,
            "url": url,
            "version": version,
        }

    def write_sources(self) -> None:
        (self.app / "Package.swift").write_text(
            "// swift-tools-version: 6.1\nlet package = \"fixture\"\n"
        )
        pins = [
            {
                "identity": dependency["identity"],
                "kind": "remoteSourceControl",
                "location": dependency["url"],
                "state": {
                    "revision": dependency["revision"],
                    "version": dependency["version"],
                },
            }
            for dependency in self.dependencies
        ]
        (self.app / "Package.resolved").write_text(
            json.dumps(
                {"originHash": "1" * 64, "pins": pins, "version": 3},
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        (self.app / "upstream-lock.json").write_text(
            json.dumps({"schema_version": 1, "reviewed": True}, sort_keys=True) + "\n"
        )
        source = self.app / "Sources/Core/Core.swift"
        source.parent.mkdir(parents=True)
        source.write_text("public struct CompanionCore {}\n")
        privacy = self.app / "Sources/Core/PrivacyInfo.xcprivacy"
        privacy.write_bytes(
            plistlib.dumps(
                {
                    "NSPrivacyAccessedAPITypes": [],
                    "NSPrivacyCollectedDataTypes": [],
                    "NSPrivacyTracking": False,
                    "NSPrivacyTrackingDomains": [],
                },
                fmt=plistlib.FMT_XML,
                sort_keys=True,
            )
        )

    @property
    def source_paths(self) -> list[str]:
        paths = ["Package.swift", "Package.resolved", "upstream-lock.json"]
        paths.extend(
            path.relative_to(self.app).as_posix()
            for path in (self.app / "Sources").rglob("*")
            if path.is_file()
        )
        return sorted(paths)

    def make_policy(self) -> dict[str, object]:
        privacy = self.app / "Sources/Core/PrivacyInfo.xcprivacy"
        return {
            "schema_version": 1,
            "policy_id": "companion-source-policy-0001",
            "release_id": "companion-source-release-0001",
            "package_name": "XiaozhiProductCompanion",
            "package_version": "1.0.0",
            "source_date_epoch": 1_786_406_400,
            "platforms": list(SUPPLY.PLATFORMS),
            "production_targets": list(SUPPLY.TARGETS),
            "source_paths": self.source_paths,
            "package_resolved_sha256": hashlib.sha256(
                (self.app / "Package.resolved").read_bytes()
            ).hexdigest(),
            "upstream_lock_sha256": hashlib.sha256(
                (self.app / "upstream-lock.json").read_bytes()
            ).hexdigest(),
            "privacy_manifest_path": "Sources/Core/PrivacyInfo.xcprivacy",
            "privacy_manifest_sha256": hashlib.sha256(privacy.read_bytes()).hexdigest(),
            "dependencies": copy.deepcopy(self.dependencies),
            "tool_sha256": hashlib.sha256(
                (TOOLS / "companion_app_supply_chain.py").read_bytes()
            ).hexdigest(),
            "signing_key_id": "companion-source-authority-2026",
            "signing_public_key_sha256": self.fingerprint(self.key),
        }

    def write_policy(self) -> None:
        self.policy_path.write_bytes(SUPPLY._json_bytes(self.policy))

    def build(self, output: pathlib.Path | None = None) -> dict[str, object]:
        return SUPPLY.build_bundle(
            project_root=self.project,
            policy_path=self.policy_path,
            signing_private_key_path=self.private_key,
            output_path=output or self.bundle,
        )

    def validate(self, bundle: pathlib.Path | None = None) -> dict[str, object]:
        return SUPPLY.validate_bundle(
            bundle or self.bundle,
            project_root=self.project,
            trusted_policy_path=self.policy_path,
            trusted_public_key_path=self.public_key,
        )

    @staticmethod
    def tree(root: pathlib.Path) -> dict[str, bytes]:
        return {
            path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*")
            if path.is_file()
        }

    def test_signed_round_trip_is_deterministic_and_explicitly_not_app_ready(self) -> None:
        first = self.build()
        validated = self.validate()
        second_bundle = self.temporary / "bundle-two"
        second = self.build(second_bundle)
        self.assertEqual(first, validated)
        self.assertEqual(first, second)
        self.assertEqual(self.tree(self.bundle), self.tree(second_bundle))
        self.assertEqual(first["result"], "SOURCE_SUPPLY_CHAIN_PASS")
        self.assertFalse(first["production_ready"])
        self.assertEqual(first["limitations"], list(SUPPLY.LIMITATIONS))
        spdx = json.loads((self.bundle / "companion-app.spdx.json").read_text())
        self.assertEqual(spdx["spdxVersion"], "SPDX-2.3")
        self.assertEqual(len(spdx["files"]), len(self.source_paths))
        provenance = json.loads(
            (self.bundle / "companion-app.provenance.json").read_text()
        )
        self.assertEqual(provenance["predicateType"], "https://slsa.dev/provenance/v1")

    def test_independent_source_change_and_extra_source_fail_closed(self) -> None:
        self.build()
        (self.app / "Sources/Core/Core.swift").write_text("public struct Changed {}\n")
        with self.assertRaisesRegex(SUPPLY.CompanionSupplyChainError, "source-manifest"):
            self.validate()

        (self.app / "Sources/Core/Extra.swift").write_text("public let extra = true\n")
        with self.assertRaisesRegex(SUPPLY.CompanionSupplyChainError, "inventory differs"):
            self.build(self.temporary / "extra-source")

    def test_source_symlink_and_dirty_dependency_fail_closed(self) -> None:
        target = self.app / "Sources/Core/Core.swift"
        target.unlink()
        target.symlink_to(self.app / "Package.swift")
        with self.assertRaisesRegex(SUPPLY.CompanionSupplyChainError, "symlink"):
            self.build()

        target.unlink()
        target.write_text("public struct CompanionCore {}\n")
        checkout = self.app / self.dependencies[0]["checkout_path"]
        (checkout / "untracked.txt").write_text("unexpected\n")
        with self.assertRaisesRegex(SUPPLY.CompanionSupplyChainError, "dirty"):
            self.build(self.temporary / "dirty-dependency")

    def test_policy_key_and_schema_downgrade_fail_closed(self) -> None:
        self.policy["schema_version"] = 0
        self.write_policy()
        with self.assertRaisesRegex(SUPPLY.CompanionSupplyChainError, "schema"):
            self.build()

        self.policy = self.make_policy()
        self.policy["tool_sha256"] = "1" * 64
        self.write_policy()
        with self.assertRaisesRegex(SUPPLY.CompanionSupplyChainError, "tool hash"):
            self.build(self.temporary / "wrong-tool")

        self.policy = self.make_policy()
        self.policy["signing_public_key_sha256"] = "2" * 64
        self.write_policy()
        with self.assertRaisesRegex(SUPPLY.CompanionSupplyChainError, "fingerprint"):
            self.build(self.temporary / "wrong-key")

    def test_bundle_tamper_ready_and_exact_file_set_fail_closed(self) -> None:
        self.build()
        unlock_tree(self.bundle)
        spdx_path = self.bundle / "companion-app.spdx.json"
        value = json.loads(spdx_path.read_text())
        value["name"] = "tampered"
        spdx_path.write_bytes(SUPPLY._json_bytes(value))
        with self.assertRaisesRegex(SUPPLY.CompanionSupplyChainError, "independent input"):
            self.validate()

        spdx_path.write_bytes(
            SUPPLY._json_bytes(
                SUPPLY._spdx(
                    self.policy,
                    *SUPPLY._source_inventory(self.app, self.policy),
                )
            )
        )
        (self.bundle / "unexpected.txt").write_text("unexpected\n")
        with self.assertRaisesRegex(SUPPLY.CompanionSupplyChainError, "file set"):
            self.validate()

        (self.bundle / "unexpected.txt").unlink()
        (self.bundle / "READY").write_text("sha256:" + "0" * 64 + "\n")
        with self.assertRaisesRegex(SUPPLY.CompanionSupplyChainError, "READY"):
            self.validate()

    def test_receipt_signature_tamper_and_output_overwrite_fail_closed(self) -> None:
        self.build()
        with self.assertRaisesRegex(SUPPLY.CompanionSupplyChainError, "already exists"):
            self.build()

        unlock_tree(self.bundle)
        receipt_path = self.bundle / "receipt.json"
        receipt = json.loads(receipt_path.read_text())
        receipt["signature_b64url"] = "A" * 86
        receipt_path.write_bytes(SUPPLY._json_bytes(receipt))
        receipt_raw = receipt_path.read_bytes()
        (self.bundle / "READY").write_text(
            f"sha256:{hashlib.sha256(receipt_raw).hexdigest()}\n"
        )
        with self.assertRaisesRegex(SUPPLY.CompanionSupplyChainError, "signature is invalid"):
            self.validate()

    def test_cli_requires_explicit_attestation(self) -> None:
        command = subprocess.run(
            [
                sys.executable,
                str(TOOLS / "build_companion_app_supply_chain_bundle.py"),
                "--project-root",
                str(self.project),
                "--policy",
                str(self.policy_path),
                "--signing-private-key",
                str(self.private_key),
                "--output",
                str(self.bundle),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertNotEqual(command.returncode, 0)
        self.assertIn("--attest-companion-source-release is required", command.stderr)

    def test_checked_in_example_covers_exact_current_app_source(self) -> None:
        example_path = PROJECT / "release/companion-app-supply-chain-policy.example.json"
        example, raw = SUPPLY.load_policy(example_path)
        self.assertEqual(raw, SUPPLY._json_bytes(example))
        self.assertEqual(
            example["tool_sha256"],
            hashlib.sha256((TOOLS / "companion_app_supply_chain.py").read_bytes()).hexdigest(),
        )
        actual_paths = ["Package.swift", "Package.resolved", "upstream-lock.json"]
        actual_paths.extend(
            path.relative_to(PROJECT / "companion-app").as_posix()
            for path in (PROJECT / "companion-app/Sources").rglob("*")
            if path.is_file()
        )
        self.assertEqual(example["source_paths"], sorted(actual_paths))
        artifacts, receipt = SUPPLY._derive(
            PROJECT / "companion-app", example, raw
        )
        self.assertEqual(receipt["source_file_count"], 19)
        self.assertIn("companion-app.spdx.json", artifacts)
        self.assertFalse(receipt["production_ready"])

    def test_schema_documents_parse(self) -> None:
        for path in (
            PROJECT / "release/companion-app-supply-chain-policy.schema.json",
            PROJECT / "release/companion-app-source-manifest.schema.json",
            PROJECT / "release/companion-app-supply-chain-receipt.schema.json",
        ):
            json.loads(path.read_text())


if __name__ == "__main__":
    unittest.main()
