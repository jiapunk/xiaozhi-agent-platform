from __future__ import annotations

import json
import hashlib
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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


PROJECT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = PROJECT / "tools"
sys.path.insert(0, str(TOOLS))
import build_ota_deployment_bundle as BUNDLE
import ota_rollout as ROLLOUT
import sign_release_manifest as SIGNER
from tools.tests.reset_qualification_fixture import signed_reset_qualification


def test_image() -> bytes:
    image = bytearray(4096)
    struct.pack_into("<II", image, 32, 0xABCD5432, 2)
    image[48 : 48 + len(b"0.18.0-dev")] = b"0.18.0-dev"
    image[80 : 80 + len(b"xiaozhi_agent_platform")] = b"xiaozhi_agent_platform"
    return bytes(image)


def sdkconfig() -> bytes:
    return (
        "CONFIG_PRODUCT_BOARD_ESP_BOX_3=y\n"
        'CONFIG_PRODUCT_OTA_CHANNEL="stable"\n'
        "CONFIG_PRODUCT_OTA_RELEASE_SEQUENCE=18\n"
    ).encode("utf-8")


def unlock_tree(root: pathlib.Path) -> None:
    if not root.exists() or root.is_symlink():
        return
    os.chmod(root, 0o700)
    for path in root.rglob("*"):
        os.chmod(path, 0o700 if path.is_dir() else 0o600)


class OTARolloutTests(unittest.TestCase):
    def setUp(self):
        self.temporary = pathlib.Path(tempfile.mkdtemp())
        self.release_private = ec.generate_private_key(ec.SECP256R1())
        release_private_pem = self.release_private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        release_public_pem = self.release_private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.image = test_image()
        self.sdkconfig = sdkconfig()
        qualification, qualification_public, _ = signed_reset_qualification(
            image_sha256=hashlib.sha256(self.image).hexdigest(),
            version="0.18.0-dev",
            secure_version=2,
        )
        manifest = SIGNER.build_manifest(
            self.image,
            self.sdkconfig.decode(),
            release_private_pem,
            qualification,
            qualification_public,
            "synthetic-ed25519-key",
            release_id="box3-stable-00000018",
            image_url="https://updates.example.com/firmware/box3/18/image.bin",
            not_before=1786200000,
            expires_at=1787500000,
            signing_key_id="release-key-2026",
        )
        self.manifest_path = self.temporary / "manifest.json"
        self.public_path = self.temporary / "release-public.pem"
        self.image_path = self.temporary / "image.bin"
        self.sdkconfig_path = self.temporary / "sdkconfig"
        self.qualification_path = self.temporary / "reset-qualification.json"
        self.qualification_public_path = self.temporary / "reset-lab-public.pem"
        self.manifest_path.write_bytes(BUNDLE._json_bytes(manifest))
        self.public_path.write_bytes(release_public_pem)
        self.image_path.write_bytes(self.image)
        self.sdkconfig_path.write_bytes(self.sdkconfig)
        self.qualification_path.write_bytes(qualification)
        self.qualification_public_path.write_bytes(qualification_public)
        self.staging = self.temporary / "staging.bundle"
        BUNDLE.build_deployment_bundle(
            manifest_path=self.manifest_path,
            public_key_path=self.public_path,
            image_path=self.image_path,
            sdkconfig_path=self.sdkconfig_path,
            reset_qualification_receipt_path=self.qualification_path,
            reset_qualification_public_key_path=self.qualification_public_path,
            reset_qualification_signing_key_id="synthetic-ed25519-key",
            expected_authority="updates.example.com",
            retry_after_seconds=900,
            output_path=self.staging,
        )

        self.approver_private = [Ed25519PrivateKey.generate() for _ in range(3)]
        entries = []
        for index, key in enumerate(self.approver_private, start=1):
            public_name = f"approver-{index}-public.pem"
            (self.temporary / public_name).write_bytes(
                key.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            entries.append(
                {
                    "approver_id": f"operator-{index}",
                    "approval_key_id": f"rollout-key-{index}",
                    "public_key_file": public_name,
                    "enabled": True,
                }
            )
        self.keyring_path = self.temporary / "approver-keyring.json"
        self.keyring_path.write_bytes(
            BUNDLE._json_bytes({"version": 1, "approvers": entries})
        )

    def tearDown(self):
        for path in self.temporary.iterdir():
            if path.is_dir() and not path.is_symlink():
                unlock_tree(path)
        shutil.rmtree(self.temporary)

    def _request(
        self,
        parent: pathlib.Path,
        generation_id: str,
        action: str,
        basis: int,
        *,
        parent_lineage: list[pathlib.Path] | None = None,
    ) -> tuple[dict[str, object], bytes]:
        request = ROLLOUT.create_rollout_request(
            parent_bundle=parent,
            parent_lineage=parent_lineage,
            parent_approver_keyring_paths=(
                [self.keyring_path] if parent_lineage is not None else None
            ),
            approver_keyring_path=self.keyring_path,
            expected_authority="updates.example.com",
            generation_id=generation_id,
            action=action,
            rollout_basis_points=basis,
            created_at=1786276800,
            expires_at=1786280400,
        )
        return request, BUNDLE._json_bytes(request)

    def _approvals(self, request_data: bytes, first=0, second=1):
        result = []
        for offset, index in enumerate((first, second), start=10):
            approval = ROLLOUT.sign_rollout_approval(
                request_data,
                self.approver_private[index].private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ),
                approver_id=f"operator-{index + 1}",
                approval_key_id=f"rollout-key-{index + 1}",
                signed_at=1786276800 + offset,
            )
            path = self.temporary / f"approval-{index + 1}-{offset}.json"
            data = BUNDLE._json_bytes(approval)
            path.write_bytes(data)
            result.append(path)
        return result

    def _promote(
        self,
        parent: pathlib.Path,
        request_data: bytes,
        output: pathlib.Path,
        *,
        parent_lineage: list[pathlib.Path] | None = None,
        approval_paths: list[pathlib.Path] | None = None,
    ) -> dict[str, object]:
        request_path = self.temporary / f"{output.name}.request.json"
        request_path.write_bytes(request_data)
        if approval_paths is None:
            approval_paths = self._approvals(request_data)
        return ROLLOUT.promote_rollout_bundle(
            parent_bundle=parent,
            parent_lineage=parent_lineage,
            parent_approver_keyring_paths=(
                [self.keyring_path] if parent_lineage is not None else None
            ),
            request_path=request_path,
            approval_paths=approval_paths,
            approver_keyring_path=self.keyring_path,
            expected_authority="updates.example.com",
            verification_time=1786276830,
            output_path=output,
        )

    def test_two_person_expand_builds_verified_active_generation(self):
        request, request_data = self._request(
            self.staging, "stable-18-g1", "EXPAND", 100
        )
        output = self.temporary / "g1.bundle"
        receipt = self._promote(self.staging, request_data, output)
        verified = ROLLOUT.validate_rollout_bundle(
            output,
            expected_authority="updates.example.com",
            approver_keyring_path=self.keyring_path,
            parent_root=self.staging,
        )
        self.assertEqual(receipt, verified)
        self.assertEqual(receipt["generation_sequence"], 1)
        self.assertTrue(receipt["rollout_enabled"])
        self.assertEqual(receipt["rollout_basis_points"], 100)
        self.assertEqual(request["parent_receipt_sha256"], BUNDLE._sha256(
            (self.staging / "deployment-receipt.json").read_bytes()
        ))
        registry = json.loads(
            (output / "control/ota-release-registry.json").read_text()
        )
        self.assertTrue(registry["releases"][0]["enabled"])
        self.assertEqual(registry["releases"][0]["rollout_basis_points"], 100)

    def test_expand_emergency_stop_and_resume_form_parent_chain(self):
        _, first_request = self._request(
            self.staging, "stable-18-g1", "EXPAND", 100
        )
        first = self.temporary / "g1.bundle"
        self._promote(self.staging, first_request, first)

        _, stop_request = self._request(
            first,
            "stable-18-stop-g2",
            "EMERGENCY_STOP",
            0,
            parent_lineage=[self.staging],
        )
        stopped = self.temporary / "g2-stop.bundle"
        stop_receipt = self._promote(
            first, stop_request, stopped, parent_lineage=[self.staging]
        )
        self.assertFalse(stop_receipt["rollout_enabled"])
        self.assertEqual(stop_receipt["generation_sequence"], 2)

        _, resume_request = self._request(
            stopped,
            "stable-18-resume-g3",
            "RESUME",
            50,
            parent_lineage=[first, self.staging],
        )
        resumed = self.temporary / "g3-resume.bundle"
        resume_receipt = self._promote(
            stopped,
            resume_request,
            resumed,
            parent_lineage=[first, self.staging],
        )
        self.assertTrue(resume_receipt["rollout_enabled"])
        self.assertEqual(resume_receipt["rollout_basis_points"], 50)
        self.assertEqual(resume_receipt["generation_sequence"], 3)
        chain_receipt = ROLLOUT.validate_rollout_chain(
            resumed,
            expected_authority="updates.example.com",
            parent_roots=[stopped, first, self.staging],
            approver_keyring_paths=[self.keyring_path],
        )
        self.assertEqual(chain_receipt, resume_receipt)
        go = shutil.which("go")
        if go is not None:
            completed = subprocess.run(
                [
                    go,
                    "run",
                    "./cmd/validaterolloutbundle",
                    "-bundle",
                    str(resumed),
                    "-parent-bundle",
                    str(stopped),
                    "-parent-bundle",
                    str(first),
                    "-parent-bundle",
                    str(self.staging),
                    "-authority",
                    "updates.example.com",
                    "-approver-keyring",
                    str(self.keyring_path),
                ],
                cwd=PROJECT / "gateway",
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("sequence=3", completed.stdout)

    def test_policy_rejects_nonmonotonic_or_wrong_action_transition(self):
        with self.assertRaisesRegex(ROLLOUT.RolloutError, "EXPAND"):
            self._request(self.staging, "bad-expand", "EXPAND", 0)
        with self.assertRaisesRegex(ROLLOUT.RolloutError, "EMERGENCY_STOP"):
            self._request(self.staging, "bad-stop", "EMERGENCY_STOP", 0)
        with self.assertRaisesRegex(ROLLOUT.RolloutError, "RESUME"):
            self._request(self.staging, "bad-resume", "RESUME", 100)
        _, request_data = self._request(
            self.staging, "stable-18-g1", "EXPAND", 100
        )
        first = self.temporary / "policy-g1.bundle"
        self._promote(self.staging, request_data, first)
        with self.assertRaisesRegex(ROLLOUT.RolloutError, "EXPAND"):
            self._request(
                first,
                "lower-cohort-g2",
                "EXPAND",
                50,
                parent_lineage=[self.staging],
            )

    def test_duplicate_approver_wrong_signature_and_request_replay_fail(self):
        _, request_data = self._request(
            self.staging, "stable-18-g1", "EXPAND", 100
        )
        duplicate = self._approvals(request_data, first=0, second=0)
        with self.assertRaisesRegex(ROLLOUT.RolloutError, "distinct"):
            self._promote(
                self.staging,
                request_data,
                self.temporary / "duplicate.bundle",
                approval_paths=duplicate,
            )
        approvals = self._approvals(request_data)
        altered = json.loads(request_data)
        altered["generation_id"] = "different-generation"
        altered_data = BUNDLE._json_bytes(altered)
        with self.assertRaisesRegex(ROLLOUT.RolloutError, "another rollout request"):
            self._promote(
                self.staging,
                altered_data,
                self.temporary / "replay.bundle",
                approval_paths=approvals,
            )

    def test_keyring_is_external_distinct_and_digest_bound(self):
        keyring = json.loads(self.keyring_path.read_text())
        keyring["approvers"][1]["public_key_file"] = keyring["approvers"][0][
            "public_key_file"
        ]
        duplicate_path = self.temporary / "duplicate-keyring.json"
        duplicate_path.write_bytes(BUNDLE._json_bytes(keyring))
        with self.assertRaisesRegex(ROLLOUT.RolloutError, "cryptographically distinct"):
            ROLLOUT.load_approver_keyring(duplicate_path)

        request, request_data = self._request(
            self.staging, "stable-18-g1", "EXPAND", 100
        )
        self.assertEqual(
            request["approval_keyring_sha256"],
            BUNDLE._sha256(self.keyring_path.read_bytes()),
        )
        keyring = json.loads(self.keyring_path.read_text())
        keyring["approvers"][2]["enabled"] = False
        changed_path = self.temporary / "changed-keyring.json"
        changed_path.write_bytes(BUNDLE._json_bytes(keyring))
        with self.assertRaisesRegex(ROLLOUT.RolloutError, "trusted keyring"):
            ROLLOUT.verify_rollout_approvals(
                request_data,
                [path.read_bytes() for path in self._approvals(request_data)],
                ROLLOUT.load_approver_keyring(changed_path),
            )

    def test_signature_tamper_wrong_signer_and_disabled_approver_fail(self):
        _, request_data = self._request(
            self.staging, "stable-18-g1", "EXPAND", 100
        )
        approvals = self._approvals(request_data)
        altered = json.loads(approvals[0].read_text())
        altered["signed_at"] += 1
        with self.assertRaisesRegex(ROLLOUT.RolloutError, "signature"):
            ROLLOUT.verify_rollout_approvals(
                request_data,
                [BUNDLE._json_bytes(altered), approvals[1].read_bytes()],
                ROLLOUT.load_approver_keyring(self.keyring_path),
            )
        wrong = ROLLOUT.sign_rollout_approval(
            request_data,
            self.approver_private[2].private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            approver_id="operator-1",
            approval_key_id="rollout-key-1",
            signed_at=1786276810,
        )
        with self.assertRaisesRegex(ROLLOUT.RolloutError, "signature"):
            ROLLOUT.verify_rollout_approvals(
                request_data,
                [BUNDLE._json_bytes(wrong), approvals[1].read_bytes()],
                ROLLOUT.load_approver_keyring(self.keyring_path),
            )

        keyring = json.loads(self.keyring_path.read_text())
        keyring["approvers"][0]["enabled"] = False
        disabled_keyring_path = self.temporary / "disabled-keyring.json"
        disabled_keyring_path.write_bytes(BUNDLE._json_bytes(keyring))
        disabled_request = dict(json.loads(request_data))
        disabled_request["approval_keyring_sha256"] = BUNDLE._sha256(
            disabled_keyring_path.read_bytes()
        )
        disabled_request_data = BUNDLE._json_bytes(disabled_request)
        disabled_approvals = self._approvals(disabled_request_data)
        with self.assertRaisesRegex(ROLLOUT.RolloutError, "not enabled"):
            ROLLOUT.verify_rollout_approvals(
                disabled_request_data,
                [path.read_bytes() for path in disabled_approvals],
                ROLLOUT.load_approver_keyring(disabled_keyring_path),
            )

    def test_noncanonical_duplicate_and_escaping_keyring_inputs_fail(self):
        request, request_data = self._request(
            self.staging, "stable-18-g1", "EXPAND", 100
        )
        compact = json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
        with self.assertRaisesRegex(ROLLOUT.RolloutError, "not canonical"):
            ROLLOUT.parse_rollout_request(compact)
        duplicate = request_data[:-2] + b',\n  "schema": 1\n}\n'
        with self.assertRaisesRegex(BUNDLE.DeploymentBundleError, "duplicate"):
            ROLLOUT.parse_rollout_request(duplicate)
        keyring = json.loads(self.keyring_path.read_text())
        keyring["approvers"][0]["public_key_file"] = "../escape.pem"
        escape_path = self.temporary / "escape-keyring.json"
        escape_path.write_bytes(BUNDLE._json_bytes(keyring))
        with self.assertRaisesRegex(ROLLOUT.RolloutError, "escapes"):
            ROLLOUT.load_approver_keyring(escape_path)

    def test_rollout_bundle_tamper_and_writable_tree_fail_validation(self):
        _, request_data = self._request(
            self.staging, "stable-18-g1", "EXPAND", 100
        )
        output = self.temporary / "tamper-g1.bundle"
        self._promote(self.staging, request_data, output)
        registry = output / "control/ota-release-registry.json"
        os.chmod(output, 0o700)
        os.chmod(registry.parent, 0o700)
        os.chmod(registry, 0o600)
        registry.write_text('{"version":1,"signing_keys":[],"releases":[]}\n')
        os.chmod(registry, 0o444)
        os.chmod(registry.parent, 0o555)
        os.chmod(output, 0o555)
        with self.assertRaisesRegex(ROLLOUT.RolloutError, "catalogs"):
            ROLLOUT.validate_rollout_bundle(
                output,
                expected_authority="updates.example.com",
                approver_keyring_path=self.keyring_path,
                parent_root=self.staging,
            )

        unlock_tree(output)
        shutil.rmtree(output)
        self._promote(self.staging, request_data, output)
        registry = output / "control/ota-release-registry.json"
        os.chmod(output, 0o700)
        os.chmod(registry.parent, 0o700)
        os.chmod(registry, 0o644)
        os.chmod(registry.parent, 0o555)
        os.chmod(output, 0o555)
        with self.assertRaisesRegex(BUNDLE.DeploymentBundleError, "read-only"):
            ROLLOUT.validate_rollout_bundle(
                output,
                expected_authority="updates.example.com",
                approver_keyring_path=self.keyring_path,
                parent_root=self.staging,
            )

    def test_expired_verification_and_existing_output_fail_closed(self):
        _, request_data = self._request(
            self.staging, "stable-18-g1", "EXPAND", 100
        )
        request_path = self.temporary / "request.json"
        request_path.write_bytes(request_data)
        approvals = self._approvals(request_data)
        output = self.temporary / "existing.bundle"
        output.mkdir()
        sentinel = output / "keep"
        sentinel.write_text("owner data")
        with self.assertRaisesRegex(ROLLOUT.RolloutError, "verification time"):
            ROLLOUT.promote_rollout_bundle(
                parent_bundle=self.staging,
                parent_lineage=None,
                parent_approver_keyring_paths=None,
                request_path=request_path,
                approval_paths=approvals,
                approver_keyring_path=self.keyring_path,
                expected_authority="updates.example.com",
                verification_time=1786280401,
                output_path=self.temporary / "expired.bundle",
            )
        with self.assertRaisesRegex(ROLLOUT.RolloutError, "already exists"):
            ROLLOUT.promote_rollout_bundle(
                parent_bundle=self.staging,
                parent_lineage=None,
                parent_approver_keyring_paths=None,
                request_path=request_path,
                approval_paths=approvals,
                approver_keyring_path=self.keyring_path,
                expected_authority="updates.example.com",
                verification_time=1786276830,
                output_path=output,
            )
        self.assertEqual(sentinel.read_text(), "owner data")

    def test_request_window_must_fit_signed_manifest_validity(self):
        with self.assertRaisesRegex(ROLLOUT.RolloutError, "manifest validity"):
            ROLLOUT.create_rollout_request(
                parent_bundle=self.staging,
                parent_lineage=None,
                parent_approver_keyring_paths=None,
                approver_keyring_path=self.keyring_path,
                expected_authority="updates.example.com",
                generation_id="outside-manifest-g1",
                action="EXPAND",
                rollout_basis_points=10,
                created_at=1787499900,
                expires_at=1787500100,
            )

    def test_full_lineage_rejects_reused_ancestor_generation_id(self):
        _, first_request = self._request(
            self.staging, "reused-generation", "EXPAND", 100
        )
        first = self.temporary / "reuse-g1.bundle"
        self._promote(self.staging, first_request, first)
        _, stop_request = self._request(
            first,
            "reuse-stop-g2",
            "EMERGENCY_STOP",
            0,
            parent_lineage=[self.staging],
        )
        stopped = self.temporary / "reuse-stop-g2.bundle"
        self._promote(
            first, stop_request, stopped, parent_lineage=[self.staging]
        )
        _, resume_request = self._request(
            stopped,
            "reused-generation",
            "RESUME",
            50,
            parent_lineage=[first, self.staging],
        )
        resumed = self.temporary / "reuse-g3.bundle"
        self._promote(
            stopped,
            resume_request,
            resumed,
            parent_lineage=[first, self.staging],
        )
        with self.assertRaisesRegex(ROLLOUT.RolloutError, "duplicated"):
            ROLLOUT.validate_rollout_chain(
                resumed,
                expected_authority="updates.example.com",
                parent_roots=[stopped, first, self.staging],
                approver_keyring_paths=[self.keyring_path],
            )

    def test_rollout_cli_chain_smoke(self):
        request_path = self.temporary / "cli-request.json"
        approval_paths = [
            self.temporary / "cli-approval-1.json",
            self.temporary / "cli-approval-2.json",
        ]
        private_paths = []
        for index in range(2):
            private_path = self.temporary / f"cli-private-{index + 1}.pem"
            private_path.write_bytes(
                self.approver_private[index].private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            os.chmod(private_path, 0o600)
            private_paths.append(private_path)
        commands = [
            [
                sys.executable,
                str(TOOLS / "create_ota_rollout_request.py"),
                "--parent-bundle",
                str(self.staging),
                "--approver-keyring",
                str(self.keyring_path),
                "--expected-authority",
                "updates.example.com",
                "--generation-id",
                "cli-stable-18-g1",
                "--action",
                "EXPAND",
                "--rollout-basis-points",
                "10",
                "--valid-for-seconds",
                "3600",
                "--output",
                str(request_path),
            ]
        ]
        for index in range(2):
            commands.append(
                [
                    sys.executable,
                    str(TOOLS / "sign_ota_rollout_approval.py"),
                    "--request",
                    str(request_path),
                    "--private-key",
                    str(private_paths[index]),
                    "--approver-id",
                    f"operator-{index + 1}",
                    "--approval-key-id",
                    f"rollout-key-{index + 1}",
                    "--output",
                    str(approval_paths[index]),
                ]
            )
        output = self.temporary / "cli-g1.bundle"
        commands.extend(
            [
                [
                    sys.executable,
                    str(TOOLS / "promote_ota_rollout_bundle.py"),
                    "--parent-bundle",
                    str(self.staging),
                    "--request",
                    str(request_path),
                    "--approval",
                    str(approval_paths[0]),
                    "--approval",
                    str(approval_paths[1]),
                    "--approver-keyring",
                    str(self.keyring_path),
                    "--expected-authority",
                    "updates.example.com",
                    "--output",
                    str(output),
                ],
                [
                    sys.executable,
                    str(TOOLS / "validate_ota_rollout_bundle.py"),
                    "--bundle",
                    str(output),
                    "--parent-bundle",
                    str(self.staging),
                    "--approver-keyring",
                    str(self.keyring_path),
                    "--expected-authority",
                    "updates.example.com",
                ],
            ]
        )
        for command in commands:
            completed = subprocess.run(
                command,
                cwd=PROJECT,
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_go_production_loaders_and_approval_verifier_accept_generation(self):
        go = shutil.which("go")
        if go is None:
            self.skipTest("Go is not available in PATH")
        _, request_data = self._request(
            self.staging, "go-stable-18-g1", "EXPAND", 25
        )
        output = self.temporary / "go-g1.bundle"
        self._promote(self.staging, request_data, output)
        completed = subprocess.run(
            [
                go,
                "run",
                "./cmd/validaterolloutbundle",
                "-bundle",
                str(output),
                "-parent-bundle",
                str(self.staging),
                "-authority",
                "updates.example.com",
                "-approver-keyring",
                str(self.keyring_path),
            ],
            cwd=PROJECT / "gateway",
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("basis_points=25", completed.stdout)


if __name__ == "__main__":
    unittest.main()
