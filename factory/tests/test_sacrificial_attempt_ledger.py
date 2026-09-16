import base64
import copy
import hashlib
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


PROJECT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = PROJECT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import sacrificial_attempt_ledger as LEDGER  # noqa: E402
import sacrificial_trusted_time as TRUSTED_TIME  # noqa: E402
from factory.tests import test_sacrificial_provisioning_plan as M58  # noqa: E402


CONSUMPTION_TIME = "2026-08-10T10:10:00Z"
TIME_PRIVATE = Ed25519PrivateKey.from_private_bytes(
    hashlib.sha256(b"m60-test-only-trusted-time-key").digest()
)
TIME_PUBLIC = TIME_PRIVATE.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)


def signed_policy(root, private, public, **changes):
    info = LEDGER.initialize_root(root)
    values = {
        "policy_id": "sacrificial-ledger-policy-0001",
        "ledger_id": "sacrificial-ledger-0001",
        "station_id": "lab-station-01",
        "fixture_id": "fixture-01",
        "fixture_version": "1.0.0",
        "authorization_key_id": "sacrificial-authority-2026",
        "trusted_time_endpoint": "https://time.example.invalid/v1/factory/trusted-time",
        "trusted_time_authority_key_id": "trusted-time-test-2026",
        "trusted_time_authority_public_key_sha256": TRUSTED_TIME.public_key_sha256(
            TIME_PUBLIC
        ),
        "trusted_time_ca_certificate_sha256": "51" * 32,
        "trusted_time_client_certificate_sha256": "52" * 32,
        "filesystem_device": info.st_dev,
        "directory_inode": info.st_ino,
        "created_at": "2026-08-10T09:00:00Z",
        "expires_at": "2026-08-10T11:00:00Z",
    }
    values.update(changes)
    request = LEDGER.build_policy_request(**values)
    receipt = dict(request)
    receipt["signature_b64url"] = base64.urlsafe_b64encode(
        private.sign(LEDGER.POLICY_SIGNATURE_DOMAIN + LEDGER.canonical_json(request))
    ).rstrip(b"=").decode("ascii")
    data = LEDGER.canonical_json(receipt)
    LEDGER.publish_policy(root, data, public)
    return receipt, data


def setup_ledger(root):
    plan, public, private = M58.signed()
    policy, policy_data = signed_policy(root, private, public)
    signing, artifact = M58.release_files()
    return (
        plan,
        M58.PLAN.canonical_json(plan),
        public,
        private,
        signing,
        artifact,
        policy,
        policy_data,
    )


def trusted_time_receipt(root, plan_data, public, when=CONSUMPTION_TIME):
    policy, policy_data = LEDGER.load_policy(root, public)
    plan = M58.PLAN.parse_canonical(plan_data, signed=True)
    request = TRUSTED_TIME.build_request(
        policy=policy,
        policy_data=policy_data,
        plan=plan,
        plan_data=plan_data,
    )
    observed = datetime.strptime(when, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    receipt = TRUSTED_TIME.build_receipt(
        request=request,
        authority_key_id="trusted-time-test-2026",
        observed_at=when,
        expires_at=(observed + timedelta(seconds=5)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
    )
    receipt["signature_b64url"] = base64.urlsafe_b64encode(
        TIME_PRIVATE.sign(
            TRUSTED_TIME.SIGNATURE_DOMAIN + TRUSTED_TIME.canonical_json(receipt)
        )
    ).rstrip(b"=").decode("ascii")
    return TRUSTED_TIME.canonical_json(receipt)


def consume(root, plan_data, public, signing, artifact, when=CONSUMPTION_TIME):
    return LEDGER._consume_attempt_with_receipt_for_test(
        root=root,
        plan_data=plan_data,
        authorization_public_key=public,
        signing_request_data=signing,
        signed_artifact_data=artifact,
        trusted_time_receipt_data=trusted_time_receipt(
            root, plan_data, public, when
        ),
        trusted_time_public_key=TIME_PUBLIC,
        https_round_trip_ms=1,
    )


def verify(root, plan_data, public, signing, artifact):
    return LEDGER.verify_consumption(
        root=root,
        plan_data=plan_data,
        authorization_public_key=public,
        signing_request_data=signing,
        signed_artifact_data=artifact,
        trusted_time_public_key=TIME_PUBLIC,
    )


class SacrificialAttemptLedgerTests(unittest.TestCase):
    def test_signed_policy_binds_real_directory_identity(self):
        with tempfile.TemporaryDirectory(prefix="xz-m59-policy-") as name:
            parent = pathlib.Path(name)
            root = parent / "ledger"
            plan, plan_data, public, _, signing, artifact, policy, data = setup_ledger(root)
            loaded, loaded_data = LEDGER.load_policy(root, public)
            self.assertEqual(loaded, policy)
            self.assertEqual(loaded_data, data)
            self.assertFalse(loaded["storage"]["multi_station_supported"])
            self.assertFalse(loaded["safety"]["executor_included"])

            copied = parent / "copied-ledger"
            shutil.copytree(root, copied)
            with self.assertRaisesRegex(LEDGER.AttemptLedgerError, "filesystem identity"):
                consume(copied, plan_data, public, signing, artifact)

    def test_consume_verify_and_exact_replay_rejection(self):
        with tempfile.TemporaryDirectory(prefix="xz-m59-consume-") as name:
            root = pathlib.Path(name) / "ledger"
            _, plan_data, public, _, signing, artifact, _, _ = setup_ledger(root)
            record, path = consume(root, plan_data, public, signing, artifact)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
            self.assertFalse(record["safety"]["executor_invoked"])
            self.assertFalse(record["safety"]["hardware_touched"])
            verified, verified_path = verify(root, plan_data, public, signing, artifact)
            self.assertEqual(verified, record)
            self.assertEqual(verified_path, path)
            original = path.read_bytes()
            with self.assertRaisesRegex(LEDGER.AttemptAlreadyConsumed, "already consumed"):
                consume(root, plan_data, public, signing, artifact)
            self.assertEqual(path.read_bytes(), original)

    def test_concurrent_processes_have_exactly_one_winner(self):
        with tempfile.TemporaryDirectory(prefix="xz-m59-race-") as name:
            parent = pathlib.Path(name)
            root = parent / "ledger"
            _, plan_data, public, _, signing, artifact, _, _ = setup_ledger(root)
            files = {
                "plan": plan_data,
                "public": public,
                "signing": signing,
                "artifact": artifact,
                "time-receipt": trusted_time_receipt(root, plan_data, public),
                "time-public": TIME_PUBLIC,
            }
            paths = {}
            for label, payload in files.items():
                path = parent / label
                path.write_bytes(payload)
                paths[label] = path
            command = [
                sys.executable,
                str(TOOLS / "tests" / "consume_sacrificial_attempt_fixture.py"),
                "--root",
                str(root),
                "--plan",
                str(paths["plan"]),
                "--authorization-public-key",
                str(paths["public"]),
                "--signing-request",
                str(paths["signing"]),
                "--signed-artifact-verification",
                str(paths["artifact"]),
                "--trusted-time-receipt",
                str(paths["time-receipt"]),
                "--trusted-time-public-key",
                str(paths["time-public"]),
            ]
            processes = [
                subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                )
                for _ in range(16)
            ]
            results = [process.communicate(timeout=20) for process in processes]
            codes = [process.returncode for process in processes]
            self.assertEqual(codes.count(0), 1, results)
            self.assertEqual(codes.count(1), 15, results)
            for index, (output, _) in enumerate(results):
                if codes[index] == 1:
                    self.assertIn("already consumed", output)
            verify(root, plan_data, public, signing, artifact)

    def test_prelink_and_postlink_crash_shapes_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="xz-m59-crash-") as name:
            root = pathlib.Path(name) / "ledger"
            _, plan_data, public, _, signing, artifact, _, _ = setup_ledger(root)
            claims = root / LEDGER.CLAIMS_DIRECTORY
            orphan = claims / (".claim-" + "0" * 32 + ".tmp")
            orphan.write_bytes(b"incomplete pre-link crash")
            orphan.chmod(0o400)
            _, final_path = consume(root, plan_data, public, signing, artifact)
            postlink = claims / (".claim-" + "1" * 32 + ".tmp")
            os.link(final_path, postlink)
            verify(root, plan_data, public, signing, artifact)
            with self.assertRaises(LEDGER.AttemptAlreadyConsumed):
                consume(root, plan_data, public, signing, artifact)

    def test_same_attempt_with_validly_resigned_subject_cannot_replay(self):
        with tempfile.TemporaryDirectory(prefix="xz-m59-subject-") as name:
            root = pathlib.Path(name) / "ledger"
            plan, plan_data, public, private, signing, artifact, _, _ = setup_ledger(root)
            consume(root, plan_data, public, signing, artifact)
            alternate = copy.deepcopy(plan)
            alternate["plan_id"] = "sacrificial-plan-alternate"
            alternate["transaction"]["base_mac"] = "02:00:00:00:00:02"
            alternate["transaction"]["device_id"] = "xz-020000000002"
            unsigned = dict(alternate)
            unsigned.pop("signature_b64url")
            alternate["signature_b64url"] = base64.urlsafe_b64encode(
                private.sign(M58.PLAN.canonical_json(unsigned))
            ).rstrip(b"=").decode("ascii")
            alternate_data = M58.PLAN.canonical_json(alternate)
            M58.PLAN.verify_receipt(alternate, public)
            with self.assertRaises(LEDGER.AttemptAlreadyConsumed):
                consume(root, alternate_data, public, signing, artifact)

    def test_station_key_and_time_mismatch_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix="xz-m59-binding-") as name:
            parent = pathlib.Path(name)
            root = parent / "ledger"
            plan, plan_data, public, private, signing, artifact, _, _ = setup_ledger(root)
            changed = copy.deepcopy(plan)
            changed["station"]["fixture_version"] = "2.0.0"
            unsigned = dict(changed)
            unsigned.pop("signature_b64url")
            changed["signature_b64url"] = base64.urlsafe_b64encode(
                private.sign(M58.PLAN.canonical_json(unsigned))
            ).rstrip(b"=").decode("ascii")
            with self.assertRaisesRegex(LEDGER.AttemptLedgerError, "plan station"):
                consume(
                    root,
                    M58.PLAN.canonical_json(changed),
                    public,
                    signing,
                    artifact,
                )
            with self.assertRaisesRegex(
                (LEDGER.AttemptLedgerError, TRUSTED_TIME.TrustedTimeError),
                "outside plan window|not active",
            ):
                consume(
                    root,
                    plan_data,
                    public,
                    signing,
                    artifact,
                    when="2026-08-10T12:00:00Z",
                )
            private_pem = private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            with self.assertRaisesRegex(LEDGER.AttemptLedgerError, "public key input"):
                consume(root, plan_data, private_pem, signing, artifact)

    def test_unknown_claim_mode_and_record_tamper_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix="xz-m59-tamper-") as name:
            root = pathlib.Path(name) / "ledger"
            _, plan_data, public, _, signing, artifact, _, _ = setup_ledger(root)
            claims = root / LEDGER.CLAIMS_DIRECTORY
            unknown = claims / "unexpected"
            unknown.write_bytes(b"x")
            unknown.chmod(0o400)
            with self.assertRaisesRegex(LEDGER.AttemptLedgerError, "unknown name"):
                consume(root, plan_data, public, signing, artifact)
            unknown.unlink()
            record, path = consume(root, plan_data, public, signing, artifact)
            path.chmod(0o600)
            with self.assertRaisesRegex(LEDGER.AttemptLedgerError, "mode differs"):
                verify(root, plan_data, public, signing, artifact)
            changed = copy.deepcopy(record)
            changed["safety"]["hardware_touched"] = True
            path.write_bytes(LEDGER.canonical_json(changed))
            path.chmod(0o400)
            with self.assertRaisesRegex(LEDGER.AttemptLedgerError, "safety boundary"):
                verify(root, plan_data, public, signing, artifact)

    def test_initialize_finalize_consume_verify_cli_flow(self):
        with tempfile.TemporaryDirectory(prefix="xz-m59-cli-") as name:
            parent = pathlib.Path(name)
            root = parent / "ledger"
            policy_request = parent / "policy-request.json"
            plan, public, private = M58.signed()
            signing, artifact = M58.release_files()
            plan_path = parent / "plan.json"
            public_path = parent / "public.pem"
            signing_path = parent / "signing.json"
            artifact_path = parent / "artifact.json"
            time_public_path = parent / "time-public.pem"
            time_ca_path = parent / "time-ca.pem"
            time_client_path = parent / "time-client.pem"
            plan_path.write_bytes(M58.PLAN.canonical_json(plan))
            public_path.write_bytes(public)
            signing_path.write_bytes(signing)
            artifact_path.write_bytes(artifact)
            time_public_path.write_bytes(TIME_PUBLIC)
            time_ca_path.write_bytes(b"test-only-ca-certificate")
            time_client_path.write_bytes(b"test-only-client-certificate")
            common_environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}

            initialize = subprocess.run(
                [
                    sys.executable,
                    str(TOOLS / "initialize_sacrificial_attempt_ledger.py"),
                    "--root",
                    str(root),
                    "--policy-id",
                    "sacrificial-ledger-policy-cli",
                    "--ledger-id",
                    "sacrificial-ledger-cli",
                    "--station-id",
                    "lab-station-01",
                    "--fixture-id",
                    "fixture-01",
                    "--fixture-version",
                    "1.0.0",
                    "--authorization-key-id",
                    "sacrificial-authority-2026",
                    "--trusted-time-endpoint",
                    "https://time.example.invalid/v1/factory/trusted-time",
                    "--trusted-time-authority-key-id",
                    "trusted-time-test-2026",
                    "--trusted-time-authority-public-key",
                    str(time_public_path),
                    "--trusted-time-ca-certificate",
                    str(time_ca_path),
                    "--trusted-time-client-certificate",
                    str(time_client_path),
                    "--created-at",
                    "2026-08-10T09:00:00Z",
                    "--expires-at",
                    "2026-08-10T11:00:00Z",
                    "--policy-request-output",
                    str(policy_request),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=common_environment,
            )
            self.assertEqual(initialize.returncode, 0, initialize.stdout)
            request = LEDGER.parse_policy(policy_request.read_bytes(), signed=False)
            signature_path = parent / "signature.bin"
            signature_path.write_bytes(
                private.sign(
                    LEDGER.POLICY_SIGNATURE_DOMAIN + LEDGER.canonical_json(request)
                )
            )
            finalize = subprocess.run(
                [
                    sys.executable,
                    str(TOOLS / "finalize_sacrificial_attempt_ledger.py"),
                    "--root",
                    str(root),
                    "--policy-request",
                    str(policy_request),
                    "--signature",
                    str(signature_path),
                    "--public-key",
                    str(public_path),
                    "--verification-time",
                    CONSUMPTION_TIME,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=common_environment,
            )
            self.assertEqual(finalize.returncode, 0, finalize.stdout)
            time_receipt_path = parent / "time-receipt.json"
            time_receipt_path.write_bytes(
                trusted_time_receipt(root, plan_path.read_bytes(), public)
            )
            base = [
                "--root",
                str(root),
                "--plan",
                str(plan_path),
                "--authorization-public-key",
                str(public_path),
                "--signing-request",
                str(signing_path),
                "--signed-artifact-verification",
                str(artifact_path),
            ]
            consumed = subprocess.run(
                [
                    sys.executable,
                    str(TOOLS / "tests" / "consume_sacrificial_attempt_fixture.py"),
                    *base,
                    "--trusted-time-receipt",
                    str(time_receipt_path),
                    "--trusted-time-public-key",
                    str(time_public_path),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=common_environment,
            )
            self.assertEqual(consumed.returncode, 0, consumed.stdout)
            checked = subprocess.run(
                [
                    sys.executable,
                    str(TOOLS / "verify_sacrificial_attempt_consumption.py"),
                    *base,
                    "--trusted-time-public-key",
                    str(time_public_path),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=common_environment,
            )
            self.assertEqual(checked.returncode, 0, checked.stdout)
            self.assertIn("ONE-TIME LOCAL HANDOFF ONLY", checked.stdout)


if __name__ == "__main__":
    unittest.main()
