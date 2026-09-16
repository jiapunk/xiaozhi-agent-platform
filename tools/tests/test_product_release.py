from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


PROJECT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = PROJECT / "tools"
sys.path.insert(0, str(TOOLS))
import product_release as RELEASE
import validate_backend_slo_observation as SLO


def unlock_tree(root: pathlib.Path) -> None:
    if not root.exists() or root.is_symlink():
        return
    os.chmod(root, 0o700)
    for path in root.rglob("*"):
        if not path.is_symlink():
            os.chmod(path, 0o700 if path.is_dir() else 0o600)


class ProductReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = pathlib.Path(tempfile.mkdtemp())
        self.release_key = Ed25519PrivateKey.generate()
        self.slo_key = Ed25519PrivateKey.generate()
        self.evidence_keys = {
            kind: Ed25519PrivateKey.generate() for kind in RELEASE.EVIDENCE_TYPES
        }
        self.release_private, self.release_public = self.write_keypair(
            "market-release", self.release_key
        )
        self.slo_private, self.slo_public = self.write_keypair(
            "backend-slo", self.slo_key
        )
        self.evidence_key_paths = {
            kind: self.write_keypair(kind, key) for kind, key in self.evidence_keys.items()
        }
        self.subject = {
            "product_release_id": "voice-agent-kit-0001",
            "sku": "VOICE_AGENT_KIT_BOX3",
            "product_version": "1.0.0",
            "firmware_sha256": hashlib.sha256(b"signed-firmware").hexdigest(),
            "firmware_security_version": 1,
            "ota_release_id": "firmware-release-0001",
            "oci_release_id": "backend-release-0001",
            "deployment_id": "backend-deployment-0001",
            "qualification_id": "cluster-qualification-0001",
        }
        self.slo_policy_path = PROJECT / "deployment/backend-slo-policy.json"
        self.slo_observation_path = self.temporary / "backend-slo-observation.json"
        self.make_slo_observation(self.slo_observation_path)
        self.policy = self.make_policy()
        self.policy_path = self.temporary / "policy.json"
        self.write_json(self.policy_path, self.policy)
        self.attestations, self.evidence_objects = self.make_attestations(
            self.policy, self.temporary / "attestations"
        )
        self.bundle = self.temporary / "release-bundle"

    def tearDown(self) -> None:
        unlock_tree(self.temporary)
        shutil.rmtree(self.temporary, ignore_errors=True)

    def write_keypair(
        self, name: str, key: Ed25519PrivateKey
    ) -> tuple[pathlib.Path, pathlib.Path]:
        private = self.temporary / f"{name}.private.pem"
        public = self.temporary / f"{name}.public.pem"
        private.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        public.write_bytes(
            key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        return private, public

    @staticmethod
    def fingerprint(key: Ed25519PrivateKey) -> str:
        raw = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def write_json(path: pathlib.Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(RELEASE._canonical(value))

    def make_policy(
        self,
        *,
        sequence: int = 1,
        previous: str = RELEASE.ZERO_SHA256,
        subject: dict[str, object] | None = None,
    ) -> dict[str, object]:
        return {
            "schema_version": 2,
            "policy_id": f"market-policy-{sequence:06d}",
            "record_id": f"market-record-{sequence:06d}",
            "release_sequence": sequence,
            "previous_record_sha256": previous,
            "subject": copy.deepcopy(subject or self.subject),
            "valid_from": "2026-08-10T12:00:00Z",
            "valid_until": "2026-09-09T12:00:00Z",
            "tool_sha256": hashlib.sha256(
                (TOOLS / "product_release.py").read_bytes()
            ).hexdigest(),
            "required_evidence": [
                {
                    "evidence_type": kind,
                    "signing_key_id": f"{kind.replace('_', '-')}-authority-2026",
                    "public_key_sha256": self.fingerprint(self.evidence_keys[kind]),
                    "max_age_seconds": 30 * 86400,
                }
                for kind in RELEASE.EVIDENCE_TYPES
            ],
            "backend_slo": {
                "collector_id": "otel-prod-01",
                "signing_key_id": "backend-slo-authority-2026",
                "public_key_sha256": self.fingerprint(self.slo_key),
                "policy_sha256": hashlib.sha256(
                    self.slo_policy_path.read_bytes()
                ).hexdigest(),
            },
            "release_signing_key_id": "market-release-authority-2026",
            "release_public_key_sha256": self.fingerprint(self.release_key),
        }

    def make_slo_observation(self, path: pathlib.Path) -> None:
        policy, policy_data = SLO.load_policy(self.slo_policy_path)
        services = []
        for target in policy["services"]:
            eligible = target["minimum_eligible_requests"]
            services.append({
                "attribute_violations": 0,
                "availability_ppm": 1_000_000,
                "eligible_requests": eligible,
                "latency_p99_ms": target["latency_p99_ms"],
                "name": target["name"],
                "result": "PASS",
                "server_errors": 0,
                "successes": eligible,
                "telemetry_export_failures": 0,
                "unknown_operations": 0,
            })
        value = {
            "collector_id": "otel-prod-01",
            "deployment_id": self.subject["deployment_id"],
            "generated_at": "2026-08-10T00:30:00Z",
            "observation_id": "backend-slo-2026-08-10",
            "policy_sha256": hashlib.sha256(policy_data).hexdigest(),
            "result": "PASS",
            "schema": 1,
            "services": services,
            "signature_algorithm": "Ed25519",
            "signing_key_id": "backend-slo-authority-2026",
            "window_end": "2026-08-10T00:00:00Z",
            "window_start": "2026-07-13T00:00:00Z",
        }
        value["signature_b64url"] = RELEASE._b64url(
            self.slo_key.sign(SLO.signature_payload(value))
        )
        path.write_bytes(SLO.oci._json_bytes(value))

    def make_attestations(
        self, policy: dict[str, object], directory: pathlib.Path
    ) -> tuple[list[pathlib.Path], dict[str, pathlib.Path]]:
        directory.mkdir(parents=True, exist_ok=True)
        object_directory = directory / "objects"
        object_directory.mkdir()
        trust = {entry["evidence_type"]: entry for entry in policy["required_evidence"]}
        paths: list[pathlib.Path] = []
        objects: dict[str, pathlib.Path] = {}
        for index, kind in enumerate(RELEASE.EVIDENCE_TYPES):
            evidence_object = object_directory / f"{kind}.evidence"
            evidence_object.write_bytes(f"reviewed detailed evidence {index}\n".encode())
            objects[kind] = evidence_object
            unsigned = {
                "schema_version": 2,
                "evidence_id": f"{kind.replace('_', '-')}-0001",
                "evidence_type": kind,
                "subject": copy.deepcopy(policy["subject"]),
                "environment": "PRODUCTION",
                "region": "us-west-2",
                "observed_at": "2026-08-09T12:00:00Z",
                "valid_until": "2026-09-30T12:00:00Z",
                "evidence_uri": f"https://worm.vendor.com/releases/0001/{kind}.json",
                "evidence_sha256": hashlib.sha256(evidence_object.read_bytes()).hexdigest(),
                "result": "PASS",
                "signing_key_id": trust[kind]["signing_key_id"],
                "signature_algorithm": "Ed25519",
            }
            value = RELEASE.sign_attestation(
                unsigned,
                private_key_path=self.evidence_key_paths[kind][0],
                expected_key_id=trust[kind]["signing_key_id"],
            )
            path = directory / f"{kind}.json"
            self.write_json(path, value)
            paths.append(path)
        return paths, objects

    @property
    def public_keys(self) -> dict[str, pathlib.Path]:
        return {kind: paths[1] for kind, paths in self.evidence_key_paths.items()}

    def build(
        self,
        *,
        policy_path: pathlib.Path | None = None,
        attestations: list[pathlib.Path] | None = None,
        output: pathlib.Path | None = None,
        previous_record: pathlib.Path | None = None,
        evidence_objects: dict[str, pathlib.Path] | None = None,
        slo_observation: pathlib.Path | None = None,
        slo_policy: pathlib.Path | None = None,
        slo_public_key: pathlib.Path | None = None,
    ) -> dict[str, object]:
        return RELEASE.build_bundle(
            policy_path=policy_path or self.policy_path,
            attestation_paths=attestations if attestations is not None else self.attestations,
            evidence_public_keys=self.public_keys,
            evidence_objects=evidence_objects or self.evidence_objects,
            backend_slo_observation_path=slo_observation or self.slo_observation_path,
            backend_slo_policy_path=slo_policy or self.slo_policy_path,
            backend_slo_public_key_path=slo_public_key or self.slo_public,
            release_private_key_path=self.release_private,
            output_path=output or self.bundle,
            previous_record_path=previous_record,
        )

    def validate(
        self,
        *,
        bundle: pathlib.Path | None = None,
        policy_path: pathlib.Path | None = None,
        previous_record: pathlib.Path | None = None,
        evaluation_time: str = "2026-08-20T12:00:00Z",
        public_keys: dict[str, pathlib.Path] | None = None,
        evidence_objects: dict[str, pathlib.Path] | None = None,
        slo_observation: pathlib.Path | None = None,
        slo_policy: pathlib.Path | None = None,
        slo_public_key: pathlib.Path | None = None,
    ) -> dict[str, object]:
        return RELEASE.validate_bundle(
            bundle or self.bundle,
            trusted_policy_path=policy_path or self.policy_path,
            evidence_public_keys=public_keys or self.public_keys,
            evidence_objects=evidence_objects or self.evidence_objects,
            backend_slo_observation_path=slo_observation or self.slo_observation_path,
            backend_slo_policy_path=slo_policy or self.slo_policy_path,
            backend_slo_public_key_path=slo_public_key or self.slo_public,
            release_public_key_path=self.release_public,
            evaluation_time=evaluation_time,
            previous_record_path=previous_record,
        )

    def resign_attestation(
        self, path: pathlib.Path, mutation: callable
    ) -> None:
        value = json.loads(path.read_text())
        mutation(value)
        value.pop("signature_b64url")
        kind = value["evidence_type"]
        value = RELEASE.sign_attestation(
            value,
            private_key_path=self.evidence_key_paths[kind][0],
            expected_key_id=value["signing_key_id"],
        )
        self.write_json(path, value)

    def resign_slo(self, mutation: callable) -> None:
        value = SLO.oci._strict_json(
            self.slo_observation_path.read_bytes(), "backend SLO observation"
        )
        mutation(value)
        value.pop("signature_b64url", None)
        value["signature_b64url"] = RELEASE._b64url(
            self.slo_key.sign(SLO.signature_payload(value))
        )
        self.slo_observation_path.write_bytes(SLO.oci._json_bytes(value))

    def test_complete_signed_market_release_round_trip(self) -> None:
        record = self.build()
        validated = self.validate()
        self.assertEqual(validated, record)
        self.assertEqual(validated["result"], "MARKET_RELEASE_PASS")
        self.assertEqual(
            [item["evidence_type"] for item in validated["evidence"]],
            list(RELEASE.EVIDENCE_TYPES),
        )
        self.assertEqual(len(validated["evidence"]), 15)
        self.assertEqual(validated["schema_version"], 2)
        self.assertEqual(
            validated["backend_slo"]["observation_id"],
            "backend-slo-2026-08-10",
        )
        self.assertTrue((self.bundle / "backend-slo-observation.json").is_file())
        self.assertTrue((self.bundle / "backend-slo-policy.json").is_file())
        self.assertFalse(any("private" in path.name for path in self.bundle.rglob("*")))

    def test_market_release_requires_exact_independent_backend_slo_proof(self) -> None:
        self.resign_slo(
            lambda value: value["services"][0].__setitem__(
                "telemetry_export_failures", 1
            )
        )
        with self.assertRaisesRegex(RELEASE.ProductReleaseError, "completeness"):
            self.build(output=self.temporary / "slo-export-loss")

        self.make_slo_observation(self.slo_observation_path)
        self.resign_slo(
            lambda value: value.__setitem__("deployment_id", "other-deployment")
        )
        with self.assertRaisesRegex(RELEASE.ProductReleaseError, "identity"):
            self.build(output=self.temporary / "slo-wrong-deployment")

        self.make_slo_observation(self.slo_observation_path)
        other_key = Ed25519PrivateKey.generate()
        _, other_public = self.write_keypair("other-slo", other_key)
        with self.assertRaisesRegex(RELEASE.ProductReleaseError, "fingerprint"):
            self.build(
                output=self.temporary / "slo-wrong-key",
                slo_public_key=other_public,
            )

    def test_bundle_slo_copy_must_match_independent_worm_input(self) -> None:
        self.build()
        unlock_tree(self.bundle)
        bundled = self.bundle / "backend-slo-observation.json"
        value = SLO.oci._strict_json(bundled.read_bytes(), "bundled SLO")
        value["observation_id"] = "backend-slo-replaced"
        value.pop("signature_b64url")
        value["signature_b64url"] = RELEASE._b64url(
            self.slo_key.sign(SLO.signature_payload(value))
        )
        bundled.write_bytes(SLO.oci._json_bytes(value))
        with self.assertRaisesRegex(RELEASE.ProductReleaseError, "independent inputs"):
            self.validate()

    def test_slo_input_replacement_cannot_change_validated_bundle_bytes(self) -> None:
        original_raw = self.slo_observation_path.read_bytes()
        replacement = SLO.oci._strict_json(original_raw, "replacement SLO")
        replacement["observation_id"] = "backend-slo-replaced-after-read"
        replacement.pop("signature_b64url")
        replacement["signature_b64url"] = RELEASE._b64url(
            self.slo_key.sign(SLO.signature_payload(replacement))
        )
        replacement_raw = SLO.oci._json_bytes(replacement)
        original_validator = SLO.validate_observation

        def replace_external_after_validation(*args: object, **kwargs: object) -> object:
            result = original_validator(*args, **kwargs)
            self.slo_observation_path.write_bytes(replacement_raw)
            return result

        with mock.patch.object(
            RELEASE.backend_slo,
            "validate_observation",
            side_effect=replace_external_after_validation,
        ):
            record = self.build(output=self.temporary / "snapshot-race")

        bundled = self.temporary / "snapshot-race/backend-slo-observation.json"
        self.assertEqual(bundled.read_bytes(), original_raw)
        self.assertEqual(
            record["backend_slo"]["observation_sha256"],
            hashlib.sha256(original_raw).hexdigest(),
        )

    def test_missing_duplicate_or_extra_evidence_is_rejected(self) -> None:
        with self.assertRaisesRegex(RELEASE.ProductReleaseError, "exactly one"):
            self.build(attestations=self.attestations[:-1])
        with self.assertRaisesRegex(RELEASE.ProductReleaseError, "duplicate"):
            self.build(
                attestations=self.attestations[:-1] + [self.attestations[0]],
                output=self.temporary / "duplicate",
            )
        extra_keys = dict(self.public_keys)
        extra_keys["unexpected"] = self.release_public
        with self.assertRaisesRegex(RELEASE.ProductReleaseError, "incomplete or has extra"):
            RELEASE.build_bundle(
                policy_path=self.policy_path,
                attestation_paths=self.attestations,
                evidence_public_keys=extra_keys,
                evidence_objects=self.evidence_objects,
                backend_slo_observation_path=self.slo_observation_path,
                backend_slo_policy_path=self.slo_policy_path,
                backend_slo_public_key_path=self.slo_public,
                release_private_key_path=self.release_private,
                output_path=self.temporary / "extra-key",
            )

    def test_cross_release_mix_is_rejected_even_when_resigned(self) -> None:
        target = self.attestations[0]
        self.resign_attestation(
            target,
            lambda value: value["subject"].update({"product_version": "1.0.1"}),
        )
        with self.assertRaisesRegex(RELEASE.ProductReleaseError, "subject does not match"):
            self.build()

    def test_tamper_and_wrong_authority_are_rejected(self) -> None:
        self.build()
        unlock_tree(self.bundle)
        target = self.bundle / "evidence" / f"{RELEASE.EVIDENCE_TYPES[0]}.json"
        value = json.loads(target.read_text())
        value["evidence_sha256"] = hashlib.sha256(b"tampered").hexdigest()
        self.write_json(target, value)
        with self.assertRaisesRegex(RELEASE.ProductReleaseError, "signature is invalid"):
            self.validate()

        other_key = Ed25519PrivateKey.generate()
        _, other_public = self.write_keypair("wrong-authority", other_key)
        wrong = dict(self.public_keys)
        wrong[RELEASE.EVIDENCE_TYPES[1]] = other_public
        with self.assertRaisesRegex(RELEASE.ProductReleaseError, "fingerprint"):
            RELEASE._collect_attestations(
                policy=self.policy,
                attestation_paths=self.attestations,
                evidence_public_keys=wrong,
                evidence_objects=self.evidence_objects,
            )
        tampered_object = self.evidence_objects[RELEASE.EVIDENCE_TYPES[2]]
        tampered_object.write_bytes(b"replaced detailed evidence\n")
        with self.assertRaisesRegex(RELEASE.ProductReleaseError, "object SHA-256 mismatch"):
            RELEASE._collect_attestations(
                policy=self.policy,
                attestation_paths=self.attestations,
                evidence_public_keys=self.public_keys,
                evidence_objects=self.evidence_objects,
            )

    def test_stale_expiring_and_out_of_window_evidence_is_rejected(self) -> None:
        stale = self.attestations[0]
        self.resign_attestation(
            stale, lambda value: value.update({"observed_at": "2026-01-01T00:00:00Z"})
        )
        with self.assertRaisesRegex(RELEASE.ProductReleaseError, "older"):
            self.build()

        self.setUp_fresh_attestations()
        expiring = self.attestations[0]
        self.resign_attestation(
            expiring, lambda value: value.update({"valid_until": "2026-08-30T00:00:00Z"})
        )
        with self.assertRaisesRegex(RELEASE.ProductReleaseError, "expires before"):
            self.build(output=self.temporary / "expiring")

        self.setUp_fresh_attestations()
        self.build(output=self.bundle)
        with self.assertRaisesRegex(RELEASE.ProductReleaseError, "not valid at evaluation"):
            self.validate(evaluation_time="2026-10-01T00:00:00Z")

    def setUp_fresh_attestations(self) -> None:
        directory = self.temporary / f"attestations-{len(list(self.temporary.glob('attestations-*')))}"
        self.attestations, self.evidence_objects = self.make_attestations(self.policy, directory)

    def test_policy_cannot_omit_gate_or_use_nonproduction_markers(self) -> None:
        incomplete = copy.deepcopy(self.policy)
        incomplete["required_evidence"] = incomplete["required_evidence"][:-1]
        with self.assertRaisesRegex(RELEASE.ProductReleaseError, "complete evidence"):
            RELEASE.validate_policy(incomplete)
        missing_slo = copy.deepcopy(self.policy)
        missing_slo.pop("backend_slo")
        with self.assertRaisesRegex(RELEASE.ProductReleaseError, "fields mismatch"):
            RELEASE.validate_policy(missing_slo)
        downgraded = copy.deepcopy(self.policy)
        downgraded["schema_version"] = 1
        with self.assertRaisesRegex(RELEASE.ProductReleaseError, "unsupported"):
            RELEASE.validate_policy(downgraded)
        marked = copy.deepcopy(self.policy)
        marked["record_id"] = "market-fixture-0001"
        with self.assertRaisesRegex(RELEASE.ProductReleaseError, "non-production"):
            RELEASE.validate_policy(marked)
        marked_sku = copy.deepcopy(self.policy)
        marked_sku["subject"]["sku"] = "VOICE_AGENT_TEST"
        with self.assertRaisesRegex(RELEASE.ProductReleaseError, "non-production"):
            RELEASE.validate_policy(marked_sku)
        wrong_tool = copy.deepcopy(self.policy)
        wrong_tool["tool_sha256"] = "a" * 64
        wrong_tool_path = self.temporary / "wrong-tool-policy.json"
        self.write_json(wrong_tool_path, wrong_tool)
        with self.assertRaisesRegex(RELEASE.ProductReleaseError, "core hash"):
            self.build(policy_path=wrong_tool_path, output=self.temporary / "wrong-tool")
        value = json.loads(self.attestations[0].read_text())
        value["evidence_uri"] = "https://evidence.example.invalid/report.json"
        value.pop("signature_b64url")
        value = RELEASE.sign_attestation(
            value,
            private_key_path=self.evidence_key_paths[value["evidence_type"]][0],
            expected_key_id=value["signing_key_id"],
        )
        self.write_json(self.attestations[0], value)
        with self.assertRaisesRegex(RELEASE.ProductReleaseError, "production HTTPS"):
            self.build()

    def test_private_or_ephemeral_evidence_uri_is_rejected(self) -> None:
        for index, uri in enumerate(
            (
                "https://127.0.0.1/releases/report.json",
                "https://10.0.0.8/releases/report.json",
                "https://worm.vendor.com/releases/report.json?token=short-lived",
            )
        ):
            self.setUp_fresh_attestations()
            target = self.attestations[0]
            self.resign_attestation(
                target, lambda value, uri=uri: value.update({"evidence_uri": uri})
            )
            with self.assertRaisesRegex(RELEASE.ProductReleaseError, "production HTTPS"):
                self.build(output=self.temporary / f"bad-uri-{index}")

    def test_validly_resigned_record_cannot_hide_an_evidence_slot(self) -> None:
        self.build()
        unlock_tree(self.bundle)
        record_path = self.bundle / "product-release-record.json"
        record = json.loads(record_path.read_text())
        record["evidence"] = record["evidence"][:-1]
        record["signature_b64url"] = RELEASE._b64url(
            self.release_key.sign(RELEASE._unsigned_record(record))
        )
        raw = RELEASE._canonical(record)
        record_path.write_bytes(raw)
        (self.bundle / "READY").write_text(f"sha256:{hashlib.sha256(raw).hexdigest()}\n")
        with self.assertRaisesRegex(RELEASE.ProductReleaseError, "does not match evidence"):
            self.validate()

    def test_ready_exact_file_set_symlink_and_no_overwrite(self) -> None:
        self.build()
        with self.assertRaisesRegex(RELEASE.ProductReleaseError, "already exists"):
            self.build()
        unlock_tree(self.bundle)
        (self.bundle / "unexpected").write_text("no\n")
        with self.assertRaisesRegex(RELEASE.ProductReleaseError, "file set mismatch"):
            self.validate()
        (self.bundle / "unexpected").unlink()
        (self.bundle / "READY").write_text("sha256:" + "a" * 64 + "\n")
        with self.assertRaisesRegex(RELEASE.ProductReleaseError, "READY"):
            self.validate()
        (self.bundle / "READY").unlink()
        (self.bundle / "READY").symlink_to("product-release-record.json")
        with self.assertRaisesRegex(RELEASE.ProductReleaseError, "open.*READY"):
            self.validate()

    def test_concurrent_output_claim_is_not_overwritten_or_deleted(self) -> None:
        output = self.temporary / "concurrent-owner"
        original_mkdir = pathlib.Path.mkdir

        def racing_mkdir(path: pathlib.Path, *args: object, **kwargs: object) -> None:
            if path == output and not path.exists():
                original_mkdir(path)
            original_mkdir(path, *args, **kwargs)

        with mock.patch.object(pathlib.Path, "mkdir", racing_mkdir):
            with self.assertRaisesRegex(RELEASE.ProductReleaseError, "claimed concurrently"):
                self.build(output=output)
        self.assertTrue(output.is_dir())
        self.assertEqual(list(output.iterdir()), [])

    def test_non_genesis_requires_exact_contiguous_previous_record(self) -> None:
        self.build()
        previous_record = self.bundle / "product-release-record.json"
        previous_sha = hashlib.sha256(previous_record.read_bytes()).hexdigest()
        policy2 = self.make_policy(sequence=2, previous=previous_sha)
        policy2_path = self.temporary / "policy2.json"
        self.write_json(policy2_path, policy2)
        attestations2, objects2 = self.make_attestations(
            policy2, self.temporary / "attestations2"
        )
        bundle2 = self.temporary / "release-bundle2"
        record2 = self.build(
            policy_path=policy2_path,
            attestations=attestations2,
            output=bundle2,
            previous_record=previous_record,
            evidence_objects=objects2,
        )
        self.assertEqual(record2["release_sequence"], 2)
        self.validate(
            bundle=bundle2,
            policy_path=policy2_path,
            previous_record=previous_record,
            evidence_objects=objects2,
        )
        with self.assertRaisesRegex(RELEASE.ProductReleaseError, "exact previous"):
            self.build(
                policy_path=policy2_path,
                attestations=attestations2,
                output=self.temporary / "missing-parent",
                evidence_objects=objects2,
            )

    def test_cli_requires_explicit_production_authorization(self) -> None:
        build = subprocess.run(
            [
                sys.executable,
                str(TOOLS / "build_product_release_bundle.py"),
                "--policy",
                str(self.policy_path),
                "--attestation",
                str(self.attestations[0]),
                "--evidence-key",
                f"{RELEASE.EVIDENCE_TYPES[0]}={self.public_keys[RELEASE.EVIDENCE_TYPES[0]]}",
                "--evidence-object",
                f"{RELEASE.EVIDENCE_TYPES[0]}={self.evidence_objects[RELEASE.EVIDENCE_TYPES[0]]}",
                "--release-signing-private-key",
                str(self.release_private),
                "--backend-slo-observation",
                str(self.slo_observation_path),
                "--backend-slo-policy",
                str(self.slo_policy_path),
                "--backend-slo-trusted-public-key",
                str(self.slo_public),
                "--output",
                str(self.bundle),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertNotEqual(build.returncode, 0)
        self.assertIn("--authorize-market-release is required", build.stderr)
        sign = subprocess.run(
            [
                sys.executable,
                str(TOOLS / "sign_product_release_evidence.py"),
                "--unsigned-attestation",
                str(self.attestations[0]),
                "--signing-private-key",
                str(self.evidence_key_paths[RELEASE.EVIDENCE_TYPES[0]][0]),
                "--signing-key-id",
                self.policy["required_evidence"][0]["signing_key_id"],
                "--output",
                str(self.temporary / "signed.json"),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertNotEqual(sign.returncode, 0)
        self.assertIn("--attest-production-evidence is required", sign.stderr)

    def test_schemas_example_and_contract_are_fixed(self) -> None:
        for path in (
            PROJECT / "release/product-release-policy.schema.json",
            PROJECT / "release/product-release-evidence.schema.json",
            PROJECT / "release/product-release-record.schema.json",
        ):
            json.loads(path.read_text())
        example_path = PROJECT / "release/product-release-policy.example.json"
        example, raw = RELEASE.load_policy(example_path)
        self.assertEqual(raw, RELEASE._canonical(example))
        self.assertEqual(
            tuple(entry["evidence_type"] for entry in example["required_evidence"]),
            RELEASE.EVIDENCE_TYPES,
        )
        self.assertEqual(example["release_sequence"], 1)
        self.assertEqual(example["schema_version"], 2)
        self.assertEqual(
            example["backend_slo"]["policy_sha256"],
            hashlib.sha256(self.slo_policy_path.read_bytes()).hexdigest(),
        )
        self.assertEqual(
            example["tool_sha256"],
            hashlib.sha256((TOOLS / "product_release.py").read_bytes()).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
