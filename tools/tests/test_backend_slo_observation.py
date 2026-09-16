from __future__ import annotations

import datetime as dt
import hashlib
import pathlib
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


PROJECT = pathlib.Path(__file__).resolve().parents[2]
TOOLS = PROJECT / "tools"
sys.path.insert(0, str(TOOLS))
import oci_release as OCI
import validate_backend_slo_observation as SLO


class BackendSLOObservationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = pathlib.Path(tempfile.mkdtemp())
        self.policy = PROJECT / "deployment/backend-slo-policy.json"
        self.private = Ed25519PrivateKey.generate()
        self.public_path = self.temporary / "slo-public.pem"
        self.public_path.write_bytes(self.private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        policy, policy_data = SLO.load_policy(self.policy)
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
        self.observation = {
            "collector_id": "otel-prod-01",
            "deployment_id": "m49-pilot",
            "generated_at": "2026-08-10T00:30:00Z",
            "observation_id": "slo-2026-08-10",
            "policy_sha256": hashlib.sha256(policy_data).hexdigest(),
            "result": "PASS",
            "schema": 1,
            "services": services,
            "signature_algorithm": "Ed25519",
            "signing_key_id": "slo-key-01",
            "window_end": "2026-08-10T00:00:00Z",
            "window_start": "2026-07-13T00:00:00Z",
        }
        self.observation_path = self.temporary / "observation.json"
        self.publish(self.observation)
        self.now = dt.datetime(2026, 8, 11, tzinfo=dt.timezone.utc)

    def publish(self, value: dict[str, object]) -> None:
        unsigned = dict(value)
        unsigned.pop("signature_b64url", None)
        value["signature_b64url"] = OCI._b64url(
            self.private.sign(SLO.signature_payload(unsigned))
        )
        self.observation_path.write_bytes(OCI._json_bytes(value))

    def validate(self, now: dt.datetime | None = None) -> dict[str, object]:
        return SLO.validate_observation(
            self.observation_path,
            self.policy,
            self.public_path,
            expected_signing_key_id="slo-key-01",
            expected_deployment_id="m49-pilot",
            expected_collector_id="otel-prod-01",
            now=now or self.now,
        )

    def test_accepts_exact_signed_twenty_eight_day_content_free_pass(self) -> None:
        self.assertEqual(self.validate()["result"], "PASS")

    def test_resigned_slo_and_completeness_failures_are_rejected(self) -> None:
        mutations = (
            ("attribute violation", lambda value: value["services"][0].__setitem__(
                "attribute_violations", 1), "completeness"),
            ("unknown operation", lambda value: value["services"][1].__setitem__(
                "unknown_operations", 1), "completeness"),
            ("export loss", lambda value: value["services"][2].__setitem__(
                "telemetry_export_failures", 1), "completeness"),
            ("latency", lambda value: value["services"][3].__setitem__(
                "latency_p99_ms", 60001), "production SLO"),
        )
        for name, mutate, message in mutations:
            with self.subTest(name=name):
                value = OCI._strict_json(
                    OCI._json_bytes(self.observation), "observation copy"
                )
                mutate(value)
                self.publish(value)
                with self.assertRaisesRegex(SLO.SLOError, message):
                    self.validate()

    def test_signature_policy_window_identity_and_age_fail_closed(self) -> None:
        value = OCI._strict_json(
            OCI._json_bytes(self.observation), "observation copy"
        )
        self.publish(value)
        payload = bytearray(self.observation_path.read_bytes())
        payload[payload.index(b"m49-pilot")] = ord("n")
        self.observation_path.write_bytes(bytes(payload))
        with self.assertRaises(SLO.SLOError):
            self.validate()

        self.publish(value)
        with self.assertRaisesRegex(SLO.SLOError, "stale"):
            self.validate(dt.datetime(2026, 8, 20, tzinfo=dt.timezone.utc))
        with self.assertRaisesRegex(SLO.SLOError, "identity"):
            SLO.validate_observation(
                self.observation_path, self.policy, self.public_path,
                expected_signing_key_id="wrong-key",
                expected_deployment_id="m49-pilot",
                expected_collector_id="otel-prod-01",
                now=self.now,
            )

    def test_schema_and_policy_fix_exact_seven_service_contract(self) -> None:
        schema = OCI._strict_json(
            (PROJECT / "deployment/backend-slo-observation.schema.json").read_bytes(),
            "SLO schema",
        )
        self.assertEqual(schema["properties"]["services"]["minItems"], 7)
        self.assertEqual(schema["properties"]["services"]["maxItems"], 7)
        self.assertEqual(
            tuple(schema["$defs"]["service"]["properties"]["name"]["enum"]),
            SLO.SERVICES,
        )


if __name__ == "__main__":
    unittest.main()
