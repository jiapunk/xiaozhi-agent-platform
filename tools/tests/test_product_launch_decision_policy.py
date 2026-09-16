from __future__ import annotations

import copy
import json
import os
import pathlib
import sys
import tempfile
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT / "tools"))
import product_launch_decision as LAUNCH


class ProductLaunchDecisionPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.example_path = (
            PROJECT / "release/product-launch-decision.example.json")
        self.proposed = LAUNCH.load(self.example_path)

    def approved(self) -> dict[str, object]:
        value = copy.deepcopy(self.proposed)
        value.update({
            "status": "APPROVED",
            "target_markets": ["TW"],
            "sales_channel": "direct_contract_invoice",
            "ios_distribution": "business_custom",
            "android_distribution": "managed_custom",
            "entitlement_source": "contract_invoice_adapter",
            "billing_provider_id": "contract-invoice-ops-2026",
            "identity_provider_id": "managed-idp-2026",
            "sdk_distribution_id": "private-go-proxy-release-1",
            "legal_review_id": "tw-legal-review-2026-08",
            "decision_owner_id": "product-owner-2026",
            "approved_at_unix": 1786492800,
            "expires_at_unix": 1786492800 + 90 * 24 * 60 * 60,
        })
        return value

    def test_proposed_recommendation_is_valid_but_not_approved(self) -> None:
        self.assertEqual(self.proposed["status"], "PROPOSED")
        self.assertEqual(
            self.proposed["customer_lane"], "developer_system_integrator")
        self.assertEqual(self.proposed["target_markets"], [])
        with self.assertRaisesRegex(
                LAUNCH.LaunchDecisionError, "not APPROVED"):
            LAUNCH.load(self.example_path, require_approved=True)

    def test_approved_developer_kit_lane_is_exact(self) -> None:
        approved = self.approved()
        self.assertEqual(
            LAUNCH.validate(approved, require_approved=True), approved)

    def test_approved_profile_rejects_unresolved_or_inconsistent_choices(self) -> None:
        cases = {
            "no market": lambda value: value.update(target_markets=[]),
            "placeholder provider": lambda value: value.update(
                billing_provider_id="UNSELECTED"),
            "consumer with contract billing": lambda value: value.update(
                customer_lane="consumer_mobile_subscription"),
            "no companion platform": lambda value: value.update(
                ios_distribution="not_offered",
                android_distribution="not_offered"),
            "unsorted markets": lambda value: value.update(
                target_markets=["US", "TW"]),
            "long approval": lambda value: value.update(
                expires_at_unix=value["approved_at_unix"] +
                181 * 24 * 60 * 60),
            "stale policy": lambda value: value.update(
                policy_reviewed_on="2026-01-01"),
            "boolean revision": lambda value: value.update(revision=True),
            "unbounded epoch": lambda value: value.update(
                approved_at_unix=10 ** 30,
                expires_at_unix=10 ** 30 + 1),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                value = self.approved()
                mutate(value)
                with self.assertRaises(LAUNCH.LaunchDecisionError):
                    LAUNCH.validate(value, require_approved=True)

    def test_loader_rejects_noncanonical_duplicate_extra_and_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_text:
            temporary = pathlib.Path(temporary_text)
            pretty = temporary / "pretty.json"
            pretty.write_text(json.dumps(self.proposed, indent=2),
                              encoding="utf-8")
            with self.assertRaisesRegex(
                    LAUNCH.LaunchDecisionError, "not canonical"):
                LAUNCH.load(pretty)
            duplicate = temporary / "duplicate.json"
            duplicate.write_bytes(
                b'{"schema_version":1,"schema_version":1}\n')
            with self.assertRaisesRegex(
                    LAUNCH.LaunchDecisionError, "duplicate"):
                LAUNCH.load(duplicate)
            extra_value = dict(self.proposed)
            extra_value["provider_webhook"] = "forbidden"
            extra = temporary / "extra.json"
            extra.write_bytes(LAUNCH.canonical_json(extra_value))
            with self.assertRaisesRegex(
                    LAUNCH.LaunchDecisionError, "unexpected"):
                LAUNCH.load(extra)
            link = temporary / "link.json"
            os.symlink(self.example_path, link)
            with self.assertRaisesRegex(
                    LAUNCH.LaunchDecisionError, "non-symlink"):
                LAUNCH.load(link)

    def test_schema_and_example_are_strict_and_content_minimized(self) -> None:
        schema_raw = (
            PROJECT / "release/product-launch-decision.schema.json").read_bytes()
        schema = json.loads(schema_raw)
        self.assertEqual(schema["additionalProperties"], False)
        self.assertEqual(schema["properties"]["schema_version"]["const"], 1)
        self.assertEqual(set(schema["required"]), LAUNCH.FIELDS)
        self.assertEqual(
            self.example_path.read_bytes(), LAUNCH.canonical_json(self.proposed))
        serialized = json.dumps(self.proposed).lower()
        for forbidden in (
            "payment_method", "card_number", "receipt", "webhook_payload",
            "provider_customer",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_launch_lanes_and_market_gate_keep_external_decision_open(self) -> None:
        docs = (
            PROJECT / "PRODUCT_LAUNCH_LANES.md").read_text(encoding="utf-8")
        release = (
            PROJECT / "PRODUCT_MARKET_RELEASE_RUNBOOK.md").read_text(
                encoding="utf-8")
        for required in (
            "Lane A", "Lane B", "Lane C", "開發者／系統整合商",
            "Apple App Review Guidelines", "Google Play Payments policy",
            "FCC Equipment Authorization", "EU Radio Equipment Directive",
            "台灣 NCC", "--require-approved", "legal_market", "WORM",
            "NO-GO", "MARKET_RELEASE_PASS",
        ):
            self.assertIn(required, docs + release)


if __name__ == "__main__":
    unittest.main()
