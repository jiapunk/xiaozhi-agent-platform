from __future__ import annotations

import copy
import pathlib
import sys
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT / "tools"))
import product_launch_decision as LAUNCH
import product_release as RELEASE


class InternationalDeveloperLaunchPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile_path = (
            PROJECT /
            "release/product-launch-decision.international-developer-proposed.json")
        self.profile = LAUNCH.load(self.profile_path)

    def test_lane_b_profile_is_exact_but_not_approved(self) -> None:
        self.assertEqual(self.profile["status"], "PROPOSED")
        self.assertEqual(self.profile["revision"], 2)
        self.assertEqual(
            self.profile["customer_lane"], "direct_consumer_hardware_cloud")
        self.assertEqual(
            self.profile["target_markets"],
            ["AU", "CA", "GB", "SG", "TW", "US"])
        self.assertEqual(self.profile["sales_channel"], "direct_web_checkout")
        self.assertEqual(
            self.profile["ios_distribution"], "public_free_companion")
        self.assertEqual(
            self.profile["android_distribution"],
            "public_consumption_only")
        self.assertEqual(
            self.profile["entitlement_source"], "web_billing_adapter")
        with self.assertRaisesRegex(
                LAUNCH.LaunchDecisionError, "not APPROVED"):
            LAUNCH.load(self.profile_path, require_approved=True)

    def test_proposed_lane_b_rejects_contradictory_selected_paths(self) -> None:
        cases = {
            "organization invoice": ("sales_channel", "direct_contract_invoice"),
            "contract entitlement": (
                "entitlement_source", "contract_invoice_adapter"),
            "business custom iOS": ("ios_distribution", "business_custom"),
            "managed Android": ("android_distribution", "managed_custom"),
            "iOS IAP with web checkout": ("ios_distribution", "public_iap"),
            "Play billing with web checkout": (
                "android_distribution", "public_play_billing"),
        }
        for name, (field, selected) in cases.items():
            with self.subTest(name=name):
                value = copy.deepcopy(self.profile)
                value[field] = selected
                with self.assertRaises(LAUNCH.LaunchDecisionError):
                    LAUNCH.validate(value)

    def test_exact_approved_lane_b_shape_is_supported(self) -> None:
        value = copy.deepcopy(self.profile)
        value.update({
            "status": "APPROVED",
            "billing_provider_id": "wave1-commerce-provider-2026",
            "identity_provider_id": "wave1-customer-idp-2026",
            "sdk_distribution_id": "signed-go-sdk-release-2",
            "legal_review_id": "wave1-legal-review-2026-08",
            "decision_owner_id": "international-kit-owner-2026",
            "approved_at_unix": 1786492800,
            "expires_at_unix": 1786492800 + 90 * 24 * 60 * 60,
        })
        self.assertEqual(
            LAUNCH.validate(value, require_approved=True), value)

    def test_profile_is_canonical_and_contains_no_commerce_secrets(self) -> None:
        self.assertEqual(
            self.profile_path.read_bytes(), LAUNCH.canonical_json(self.profile))
        serialized = self.profile_path.read_text(encoding="utf-8").lower()
        for forbidden in (
            "payment_method", "card_number", "provider_customer",
            "webhook_payload", "tax_id", "shipping_address",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_wave_one_has_separate_official_regulatory_entry_points(self) -> None:
        docs = (PROJECT / "INTERNATIONAL_DEVELOPER_KIT_LAUNCH.md").read_text(
            encoding="utf-8")
        for required in (
            "| AU |", "| CA |", "| GB |", "| SG |", "| TW |", "| US |",
            "acma.gov.au", "ised-isde.canada.ca", "gov.uk",
            "iris.imda.gov.sg", "ncclaw.ncc.gov.tw", "opendata.fcc.gov",
            "NO-GO pending evidence", "Wave 2", "EU／EEA", "日本", "韓國",
        ):
            self.assertIn(required, docs)

    def test_public_companion_and_web_billing_boundaries_are_explicit(self) -> None:
        launch = (
            PROJECT / "INTERNATIONAL_DEVELOPER_KIT_LAUNCH.md").read_text(
                encoding="utf-8")
        billing = (PROJECT / "WEB_BILLING_ADAPTER_CONTRACT.md").read_text(
            encoding="utf-8")
        for required in (
            "App 內不提供購買", "外部付款", "public_free_companion",
            "public_consumption_only", "web billing adapter",
            "return URL", "provider API re-fetch", "不得自動建立 account",
            "cancel at period end", "chargeback", "400 invalid",
            "401 unauthorized", "404 not found", "409 conflict",
            "503 unavailable", "不自動重試",
        ):
            self.assertIn(required, launch + billing)

    def test_market_release_and_deployment_cardinality_do_not_expand(self) -> None:
        billing = (PROJECT / "WEB_BILLING_ADAPTER_CONTRACT.md").read_text(
            encoding="utf-8")
        launch = (
            PROJECT / "INTERNATIONAL_DEVELOPER_KIT_LAUNCH.md").read_text(
                encoding="utf-8")
        self.assertEqual(len(RELEASE.EVIDENCE_TYPES), 15)
        self.assertIn("legal_market", RELEASE.EVIDENCE_TYPES)
        self.assertIn(
            "七個 workloads、44 resources、30 value-free prerequisites", billing)
        self.assertNotIn("MARKET_RELEASE_PASS", launch)


if __name__ == "__main__":
    unittest.main()
