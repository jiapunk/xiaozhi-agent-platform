import json
import pathlib
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class AppDeliveryQualificationPolicyTests(unittest.TestCase):
    def read(self, path):
        return (PROJECT / path).read_text(encoding="utf-8")

    def test_swift_observation_is_content_minimized_and_lifecycle_bound(self):
        recorder = self.read(
            "companion-app/Sources/ProductOnboardingCore/"
            "AgentActionConsentDeliveryQualification.swift"
        )
        session = self.read(
            "companion-app/Sources/ProductOnboardingCore/"
            "AgentActionConsentSession.swift"
        )
        for required in (
            "XIAOZHI-M70-CHALLENGE-BINDING-V1",
            "XIAOZHI-M70-DEVICE-BINDING-V1",
            '"background_network_request\\\":false',
            '"decision_issued\\\":false',
            "maximumWakeToFetchMilliseconds",
            "actionConsentDidReceiveContentFreeWake",
            "actionConsentDidEnterForeground",
            "actionConsentDidPresentAuthenticatedTicket",
        ):
            self.assertIn(required, recorder + session)
        for forbidden in (
            '"challenge_id"', '"device_id"', '"arguments"',
            '"access_token"', '"provider_token"',
        ):
            self.assertNotIn(forbidden, recorder)

    def test_go_chain_reverifies_every_subordinate_evidence(self):
        receipt = self.read(
            "gateway/internal/appdeliveryqualification/receipt.go"
        )
        attestation = self.read(
            "gateway/internal/appdeliveryqualification/attestation.go"
        )
        for required in (
            "pushqualification.VerifyReceiptFile",
            "VerifyAttestationFile",
            "providerSupportsObservation",
            "options.RequireLive",
            "ReceiptMatchesEvidence",
            "XIAOZHI-APP-DELIVERY-QUALIFICATION-V1",
            "fixtureUnresolvedProductionGates",
            "liveUnresolvedProductionGates",
            '"end_to_end_mtls_dispatch"',
            '"provider_credential_revocation"',
            '"signed_app_delivery_receipt"',
        ):
            self.assertIn(required, receipt)
        self.assertIn("XIAOZHI-APP-DELIVERY-ATTESTATION-V1", attestation)
        self.assertIn("maximumAttestationLifetime = 24 * time.Hour", attestation)

    def test_live_commands_require_explicit_ack_and_independent_trust(self):
        signer = self.read("gateway/cmd/signappdeliveryattestation/main.go")
        builder = self.read("gateway/cmd/buildappdeliveryqualification/main.go")
        validator = self.read(
            "gateway/cmd/validateappdeliveryqualification/main.go"
        )
        self.assertIn("acknowledge-live-vendor-attestation", signer)
        self.assertIn("acknowledge-live-signed-app-delivery", builder)
        for required in (
            "provider-trusted-public-key",
            "app-attestation-trusted-public-key",
            "expected-app-binary-sha256",
            "expected-vendor-evidence-sha256",
            "require-live",
        ):
            self.assertIn(required, validator)

    def test_three_schemas_keep_fixture_and_live_results_separate(self):
        observation = json.loads(self.read(
            "gateway/app-delivery-observation.schema.json"
        ))
        attestation = json.loads(self.read(
            "gateway/app-delivery-attestation-receipt.schema.json"
        ))
        receipt = json.loads(self.read(
            "gateway/app-delivery-qualification-receipt.schema.json"
        ))
        for schema in (observation, attestation, receipt):
            self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            observation["properties"]["background_network_request"],
            {"const": False},
        )
        self.assertEqual(
            receipt["properties"]["production_ready"], {"const": False}
        )
        self.assertEqual(
            receipt["properties"]["unresolved_production_gates"]
            ["minItems"], 3
        )
        self.assertEqual(
            receipt["properties"]["unresolved_production_gates"]
            ["maxItems"], 4
        )
        schema_text = json.dumps(receipt, sort_keys=True)
        self.assertIn("FIXTURE_APP_FLOW_PASS", schema_text)
        self.assertIn("LIVE_SIGNED_APP_FLOW_PASS", schema_text)
        self.assertIn("signed_app_delivery_receipt", schema_text)

    def test_docs_preserve_signed_app_and_market_boundaries(self):
        runbook = self.read("APP_DELIVERY_QUALIFICATION_RUNBOOK.md")
        report = self.read("M70_APP_DELIVERY_QUALIFICATION_REPORT.md")
        market = self.read("PRODUCT_MARKET_RELEASE_RUNBOOK.md")
        for required in (
            "LIVE_SIGNED_APP_FLOW_PASS", "FIXTURE_APP_FLOW_PASS",
            "Apple App Attest", "signed App", "WORM", "NO-GO",
        ):
            self.assertIn(required, runbook + report)
        self.assertIn("push_provider_delivery", market)


if __name__ == "__main__":
    unittest.main()
