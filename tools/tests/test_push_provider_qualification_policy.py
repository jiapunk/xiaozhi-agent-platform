import json
import pathlib
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class PushProviderQualificationPolicyTests(unittest.TestCase):
    def read(self, path):
        return (PROJECT / path).read_text(encoding="utf-8")

    def test_runner_requires_rotation_invalidation_and_retry_without_targets(self):
        qualification = self.read(
            "gateway/internal/pushqualification/qualification.go"
        )
        receipt = self.read("gateway/internal/pushqualification/receipt.go")
        for required in (
            "candidate.Current", "candidate.Next", "DeliveryAccepted",
            "DeliveryInvalidInstallation", "DeliveryRetry",
            "CurrentCredentialID", "NextCredentialID", "SecretFree: true",
            '"end_to_end_mtls_dispatch"', '"signed_app_delivery_receipt"',
        ):
            self.assertIn(required, qualification)
        for forbidden in (
            'json:"provider_token"', 'json:"valid_target"',
            'json:"access_token"', 'json:"private_key"',
        ):
            self.assertNotIn(forbidden, qualification)
            self.assertNotIn(forbidden, receipt)
        self.assertIn("XIAOZHI-PUSH-PROVIDER-QUALIFICATION-V1", receipt)
        self.assertIn("options.RequireLive && receipt.DevelopmentOnly", receipt)

    def test_live_command_requires_double_ack_and_private_inputs(self):
        config = self.read("gateway/internal/pushqualification/config.go")
        command = self.read("gateway/cmd/qualifypushprovider/main.go")
        fixture = self.read(
            "gateway/cmd/generatepushqualificationfixture/main.go"
        )
        for required in (
            "AcknowledgeLiveProviderCalls", "readRegular(path, maximumConfigBytes, true)",
            "validatePrivateCredentialFile", "LoadAPNsPrivateKey",
            "LoadGoogleServiceAccountCredential", "ConfigSHA256",
        ):
            self.assertIn(required, config)
        self.assertIn("acknowledge-live-provider-calls", command)
        self.assertIn("LiveResult", command)
        self.assertNotIn("ValidTarget", command)
        self.assertIn("DevelopmentOnly: true", fixture)
        self.assertIn("FixtureResult", fixture)

    def test_schemas_and_market_release_slot_are_exact(self):
        receipt_schema = json.loads(self.read(
            "gateway/push-provider-qualification-receipt.schema.json"
        ))
        config_schema = json.loads(self.read(
            "gateway/push-provider-qualification-config.schema.json"
        ))
        self.assertFalse(receipt_schema["additionalProperties"])
        self.assertEqual(receipt_schema["properties"]["secret_free"], {"const": True})
        self.assertEqual(receipt_schema["properties"]["production_ready"], {"const": False})
        self.assertEqual(
            receipt_schema["properties"]["providers"]["minItems"], 1
        )
        self.assertEqual(
            config_schema["properties"]["acknowledge_live_provider_calls"],
            {"const": True},
        )
        release = self.read("tools/product_release.py")
        policy_schema = json.loads(self.read(
            "release/product-release-policy.schema.json"
        ))
        record_schema = json.loads(self.read(
            "release/product-release-record.schema.json"
        ))
        self.assertIn('"push_provider_delivery",', release)
        self.assertEqual(
            (policy_schema["properties"]["required_evidence"]["minItems"],
             policy_schema["properties"]["required_evidence"]["maxItems"]),
            (15, 15),
        )
        self.assertEqual(
            (record_schema["properties"]["evidence"]["minItems"],
             record_schema["properties"]["evidence"]["maxItems"]),
            (15, 15),
        )

    def test_docs_keep_live_and_market_release_boundaries(self):
        runbook = self.read("PUSH_PROVIDER_QUALIFICATION_RUNBOOK.md")
        report = self.read("M69_PUSH_PROVIDER_QUALIFICATION_REPORT.md")
        market = self.read("PRODUCT_MARKET_RELEASE_RUNBOOK.md")
        for required in (
            "LIVE_PROVIDER_API_PASS", "FIXTURE_PROTOCOL_PASS",
            "signed App", "WORM", "NO-GO",
        ):
            self.assertIn(required, runbook + report)
        self.assertIn("push_provider_delivery", market)
        self.assertIn("15 類", market)


if __name__ == "__main__":
    unittest.main()

