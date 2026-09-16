import json
import pathlib
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class MTLSDispatchQualificationPolicyTests(unittest.TestCase):
    def read(self, path):
        return (PROJECT / path).read_text(encoding="utf-8")

    def test_runner_uses_production_wake_path_and_exact_tls_failures(self):
        runner = self.read(
            "gateway/internal/mtlsdispatchqualification/run.go"
        )
        transport = self.read("gateway/internal/pushdelivery/private_wake.go")
        observation = self.read(
            "gateway/internal/mtlsdispatchqualification/observation.go"
        )
        for required in (
            "SendWakeWithTransportEvidence",
            "positiveProbe",
            "rejectedTLSHandshake",
            "rejectedServerName",
            "tls.VersionTLS13",
            "HTTP2Protocol",
            '"h2"',
            "CurrentClientCertificateSHA256",
            "NextClientCertificateSHA256",
            "RevokedClientCertificateSHA256",
            "PrivateWakeContract",
        ):
            self.assertIn(required, runner + transport + observation)
        for forbidden in (
            'json:"tenant_id"', 'json:"subject"', 'json:"device_id"',
            'json:"access_token"', 'json:"provider_token"',
        ):
            self.assertNotIn(forbidden, observation)

    def test_final_receipt_reverifies_m70_and_cluster_attestation(self):
        receipt = self.read(
            "gateway/internal/mtlsdispatchqualification/receipt.go"
        )
        for required in (
            "appdeliveryqualification.VerifyReceiptFile",
            "appdeliveryqualification.BuildReceipt",
            "appdeliveryqualification.ReceiptMatchesEvidence",
            "VerifyAttestationFile",
            "ReceiptMatchesEvidence",
            "LIVE_MTLS_DISPATCH_PASS",
            "fixtureUnresolvedProductionGates",
            "liveUnresolvedProductionGates",
            '"managed_database_failover"',
            '"provider_credential_revocation"',
            '"end_to_end_mtls_dispatch"',
            '"signed_app_delivery_receipt"',
        ):
            self.assertIn(required, receipt)

    def test_live_commands_require_explicit_ack_and_independent_trust(self):
        runner = self.read("gateway/cmd/qualifymtlsdispatch/main.go")
        controlplane = self.read("gateway/cmd/controlplane/main.go")
        attestation = self.read(
            "gateway/cmd/signmtlsdispatchattestation/main.go"
        )
        builder = self.read(
            "gateway/cmd/buildmtlsdispatchqualification/main.go"
        )
        validator = self.read(
            "gateway/cmd/validatemtlsdispatchqualification/main.go"
        )
        self.assertIn("acknowledge-live-mtls-dispatch", runner)
        self.assertIn('os.Args[1] != "qualify-mtls-dispatch"', controlplane)
        self.assertIn("runMTLSDispatchQualification", controlplane)
        self.assertIn("acknowledge-live-cluster-attestation", attestation)
        self.assertIn("acknowledge-live-mtls-dispatch", builder)
        for required in (
            "app-delivery-trusted-public-key",
            "provider-trusted-public-key",
            "app-attestation-trusted-public-key",
            "deployment-attestation-trusted-public-key",
            "expected-workload-evidence-sha256",
            "expected-deployment-id",
            "expected-oci-release-id",
            "require-live",
        ):
            self.assertIn(required, validator)

    def test_schemas_fix_exact_services_and_fixture_live_separation(self):
        config = json.loads(self.read(
            "gateway/mtls-dispatch-qualification-config.schema.json"
        ))
        observation = json.loads(self.read(
            "gateway/mtls-dispatch-observation.schema.json"
        ))
        attestation = json.loads(self.read(
            "gateway/mtls-dispatch-deployment-attestation.schema.json"
        ))
        receipt = json.loads(self.read(
            "gateway/mtls-dispatch-qualification-receipt.schema.json"
        ))
        for schema in (config, observation, attestation, receipt):
            self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            config["properties"]["acknowledge_live_dispatch"], {"const": True}
        )
        services = observation["$defs"]["services"]
        self.assertEqual(services["minItems"], 7)
        self.assertEqual(services["maxItems"], 7)
        self.assertEqual(
            [item["const"] for item in services["prefixItems"]],
            [
                "gateway", "controlplane", "agentproxy", "firmwareorigin",
                "generationcoordinator", "accountauthorization",
                "factorytimeauthority",
            ],
        )
        self.assertEqual(
            observation["properties"]["negotiated_protocol"], {"const": "h2"}
        )
        self.assertEqual(
            receipt["properties"]["production_ready"], {"const": False}
        )
        schema_text = json.dumps(receipt, sort_keys=True)
        self.assertIn("FIXTURE_MTLS_DISPATCH_PASS", schema_text)
        self.assertIn("LIVE_MTLS_DISPATCH_PASS", schema_text)
        self.assertIn("end_to_end_mtls_dispatch", schema_text)

    def test_companion_provider_secrets_are_actually_mounted(self):
        deployment = self.read("tools/kubernetes_deployment.py")
        tests = self.read("tools/tests/test_kubernetes_deployment.py")
        self.assertIn(
            "for key in _secret_file_keys(profile, service)", deployment
        )
        for required in (
            '"push-token-keyring.json"', '"apns-private-key.p8"',
            '"fcm-service-account.json"',
        ):
            self.assertIn(required, tests)

    def test_docs_preserve_live_cluster_and_market_boundaries(self):
        runbook = self.read("MTLS_DISPATCH_QUALIFICATION_RUNBOOK.md")
        report = self.read("M71_MTLS_DISPATCH_QUALIFICATION_REPORT.md")
        market = self.read("PRODUCT_MARKET_RELEASE_RUNBOOK.md")
        for required in (
            "LIVE_MTLS_DISPATCH_PASS", "FIXTURE_MTLS_DISPATCH_PASS",
            "TLS 1.3", "HTTP/2", "current", "next", "revoked",
            "seven-service", "WORM", "NO-GO",
        ):
            self.assertIn(required, runbook + report)
        self.assertIn("push_provider_delivery", market)


if __name__ == "__main__":
    unittest.main()
