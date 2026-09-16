import json
import pathlib
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class ProviderRevocationQualificationPolicyTests(unittest.TestCase):
    def read(self, path):
        return (PROJECT / path).read_text(encoding="utf-8")

    def test_runtime_types_only_explicit_provider_authentication_rejection(self):
        provider = self.read("gateway/internal/pushdelivery/provider.go")
        apns = self.read("gateway/internal/pushdelivery/apns.go")
        google = self.read("gateway/internal/pushdelivery/google_oauth.go")
        fcm = self.read("gateway/internal/pushdelivery/fcm.go")
        for required in (
            "ErrCredentialRejected", "InvalidProviderToken", "invalid_grant",
            "invalid_client", "http.StatusForbidden", "http.StatusBadRequest",
            "errors.Is(err, ErrCredentialRejected)",
        ):
            self.assertIn(required, provider + apns + google + fcm)
        self.assertNotIn("ExpiredProviderToken", apns)

    def test_runner_uses_fresh_active_revoked_active_sandwich(self):
        runner = self.read(
            "gateway/internal/providerrevocationqualification/run.go"
        )
        observation = self.read(
            "gateway/internal/providerrevocationqualification/observation.go"
        )
        for required in (
            "ActiveBefore", "Revoked", "ActiveAfter",
            "ErrCredentialRejected", "ErrUnavailable",
            "RevokedPublicKeySHA256", "ActivePublicKeySHA256",
            "google-oauth-invalid-grant", "apns-invalid-provider-token",
            "filepath.IsAbs", "ActiveBeforeAccepted",
            "RevokedCredentialRejected", "ActiveAfterAccepted",
        ):
            self.assertIn(required, runner + observation)
        for forbidden in (
            'json:"valid_target"', 'json:"access_token"',
            'json:"private_key"', 'json:"team_id"',
        ):
            self.assertNotIn(forbidden, observation)

    def test_final_receipt_rebuilds_the_entire_m69_through_m71_chain(self):
        receipt = self.read(
            "gateway/internal/providerrevocationqualification/receipt.go"
        )
        manifest = self.read(
            "gateway/internal/providerrevocationqualification/manifest.go"
        )
        for required in (
            "mtlsdispatchqualification.VerifyReceiptFile",
            "mtlsdispatchqualification.BuildReceipt",
            "mtlsdispatchqualification.ReceiptMatchesEvidence",
            "pushqualification.VerifyReceiptFile",
            "VerifyAttestationFile", "observationMatchesProviderReceipt",
            "LIVE_PROVIDER_CREDENTIAL_REVOCATION_PASS",
            '"managed_database_failover"',
            '"provider_credential_revocation"',
            "LoadEvidenceManifest", "DisallowUnknownFields",
        ):
            self.assertIn(required, receipt + manifest)
        self.assertEqual(receipt.count('"managed_database_failover"'), 2)

    def test_live_commands_require_ack_and_independent_trust_manifest(self):
        qualifier = self.read("gateway/cmd/qualifyproviderrevocation/main.go")
        attester = self.read(
            "gateway/cmd/signproviderrevocationattestation/main.go"
        )
        builder = self.read(
            "gateway/cmd/buildproviderrevocationqualification/main.go"
        )
        validator = self.read(
            "gateway/cmd/validateproviderrevocationqualification/main.go"
        )
        self.assertIn("acknowledge-live-provider-credential-revocation", qualifier)
        self.assertIn("acknowledge-live-provider-console-revocation", attester)
        self.assertIn("acknowledge-live-provider-credential-revocation", builder)
        for required in (
            "evidence-manifest", "trusted-public-key",
            "expected-signing-key-id", "require-live", "BuildReceipt",
            "ReceiptMatchesEvidence",
        ):
            self.assertIn(required, validator)

    def test_schemas_are_strict_and_preserve_fixture_live_separation(self):
        names = (
            "provider-revocation-qualification-config.schema.json",
            "provider-revocation-observation.schema.json",
            "provider-revocation-attestation.schema.json",
            "provider-revocation-qualification-receipt.schema.json",
            "provider-revocation-evidence-manifest.schema.json",
        )
        schemas = [json.loads(self.read("gateway/" + name)) for name in names]
        for schema in schemas:
            self.assertFalse(schema["additionalProperties"])
        config, observation, attestation, receipt, manifest = schemas
        self.assertEqual(
            config["properties"]["acknowledge_live_credential_revocation"],
            {"const": True},
        )
        provider = observation["$defs"]["provider"]
        self.assertEqual(provider["properties"]["active_before_accepted"],
                         {"const": True})
        self.assertIn("LIVE_PROVIDER_CONSOLE_REVOCATION_PASS",
                      json.dumps(attestation))
        self.assertEqual(receipt["properties"]["production_ready"],
                         {"const": False})
        self.assertIn("managed_database_failover", json.dumps(receipt))
        self.assertEqual(manifest["$defs"]["path"]["pattern"], "^/")

    def test_docs_keep_live_provider_and_market_release_boundary(self):
        runbook = self.read("PROVIDER_CREDENTIAL_REVOCATION_RUNBOOK.md")
        report = self.read("M72_PROVIDER_CREDENTIAL_REVOCATION_REPORT.md")
        market = self.read("PRODUCT_MARKET_RELEASE_RUNBOOK.md")
        for required in (
            "LIVE_PROVIDER_CREDENTIAL_REVOCATION_PASS",
            "FIXTURE_PROVIDER_CREDENTIAL_REVOCATION_PASS",
            "APNs", "FCM", "active", "revoked", "WORM", "NO-GO",
            "managed_database_failover",
        ):
            self.assertIn(required, runbook + report + market)


if __name__ == "__main__":
    unittest.main()
