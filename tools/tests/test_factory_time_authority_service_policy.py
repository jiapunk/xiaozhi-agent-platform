import json
import pathlib
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class FactoryTimeAuthorityServicePolicyTests(unittest.TestCase):
    def read(self, relative):
        return (PROJECT / relative).read_text(encoding="utf-8")

    def load(self, relative):
        return json.loads(self.read(relative))

    def test_standalone_service_wires_database_signer_mtls_and_private_probes(self):
        main = self.read("gateway/cmd/factorytimeauthority/main.go")
        for required in (
            'sql.Open("pgx", settings.DatabaseURL)',
            "store.VerifySchema()",
            "factorytime.LoadRemoteSigner",
            "signer.Ready(context.Background())",
            "factorytime.NewAuthority(store, signer",
            "factorytime.LoadMTLSServerConfig",
            "tls.NewListener(listener, tlsConfiguration)",
            "factorytime.NewProbeHandler(store, signer)",
            "ReadHeaderTimeout:",
            "MaxHeaderBytes:",
            'ErrorLog:          log.New(io.Discard, "", 0)',
            "signal.NotifyContext",
        ):
            self.assertIn(required, main)
        self.assertNotIn("settings.DatabaseURL,", main.split("logger", 1)[0])
        self.assertNotIn("FACTORY_TIME_SIGNING_PRIVATE_KEY", main)

    def test_remote_signer_is_exact_tls13_mtls_pinned_and_non_oracular(self):
        signer = self.read("gateway/internal/factorytime/remote_signer.go")
        contract = self.read("gateway/internal/factorytime/contract.go")
        for required in (
            'SignerEndpointPath     = "/v1/factory/trusted-time/sign"',
            "Proxy: nil",
            "DisableCompression:    true",
            "MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13",
            "SessionTicketsDisabled: true",
            "CheckRedirect:",
            "publicDigest != files.PublicKeySHA256",
            "fileDigest(caPEM) != files.CACertificateSHA256",
            "fileDigest(clientCertificatePEM) !=",
            "ParseUnsignedReceipt(unsigned)",
            "bytes.Equal(payload[:len(SignatureDomain)], []byte(SignatureDomain))",
            "ed25519.Verify(signer.publicKey, payload, signature)",
            "verifiedSignerResponseTLS(httpResponse)",
        ):
            self.assertIn(required, signer)
        self.assertIn("func ParseUnsignedReceipt", contract)
        self.assertIn("bytes.Equal(canonical, data)", contract)
        self.assertNotIn("ProxyFromEnvironment", signer)
        self.assertNotIn("ed25519.Sign(", signer)

    def test_external_signer_wire_schemas_are_closed_and_domain_bound(self):
        request = self.load("factory/factory-time-sign-request.schema.json")
        response = self.load("factory/factory-time-sign-response.schema.json")
        self.assertFalse(request["additionalProperties"])
        self.assertFalse(response["additionalProperties"])
        self.assertEqual(
            request["properties"]["signature_domain_b64url"]["const"],
            "eHotc2FjcmlmaWNpYWwtdHJ1c3RlZC10aW1lLXJlY2VpcHQtdjEA",
        )
        self.assertEqual(
            request["properties"]["result"]["const"],
            "FACTORY_TIME_SIGNATURE_REQUESTED",
        )
        self.assertEqual(
            response["properties"]["result"]["const"],
            "FACTORY_TIME_RECEIPT_SIGNED",
        )
        self.assertEqual(
            response["properties"]["signature_b64url"]["pattern"],
            "^[A-Za-z0-9_-]{86}$",
        )

    def test_production_package_has_no_receipt_signing_private_key_or_executor(self):
        source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(
                (PROJECT / "gateway/internal/factorytime").glob("*.go")
            )
            if not path.name.endswith("_test.go")
        )
        for forbidden in (
            "ed25519.PrivateKey",
            "ed25519.Sign(",
            "os/exec",
            "espefuse",
            "esptool",
            "burn_key",
            "erase_flash",
        ):
            self.assertNotIn(forbidden, source)

    def test_oci_contract_is_v3_and_contains_exact_seven_service_order(self):
        python = self.read("tools/oci_release.py")
        go = self.read("gateway/internal/ocirelease/validate.go")
        schema = self.load("gateway/oci-release-receipt.schema.json")
        expected = [
            "gateway",
            "controlplane",
            "agentproxy",
            "firmwareorigin",
            "generationcoordinator",
            "accountauthorization",
            "factorytimeauthority",
        ]
        self.assertIn("SCHEMA_VERSION = 3", python)
        self.assertIn('"factorytimeauthority",', python)
        self.assertIn("XIAOZHI-AGENT-OCI-RELEASE-V3", python)
        self.assertIn("receipt.Schema != 3", go)
        self.assertIn('"factorytimeauthority": true', go)
        self.assertEqual(schema["properties"]["schema"]["const"], 3)
        services = schema["properties"]["services"]
        self.assertEqual((services["minItems"], services["maxItems"]), (7, 7))
        self.assertEqual(
            services["items"]["properties"]["name"]["enum"], expected
        )

    def test_kubernetes_contract_is_v7_and_isolates_authority_dependencies(self):
        deployment = self.read("tools/kubernetes_deployment.py")
        profile = self.load("deployment/kubernetes-deployment-profile.example.json")
        profile_schema = self.load(
            "deployment/kubernetes-deployment-profile.schema.json"
        )
        receipt_schema = self.load(
            "deployment/kubernetes-deployment-receipt.schema.json"
        )
        for required in (
            "SCHEMA_VERSION = 7",
            '"factorytimeauthority": 9445',
            '"FACTORY_TIME_HEALTH_LISTEN_ADDR": ":9081"',
            '"station-client-ca.pem", "signer.pub"',
            '"factorytimeauthority": (("database", 5432), ("signer", 443))',
            'factory-time-station-ingress',
        ):
            self.assertIn(required, deployment)
        self.assertEqual(profile["schema"], 7)
        self.assertEqual(profile_schema["properties"]["schema"]["const"], 7)
        self.assertIn("signer", profile["external_egress"])
        self.assertEqual(
            profile["secret_files"]["factorytimeauthority"],
            "m62-factorytimeauthority-files",
        )
        services = receipt_schema["properties"]["services"]
        self.assertEqual((services["minItems"], services["maxItems"]), (7, 7))


if __name__ == "__main__":
    unittest.main()
