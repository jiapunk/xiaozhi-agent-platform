import pathlib
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class FactoryTimeSignerEnforcementPolicyTests(unittest.TestCase):
    def read(self, relative):
        return (PROJECT / relative).read_text(encoding="utf-8")

    def test_signer_service_authorizes_before_backend_and_verifies_signature(self):
        source = self.read("gateway/internal/factorytime/signer_server.go")
        authorize = source.index("service.authorizer.AuthorizeSigning")
        sign = source.index("service.backend.Sign")
        verify = source.index("ed25519.Verify(service.publicKey")
        self.assertLess(authorize, sign)
        self.assertLess(sign, verify)
        self.assertEqual(source.count("service.authorizer.AuthorizeSigning"), 2)
        for required in (
            "parseSignerRequest(requestBody)",
            "request.KeyID != service.keyID",
            "receipt.AuthorityKeyID != service.keyID",
            "len(SignatureDomain)+len(unsigned)",
            "len(signature) != ed25519.SignatureSize",
        ):
            self.assertIn(required, source)

    def test_signer_handler_requires_exact_tls13_leaf_pin_and_transport(self):
        source = self.read("gateway/internal/factorytime/signer_server.go")
        for required in (
            "tls.VersionTLS13",
            "request.TLS.PeerCertificates[0].Equal",
            "sha256.Sum256(request.TLS.PeerCertificates[0].Raw)",
            "equalDigest(digest[:], wanted[:])",
            'singleHeader(request.Header, "Content-Type")',
            'singleHeader(request.Header, "Accept")',
            'singleHeader(request.Header, "Cache-Control")',
            "request.ContentLength",
            "request.TransferEncoding",
            "SignerEndpointPath",
            "SignerReadinessPath",
        ):
            self.assertIn(required, source)

    def test_postgres_authorizer_rechecks_exact_committed_row_and_database_time(self):
        source = self.read("gateway/internal/factorytime/postgres_signer.go")
        for required in (
            "FROM factory_trusted_time_requests",
            "WHERE request_sha256 = $1",
            "CURRENT_TIMESTAMP",
            "record.RequestID != receipt.RequestID",
            "record.StationID != receipt.Station.ID",
            "record.FixtureVersion != receipt.Station.FixtureVersion",
            "record.PolicyID != receipt.Ledger.PolicyID",
            "record.LedgerID != receipt.Ledger.LedgerID",
            "record.PlanID != receipt.Authorization.PlanID",
            "record.AttemptID != receipt.Transaction.AttemptID",
            "record.DeviceID != receipt.Transaction.DeviceID",
            "record.BaseMAC != receipt.Transaction.BaseMAC",
            "record.AuthorityKeyID != receipt.AuthorityKeyID",
            "!record.ObservedAt.Equal(observed)",
            "!record.ReceiptExpiresAt.Equal(receiptExpires)",
            "!databaseNow.Before(receiptExpires)",
        ):
            self.assertIn(required, source)
        self.assertNotIn("INSERT INTO", source)
        self.assertNotIn("UPDATE ", source)
        self.assertNotIn("DELETE FROM", source)

    def test_signer_parser_rejects_generic_or_noncanonical_payloads(self):
        source = self.read("gateway/internal/factorytime/remote_signer.go")
        for required in (
            "func parseSignerRequest",
            "rejectDuplicateMembers(data)",
            "decoder.DisallowUnknownFields()",
            "!bytes.Equal(canonical, data)",
            "request.SignatureDomainB64URL != base64.RawURLEncoding",
            "ParseUnsignedReceipt(unsigned)",
            "receipt.AuthorityKeyID != request.KeyID",
        ):
            self.assertIn(required, source)

    def test_production_signer_core_has_no_private_signer_or_hardware_executor(self):
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
            "PRIVATE KEY-----",
            "os/exec",
            "espefuse",
            "esptool",
            "burn_key",
            "erase_flash",
        ):
            self.assertNotIn(forbidden, source)

    def test_signer_remains_outside_product_service_and_image_inventory(self):
        release = self.read("tools/oci_release.py")
        deployment = self.read("tools/kubernetes_deployment.py")
        self.assertIn('"factorytimeauthority",', release)
        self.assertNotIn('"factorytimesigner",', release)
        self.assertNotIn('"factorytimesigner":', deployment)
        self.assertIn('"factorytimeauthority": (("database", 5432), ("signer", 443))', deployment)

    def test_cross_tls_and_live_postgres_gates_cover_server_side_enforcement(self):
        tls_test = self.read(
            "gateway/internal/factorytime/signer_server_test.go"
        )
        postgres_test = self.read(
            "gateway/internal/factorytime/postgres_integration_test.go"
        )
        self.assertIn(
            "TestRemoteSignerAndReceiptSignerHandlerInteroperateOverRealTLS13MTLS",
            tls_test,
        )
        self.assertIn("NewPostgresSignerAuthorizer(databaseB", postgres_test)
        self.assertIn("AuthorizeSigning(ctx, receipt)", postgres_test)
        self.assertIn("tampered receipt signer authorization", postgres_test)


if __name__ == "__main__":
    unittest.main()
