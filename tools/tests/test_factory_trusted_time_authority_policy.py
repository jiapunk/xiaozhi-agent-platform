import pathlib
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class FactoryTrustedTimeAuthorityPolicyTests(unittest.TestCase):
    def read(self, relative):
        return (PROJECT / relative).read_text(encoding="utf-8")

    def test_database_schema_separates_station_registry_and_hashed_replay_rows(self):
        schema = self.read(
            "gateway/migrations/factorytime/0001_factory_trusted_time.sql"
        )
        self.assertIn("CREATE TABLE factory_time_stations", schema)
        self.assertIn("CREATE TABLE factory_trusted_time_requests", schema)
        self.assertIn("client_certificate_sha256 bytea NOT NULL", schema)
        self.assertIn("request_sha256 bytea PRIMARY KEY", schema)
        self.assertIn("request_id varchar(128) NOT NULL UNIQUE", schema)
        self.assertIn("nonce_sha256 bytea NOT NULL UNIQUE", schema)
        self.assertIn("authorization_issued_at timestamptz NOT NULL", schema)
        self.assertIn("authority_key_id varchar(128) NOT NULL", schema)
        self.assertNotIn("raw_nonce", schema)
        self.assertNotIn("private_key", schema)
        self.assertNotIn("UNIQUE (attempt_id", schema)

    def test_station_authorization_time_and_nonce_share_one_transaction(self):
        store = self.read("gateway/internal/factorytime/postgres.go")
        self.assertIn("sql.LevelSerializable", store)
        self.assertIn("SELECT CURRENT_TIMESTAMP", store)
        self.assertIn("FROM factory_time_stations", store)
        self.assertIn("FOR SHARE", store)
        self.assertIn("factory_trusted_time_requests", store)
        self.assertIn('postgresError.Code == "40001"', store)
        self.assertIn('postgresError.Code == "40P01"', store)
        self.assertIn('postgresError.Code == "23505"', store)

    def test_handler_requires_exact_tls13_mtls_and_bounded_canonical_transport(self):
        handler = self.read("gateway/internal/factorytime/handler.go")
        contract = self.read("gateway/internal/factorytime/contract.go")
        server_tls = self.read("gateway/internal/factorytime/server_tls.go")
        for required in (
            "request.TLS.PeerCertificates",
            "request.TLS.VerifiedChains",
            "tls.VersionTLS13",
            'singleHeader(request.Header, "Content-Type")',
            'singleHeader(request.Header, "Accept")',
            'singleHeader(request.Header, "Cache-Control")',
            "request.ContentLength",
            "request.TransferEncoding",
            'header.Set("Cache-Control", "no-store")',
        ):
            self.assertIn(required, handler)
        self.assertIn("rejectDuplicateMembers", contract)
        self.assertIn("bytes.Equal(canonical, data)", contract)
        self.assertIn("tls.RequireAndVerifyClientCert", server_tls)
        self.assertIn("MinVersion:             tls.VersionTLS13", server_tls)
        self.assertIn("MaxVersion:             tls.VersionTLS13", server_tls)
        self.assertIn("SessionTicketsDisabled: true", server_tls)

    def test_signing_key_is_an_external_interface_and_failures_consume_nonce(self):
        authority = self.read("gateway/internal/factorytime/authority.go")
        test_source = self.read(
            "gateway/internal/factorytime/authority_test.go"
        )
        self.assertIn("type Signer interface", authority)
        self.assertIn("Sign(context.Context, []byte)", authority)
        self.assertNotIn("ed25519.PrivateKey", authority)
        self.assertNotIn("PRIVATE KEY", authority)
        reserve = authority.index("authority.store.Reserve")
        sign = authority.index("authority.signer.Sign")
        self.assertLess(reserve, sign)
        self.assertIn("TestFailedSignerStillConsumesNonce", test_source)

    def test_m60_python_verifier_accepts_go_handler_receipt(self):
        python_test = self.read(
            "factory/tests/test_sacrificial_trusted_time.py"
        )
        fixture = self.read(
            "gateway/tools/tests/factorytimefixture/main.go"
        )
        self.assertIn(
            "test_go_m61_authority_receipt_is_accepted_by_m60_verifier",
            python_test,
        )
        self.assertIn("TIME.verify_receipt", python_test)
        self.assertIn("test-only cross-language fixture", fixture)
        self.assertIn("M61 CROSS LANGUAGE TEST KEY ONLY", fixture)
        self.assertNotIn("gateway/cmd/factorytime", fixture)

    def test_live_postgres_gate_is_explicit_and_exercises_two_stores(self):
        gate = self.read("tools/run_factory_time_postgres_integration_gate.sh")
        integration = self.read(
            "gateway/internal/factorytime/postgres_integration_test.go"
        )
        self.assertIn("FACTORY_TIME_TEST_DATABASE_URL is required", gate)
        self.assertIn("storeA", integration)
        self.assertIn("storeB", integration)
        self.assertIn("successes.Load() != 1", integration)
        self.assertIn("replays.Load() != 15", integration)
        self.assertIn("raw nonce crossed database boundary", integration)
        self.assertIn("fresh ticket for same attempt", integration)

    def test_authority_core_contains_no_executor_or_hardware_operation(self):
        source = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(
                (PROJECT / "gateway/internal/factorytime").glob("*.go")
            )
            if not path.name.endswith("_test.go")
        )
        for forbidden in (
            "os/exec",
            "espefuse",
            "esptool",
            "burn_key",
            "erase_flash",
            "WriteFile(",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
