import pathlib
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class AccountAuthorizationLedgerPolicyTests(unittest.TestCase):
    def read(self, relative):
        return (PROJECT / relative).read_text(encoding="utf-8")

    def test_schema_separates_account_epoch_from_jti_ledger(self):
        schema = self.read(
            "gateway/migrations/account/0001_companion_authorization.sql"
        )
        self.assertIn("CREATE TABLE companion_accounts", schema)
        self.assertIn("CREATE TABLE companion_tokens", schema)
        self.assertIn("PRIMARY KEY (tenant_id, subject)", schema)
        self.assertIn("account_revision bigint NOT NULL", schema)
        self.assertIn("revoked_at timestamptz", schema)
        self.assertIn("expires_at_unix bigint", schema)
        self.assertNotIn("raw_jwt", schema)
        self.assertNotIn("bearer", schema)

    def test_jwt_is_returned_only_after_jti_registration(self):
        service = self.read("gateway/internal/accountauth/service.go")
        register = service.index("service.ledger.RegisterToken")
        publish = service.index("return IssuedToken{Bearer: bearer")
        self.assertLess(register, publish)
        self.assertIn("return IssuedToken{}, err", service[register:publish])
        self.assertIn("exact session revision", service)

    def test_logout_and_issuance_share_account_revision_fence(self):
        postgres = self.read("gateway/internal/accountauth/postgres.go")
        self.assertIn("sql.LevelSerializable", postgres)
        self.assertIn("FOR UPDATE", postgres)
        self.assertIn("account.Revision != session.AccountRevision", postgres)
        self.assertIn("SET revision = revision + 1", postgres)
        self.assertIn("account_revision <= $5", postgres)
        self.assertIn('postgresError.Code == "40001"', postgres)
        self.assertIn('postgresError.Code == "40P01"', postgres)

    def test_introspection_uses_same_durable_ordering_domain(self):
        postgres = self.read("gateway/internal/accountauth/postgres.go")
        self.assertIn("FOR SHARE OF token, account", postgres)
        self.assertIn("tokenRevision != accountRevision", postgres)
        self.assertIn("stored != binding", postgres)
        self.assertIn("stored.ExpiresAt <= now.Unix()", postgres)
        self.assertIn("SELECT CURRENT_TIMESTAMP", postgres)

    def test_private_http_contract_requires_verified_mtls_and_canonical_json(self):
        handler = self.read("gateway/internal/accountauth/handler.go")
        server_tls = self.read("gateway/internal/accountauth/server_tls.go")
        self.assertIn("request.TLS.PeerCertificates", handler)
        self.assertIn("request.TLS.VerifiedChains", handler)
        self.assertIn("bytes.Equal(canonical, body)", handler)
        self.assertIn("http.StatusNoContent", handler)
        self.assertIn("http.StatusServiceUnavailable", handler)
        self.assertIn("tls.RequireAndVerifyClientCert", server_tls)
        self.assertIn("SessionTicketsDisabled: true", server_tls)

    def test_deployable_reader_verifies_schema_and_database_transport(self):
        config = self.read("gateway/internal/accountauth/config.go")
        command = self.read("gateway/cmd/accountauthorization/main.go")
        self.assertIn("ACCOUNT_AUTHORIZATION_DATABASE_URL", config)
        self.assertIn('sslModes[0] == "verify-full"', config)
        self.assertIn('sql.Open("pgx"', command)
        self.assertIn("ledger.VerifySchema()", command)
        self.assertIn("LoadIntrospectionMTLSServerConfig", command)
        self.assertIn("tls.NewListener(listener, tlsConfiguration)", command)
        self.assertIn("server.Serve(secureListener)", command)
        self.assertIn('log.New(io.Discard, "", 0)', command)
        self.assertNotIn("CompanionJWTIssuer", command)

    def test_idp_authentication_is_an_explicit_external_adapter_boundary(self):
        store = self.read("gateway/internal/accountauth/store.go")
        service = self.read("gateway/internal/accountauth/service.go")
        self.assertIn("external IdP adapter", store)
        self.assertIn("does not implement passwords, passkeys", service)
        self.assertNotIn("/login", service)
        self.assertNotIn("password", self.read(
            "gateway/migrations/account/0001_companion_authorization.sql"
        ))

    def test_cross_replica_database_gate_covers_revocation_races(self):
        integration = self.read(
            "gateway/internal/accountauth/postgres_integration_test.go"
        )
        gate = self.read(
            "tools/run_account_authorization_postgres_integration_gate.sh"
        )
        self.assertIn("ACCOUNT_AUTHORIZATION_TEST_DATABASE_URL", integration)
        self.assertIn("storeA.Introspect", integration)
        self.assertIn("serviceB.Logout", integration)
        self.assertIn("duplicate JTI winners", integration)
        self.assertIn("race token active", integration)
        self.assertIn("ACCOUNT_AUTHORIZATION_TEST_DATABASE_URL is required", gate)


if __name__ == "__main__":
    unittest.main()
