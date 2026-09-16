import pathlib
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class OwnershipPersistencePolicyTests(unittest.TestCase):
    def read(self, relative):
        return (PROJECT / relative).read_text(encoding="utf-8")

    def test_schema_separates_ephemeral_claims_owner_and_audit(self):
        schema = self.read(
            "gateway/migrations/ownership/0001_ownership.sql"
        )
        for table in (
            "ownership_app_nonces",
            "ownership_claims",
            "device_owners",
            "device_ownership_events",
        ):
            self.assertIn("CREATE TABLE " + table, schema)
        self.assertIn("claim_digest bytea NOT NULL UNIQUE", schema)
        self.assertNotIn("raw_claim", schema)
        self.assertNotIn("claim_code", schema)
        self.assertIn("UNIQUE (device_id, binding_revision)", schema)
        self.assertIn("status IN ('active', 'released')", schema)
        self.assertIn("event_type IN ('bind', 'release')", schema)

    def test_mutations_share_serializable_advisory_lock_domain(self):
        store = self.read("gateway/internal/deviceclaim/postgres.go")
        self.assertIn("sql.LevelSerializable", store)
        self.assertIn("pg_advisory_xact_lock", store)
        self.assertIn('"claim:" + hex.EncodeToString', store)
        self.assertIn('"device:" + deviceID', store)
        self.assertIn("maximumDBAttempts", store)
        self.assertIn('pgErr.Code == "40001"', store)
        self.assertIn('pgErr.Code == "40P01"', store)

    def test_database_time_drives_expiry_and_audit(self):
        store = self.read("gateway/internal/deviceclaim/postgres.go")
        self.assertIn("func transactionTime(", store)
        self.assertIn("SELECT CURRENT_TIMESTAMP", store)
        self.assertIn("databaseNow.Add(store.ttl)", store)
        self.assertIn("CURRENT_TIMESTAMP - ($1 * INTERVAL '1 second')", store)

    def test_serving_binary_verifies_exact_schema_contract(self):
        store = self.read("gateway/internal/deviceclaim/postgres.go")
        schema = self.read(
            "gateway/migrations/ownership/0001_ownership.sql"
        )
        contract = "xz-owner-v3-20260809-lifecycle"
        self.assertIn(contract, store)
        self.assertIn(contract, schema)
        self.assertIn("func (store *PostgresStore) VerifySchema() error", store)
        self.assertIn("postgresSchemaVersion  = 3", store)
        self.assertIn("postgresStore.VerifySchema()", self.read(
            "gateway/cmd/controlplane/main.go"
        ))

    def test_production_database_transport_fails_closed(self):
        config = self.read("gateway/internal/controlplane/config.go")
        command = self.read("gateway/cmd/controlplane/main.go")
        server = self.read("gateway/internal/controlplane/server.go")
        self.assertIn("OWNERSHIP_DATABASE_URL", config)
        self.assertIn('sslModes[0] != "verify-full"', config)
        self.assertIn('sql.Open("pgx"', command)
        self.assertIn("deviceclaim.ReadyOwnershipResolver", server)
        self.assertIn("ownership unavailable", server)

    def test_prune_cannot_remove_owner_or_audit(self):
        store = self.read("gateway/internal/deviceclaim/postgres.go")
        prune = store[store.index("func (store *PostgresStore) Prune"):]
        self.assertIn("DELETE FROM ownership_app_nonces", prune)
        self.assertIn("DELETE FROM ownership_claims", prune)
        self.assertNotIn("DELETE FROM device_owners", prune)
        self.assertNotIn("DELETE FROM device_ownership_events", prune)

    def test_live_gate_requires_an_explicit_test_database(self):
        gate = self.read("tools/run_ownership_postgres_integration_gate.sh")
        integration = self.read(
            "gateway/internal/deviceclaim/postgres_integration_test.go"
        )
        self.assertIn("OWNERSHIP_TEST_DATABASE_URL is required", gate)
        self.assertIn("storeA.Begin", integration)
        self.assertIn("storeB.Confirm", integration)
        self.assertIn("multiple race winners", integration)
        self.assertIn("audit retention after prune", integration)
        self.assertIn("storeA.Release", integration)
        self.assertIn("BindingRevision != 3", integration)


if __name__ == "__main__":
    unittest.main()
