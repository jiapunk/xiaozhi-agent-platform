import json
import pathlib
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class ManagedDatabaseQualificationPolicyTests(unittest.TestCase):
    def read(self, path):
        return (PROJECT / path).read_text(encoding="utf-8")

    def test_exact_three_product_databases_have_append_only_canary_schema(self):
        migrations = [
            "gateway/migrations/ownership/0004_managed_database_qualification.sql",
            "gateway/migrations/account/0003_managed_database_qualification.sql",
            "gateway/migrations/factorytime/0002_managed_database_qualification.sql",
        ]
        for path in migrations:
            source = self.read(path)
            for required in (
                "xz_managed_database_qualification_schema",
                "managed_database_qualification_events",
                "xz-managed-db-qualification-v1-20260810",
                "PRIMARY KEY", "ON managed_database_qualification_events",
                "restore-marker", "restore-exclusion", "heartbeat", "post",
                "BEFORE UPDATE OR DELETE", "events are append-only",
            ):
                self.assertIn(required, source)

    def test_runner_requires_schema_node_change_and_exact_reconciliation(self):
        runner = self.read("gateway/internal/databasequalification/failover.go")
        store = self.read("gateway/internal/databasequalification/store.go")
        config = self.read("gateway/internal/databasequalification/config.go")
        dsn = self.read("gateway/internal/databasequalification/dsn.go")
        for required in (
            "VerifySchema", "Snapshot", "BeforeNodeBindingSHA256",
            "AfterNodeBindingSHA256", "AppendEvent", "LoadEvents",
            "EventsMatch", "PhaseRestoreMarker", "PhaseRestoreExclusion",
            "ON CONFLICT", "Existing", "SignalReady", "sslmode",
            '"verify-full"', "filepath.IsAbs", "ErrUnavailable",
        ):
            self.assertIn(required, runner + store + config + dsn)
        for forbidden in ('json:"database_url"', 'json:"password"'):
            self.assertNotIn(forbidden, self.read(
                "gateway/internal/databasequalification/observation.go"))

    def test_restore_requires_marker_and_excludes_every_later_phase(self):
        restore = self.read("gateway/internal/databasequalification/restore.go")
        observation = self.read(
            "gateway/internal/databasequalification/restore_observation.go")
        for required in (
            "len(events) != 2", "PhasePre", "PhaseRestoreMarker",
            "RestoreExclusionAbsent", "HeartbeatEventsAbsent",
            "PostFailoverEventAbsent", "RestoredEventCount",
            "SourceEndpointAuthoritySHA256", "RestoreEndpointAuthoritySHA256",
        ):
            self.assertIn(required, restore + observation)

    def test_final_receipt_rebuilds_m72_and_removes_only_software_gate(self):
        receipt = self.read("gateway/internal/databasequalification/receipt.go")
        manifest = self.read("gateway/internal/databasequalification/manifest.go")
        for required in (
            "providerrevocationqualification.VerifyReceiptFile",
            "providerrevocationqualification.BuildReceipt",
            "providerrevocationqualification.ReceiptMatchesEvidence",
            "VerifyDatabaseAttestationFile", "LoadFailoverObservation",
            "LoadRestoreObservation", "LoadReadySignal",
            "LIVE_MANAGED_DATABASE_FAILOVER_RESTORE_PASS",
            "liveDatabaseUnresolvedProductionGates",
            "= []string{}",
            "ProductionReady: false", "LoadEvidenceManifest",
            "DisallowUnknownFields",
        ):
            self.assertIn(required, receipt + manifest)

    def test_live_commands_require_explicit_ack_and_independent_manifest(self):
        commands = "".join(self.read(path) for path in (
            "gateway/cmd/qualifydatabasefailover/main.go",
            "gateway/cmd/qualifydatabaserestore/main.go",
            "gateway/cmd/signmanageddatabaseattestation/main.go",
            "gateway/cmd/buildmanageddatabasequalification/main.go",
            "gateway/cmd/validatemanageddatabasequalification/main.go",
        ))
        for required in (
            "acknowledge-live-managed-database-failover",
            "acknowledge-live-isolated-point-in-time-restore",
            "acknowledge-live-managed-database-provider-audit",
            "acknowledge-live-managed-database-qualification",
            "evidence-manifest", "trusted-public-key",
            "expected-signing-key-id", "require-live",
        ):
            self.assertIn(required, commands)

    def test_schemas_and_docs_keep_fixture_live_and_market_boundaries(self):
        names = (
            "managed-database-failover-config.schema.json",
            "managed-database-restore-config.schema.json",
            "managed-database-failover-ready.schema.json",
            "managed-database-failover-observation.schema.json",
            "managed-database-restore-observation.schema.json",
            "managed-database-provider-audit.schema.json",
            "managed-database-attestation.schema.json",
            "managed-database-qualification-receipt.schema.json",
            "managed-database-evidence-manifest.schema.json",
        )
        schemas = [json.loads(self.read("gateway/" + name)) for name in names]
        for schema in schemas:
            self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            schemas[0]["properties"]["acknowledge_managed_database_failover"],
            {"const": True},
        )
        self.assertEqual(
            schemas[1]["properties"]["acknowledge_isolated_point_in_time_restore"],
            {"const": True},
        )
        self.assertEqual(schemas[7]["properties"]["production_ready"],
                         {"const": False})
        self.assertEqual(schemas[8]["$defs"]["path"]["pattern"], "^/")
        docs = self.read("MANAGED_DATABASE_RESILIENCE_RUNBOOK.md") + self.read(
            "M73_MANAGED_DATABASE_RESILIENCE_REPORT.md") + self.read(
            "PRODUCT_MARKET_RELEASE_RUNBOOK.md")
        for required in (
            "LIVE_MANAGED_DATABASE_FAILOVER_RESTORE_PASS", "PITR", "RPO",
            "RTO", "WORM", "NO-GO", "MARKET_RELEASE_PASS",
        ):
            self.assertIn(required, docs)


if __name__ == "__main__":
    unittest.main()
