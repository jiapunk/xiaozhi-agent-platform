from __future__ import annotations

import pathlib
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class RuntimeCoordinationPolicyTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (PROJECT / relative).read_text()

    def test_migration_stores_only_digests_and_fenced_ephemeral_state(self) -> None:
        migration = self.read(
            "gateway/migrations/ownership/0005_runtime_coordination.sql")
        self.assertIn("xz-runtime-coordination-v1-20260810", migration)
        self.assertGreaterEqual(migration.count("subject_sha256 bytea"), 4)
        self.assertIn("nonce_sha256 bytea", migration)
        self.assertIn("token_sha256 bytea", migration)
        self.assertIn("lease_id bytea", migration)
        self.assertGreaterEqual(
            migration.count("expires_at timestamptz NOT NULL"), 5)
        self.assertIn("runtime_coordination_proof_limit_expiry_idx", migration)
        self.assertIn("runtime_coordination_agent_limit_expiry_idx", migration)
        self.assertIn("PRIMARY KEY (lease_kind, subject_sha256)", migration)
        self.assertIn("CHECK (octet_length(lease_id) = 16)", migration)
        for forbidden in (
            "device_id varchar", "owner_id varchar", "tenant_id varchar",
            "token_id varchar", "nonce varchar",
        ):
            self.assertNotIn(forbidden, migration)

    def test_postgres_adapter_is_serializable_database_timed_and_fenced(self) -> None:
        adapter = self.read(
            "gateway/internal/runtimecoordination/postgres.go")
        self.assertIn("sql.LevelSerializable", adapter)
        self.assertIn("SELECT CURRENT_TIMESTAMP", adapter)
        self.assertIn("FOR UPDATE", adapter)
        self.assertIn("runtime_coordination_guard", adapter)
        self.assertIn("active >= MaximumProofNonces", adapter)
        self.assertIn("globalActive >= globalMaximum", adapter)
        self.assertIn(
            "DELETE FROM runtime_coordination_proof_limits WHERE expires_at <= $1",
            adapter,
        )
        self.assertIn(
            "DELETE FROM runtime_coordination_voice_tokens WHERE expires_at <= $1",
            adapter,
        )
        self.assertIn(
            "DELETE FROM runtime_coordination_agent_limits WHERE expires_at <= $1",
            adapter,
        )
        self.assertIn("lease_id = $3", adapter)
        self.assertIn("holder_id = $4", adapter)
        self.assertIn("ErrLeaseLost", adapter)
        self.assertIn('fmt.Errorf("%w: %s", ErrUnavailable, action)', adapter)
        self.assertNotIn("err.Error()", adapter)

    def test_all_three_runtime_paths_use_the_shared_contract(self) -> None:
        provisioning = self.read("gateway/internal/provisioning/proof.go")
        gateway = self.read("gateway/internal/gateway/handler.go")
        agent = self.read("gateway/internal/agentproxy/proxy.go")
        control_main = self.read("gateway/cmd/controlplane/main.go")
        gateway_main = self.read("gateway/cmd/gateway/main.go")
        agent_main = self.read("gateway/cmd/agentproxy/main.go")
        self.assertIn("coordinator.ReserveProof", provisioning)
        self.assertIn("AcquireVoice", gateway)
        self.assertIn("ConsumeVoiceToken", gateway)
        self.assertIn("renewRuntimeLease", gateway)
        self.assertIn("AcquireAgent", agent)
        self.assertIn("releaseRuntimeLease", agent)
        self.assertIn("proof.SetCoordinator(postgresCoordinator)", control_main)
        for source in (gateway_main, control_main, agent_main):
            self.assertIn("RUNTIME_COORDINATION_WORKER_ID", source)
            self.assertIn("VerifySchema", source)

    def test_deployment_keeps_seven_workloads_and_pod_binds_workers(self) -> None:
        deployment = self.read("tools/kubernetes_deployment.py")
        self.assertIn('"RUNTIME_COORDINATION_WORKER_ID"', deployment)
        self.assertIn('"fieldPath": "metadata.name"', deployment)
        self.assertIn(
            '"gateway": (("speech", 443), ("identity", 443), '
            '("database", 5432))', deployment)
        self.assertNotIn('"redis"', deployment.lower())

    def test_cross_replica_and_live_postgres_tests_remain_required(self) -> None:
        gateway_test = self.read("gateway/internal/gateway/handler_test.go")
        agent_test = self.read("gateway/internal/agentproxy/proxy_test.go")
        integration = self.read(
            "gateway/internal/runtimecoordination/postgres_integration_test.go")
        self.assertIn("TestSharedCoordinatorBlocksCrossReplicaVoiceAndTokenReplay",
                      gateway_test)
        self.assertIn("TestProxyUsesSharedAgentPermitAndFailsClosed", agent_test)
        self.assertIn("OWNERSHIP_TEST_DATABASE_URL", integration)
        self.assertIn("stale voice release fencing", integration)
        self.assertIn("proof tombstone capacity", integration)


if __name__ == "__main__":
    unittest.main()
