from __future__ import annotations

import json
import pathlib
import sys
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT / "tools"))
import kubernetes_deployment as K8S


class AgentUsageBudgetPolicyTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (PROJECT / relative).read_text(encoding="utf-8")

    def test_migration_is_content_free_and_cross_profile_budgeted(self) -> None:
        migration = self.read(
            "gateway/migrations/ownership/0006_agent_usage_budget.sql")
        for required in (
            "xz-agent-usage-budget-v1-20260811",
            "agent_usage_pricing_profiles",
            "agent_usage_budget_daily",
            "agent_usage_profile_daily",
            "agent_usage_reservations",
            "subject_hmac bytea",
            "CHECK (octet_length(subject_hmac) = 32)",
            "pricing_profile_id",
            "uncertain_cost_microusd",
            "reserved_cost_microusd",
            "agent_usage_reservation_expiry_idx",
        ):
            self.assertIn(required, migration)
        ddl = "\n".join(line for line in migration.lower().splitlines()
                        if not line.lstrip().startswith("--"))
        for forbidden in (
            "device_id", "owner_id", "tenant_id", "binding_id",
            "prompt", "message", "content", "provider_url", "model_output",
        ):
            self.assertNotIn(forbidden, ddl)

    def test_postgres_adapter_reserves_then_settles_or_marks_uncertain(self) -> None:
        adapter = self.read("gateway/internal/usagebudget/postgres.go")
        contract = self.read("gateway/internal/usagebudget/contract.go")
        for required in (
            "sql.LevelSerializable", "CURRENT_TIMESTAMP",
            "AT TIME ZONE 'UTC'", "FOR UPDATE OF d, r",
            "reconcileExpired", "FOR UPDATE SKIP LOCKED",
            "ErrBudgetExceeded", "ErrUsageExceeded",
            "committed+uncertain+alreadyReserved",
            "subjectHMAC", "hmac.New(sha256.New",
            "DailyBudgetMicrousd", "reservationCost",
        ):
            self.assertIn(required, adapter + contract)
        self.assertNotIn("err.Error()", adapter)

    def test_proxy_requires_usage_and_never_delivers_before_settlement(self) -> None:
        proxy = self.read("gateway/internal/agentproxy/proxy.go")
        reserve = proxy.index("UsageLedger.Reserve")
        contact = proxy.index("HTTPClient.Do")
        settle = proxy.index("UsageLedger.Settle")
        deliver = proxy.index('writer.WriteHeader(http.StatusOK)')
        self.assertLess(reserve, contact)
        self.assertLess(contact, settle)
        self.assertLess(settle, deliver)
        for required in (
            "providerUsage", "PromptTokens", "CompletionTokens", "TotalTokens",
            "markUsageUncertain", "usage.Validate()",
            "xiaozhi_agent_proxy_budget_rejected_total",
            "xiaozhi_agent_proxy_usage_uncertain_microusd_total",
        ):
            self.assertIn(required, proxy)
        metrics = proxy[proxy.index("func (proxy *Proxy) metrics"):]
        for forbidden in ("device_id", "owner_id", "tenant_id", "ownedScope"):
            self.assertNotIn(forbidden, metrics)

    def test_production_configuration_uses_private_isolated_key(self) -> None:
        config = self.read("gateway/internal/agentproxy/config.go")
        key = self.read("gateway/internal/usagebudget/key.go")
        for required in (
            "AGENT_PRICING_PROFILE_ID",
            "AGENT_INPUT_MICROUSD_PER_MILLION_TOKENS",
            "AGENT_OUTPUT_MICROUSD_PER_MILLION_TOKENS",
            "AGENT_DAILY_BUDGET_MICROUSD",
            "AGENT_USAGE_DIGEST_KEY_FILE",
            "ReservationTTL < settings.RequestTimeout+15*time.Second",
        ):
            self.assertIn(required, config)
        for required in ("os.Lstat", "os.SameFile", "Mode().Perm()&0o077", "len(decoded) != 32"):
            self.assertIn(required, key)
        self.assertNotIn("AGENT_TOKEN_HMAC", key)

    def test_signed_kubernetes_v7_profile_carries_pricing_without_eighth_service(self) -> None:
        profile_path = PROJECT / "deployment/kubernetes-deployment-profile.example.json"
        profile, _ = K8S.load_profile(profile_path)
        self.assertEqual(K8S.SCHEMA_VERSION, 7)
        self.assertEqual(len(K8S.SERVICES), 7)
        env = {item["name"]: item.get("value") for item in
               K8S._fixed_env(profile, "agentproxy")}
        for key in (
            "AGENT_PRICING_PROFILE_ID",
            "AGENT_INPUT_MICROUSD_PER_MILLION_TOKENS",
            "AGENT_OUTPUT_MICROUSD_PER_MILLION_TOKENS",
            "AGENT_DAILY_BUDGET_MICROUSD",
            "AGENT_INPUT_TOKEN_OVERHEAD",
            "AGENT_USAGE_RESERVATION_TTL_SECONDS",
            "AGENT_USAGE_DIGEST_KEY_FILE",
        ):
            self.assertIn(key, env)
        self.assertIn("usage-digest.key", K8S.SECRET_FILE_KEYS["agentproxy"])
        pod = K8S._pod_spec(profile, "agentproxy", "registry.example/agentproxy@sha256:" + "0" * 64)
        self.assertIn({
            "mountPath": "/run/secrets/files/usage-digest.key",
            "name": "service-files", "readOnly": True,
            "subPath": "usage-digest.key",
        }, pod["containers"][0]["volumeMounts"])
        prerequisites = K8S.build_prerequisites(profile)
        objects = prerequisites["objects"]
        self.assertEqual(len([item for item in objects
                              if item.get("purpose") == "secret-files"]), 7)
        self.assertNotIn("notification", json.dumps(objects).lower())

    def test_oci_source_manifest_binds_database_migrations(self) -> None:
        source = self.read("tools/oci_release.py")
        self.assertIn('(project_root / "gateway/migrations").rglob("*.sql")',
                      source)

    def test_runbook_keeps_live_billing_and_speech_cost_open(self) -> None:
        docs = self.read("AGENT_USAGE_BUDGET_RUNBOOK.md") + self.read(
            "M81_AGENT_USAGE_BUDGET_REPORT.md")
        for required in (
            "micro-USD", "ASR", "TTS", "真實供應商", "NO-GO",
            "MARKET_RELEASE_PASS", "不保存 prompt", "WORM",
        ):
            self.assertIn(required, docs)


if __name__ == "__main__":
    unittest.main()
