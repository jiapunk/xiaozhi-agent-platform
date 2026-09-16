from __future__ import annotations

import json
import pathlib
import sys
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT / "tools"))
import kubernetes_deployment as K8S


class SpeechUsageBudgetPolicyTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (PROJECT / relative).read_text(encoding="utf-8")

    def test_migration_is_content_free_and_cross_mode_budgeted(self) -> None:
        migration = self.read(
            "gateway/migrations/ownership/0007_speech_usage_budget.sql")
        for required in (
            "xz-speech-usage-budget-v1-20260811",
            "speech_usage_pricing_profiles",
            "speech_usage_budget_daily",
            "speech_usage_profile_daily",
            "speech_usage_reservations",
            "committed_stt_audio_ms",
            "committed_tts_characters",
            "committed_tts_output_audio_ms",
            "uncertain_cost_microusd",
            "speech_usage_reservation_expiry_idx",
        ):
            self.assertIn(required, migration)
        ddl = "\n".join(line for line in migration.lower().splitlines()
                        if not line.lstrip().startswith("--"))
        for forbidden in (
            "device_id", "owner_id", "tenant_id", "binding_id",
            "transcript", "request_text", "audio_payload", "provider_url",
        ):
            self.assertNotIn(forbidden, ddl)

    def test_postgres_adapter_is_serializable_hmac_and_crash_conservative(self) -> None:
        adapter = self.read("gateway/internal/speechbudget/postgres.go")
        contract = self.read("gateway/internal/speechbudget/contract.go")
        for required in (
            "sql.LevelSerializable", "CURRENT_TIMESTAMP",
            "AT TIME ZONE 'UTC'", "FOR UPDATE OF d, r",
            "reconcileExpired", "FOR UPDATE SKIP LOCKED",
            "ErrBudgetExceeded", "ErrUsageExceeded",
            "committed+uncertain+alreadyReserved",
            "subjectHMAC", "hmac.New(sha256.New",
            "STTMicrousdPerMillionAudioMS",
            "TTSMicrousdPerMillionCharacters",
            "TTSMicrousdPerMillionOutputAudioMS",
        ):
            self.assertIn(required, adapter + contract)
        self.assertNotIn("err.Error()", adapter)

    def test_gateway_reserves_before_provider_and_fails_conservatively(self) -> None:
        meter = self.read("gateway/internal/gateway/speech_meter.go")
        handler = self.read("gateway/internal/gateway/handler.go")
        stt_reserve = meter.index("meter.ledger.Reserve")
        stt_send = meter.index("if err := send()")
        self.assertLess(stt_reserve, stt_send)
        tts_reserve = handler.index("connection.server.reserveTTS")
        tts_provider = handler.index("config.Synthesizer.Stream")
        self.assertLess(tts_reserve, tts_provider)
        for required in (
            "markUncertainLocked", "uncertainTTS",
            "speech_budget_exceeded", "speech_budget_unavailable",
            "speechCommittedMicrousd", "speechUncertainMicrousd",
            "utf8.RuneCountInString", "TTSMaxOutputAudioMS",
        ):
            self.assertIn(required, meter + handler)

    def test_tts_adapter_enforces_the_reserved_duration(self) -> None:
        adapter = self.read("gateway/internal/tts/framed_http.go")
        self.assertIn("MaxOutputAudioMS", adapter)
        self.assertIn("client.maxFrames", adapter)
        self.assertIn("exceeded maximum output duration", adapter)

    def test_content_free_errors_have_product_safe_device_semantics(self) -> None:
        handler_test = self.read("gateway/internal/gateway/handler_test.go")
        adapter = self.read(
            "components/xiaozhi_agent_adapter/xiaozhi_agent_adapter.c")
        client = self.read("components/device_voice_client/device_voice_client.c")
        client_header = self.read(
            "components/device_voice_client/include/device_voice_client.h")
        supervisor = self.read(
            "components/box3_agent_supervisor/box3_agent_supervisor.c")
        adapter_test = self.read("tests/host/test_xiaozhi_agent_adapter.c")
        runtime_test = self.read("tests/host/test_device_voice_runtime.c")
        for required in (
            "TestSpeechBudgetErrorsAreContentFreeAndDoNotCountAsProtocolViolations",
            "len(fields) != 2", "write after STT budget rejection",
            "protocolViolations.Load() != 0",
        ):
            self.assertIn(required, handler_test)
        for required in (
            "XIAOZHI_AGENT_SERVICE_ERROR_SPEECH_BUDGET_EXCEEDED",
            "XIAOZHI_AGENT_SERVICE_ERROR_SPEECH_BUDGET_UNAVAILABLE",
            "VOICE_AGENT_TTS_ERROR",
        ):
            self.assertIn(required, adapter)
        for required in (
            "DEVICE_VOICE_CLIENT_EVENT_SPEECH_BUDGET_EXCEEDED",
            "DEVICE_VOICE_CLIENT_EVENT_SPEECH_BUDGET_UNAVAILABLE",
        ):
            self.assertIn(required, client + client_header)
        self.assertIn("set_capture(client, false)", client)
        self.assertIn("DEVICE_VOICE_CLIENT_EVENT_SPEECH_BUDGET_UNAVAILABLE",
                      supervisor)
        self.assertNotIn(
            "event->type == DEVICE_VOICE_CLIENT_EVENT_SPEECH_BUDGET_EXCEEDED",
            supervisor)
        self.assertIn(
            "test_speech_budget_errors_are_typed_and_reset_tts", adapter_test)
        self.assertIn(
            "test_speech_budget_error_resets_pending_tts", runtime_test)

    def test_production_configuration_uses_an_isolated_private_key(self) -> None:
        config = self.read("gateway/internal/config/config.go")
        key = self.read("gateway/internal/speechbudget/key.go")
        main = self.read("gateway/cmd/gateway/main.go")
        for required in (
            "SPEECH_PRICING_PROFILE_ID",
            "SPEECH_STT_MICROUSD_PER_MILLION_AUDIO_MS",
            "SPEECH_TTS_MICROUSD_PER_MILLION_CHARACTERS",
            "SPEECH_TTS_MICROUSD_PER_MILLION_OUTPUT_AUDIO_MS",
            "SPEECH_DAILY_BUDGET_MICROUSD",
            "SPEECH_USAGE_DIGEST_KEY_FILE",
        ):
            self.assertIn(required, config)
        for required in (
            "os.Lstat", "os.SameFile", "Mode().Perm()&0o077",
            "len(decoded) != 32",
        ):
            self.assertIn(required, key)
        self.assertIn("speechbudget.NewPostgresLedger", main)
        self.assertNotIn("AGENT_USAGE_DIGEST", key)

    def test_signed_kubernetes_v7_profile_preserves_seven_workloads(self) -> None:
        profile, _ = K8S.load_profile(
            PROJECT / "deployment/kubernetes-deployment-profile.example.json")
        self.assertEqual(K8S.SCHEMA_VERSION, 7)
        self.assertEqual(len(K8S.SERVICES), 7)
        env = {item["name"]: item.get("value") for item in
               K8S._fixed_env(profile, "gateway")}
        for key in (
            "SPEECH_PRICING_PROFILE_ID",
            "SPEECH_STT_MICROUSD_PER_MILLION_AUDIO_MS",
            "SPEECH_TTS_MICROUSD_PER_MILLION_CHARACTERS",
            "SPEECH_TTS_MICROUSD_PER_MILLION_OUTPUT_AUDIO_MS",
            "SPEECH_DAILY_BUDGET_MICROUSD",
            "SPEECH_STT_RESERVATION_CHUNK_AUDIO_MS",
            "SPEECH_TTS_MAX_OUTPUT_AUDIO_MS",
            "SPEECH_USAGE_RESERVATION_TTL_SECONDS",
            "SPEECH_USAGE_DIGEST_KEY_FILE",
        ):
            self.assertIn(key, env)
        self.assertIn("speech-usage-digest.key",
                      K8S.SECRET_FILE_KEYS["gateway"])
        pod = K8S._pod_spec(profile, "gateway", "registry.example/gateway@sha256:" + "0" * 64)
        self.assertIn({
            "mountPath": "/run/secrets/files/speech-usage-digest.key",
            "name": "service-files", "readOnly": True,
            "subPath": "speech-usage-digest.key",
        }, pod["containers"][0]["volumeMounts"])
        prerequisites = K8S.build_prerequisites(profile)
        self.assertEqual(len(prerequisites["objects"]), 30)
        self.assertNotIn("speechbudget", json.dumps(K8S.SERVICES).lower())

    def test_runbook_keeps_live_price_invoice_traffic_and_market_open(self) -> None:
        docs = self.read("SPEECH_USAGE_BUDGET_RUNBOOK.md") + self.read(
            "M82_SPEECH_USAGE_BUDGET_REPORT.md")
        for required in (
            "micro-USD", "Unicode scalar", "ASR", "TTS", "NO-GO",
            "真實供應商", "invoice", "WORM", "MARKET_RELEASE_PASS",
        ):
            self.assertIn(required, docs)


if __name__ == "__main__":
    unittest.main()
