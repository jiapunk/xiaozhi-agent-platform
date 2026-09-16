import hashlib
import json
import pathlib
import subprocess
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]
PATCH = PROJECT / "patches/esp-claw/0001-redact-agent-content-logs.patch"
CLAW = PROJECT / "third_party/esp-claw"


class AgentContentLogPolicyTests(unittest.TestCase):
    def read(self, path):
        return (PROJECT / path).read_text()

    def test_product_patch_is_digest_locked_and_reproducible(self):
        lock = json.loads(self.read("upstream.lock.json"))
        patches = lock["upstreams"]["esp-claw"]["patches"]
        self.assertEqual(len(patches), 1)
        self.assertEqual(patches[0]["path"], str(PATCH.relative_to(PROJECT)))
        digest = hashlib.sha256(PATCH.read_bytes()).hexdigest()
        self.assertEqual(patches[0]["sha256"], digest)
        sync = self.read("tools/sync_upstreams.sh")
        self.assertIn(digest, sync)
        self.assertIn('git -C "$third_party_dir/esp-claw"', sync)
        self.assertIn('apply --check "$esp_claw_patch"', sync)
        self.assertIn('apply "$esp_claw_patch"', sync)

    def test_checked_out_claw_matches_the_locked_patch(self):
        diff = subprocess.run(
            ["git", "-C", str(CLAW), "diff", "--binary"],
            check=True, capture_output=True, text=True,
        ).stdout
        self.assertEqual(diff, PATCH.read_text())
        reverse = subprocess.run(
            ["git", "-C", str(CLAW), "apply", "--reverse", "--check",
             str(PATCH)], capture_output=True, text=True,
        )
        self.assertEqual(reverse.returncode, 0, reverse.stderr)

    def test_completion_tool_and_reasoning_logs_are_content_free(self):
        context = self.read(
            "third_party/esp-claw/components/claw_modules/claw_core/src/"
            "claw_core_context.c"
        )
        utils = self.read(
            "third_party/esp-claw/components/claw_modules/claw_core/src/"
            "claw_core_utils.c"
        )
        for forbidden in (
            "status=done raw=", "args=%.*s", "output=%.*s",
            "llm_reasoning_content", "content=%.*s",
        ):
            self.assertNotIn(forbidden, context + utils)
        for required in (
            "text_len=%u", "args_len=%u", "output_len=%u",
            "content_len=%u",
        ):
            self.assertIn(required, context + utils)

    def test_provider_error_body_never_becomes_log_or_agent_error(self):
        transport = self.read(
            "third_party/esp-claw/components/claw_modules/claw_core/src/llm/"
            "claw_llm_http_transport.c"
        )
        parser = transport[
            transport.index("static char *parse_error_message_body"):
            transport.index("esp_err_t claw_llm_http_post_json")
        ]
        self.assertIn("(void)body", parser)
        self.assertIn('dup_printf("HTTP %d", status)', parser)
        self.assertNotIn("cJSON_Parse", parser)
        self.assertNotIn("valuestring", parser)
        self.assertNotIn('"LLM error: %s"', transport)

    def test_full_request_and_verbose_stage_modes_fail_product_policy(self):
        llm = self.read(
            "third_party/esp-claw/components/claw_modules/claw_core/src/"
            "claw_core_llm.c"
        )
        cmake = self.read("main/CMakeLists.txt")
        self.assertIn("Product builds forbid full LLM request logging", llm)
        self.assertIn("CLAW_CORE_LOG_FULL_LLM_REQUEST", llm)
        self.assertIn("CONFIG_CLAW_CORE_STAGE_VERBOSITY_SIMPLE", cmake)
        self.assertIn("CONFIG_CLAW_CORE_STAGE_VERBOSITY_VERBOSE", cmake)
        self.assertIn("forbids Agent reasoning/tool arguments", cmake)
        self.assertIn("CONFIG_LOG_MAXIMUM_LEVEL GREATER 3", cmake)
        self.assertIn("CONFIG_ESP_COREDUMP_ENABLE", cmake)
        self.assertIn("forbids unreviewed core dumps", cmake)

    def test_live_runtime_does_not_enable_context_or_stage_persistence(self):
        runtime = self.read("components/esp_claw_runtime/esp_claw_runtime.c")
        self.assertNotIn("CLAW_CORE_REQUEST_FLAG_PUBLISH_STAGE_MESSAGE", runtime)
        self.assertNotIn("CLAW_CORE_REQUEST_FLAG_PUBLISH_OUT_MESSAGE", runtime)
        self.assertNotIn(".persist_context", runtime)
        self.assertNotIn(".collect_stage_note", runtime)

    def test_observability_retains_only_closed_saturating_counters(self):
        header = self.read(
            "components/product_agent_observability/include/"
            "product_agent_observability.h"
        )
        source = self.read(
            "components/product_agent_observability/"
            "product_agent_observability.c"
        )
        app = self.read("main/app_main.c")
        counter_struct = header[
            header.index("typedef struct {"):
            header.index("} product_agent_observability_stats_t;")
        ]
        for forbidden in ("session_id", "request_id", "char *"):
            self.assertNotIn(forbidden, counter_struct)
        for forbidden in ("ESP_LOG", "input_json", "output_json", "user_text"):
            self.assertNotIn(forbidden, header + source)
        self.assertIn("saturating_increment", source)
        self.assertIn("current != UINT_MAX", source)
        for capability in (
            "device.get_status", "device.set_indicator", "memory.list",
            "memory.get", "memory.put", "memory.forget",
        ):
            self.assertIn(capability, source)
        self.assertIn(
            ".capability_audit = product_agent_observability_record", app
        )
        self.assertNotIn("product_agent_capability_audit", app)

    def test_runbook_forbids_content_and_keeps_release_gates(self):
        runbook = self.read("AGENT_CONTENT_PRIVACY_OBSERVABILITY_RUNBOOK.md")
        for statement in (
            "內容零落盤", "不得記錄 prompt／response",
            "provider error body", "只允許單調飽和計數器",
            "禁止出貨", "合成資料",
        ):
            self.assertIn(statement, runbook)


if __name__ == "__main__":
    unittest.main()
