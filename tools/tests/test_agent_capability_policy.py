import pathlib
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class AgentCapabilityPolicyTests(unittest.TestCase):
    def read(self, path):
        return (PROJECT / path).read_text()

    def test_public_contract_is_closed_and_explicit(self):
        header = self.read(
            "components/esp_claw_runtime/include/esp_claw_runtime.h"
        )
        self.assertIn("ESP_CLAW_CAPABILITY_NONE = 0", header)
        self.assertIn("ESP_CLAW_CAPABILITY_DEVICE_GET_STATUS", header)
        self.assertIn("ESP_CLAW_CAPABILITY_DEVICE_SET_INDICATOR", header)
        self.assertIn("ESP_CLAW_CAPABILITY_ALL", header)
        self.assertIn("enabled_capabilities", header)
        self.assertIn("~ESP_CLAW_CAPABILITY_ALL", self.read(
            "components/esp_claw_runtime/esp_claw_runtime.c"
        ))

    def test_model_visibility_is_separate_for_read_and_action(self):
        runtime = self.read("components/esp_claw_runtime/esp_claw_runtime.c")
        self.assertIn('.group_id = "product_device_read"', runtime)
        self.assertIn('.group_id = "product_device_action"', runtime)
        self.assertIn("ESP_CLAW_CAPABILITY_DEVICE_GET_STATUS) != 0", runtime)
        self.assertIn("ESP_CLAW_CAPABILITY_DEVICE_SET_INDICATOR) != 0", runtime)
        self.assertIn("claw_cap_set_llm_visible_groups", runtime)
        self.assertNotIn('snprintf(output, output_size, "{\\"ready\\":true}")', runtime)

    def test_every_direct_device_call_rechecks_context_and_policy(self):
        runtime = self.read("components/esp_claw_runtime/esp_claw_runtime.c")
        self.assertIn("root_request_context_valid(ctx)", runtime)
        self.assertIn("capability_enabled(ESP_CLAW_CAPABILITY_DEVICE_GET_STATUS)", runtime)
        self.assertIn("capability_enabled(ESP_CLAW_CAPABILITY_DEVICE_SET_INDICATOR)", runtime)
        self.assertGreaterEqual(
            runtime.count("CLAW_CAP_FLAG_ROOT_AGENT_ONLY"), 6
        )
        self.assertIn("CLAW_CAP_FLAG_RESTRICTED", runtime)

    def test_state_change_uses_one_use_request_session_grant(self):
        runtime = self.read("components/esp_claw_runtime/esp_claw_runtime.c")
        grant = self.read(
            "components/esp_claw_runtime/esp_claw_capability_grant_core.c"
        )
        for binding in (
            "ctx->request_id",
            "ctx->session_id",
            "ESP_CLAW_CAPABILITY_GRANT_SET_INDICATOR",
            "esp_claw_capability_grant_core_consume",
            "revoke_request_grants(runtime, request_id)",
            "indicator_on ? 1U : 0U",
        ):
            self.assertIn(binding, runtime)
        self.assertIn("uint32_t argument_binding", grant)
        self.assertIn("entry->argument_binding != argument_binding", grant)
        self.assertIn("entry->flags &= ~flag", grant)
        self.assertIn("memset(entry, 0", grant)

    def test_trusted_consent_and_metadata_only_audit_are_required(self):
        header = self.read(
            "components/esp_claw_runtime/include/esp_claw_runtime.h"
        )
        runtime = self.read("components/esp_claw_runtime/esp_claw_runtime.c")
        app = self.read("main/app_main.c")
        self.assertIn("user_text alone is never", header)
        self.assertIn("Voice text is never passed", header)
        self.assertIn("esp_claw_capability_action_t", header)
        self.assertIn("ESP_CLAW_CAPABILITY_ACTION_SET_INDICATOR", header)
        self.assertIn("Metadata only", header)
        self.assertIn("!config->capability_consent", runtime)
        self.assertIn("!config->capability_audit", runtime)
        for decision in (
            "AUDIT_DENIED_DISABLED",
            "AUDIT_DENIED_CONTEXT",
            "AUDIT_DENIED_CONSENT",
            "AUDIT_INVALID_INPUT",
            "AUDIT_EXECUTION_FAILED",
            "AUDIT_EXECUTED",
        ):
            self.assertIn(decision, runtime)
        start = runtime.index("static esp_err_t set_indicator_execute")
        end = runtime.index("static bool parse_exact_object", start)
        action = runtime[start:end]
        self.assertLess(action.index("parse_exact_object"),
                        action.index("capability_consent"))
        self.assertLess(action.index("capability_consent"),
                        action.index("execute_approved_indicator_action"))
        commit = runtime[
            runtime.index("static esp_err_t execute_approved_indicator_action"):
            start
        ]
        self.assertLess(commit.index("canceled_request_id"),
                        commit.rindex("device_ops.set_indicator"))
        self.assertIn("committed_action_request_id", commit)
        submit = runtime[runtime.index("esp_err_t esp_claw_runtime_submit"):]
        submit = submit[:submit.index("esp_err_t esp_claw_runtime_cancel")]
        self.assertNotIn("capability_consent", submit)
        self.assertIn("Never log input/output JSON, memory values, or text", app)

    def test_box3_exposes_real_status_and_gated_indicator_adapter(self):
        app = self.read("main/app_main.c")
        sku = self.read("components/product_sku/product_sku_core.c")
        self.assertIn("product_agent_capabilities_for_sku()", app)
        self.assertIn("product_sku_capability_allowed(", app)
        self.assertIn("PRODUCT_SKU_CAPABILITY_DEVICE_GET_STATUS", app)
        self.assertIn(
            ".allowed_read_capabilities =\n"
            "        PRODUCT_SKU_CAPABILITY_DEVICE_GET_STATUS",
            sku,
        )
        self.assertIn("PRODUCT_SKU_CAPABILITY_DEVICE_SET_INDICATOR", sku)
        self.assertIn(".status_indicator_gpio = 47", sku)
        self.assertIn("CONFIG_PRODUCT_AGENT_INDICATOR_ACTION_ENABLE", app)
        self.assertIn("ESP_CLAW_CAPABILITY_DEVICE_SET_INDICATOR", app)
        self.assertIn("product_status_indicator_create", app)
        self.assertIn(".set_indicator = product_agent_set_indicator", app)
        self.assertIn("product_agent_get_status_json", app)
        self.assertIn("box3_product_runtime_get_stats", app)

    def test_no_arbitrary_upstream_execution_surface_is_imported(self):
        cmake = self.read("CMakeLists.txt")
        for forbidden in (
            "claw_modules/claw_memory",
            "claw_modules/claw_mcp",
            "claw_modules/claw_lua",
            "claw_modules/claw_shell",
        ):
            self.assertNotIn(forbidden, cmake)
        runtime = self.read("components/esp_claw_runtime/esp_claw_runtime.c")
        for forbidden_capability in (
            '"filesystem.', '"shell.', '"http.', '"ota.install"',
            '"factory_reset"', '"ownership.release"',
        ):
            self.assertNotIn(forbidden_capability, runtime)

    def test_host_and_release_runbook_keep_hardware_gates_explicit(self):
        runner = self.read("tools/run_host_tests.sh")
        runbook = self.read("AGENT_CAPABILITY_SECURITY_RUNBOOK.md")
        self.assertIn("test_esp_claw_capability_grant_core.c", runner)
        for statement in (
            "預設拒絕",
            "語音文字本身不是 consent",
            "不得記錄 input／output JSON",
            "BOX-3 開發驗證 profile",
            "禁止出貨",
        ):
            self.assertIn(statement, runbook)


if __name__ == "__main__":
    unittest.main()
