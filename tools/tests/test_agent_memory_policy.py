import pathlib
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class AgentMemoryPolicyTests(unittest.TestCase):
    def test_memory_is_bounded_and_not_transcript_storage(self):
        public = (
            PROJECT
            / "components"
            / "product_agent_memory"
            / "include"
            / "product_agent_memory.h"
        ).read_text()
        self.assertIn("PRODUCT_AGENT_MEMORY_ITEM_LIMIT = 8", public)
        self.assertIn("PRODUCT_AGENT_MEMORY_KEY_BYTES = 33", public)
        self.assertIn("PRODUCT_AGENT_MEMORY_VALUE_BYTES = 161", public)
        self.assertIn("PRODUCT_AGENT_MEMORY_MUTATIONS_PER_BOOT_LIMIT = 128", public)
        self.assertNotIn("transcript", public.lower())

    def test_memory_uses_product_nvs_owner_not_fat(self):
        source = (
            PROJECT
            / "components"
            / "product_agent_memory"
            / "product_agent_memory.c"
        ).read_text()
        self.assertIn('PARTITION = "nvs"', source)
        self.assertIn('NAMESPACE = "agent_mem"', source)
        self.assertIn("product_storage_require_ready", source)
        self.assertNotIn("esp_vfs_fat", source)
        self.assertNotIn("nvs_flash_init", source)

    def test_runtime_has_request_bound_one_use_consent(self):
        runtime = (
            PROJECT
            / "components"
            / "esp_claw_runtime"
            / "esp_claw_runtime.c"
        ).read_text()
        grants = (
            PROJECT
            / "components"
            / "esp_claw_runtime"
            / "esp_claw_memory_grant_core.c"
        ).read_text()
        self.assertIn("memory_consent", runtime)
        self.assertIn("ctx->request_id", runtime)
        self.assertIn("ctx->session_id", runtime)
        self.assertIn("CLAW_CAP_CALLER_ROOT_AGENT", runtime)
        self.assertIn("esp_claw_memory_grant_core_consume", runtime)
        self.assertIn("entry->flags &= ~flag", grants)
        self.assertIn("revoke_request_grants(runtime, request_id)", runtime)
        self.assertIn('audit_capability("memory.put"', runtime)
        self.assertIn('audit_capability("memory.forget"', runtime)

    def test_llm_cannot_bulk_clear_or_auto_persist(self):
        runtime = (
            PROJECT
            / "components"
            / "esp_claw_runtime"
            / "esp_claw_runtime.c"
        ).read_text()
        for capability in (
            '"memory.list"',
            '"memory.get"',
            '"memory.put"',
            '"memory.forget"',
        ):
            self.assertIn(capability, runtime)
        self.assertNotIn('"memory.clear"', runtime)
        self.assertNotIn("persist_context =", runtime)
        self.assertIn("untrusted_user_data", runtime)
        self.assertIn("Never store", runtime)
        self.assertIn("conversation transcripts or secrets", runtime)

    def test_upstream_filesystem_memory_is_not_imported(self):
        cmake = (PROJECT / "CMakeLists.txt").read_text()
        self.assertNotIn("claw_modules/claw_memory", cmake)
        self.assertNotIn("edge_agent", cmake)
        self.assertNotIn("app_claw", cmake)

    def test_production_profile_protects_the_nvs_partition(self):
        defaults = (PROJECT / "sdkconfig.secure-storage.defaults").read_text()
        self.assertIn(
            "CONFIG_PRODUCT_STORAGE_REQUIRE_HMAC_NVS_ENCRYPTION=y",
            defaults,
        )
        self.assertIn("CONFIG_PRODUCT_STORAGE_NVS_HMAC_KEY_ID=4", defaults)


if __name__ == "__main__":
    unittest.main()
