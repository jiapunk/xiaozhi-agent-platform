import pathlib
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class FactoryResetPolicyTests(unittest.TestCase):
    def read(self, path):
        return (PROJECT / path).read_text()

    def test_boot_resumes_before_sensitive_state_opens(self):
        app = self.read("main/app_main.c")
        boot = app[app.index("void app_main(void)") :]
        resume = boot.index("product_factory_reset_resume")
        memory = boot.index("product_agent_memory_open")
        runtime = boot.index("start_product_runtime()")
        self.assertLess(resume, memory)
        self.assertLess(memory, runtime)
        self.assertIn("Factory reset recovery failed closed", boot)

    def test_erase_scope_is_exact_and_never_partition_wide(self):
        source = self.read(
            "components/product_factory_reset/product_factory_reset.c"
        )
        self.assertIn('WIFI_NAMESPACE = "prod_wifi"', source)
        self.assertIn('MEMORY_NAMESPACE = "agent_mem"', source)
        self.assertEqual(source.count("nvs_erase_all(nvs)"), 1)
        for forbidden in (
            "nvs_flash_erase",
            "nvs_factory",
            "esp_efuse",
            "HMAC_KEY",
            "ota_",
        ):
            self.assertNotIn(forbidden, source)

    def test_intent_commit_precedes_restart(self):
        reset = self.read(
            "components/product_factory_reset/product_factory_reset.c"
        )
        prepare = reset[reset.index("product_factory_reset_prepare") :]
        self.assertIn("write_phase", prepare)
        self.assertIn("nvs_commit(journal)", reset)
        runtime = self.read(
            "components/box3_product_runtime/box3_product_runtime.c"
        )
        trigger = runtime[runtime.index("trigger_from_local_action") :]
        self.assertLess(
            trigger.index("product_factory_reset_prepare"),
            trigger.index("esp_restart()"),
        )
        self.assertIn("xTaskCreate(factory_reset_restart_task", trigger)
        action = self.read(
            "components/product_local_action/product_local_action.c"
        )
        branch = action[action.index(
            "PRODUCT_LOCAL_ACTION_TRANSITION_FACTORY_RESET"
        ) :]
        self.assertLess(branch.index("action->trigger("),
                        branch.index("PRODUCT_LOCAL_ACTION_EVENT_FACTORY_RESET"))

    def test_journal_order_is_wifi_memory_then_marker(self):
        core = self.read(
            "components/product_factory_reset/product_factory_reset_core.c"
        )
        order = core[core.index("product_factory_reset_core_next_action") :]
        self.assertLess(order.index("ACTION_ERASE_WIFI"),
                        order.index("ACTION_ERASE_MEMORY"))
        self.assertLess(order.index("ACTION_ERASE_MEMORY"),
                        order.index("ACTION_CLEAR_JOURNAL"))
        reset = self.read(
            "components/product_factory_reset/product_factory_reset.c"
        )
        self.assertIn("product_factory_reset_core_advance", reset)
        self.assertIn("write_phase(journal, next_phase)", reset)

    def test_physical_reset_is_release_classified(self):
        core = self.read(
            "components/product_local_action/product_local_action_core.c"
        )
        release = core[core.index("const bool completed_press") :]
        self.assertIn("core->raw_changed_at_ms - core->pressed_at_ms", release)
        self.assertIn("PRODUCT_LOCAL_ACTION_TRANSITION_FACTORY_RESET", release)
        before_release = core[: core.index("const bool completed_press")]
        self.assertNotIn("TRANSITION_FACTORY_RESET", before_release)
        self.assertIn("core->armed = false", core)

    def test_release_thresholds_are_frozen_and_ordered(self):
        kconfig = self.read("main/Kconfig.projbuild")
        self.assertIn("config PRODUCT_FACTORY_RESET_PRESS_MS", kconfig)
        self.assertIn("default 10000", kconfig)
        cmake = self.read("main/CMakeLists.txt")
        self.assertIn("CONFIG_PRODUCT_FACTORY_RESET_PRESS_MS LESS_EQUAL", cmake)
        self.assertIn("CONFIG_PRODUCT_ONBOARDING_BUTTON_LONG_PRESS_MS", cmake)

    def test_host_gate_covers_crc_and_every_power_cut_boundary(self):
        test = self.read("tests/host/test_product_factory_reset_core.c")
        self.assertIn("test_journal_round_trip_and_corruption", test)
        self.assertIn("test_every_power_cut_boundary_converges", test)
        self.assertIn("checkpoint < 6", test)
        runner = self.read("tools/run_host_tests.sh")
        self.assertIn("test_product_factory_reset_core.c", runner)

    def test_resale_runbook_separates_cloud_and_local_actions(self):
        runbook = self.read("FACTORY_RESET_RESALE_RUNBOOK.md")
        self.assertIn("恢復原廠」只清除裝置本機資料", runbook)
        self.assertIn("只做實體恢復原廠的裝置仍屬於原 owner", runbook)
        self.assertIn("nvs_factory", runbook)
        self.assertIn("eFuse", runbook)
        self.assertIn("真機出貨驗收矩陣", runbook)


if __name__ == "__main__":
    unittest.main()
