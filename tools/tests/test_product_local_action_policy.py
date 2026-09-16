import pathlib
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class ProductLocalActionPolicyTests(unittest.TestCase):
    def test_box3_release_profile_uses_reviewed_gpio0_active_low(self):
        kconfig = (PROJECT / "main" / "Kconfig.projbuild").read_text()
        section = kconfig[kconfig.index("config PRODUCT_ONBOARDING_BUTTON_GPIO") :]
        self.assertIn("default 0", section)
        self.assertIn("config PRODUCT_ONBOARDING_BUTTON_ACTIVE_HIGH", section)
        self.assertIn("default n", section)
        self.assertIn("default 3000", section)
        self.assertIn("config PRODUCT_FACTORY_RESET_PRESS_MS", section)
        self.assertIn("default 10000", section)
        defaults = (
            PROJECT / "sdkconfig.live-runtime-compile.defaults"
        ).read_text()
        self.assertIn("CONFIG_PRODUCT_ONBOARDING_BUTTON_GPIO=0", defaults)
        self.assertIn(
            "# CONFIG_PRODUCT_ONBOARDING_BUTTON_ACTIVE_HIGH is not set",
            defaults,
        )
        self.assertIn("CONFIG_PRODUCT_FACTORY_RESET_PRESS_MS=10000", defaults)

    def test_app_wires_release_values_only_into_aggregate(self):
        source = (PROJECT / "main" / "app_main.c").read_text()
        self.assertIn(
            ".onboarding_button_gpio = CONFIG_PRODUCT_ONBOARDING_BUTTON_GPIO",
            source,
        )
        self.assertIn("PRODUCT_ONBOARDING_BUTTON_ACTIVE_HIGH_VALUE", source)
        self.assertIn("BOX3_PRODUCT_RUNTIME_EVENT_LOCAL_ACTION", source)
        self.assertNotIn(
            "box3_product_runtime_open_onboarding(s_product_runtime", source
        )

    def test_gpio_polling_owner_never_runs_action_from_an_isr(self):
        source = (
            PROJECT
            / "components"
            / "product_local_action"
            / "product_local_action.c"
        ).read_text()
        self.assertIn("gpio_get_level", source)
        self.assertIn("GPIO_MODE_INPUT", source)
        self.assertIn("GPIO_INTR_DISABLE", source)
        self.assertNotIn("gpio_isr", source.lower())
        self.assertNotIn("xQueueSendFromISR", source)
        self.assertEqual(source.count("action->trigger("), 2)

    def test_core_requires_release_and_classifies_once_per_press(self):
        source = (
            PROJECT
            / "components"
            / "product_local_action"
            / "product_local_action_core.c"
        ).read_text()
        self.assertIn("core->armed = true", source)
        self.assertIn("core->raw_changed_at_ms - core->pressed_at_ms", source)
        self.assertIn(
            "core->completed_hold_ms >= core->factory_reset_press_ms", source
        )
        self.assertNotIn("long_press_fired", source)
        self.assertIn("now_ms < core->last_sample_at_ms", source)

    def test_runtime_stops_button_owner_before_provisioning(self):
        source = (
            PROJECT
            / "components"
            / "box3_product_runtime"
            / "box3_product_runtime.c"
        ).read_text()
        cleanup = source[source.index("static esp_err_t cleanup_runtime") :]
        local_action = cleanup.index("RESOURCE_LOCAL_ACTION")
        provisioning = cleanup.index("RESOURCE_PROVISIONING")
        self.assertLess(local_action, provisioning)
        self.assertIn("product_local_action_start(runtime->local_action)", source)
        cmake = (PROJECT / "main" / "CMakeLists.txt").read_text()
        self.assertIn(
            "CONFIG_PRODUCT_ONBOARDING_BUTTON_DEBOUNCE_MS LESS", cmake
        )
        self.assertIn(
            "CONFIG_PRODUCT_ONBOARDING_BUTTON_GPIO EQUAL 0", cmake
        )
        self.assertIn(
            "CONFIG_PRODUCT_ONBOARDING_BUTTON_ACTIVE_HIGH", cmake
        )
        self.assertIn("CONFIG_PRODUCT_FACTORY_RESET_PRESS_MS LESS_EQUAL", cmake)

    def test_gpio_owner_itself_cannot_erase_identity_or_credentials(self):
        component = PROJECT / "components" / "product_local_action"
        text = "\n".join(
            path.read_text()
            for path in component.rglob("*")
            if path.is_file() and path.suffix in {".c", ".h"}
        )
        for forbidden in (
            "nvs_erase",
            "esp_efuse",
            "product_wifi_clear_credentials",
            "esp_restart",
        ):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
