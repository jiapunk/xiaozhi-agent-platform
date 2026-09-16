import pathlib
import stat
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class ProductRuntimePolicyTests(unittest.TestCase):
    def test_live_runtime_is_opt_in_and_requires_release_authorities(self):
        kconfig = (PROJECT / "main" / "Kconfig.projbuild").read_text()
        self.assertIn("config PRODUCT_LIVE_RUNTIME_ENABLE", kconfig)
        self.assertIn("depends on PRODUCT_BOARD_ESP_BOX_3", kconfig)
        self.assertIn('config PRODUCT_CONTROL_AUTHORITY', kconfig)
        self.assertIn('config PRODUCT_AGENT_PROXY_AUTHORITY', kconfig)
        self.assertIn('config PRODUCT_SNTP_SERVER_1', kconfig)
        cmake = (PROJECT / "main" / "CMakeLists.txt").read_text()
        self.assertIn("PRODUCT_LIVE_RUNTIME_ENABLE requires", cmake)
        self.assertIn("Identity and NVS encryption must use different", cmake)

    def test_compile_gate_is_non_routable_and_executable(self):
        defaults = (
            PROJECT / "sdkconfig.live-runtime-compile.defaults"
        ).read_text()
        self.assertIn("CONFIG_PRODUCT_LIVE_RUNTIME_ENABLE=y", defaults)
        self.assertEqual(defaults.count(".example.invalid"), 3)
        self.assertIn("never be promoted or shipped", defaults)
        mode = (
            PROJECT / "tools" / "build_box3_live_compile_gate.sh"
        ).stat().st_mode
        self.assertTrue(mode & stat.S_IXUSR)

    def test_app_derives_identity_and_does_not_auto_open_onboarding(self):
        source = (PROJECT / "main" / "app_main.c").read_text()
        self.assertIn("esp_read_mac(base_mac, ESP_MAC_BASE)", source)
        self.assertIn("box3_product_runtime_format_device_id", source)
        self.assertIn("esp_fill_random(boot_random", source)
        self.assertIn("box3_product_runtime_format_client_id", source)
        self.assertNotIn(
            "box3_product_runtime_open_onboarding(s_product_runtime", source
        )
        self.assertNotIn('"sk-', source)

    def test_runtime_owns_exact_endpoint_paths_and_reverse_cleanup(self):
        source = (
            PROJECT
            / "components"
            / "box3_product_runtime"
            / "box3_product_runtime.c"
        ).read_text()
        for path in ("/v1/time", "/v1/agent-token", "/v1/session", "/v1"):
            self.assertIn(f'"{path}"', source)
        order = [
            "RESOURCE_LOCAL_ACTION",
            "RESOURCE_PROVISIONING",
            "RESOURCE_WIFI",
            "RESOURCE_TIME_BOOTSTRAP",
            "RESOURCE_SUPERVISOR",
            "RESOURCE_CREDENTIALS",
            "RESOURCE_CONTROL",
            "RESOURCE_IDENTITY",
        ]
        cleanup = source[source.index("static esp_err_t cleanup_runtime") :]
        positions = [cleanup.index(name) for name in order]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("physical_presence_grant", source)
        self.assertIn("atomic_exchange_explicit", source)
        self.assertIn("product_time_bootstrap_set_network_available", source)

    def test_sntp_is_only_an_approximate_tls_bootstrap(self):
        header = (
            PROJECT
            / "components"
            / "product_time_bootstrap"
            / "include"
            / "product_time_bootstrap.h"
        ).read_text()
        source = (
            PROJECT
            / "components"
            / "product_time_bootstrap"
            / "product_time_bootstrap.c"
        ).read_text()
        self.assertIn("not authenticated product time", header)
        self.assertNotIn("agent_device_identity", source)
        self.assertIn("esp_netif_sntp_sync_wait", source)
        self.assertIn("TIME_HEALTH_POLL_MS", source)
        self.assertIn("publish(bootstrap, false, ESP_ERR_INVALID_STATE", source)

    def test_saleable_receipt_binds_device_id_to_base_mac(self):
        schema = (
            PROJECT / "factory" / "enrollment-receipt.schema.json"
        ).read_text()
        verifier = (PROJECT / "tools" / "verify_factory_receipt.py").read_text()
        self.assertIn('^xz-[0-9a-f]{12}$', schema)
        self.assertIn('"xz-" + chip["base_mac"]', verifier)


if __name__ == "__main__":
    unittest.main()
