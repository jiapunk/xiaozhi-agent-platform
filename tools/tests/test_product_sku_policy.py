import json
import pathlib
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class ProductSKUPolicyTests(unittest.TestCase):
    def read(self, path):
        return (PROJECT / path).read_text()

    def test_two_profiles_have_distinct_fail_closed_lifecycles(self):
        core = self.read("components/product_sku/product_sku_core.c")
        self.assertIn('XIAOZHI_AGENT_S3_REFERENCE', core)
        self.assertIn('VOICE_AGENT_KIT_BOX3', core)
        self.assertIn('PRODUCT_SKU_LIFECYCLE_DEVELOPMENT_ONLY', core)
        self.assertIn('PRODUCT_SKU_LIFECYCLE_CANDIDATE', core)
        self.assertIn('.live_runtime_allowed = false', core)
        self.assertIn('.factory_qualification_required = true', core)
        self.assertIn('.production_security_required = true', core)
        self.assertGreaterEqual(core.count('.allowed_action_capabilities = 0'), 1)
        self.assertIn('PRODUCT_SKU_CAPABILITY_DEVICE_SET_INDICATOR', core)
        self.assertIn('.status_indicator_gpio = 47', core)

    def test_board_sku_revision_and_live_build_pairs_are_guarded(self):
        cmake = self.read("main/CMakeLists.txt")
        for contract in (
            'CONFIG_PRODUCT_BOARD_ESP_BOX_3',
            'CONFIG_PRODUCT_BOARD_S3_N32R16_REFERENCE',
            'CONFIG_PRODUCT_SKU_VOICE_AGENT_KIT_BOX3',
            'CONFIG_PRODUCT_SKU_S3_N32R16_REFERENCE',
            'CONFIG_PRODUCT_HARDWARE_REVISION EQUAL 1',
            'CONFIG_PRODUCT_LIVE_RUNTIME_ENABLE',
            'CONFIG_PRODUCT_PRODUCTION_SECURITY_PROFILE',
        ):
            self.assertIn(contract, cmake)
        self.assertGreaterEqual(cmake.count('message(FATAL_ERROR'), 10)

    def test_defaults_select_matching_profiles(self):
        generic = self.read("sdkconfig.defaults")
        box3 = self.read("sdkconfig.box3.defaults")
        self.assertIn('CONFIG_PRODUCT_SKU_S3_N32R16_REFERENCE=y', generic)
        self.assertIn('CONFIG_PRODUCT_HARDWARE_REVISION=0', generic)
        self.assertIn('CONFIG_PRODUCT_SKU_VOICE_AGENT_KIT_BOX3=y', box3)
        self.assertIn('CONFIG_PRODUCT_HARDWARE_REVISION=1', box3)

    def test_indicator_action_is_hardware_bound_and_production_gated(self):
        header = self.read(
            "components/product_sku/include/product_sku_core.h"
        )
        adapter = self.read(
            "components/product_status_indicator/product_status_indicator.c"
        )
        app = self.read("main/app_main.c")
        live = self.read("sdkconfig.live-runtime-compile.defaults")
        production = self.read("sdkconfig.production-security.defaults")
        cmake = self.read("main/CMakeLists.txt")
        live_gate = self.read("tools/build_box3_live_compile_gate.sh")
        production_gate = self.read(
            "tools/build_box3_production_security_gate.sh"
        )
        for contract in (
            "status_indicator_present",
            "status_indicator_gpio",
            "status_indicator_active_high",
            "PRODUCT_SKU_CAPABILITY_DEVICE_SET_INDICATOR",
        ):
            self.assertIn(contract, header)
        for contract in (
            "gpio_reset_pin",
            "gpio_set_level",
            "gpio_set_direction",
            "product_sku_capability_allowed",
        ):
            self.assertIn(contract, adapter)
        self.assertIn("product_status_indicator_create", app)
        self.assertIn("product_agent_set_indicator", app)
        self.assertIn("CONFIG_PRODUCT_AGENT_INDICATOR_ACTION_ENABLE=y", live)
        self.assertIn(
            "# CONFIG_PRODUCT_AGENT_INDICATOR_ACTION_ENABLE is not set",
            production,
        )
        self.assertIn(
            "if(CONFIG_PRODUCT_AGENT_INDICATOR_ACTION_ENABLE)", cmake
        )
        self.assertIn("verify_indicator_action_build.py", live_gate)
        self.assertIn("--expect enabled", live_gate)
        self.assertIn("verify_indicator_action_build.py", production_gate)
        self.assertIn("--expect disabled", production_gate)

    def test_hardware_guard_precedes_storage_and_network_startup(self):
        app = self.read("main/app_main.c")
        guard = app.index('product_sku_validate_hardware(&sku_detail)')
        storage = app.index('product_storage_initialize()', guard)
        factory_identity = app.index(
            'product_sku_validate_factory_identity(', storage
        )
        runtime = app.index('start_product_runtime()', factory_identity)
        self.assertLess(guard, storage)
        self.assertLess(storage, factory_identity)
        self.assertLess(factory_identity, runtime)
        self.assertIn('Product SKU hardware geometry failed closed', app)
        self.assertIn('Factory SKU identity failed closed', app)

    def test_runtime_observes_only_readable_silicon_geometry(self):
        runtime = self.read("components/product_sku/product_sku.c")
        for api in ('esp_chip_info(', 'esp_flash_get_size(', 'esp_psram_get_size('):
            self.assertIn(api, runtime)
        for forbidden in ('codec', 'gpio_get_level'):
            self.assertNotIn(forbidden, runtime.lower())

    def test_factory_identity_is_authenticated_and_has_no_write_api(self):
        runtime = self.read("components/product_sku/product_sku.c")
        core = self.read("components/product_sku/product_sku_core.c")
        generator = self.read("tools/factory_sku_manifest.py")
        for contract in (
            '"nvs_factory"', '"prod_sku"', '"manifest"',
            'esp_hmac_calculate(', 'esp_read_mac(base_mac, ESP_MAC_BASE)',
            'esp_efuse_get_key_dis_read', 'esp_efuse_get_key_dis_write',
        ):
            self.assertIn(contract, runtime)
        self.assertNotIn('nvs_set_', runtime)
        self.assertNotIn('nvs_erase_', runtime)
        domain = 'XIAOZHI-PRODUCT-SKU-MANIFEST-V1'
        self.assertIn(domain, core)
        self.assertIn(domain, generator)
        self.assertIn('PRODUCT_SKU_FACTORY_MANIFEST_BYTES = 70', self.read(
            "components/product_sku/include/product_sku_core.h"
        ))

    def test_factory_receipt_v4_binds_manifest_and_registry(self):
        schema = json.loads(self.read("factory/enrollment-receipt.schema.json"))
        self.assertEqual(schema["properties"]["version"]["const"], 4)
        identity = schema["properties"]["product_identity"]
        self.assertFalse(identity["additionalProperties"])
        for field in (
            "sku", "board", "hardware_revision", "chip_revision",
            "base_mac", "manifest_id", "factory_record_version",
            "manifest_sha256", "runtime_verification_pass",
        ):
            self.assertIn(field, identity["required"])
        registry = schema["properties"]["registry"]["required"]
        self.assertIn("factory_manifest_sha256", registry)

    def test_current_sbom_and_docs_preserve_candidate_boundary(self):
        policy = json.loads(self.read("firmware/sbom-release-policy.json"))
        self.assertIn(
            'SPDXRef-COMPONENT-product-sku',
            policy['required_spdx_ids']['app'],
        )
        report = self.read("M53_PRODUCT_SKU_HARDWARE_GUARD_REPORT.md")
        self.assertIn('仍不是量產合格 SKU', report)
        self.assertIn('無法只靠 ESP32 API 分辨 BOX-3', report)
        self.assertIn('沒有建立 M52 market-release bundle',
                      self.read("M52_PRODUCT_MARKET_RELEASE_EVIDENCE_REPORT.md"))


if __name__ == "__main__":
    unittest.main()
