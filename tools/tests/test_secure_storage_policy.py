import pathlib
import stat
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class SecureStoragePolicyTests(unittest.TestCase):
    def test_secure_profile_requires_manual_hmac_scheme(self):
        defaults = (PROJECT / "sdkconfig.secure-storage.defaults").read_text()
        self.assertIn("CONFIG_NVS_ENCRYPTION=n", defaults)
        self.assertIn(
            "CONFIG_PRODUCT_STORAGE_REQUIRE_HMAC_NVS_ENCRYPTION=y",
            defaults,
        )
        self.assertIn("CONFIG_PRODUCT_STORAGE_NVS_HMAC_KEY_ID=4", defaults)
        for name in ("partitions_32MB.csv", "partitions_16MB_box3.csv"):
            table = (PROJECT / name).read_text()
            self.assertNotIn("nvs_keys", table)

    def test_runtime_cannot_generate_or_burn_keys(self):
        source = (
            PROJECT / "components" / "product_storage" / "product_storage.c"
        ).read_text()
        self.assertNotIn("nvs_flash_generate_keys_v2(&", source)
        self.assertNotIn("esp_efuse_write", source)
        self.assertNotIn("nvs_flash_erase", source)
        self.assertIn("nvs_flash_read_security_cfg_v2", source)
        self.assertIn("esp_efuse_get_key_dis_read", source)
        self.assertIn("esp_efuse_get_key_dis_write", source)

    def test_storage_has_single_initialization_owner(self):
        for relative in (
            "components/product_wifi/product_wifi.c",
            "components/product_provisioning/product_provisioning.c",
        ):
            source = (PROJECT / relative).read_text()
            self.assertNotIn("nvs_flash_init_partition", source)
            self.assertIn("product_storage_require_ready", source)

    def test_secure_build_scripts_are_executable(self):
        for name in (
            "build_secure_storage_generic.sh",
            "build_secure_storage_box3.sh",
        ):
            mode = (PROJECT / "tools" / name).stat().st_mode
            self.assertTrue(mode & stat.S_IXUSR)

    def test_factory_receipt_v4_binds_storage_onboarding_boot_and_sku(self):
        schema = (
            PROJECT / "factory" / "enrollment-receipt.schema.json"
        ).read_text()
        self.assertIn('"version": { "const": 4 }', schema)
        self.assertIn('"product_identity"', schema)
        self.assertIn('"identity_key"', schema)
        self.assertIn('"secure_storage"', schema)
        self.assertIn('"nvs_factory_readback_sha256"', schema)
        self.assertIn('"encrypted_nvs_roundtrip_pass"', schema)
        self.assertIn('"boot_security"', schema)
        self.assertIn('"signed_artifact_verification_sha256"', schema)
        self.assertIn('"encrypted_flash_manifest_sha256"', schema)

    def test_factory_key_generator_is_executable(self):
        mode = (
            PROJECT / "tools" / "generate_factory_hmac_key.py"
        ).stat().st_mode
        self.assertTrue(mode & stat.S_IXUSR)


if __name__ == "__main__":
    unittest.main()
