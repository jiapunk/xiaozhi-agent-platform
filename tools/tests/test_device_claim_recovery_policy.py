import pathlib
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class DeviceClaimRecoveryPolicyTests(unittest.TestCase):
    def read(self, relative):
        return (PROJECT / relative).read_text(encoding="utf-8")

    def test_wifi_and_claim_share_one_checked_state_blob(self):
        state = self.read(
            "components/product_wifi/product_wifi_state_core.c"
        )
        wifi = self.read("components/product_wifi/product_wifi.c")
        self.assertIn("PRODUCT_WIFI_STATE_BLOB_SIZE = 163", self.read(
            "components/product_wifi/private_include/"
            "product_wifi_state_core.h"
        ))
        self.assertIn("CREDENTIAL_OFFSET", state)
        self.assertIn("CLAIM_OFFSET", state)
        self.assertIn("crc32(output, CHECKSUM_OFFSET)", state)
        self.assertIn('NVS_STATE_KEY = "network_state"', wifi)
        self.assertIn("encode_and_set_state", wifi)
        self.assertIn("nvs_commit(nvs)", wifi)

    def test_legacy_credentials_migrate_without_losing_recovery_state(self):
        wifi = self.read("components/product_wifi/product_wifi.c")
        self.assertIn('NVS_LEGACY_CREDENTIAL_KEY = "credential"', wifi)
        self.assertIn("nvs_get_blob(nvs, NVS_STATE_KEY", wifi)
        self.assertIn("nvs_get_blob(nvs, NVS_LEGACY_CREDENTIAL_KEY", wifi)
        self.assertIn("either old or new is valid", wifi)

    def test_product_onboarding_can_only_commit_a_disclosed_claim(self):
        provisioning = self.read(
            "components/product_provisioning/product_provisioning.c"
        )
        self.assertIn("!provisioning->claim_valid", provisioning)
        self.assertIn("!provisioning->claim_disclosed", provisioning)
        self.assertIn("product_wifi_submit_claimed_credentials", provisioning)
        self.assertIn("product_wifi_complete_device_claim", provisioning)
        self.assertIn("product_wifi_abandon_device_claim", provisioning)

    def test_boot_recovery_is_idempotent_and_terminal_errors_do_not_spin(self):
        provisioning = self.read(
            "components/product_provisioning/product_provisioning.c"
        )
        protocol = self.read(
            "components/agent_control_plane_client/"
            "agent_control_plane_protocol.c"
        )
        client = self.read(
            "components/agent_control_plane_client/"
            "agent_control_plane_client.c"
        )
        recovery_core = self.read(
            "components/product_provisioning/product_provisioning_core.c"
        )
        self.assertIn("recover_pending_claim", provisioning)
        self.assertIn("product_claim_recovery_core_should_attempt",
                      provisioning)
        self.assertIn("CLAIM_RETRY_MS = 2000", recovery_core)
        self.assertIn("session_inactive && wifi_online", recovery_core)
        self.assertIn("status_code != 408 && status_code != 429", protocol)
        self.assertIn("DEVICE_CLAIM_REJECTED", client)

    def test_terminal_recovery_requires_a_new_physical_window(self):
        provisioning = self.read(
            "components/product_provisioning/product_provisioning.c"
        )
        runtime = self.read(
            "components/box3_product_runtime/box3_product_runtime.c"
        )
        storage = self.read("components/product_storage/product_storage.c")
        self.assertIn(
            "PRODUCT_PROVISIONING_EVENT_CLAIM_RECOVERY_REQUIRED",
            provisioning,
        )
        self.assertIn("BOX3_PRODUCT_RUNTIME_ONBOARDING_REQUIRED", runtime)
        self.assertIn("CONFIG_PRODUCT_STORAGE_REQUIRE_HMAC_NVS_ENCRYPTION",
                      storage)
        self.assertIn("nvs_flash_secure_init_partition", storage)


if __name__ == "__main__":
    unittest.main()
