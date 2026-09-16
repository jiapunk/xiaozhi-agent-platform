import csv
import pathlib
import stat
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class OtaPolicyTests(unittest.TestCase):
    def test_build_profiles_enable_bootloader_rollback(self):
        for name in ("sdkconfig.defaults", "sdkconfig.box3.defaults"):
            defaults = (PROJECT / name).read_text()
            self.assertIn("CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y", defaults)
            self.assertIn("CONFIG_APP_PROJECT_VER_FROM_CONFIG=y", defaults)
            self.assertIn("CONFIG_PRODUCT_OTA_RELEASE_SEQUENCE=14", defaults)
            self.assertIn('CONFIG_PRODUCT_OTA_CHANNEL="development"', defaults)

    def test_partition_tables_have_symmetric_ab_slots(self):
        for name in ("partitions_32MB.csv", "partitions_16MB_box3.csv"):
            with (PROJECT / name).open(newline="") as stream:
                rows = {
                    row[0].strip(): row
                    for row in csv.reader(
                        line for line in stream if not line.lstrip().startswith("#")
                    )
                    if row
                }
            self.assertIn("otadata", rows)
            self.assertIn("ota_0", rows)
            self.assertIn("ota_1", rows)
            self.assertEqual(rows["ota_0"][4].strip(), rows["ota_1"][4].strip())

    def test_downloader_fails_closed_on_transport_and_artifact_checks(self):
        source = (PROJECT / "components/product_ota/product_ota.c").read_text()
        for contract in (
            ".disable_auto_redirect = true",
            ".max_authorization_retries = -1",
            ".skip_cert_common_name_check = false",
            'esp_http_client_set_header(client, "Authorization"',
            "esp_https_ota_get_img_desc",
            "constant_time_equal(downloaded_sha256, manifest.image_sha256",
            "esp_https_ota_finish(ota)",
        ):
            self.assertIn(contract, source)
        self.assertLess(
            source.index("constant_time_equal(downloaded_sha256"),
            source.index("esp_https_ota_finish(ota)"),
        )

    def test_manifest_enforces_target_time_sequence_and_signature(self):
        runtime = (PROJECT / "components/product_ota/product_ota.c").read_text()
        core = (PROJECT / "components/product_ota/product_ota_core.c").read_text()
        for contract in (
            "manifest->release_sequence <= policy->current_release_sequence",
            "manifest->secure_version < policy->current_secure_version",
            "policy->authenticated_time < manifest->not_before",
            "policy->authenticated_time > manifest->expires_at",
            "product_ota_url_has_authority(manifest->image_url",
        ):
            self.assertIn(contract, core)
        self.assertIn("verify_manifest_signature(manifest, key)", runtime)
        self.assertIn("mbedtls_pk_get_bitlen(&public_key) != 256", runtime)

    def test_app_never_auto_confirms_pending_image(self):
        app = (PROJECT / "main/app_main.c").read_text()
        self.assertIn("OTA image pending health verification", app)
        self.assertNotIn("product_ota_confirm_running_image(", app)
        self.assertNotIn("product_ota_reject_running_image_and_reboot(", app)

    def test_box3_requires_audio_health(self):
        generic = (PROJECT / "sdkconfig.defaults").read_text()
        box3 = (PROJECT / "sdkconfig.box3.defaults").read_text()
        self.assertNotIn("CONFIG_PRODUCT_OTA_REQUIRE_AUDIO_HEALTH=y", generic)
        self.assertIn("CONFIG_PRODUCT_OTA_REQUIRE_AUDIO_HEALTH=y", box3)

    def test_release_tools_are_executable_and_schema_is_exact(self):
        for name in (
            "sign_release_manifest.py",
            "verify_release_manifest.py",
            "build_ota_deployment_bundle.py",
            "validate_ota_deployment_bundle.py",
            "create_ota_rollout_request.py",
            "sign_ota_rollout_approval.py",
            "promote_ota_rollout_bundle.py",
            "validate_ota_rollout_bundle.py",
        ):
            self.assertTrue((PROJECT / "tools" / name).stat().st_mode & stat.S_IXUSR)
        schema = (PROJECT / "ota/release-manifest.schema.json").read_text()
        self.assertIn('"additionalProperties": false', schema)
        self.assertIn('"signature_algorithm": { "const": "ECDSA_P256_SHA256" }', schema)
        receipt_schema = (
            PROJECT / "gateway" / "ota-deployment-receipt.schema.json"
        ).read_text()
        self.assertIn('"rollout_enabled": { "const": false }', receipt_schema)
        self.assertIn('"rollout_basis_points": { "const": 0 }', receipt_schema)
        rollout_request_schema = (
            PROJECT / "gateway" / "ota-rollout-request.schema.json"
        ).read_text()
        rollout_approval_schema = (
            PROJECT / "gateway" / "ota-rollout-approval.schema.json"
        ).read_text()
        self.assertIn('"EMERGENCY_STOP"', rollout_request_schema)
        self.assertIn('"signature_algorithm": { "const": "Ed25519" }',
                      rollout_approval_schema)


if __name__ == "__main__":
    unittest.main()
