import csv
import json
import pathlib
import stat
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class ProductionSecurityPolicyTests(unittest.TestCase):
    def test_profile_is_reproducible_external_signing_only(self):
        defaults = (
            PROJECT / "sdkconfig.production-security.defaults"
        ).read_text()
        for setting in (
            "CONFIG_PRODUCT_PRODUCTION_SECURITY_PROFILE=y",
            "CONFIG_APP_REPRODUCIBLE_BUILD=y",
            "CONFIG_SECURE_BOOT=y",
            "CONFIG_SECURE_BOOT_V2_ENABLED=y",
            "CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME=y",
            "# CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES is not set",
            "CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE=y",
            "CONFIG_SECURE_FLASH_ENCRYPTION_AES128=y",
            "CONFIG_SECURE_ENABLE_SECURE_ROM_DL_MODE=y",
            "CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y",
            "CONFIG_BOOTLOADER_APP_SECURE_VERSION=1",
        ):
            self.assertIn(setting, defaults)
        self.assertNotIn("secure_boot_signing_key.pem", defaults)

    def test_eight_security_fail_closed_cmake_groups_are_present(self):
        cmake = (PROJECT / "main" / "CMakeLists.txt").read_text()
        for contract in (
            "CONFIG_APP_REPRODUCIBLE_BUILD",
            "CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME",
            "CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES",
            "CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE",
            "CONFIG_SECURE_ENABLE_SECURE_ROM_DL_MODE",
            "CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK",
            "CONFIG_PRODUCT_STORAGE_NVS_HMAC_KEY_ID EQUAL 4",
            "partitions_16MB_box3_production.csv",
        ):
            self.assertIn(contract, cmake)

    def test_production_partition_layout_is_aligned_and_exactly_16_mib(self):
        path = PROJECT / "partitions_16MB_box3_production.csv"
        with path.open(newline="") as stream:
            rows = [
                row
                for row in csv.reader(
                    line for line in stream if not line.lstrip().startswith("#")
                )
                if row
            ]
        entries = {row[0].strip(): row for row in rows}
        self.assertEqual(entries["ota_0"][3].strip(), "0x40000")
        self.assertEqual(entries["ota_0"][4].strip(), "0x580000")
        self.assertEqual(entries["ota_1"][4].strip(), "0x580000")
        self.assertEqual(entries["data"][4].strip(), "0x2C0000")
        for name in ("otadata", "phy_init", "coredump", "system", "data"):
            self.assertEqual(entries[name][5].strip(), "encrypted")
        for name in ("nvs_factory", "nvs", "ota_0", "ota_1"):
            self.assertEqual(entries[name][5].strip(), "")
        self.assertEqual(0xD40000 + 0x2C0000, 0x1000000)

    def test_remote_signing_test_is_ephemeral_and_three_key(self):
        path = PROJECT / "tools" / "test_production_remote_signing_flow.sh"
        script = path.read_text()
        self.assertTrue(path.stat().st_mode & stat.S_IXUSR)
        self.assertIn("mktemp -d /tmp/xz-security-signing", script)
        self.assertEqual(script.count("generate-signing-key"), 1)
        self.assertIn('"$product_key0" "$product_key1" "$product_key2"', script)
        self.assertIn("--append-signatures", script)
        self.assertIn("command -v openssl", script)
        self.assertIn("verify_production_signed_artifacts.py", script)
        self.assertIn("run_box3_virtual_efuse_rehearsal.py", script)
        self.assertIn("verify_box3_virtual_efuse_rehearsal.py", script)
        self.assertIn("test_sacrificial_provisioning_plan_flow.py", script)
        self.assertIn("VIRTUAL_TEST_ONLY", script)
        self.assertIn("test_factory_flash_manifest_flow.sh", script)
        self.assertIn('unlink "$product_file"', script)
        self.assertNotIn("rm -rf", script)

    def test_per_unit_factory_flash_manifest_is_strict_and_executable(self):
        schema = json.loads(
            (PROJECT / "factory" / "encrypted-flash-manifest.schema.json").read_text()
        )
        self.assertIs(schema["properties"]["complete"]["const"], True)
        self.assertEqual(schema["properties"]["version"]["const"], 2)
        self.assertIn("physical_flash_observation", schema["required"])
        self.assertEqual(
            schema["properties"]["programmed_regions"]["minItems"], 5
        )
        self.assertEqual(
            schema["properties"]["factory_material"]["properties"][
                "nvs_factory_size"
            ]["const"],
            0x6000,
        )
        builder = PROJECT / "tools" / "build_factory_flash_manifest.py"
        flow = PROJECT / "tools" / "test_factory_flash_manifest_flow.sh"
        self.assertTrue(builder.stat().st_mode & stat.S_IXUSR)
        self.assertTrue(flow.stat().st_mode & stat.S_IXUSR)
        source = builder.read_text()
        for contract in (
            "encrypt-flash-data",
            "--integrity-check",
            "factory_sku_evidence",
            "readback_paths",
            "--physical-observation",
            "--physical-observation-public-key",
            "write_new",
        ):
            self.assertIn(contract, source)
        flow_source = flow.read_text()
        self.assertIn("cross-device factory flash manifest", flow_source)
        self.assertIn("simulated copies", flow_source)
        self.assertIn("ephemeral untrusted test key", flow_source)
        self.assertIn(
            "tools/tests/sign_factory_physical_observation_fixture.py", flow_source
        )
        fixture_signer = (
            PROJECT / "tools" / "tests" / "sign_factory_physical_observation_fixture.py"
        ).read_text()
        self.assertIn("TEST ONLY", fixture_signer)
        self.assertNotIn("sign_factory_physical_observation_fixture", source)
        observation_schema = json.loads(
            (PROJECT / "factory" / "physical-flash-observation.schema.json").read_text()
        )
        self.assertEqual(
            observation_schema["properties"]["environment"]["const"],
            "PRODUCTION_FACTORY",
        )
        self.assertEqual(
            observation_schema["properties"]["phase"]["const"],
            "PRE_SECURE_DOWNLOAD_LOCK",
        )
        for name in (
            "build_factory_physical_observation_request.py",
            "finalize_factory_physical_observation.py",
            "verify_factory_physical_observation.py",
            "capture_factory_physical_readback.sh",
        ):
            self.assertTrue((PROJECT / "tools" / name).stat().st_mode & stat.S_IXUSR)
        capture = (
            PROJECT / "tools" / "capture_factory_physical_readback.sh"
        ).read_text()
        self.assertIn("--no-stub read-flash", capture)
        self.assertIn("physical readback CAPTURED; not yet PASS", capture)
        self.assertNotIn("write-flash", capture)
        self.assertNotIn("burn-efuse", capture)
        receipt_verifier = (PROJECT / "tools" / "verify_factory_receipt.py").read_text()
        self.assertIn('"--encrypted-flash-manifest"', receipt_verifier)
        self.assertIn("required=True", receipt_verifier)
        self.assertIn("validate_encrypted_flash_manifest_binding", receipt_verifier)
        self.assertIn('"--physical-observation"', receipt_verifier)
        self.assertIn('"--physical-observation-public-key"', receipt_verifier)

    def test_build_gate_runs_artifact_and_signing_verifiers(self):
        path = PROJECT / "tools" / "build_box3_production_security_gate.sh"
        script = path.read_text()
        self.assertTrue(path.stat().st_mode & stat.S_IXUSR)
        self.assertIn("verify_production_security_build.py", script)
        self.assertIn("production-security-signing-request.json", script)
        self.assertIn("test_production_remote_signing_flow.sh", script)
        self.assertIn("do not flash", script)

    def test_virtual_efuse_gate_is_strictly_test_only(self):
        runner = PROJECT / "tools" / "run_box3_virtual_efuse_rehearsal.py"
        verifier = PROJECT / "tools" / "verify_box3_virtual_efuse_rehearsal.py"
        policy = PROJECT / "tools" / "virtual_efuse_rehearsal.py"
        for path in (runner, verifier):
            self.assertTrue(path.stat().st_mode & stat.S_IXUSR)
        source = runner.read_text()
        self.assertIn('"--virt"', source)
        self.assertIn("refuses every serial-port argument", source)
        self.assertIn("secure_boot_private_keys_persisted", source)
        self.assertNotIn("PrivateFormat", source)
        self.assertNotIn("--show-sensitive-info", source)
        self.assertNotIn("--force-write-always", source)
        self.assertIn("ENABLE_SECURITY_DOWNLOAD", source)
        self.assertIn("write-protect-efuse", source)
        self.assertIn("VIRTUAL_TEST_ONLY", policy.read_text())
        schema = json.loads(
            (PROJECT / "factory" / "virtual-efuse-rehearsal.schema.json").read_text()
        )
        self.assertEqual(schema["properties"]["environment"]["const"], "VIRTUAL_TEST_ONLY")
        self.assertIs(
            schema["properties"]["boundary"]["const"]["physical_device_touched"],
            False,
        )

    def test_sacrificial_preflight_and_plan_are_non_executing(self):
        names = (
            "build_sacrificial_provisioning_plan_request.py",
            "finalize_sacrificial_provisioning_plan.py",
            "verify_sacrificial_provisioning_plan.py",
            "capture_sacrificial_blank_preflight.sh",
            "test_sacrificial_provisioning_plan_flow.py",
        )
        for name in names:
            self.assertTrue((PROJECT / "tools" / name).stat().st_mode & stat.S_IXUSR)
        capture = (PROJECT / "tools/capture_sacrificial_blank_preflight.sh").read_text()
        for required in ("chip-id", "flash-id", "summary --format json", "check-error"):
            self.assertIn(required, capture)
        for forbidden in (
            "burn-efuse",
            "burn-key",
            "write-flash",
            "erase-flash",
            "read-protect-efuse",
            "write-protect-efuse",
        ):
            self.assertNotIn(forbidden, capture)
        policy = (PROJECT / "tools/sacrificial_provisioning_plan.py").read_text()
        self.assertIn('"executor_included": False', policy)
        self.assertIn('"production_inventory_eligible": False', policy)
        self.assertNotIn("import subprocess", policy)
        release_flow = (PROJECT / "tools/test_sacrificial_provisioning_plan_flow.py").read_text()
        self.assertIn("--virt", release_flow)
        self.assertIn("TEST ONLY", release_flow)
        for forbidden in ("burn-efuse", "burn-key", "write-flash", "erase-flash"):
            self.assertNotIn(forbidden, release_flow)
        fixture_signer = (
            PROJECT / "tools/tests/sign_sacrificial_provisioning_plan_fixture.py"
        ).read_text()
        self.assertIn("TEST ONLY", fixture_signer)
        self.assertNotIn("private_bytes", fixture_signer)
        schema = json.loads(
            (PROJECT / "factory/sacrificial-provisioning-plan.schema.json").read_text()
        )
        authorization = schema["properties"]["authorization"]["properties"]
        self.assertIs(authorization["executor_included"]["const"], False)
        self.assertIs(authorization["production_inventory_eligible"]["const"], False)

    def test_sacrificial_attempt_ledger_is_atomic_and_non_executing(self):
        names = (
            "initialize_sacrificial_attempt_ledger.py",
            "finalize_sacrificial_attempt_ledger.py",
            "consume_sacrificial_attempt.py",
            "verify_sacrificial_attempt_consumption.py",
        )
        for name in names:
            self.assertTrue((PROJECT / "tools" / name).stat().st_mode & stat.S_IXUSR)
        policy = (PROJECT / "tools/sacrificial_attempt_ledger.py").read_text()
        for required in (
            "POLICY_SIGNATURE_DOMAIN",
            "filesystem_device",
            "directory_inode",
            "os.O_EXCL",
            "os.link",
            "os.fsync",
            "AttemptAlreadyConsumed",
            '"executor_invoked": False',
            '"hardware_touched": False',
            '"deletion_api_included": False',
            '"production_inventory_eligible": False',
        ):
            self.assertIn(required, policy)
        self.assertNotIn("import subprocess", policy)
        for forbidden in (
            "burn-efuse",
            "burn-key",
            "write-flash",
            "erase-flash",
            "read-protect-efuse",
            "write-protect-efuse",
        ):
            self.assertNotIn(forbidden, policy)
            for name in names:
                self.assertNotIn(forbidden, (PROJECT / "tools" / name).read_text())
        policy_schema = json.loads(
            (PROJECT / "factory/sacrificial-attempt-ledger-policy.schema.json").read_text()
        )
        record_schema = json.loads(
            (PROJECT / "factory/sacrificial-attempt-consumption.schema.json").read_text()
        )
        self.assertIs(
            policy_schema["properties"]["storage"]["properties"]
            ["multi_station_supported"]["const"],
            False,
        )
        for schema in (policy_schema, record_schema):
            safety = schema["properties"]["safety"]["properties"]
            self.assertIs(safety["executor_invoked"]["const"], False)
            self.assertIs(safety["production_inventory_eligible"]["const"], False)
            self.assertIs(safety["deletion_api_included"]["const"], False)
        release_flow = (PROJECT / "tools/test_sacrificial_provisioning_plan_flow.py").read_text()
        self.assertIn("M59 attempt ledger PASS", release_flow)
        self.assertIn("AttemptAlreadyConsumed", release_flow)

    def test_sacrificial_consumption_requires_online_signed_trusted_time(self):
        client = (PROJECT / "tools/consume_sacrificial_attempt.py").read_text()
        ledger = (PROJECT / "tools/sacrificial_attempt_ledger.py").read_text()
        trusted_time = (PROJECT / "tools/sacrificial_trusted_time.py").read_text()
        self.assertIn("consume_attempt_online", client)
        self.assertNotIn("--verification-time", client)
        self.assertNotIn("--trusted-time-receipt", client)
        for required in (
            "--trusted-time-public-key",
            "--trusted-time-ca-certificate",
            "--trusted-time-client-certificate",
            "--trusted-time-client-private-key",
        ):
            self.assertIn(required, client)
        for required in (
            "HTTPSConnection",
            "TLSv1_3",
            "load_cert_chain",
            '"Transfer-Encoding"',
            '"Content-Length"',
            "time.monotonic_ns",
            "SIGNATURE_DOMAIN",
            "request binding differs",
        ):
            self.assertIn(required, trusted_time)
        self.assertNotIn("urllib.request", trusted_time)
        self.assertNotIn("import subprocess", trusted_time)
        self.assertIn("trusted_time_public_key", ledger)
        self.assertIn("authority_public_key_sha256", ledger)
        self.assertIn("client_certificate_sha256", ledger)
        policy_schema = json.loads(
            (PROJECT / "factory/sacrificial-attempt-ledger-policy.schema.json").read_text()
        )
        record_schema = json.loads(
            (PROJECT / "factory/sacrificial-attempt-consumption.schema.json").read_text()
        )
        request_schema = json.loads(
            (PROJECT / "factory/sacrificial-trusted-time-request.schema.json").read_text()
        )
        receipt_schema = json.loads(
            (PROJECT / "factory/sacrificial-trusted-time-receipt.schema.json").read_text()
        )
        self.assertEqual(
            policy_schema["properties"]["schema"]["const"],
            "xz-sacrificial-attempt-ledger-policy-v2",
        )
        time_policy = policy_schema["properties"]["trusted_time"]["properties"]
        self.assertEqual(time_policy["timeout_ms"]["const"], 5000)
        self.assertEqual(time_policy["tls_minimum_version"]["const"], "1.3")
        self.assertIs(time_policy["mtls_required"]["const"], True)
        self.assertIs(time_policy["redirects_allowed"]["const"], False)
        self.assertIs(time_policy["proxies_allowed"]["const"], False)
        self.assertEqual(
            record_schema["properties"]["schema"]["const"],
            "xz-sacrificial-attempt-consumption-v2",
        )
        self.assertIn("trusted_time", record_schema["required"])
        self.assertEqual(
            request_schema["properties"]["result"]["const"],
            "TRUSTED_TIME_REQUESTED",
        )
        self.assertEqual(
            receipt_schema["properties"]["result"]["const"],
            "TRUSTED_TIME_ATTESTED",
        )
        fixture = (
            PROJECT / "tools/tests/consume_sacrificial_attempt_fixture.py"
        ).read_text()
        self.assertIn("TEST ONLY", fixture)
        self.assertNotIn("consume_sacrificial_attempt_fixture", client)
        release_flow = (PROJECT / "tools/test_sacrificial_provisioning_plan_flow.py").read_text()
        self.assertIn("M60 trusted-time binding PASS", release_flow)

    def test_factory_schema_is_v4_and_binds_boot_security_and_sku(self):
        schema = json.loads(
            (PROJECT / "factory" / "enrollment-receipt.schema.json").read_text()
        )
        self.assertEqual(schema["properties"]["version"]["const"], 4)
        self.assertIn("product_identity", schema["required"])
        boot = schema["properties"]["boot_security"]
        self.assertFalse(boot["additionalProperties"])
        self.assertIn("secure_boot_digests", boot["required"])
        self.assertIn("flash_encryption_key", boot["required"])
        self.assertIn("anti_rollback_efuse_version", boot["required"])
        self.assertIn("signed_artifact_verification_sha256", boot["required"])
        self.assertIn("encrypted_flash_manifest_sha256", boot["required"])
        self.assertEqual(
            schema["properties"]["firmware"]["properties"]["security_version"]["maximum"],
            16,
        )

    def test_signed_artifact_verifier_is_fail_closed_and_executable(self):
        path = PROJECT / "tools" / "verify_production_signed_artifacts.py"
        source = path.read_text()
        self.assertTrue(path.stat().st_mode & stat.S_IXUSR)
        self.assertIn('b"PRIVATE KEY"', source)
        self.assertIn("boot_digests != key_digests", source)
        self.assertIn("signed-artifact receipt differs", source)

    def test_production_runbooks_freeze_irreversible_order_and_dual_signing(self):
        boot = (PROJECT / "PRODUCTION_BOOT_SECURITY_RUNBOOK.md").read_text()
        factory = (PROJECT / "FACTORY_IDENTITY_RUNBOOK.md").read_text()
        ota = (PROJECT / "OTA_RELEASE_RUNBOOK.md").read_text()
        for contract in (
            "BLOCK_KEY3",
            "XTS_AES_128_KEY",
            "Sign first, encrypt second",
            "Secure ROM download mode last",
            "encrypted_flash_manifest_sha256",
            "factory receipt v4",
        ):
            self.assertIn(contract, boot)
        self.assertIn("Create a v4 receipt", factory)
        self.assertNotIn("Create a v3 receipt", factory)
        self.assertIn("xiaozhi_agent_platform-sbv2-signed.bin", ota)
        self.assertIn("P-256 release-manifest signer is separate", ota)


if __name__ == "__main__":
    unittest.main()
