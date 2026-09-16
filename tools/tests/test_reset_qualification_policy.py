import json
import pathlib
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class ResetQualificationPolicyTests(unittest.TestCase):
    def read(self, path):
        return (PROJECT / path).read_text()

    def test_receipt_schema_requires_physical_identity_and_security_evidence(self):
        schema = json.loads(
            self.read("factory/reset-hardware-qualification.schema.json")
        )
        self.assertEqual(
            schema["properties"]["schema"]["const"],
            "xz-reset-hardware-qualification-v1",
        )
        sample = schema["$defs"]["sample"]
        for field in (
            "pre_identity_proof_sha256",
            "post_identity_proof_sha256",
            "pre_nvs_factory_sha256",
            "post_nvs_factory_sha256",
            "pre_efuse_summary_sha256",
            "post_efuse_summary_sha256",
            "wifi_raw_keys_absent_pass",
            "agent_memory_raw_slots_absent_pass",
            "secure_boot_preserved_pass",
            "flash_encryption_preserved_pass",
            "anti_rollback_preserved_pass",
        ):
            self.assertIn(field, sample["required"])
        self.assertEqual(schema["properties"]["samples"]["minItems"], 3)

    def test_every_power_cut_boundary_and_frozen_gesture_are_required(self):
        schema = json.loads(
            self.read("factory/reset-hardware-qualification.schema.json")
        )
        required = schema["properties"]["power_cut"]["required"]
        self.assertEqual(len(required), 6)
        for boundary in (
            "after_intent_commit",
            "after_wifi_erase",
            "after_wifi_phase_commit",
            "after_memory_erase",
            "after_memory_phase_commit",
            "after_journal_erase",
        ):
            self.assertIn(boundary, required)
        gesture = schema["properties"]["gesture"]["properties"]
        self.assertEqual(gesture["short_press_ms"]["const"], 2900)
        self.assertEqual(gesture["onboarding_min_ms"]["const"], 3000)
        self.assertEqual(gesture["onboarding_max_ms"]["const"], 9900)
        self.assertEqual(gesture["reset_min_ms"]["const"], 10000)

    def test_verifier_is_strict_signed_and_release_bound(self):
        verifier = self.read("tools/verify_reset_hardware_qualification.py")
        for contract in (
            "canonical_json(receipt) != data",
            "duplicate JSON member",
            "Ed25519PublicKey",
            "public_key.verify",
            "expected_image_sha256",
            "expected_secure_version",
            "expected_signing_key_id",
            "physical reset wear evidence must total at least 1000 cycles",
            "changed across reset",
        ):
            self.assertIn(contract, verifier)

    def test_release_signer_requires_and_binds_qualification(self):
        signer = self.read("tools/sign_release_manifest.py")
        deployment = self.read("tools/build_ota_deployment_bundle.py")
        for flag in (
            "--reset-qualification-receipt",
            "--reset-qualification-public-key",
            "--reset-qualification-signing-key-id",
        ):
            self.assertIn(flag, signer)
            self.assertIn(flag, deployment)
        self.assertIn("reset_qualification.verify_receipt_bytes", signer)
        self.assertIn('"reset_qualification_sha256"', signer)
        self.assertIn("xiaozhi-product-ota-v2", signer)
        self.assertIn("reset_qualification_receipt_path", deployment)

    def test_device_gateway_and_schema_reject_unbound_v1(self):
        firmware = self.read("components/product_ota/product_ota_core.c")
        gateway = self.read("gateway/internal/ota/releases.go")
        schema = json.loads(self.read("ota/release-manifest.schema.json"))
        self.assertEqual(schema["properties"]["schema"]["const"], 2)
        self.assertIn("reset_qualification_sha256", schema["required"])
        for source in (firmware, gateway):
            self.assertIn("xiaozhi-product-ota-v2", source)
            self.assertIn("reset_qualification_sha256", source)
            self.assertNotIn("xiaozhi-product-ota-v1", source)

    def test_runbook_forbids_synthetic_or_local_self_attestation(self):
        runbook = self.read("RESET_HARDWARE_QUALIFICATION_RUNBOOK.md")
        for statement in (
            "不得由 release pipeline 自行產生 PASS",
            "合成測試資料不是真機證據",
            "至少三台不同實體裝置",
            "累計至少 1,000 次",
            "六個斷電邊界",
            "WORM",
            "禁止出貨",
        ):
            self.assertIn(statement, runbook)

    def test_dedicated_gate_covers_all_three_verifiers(self):
        runner = self.read("tools/run_reset_qualification_gate.sh")
        self.assertIn("run_host_tests.sh", runner)
        self.assertIn("test_verify_reset_hardware_qualification", runner)
        self.assertIn("test_sign_release_manifest", runner)
        self.assertIn("test_ota_deployment_bundle", runner)
        self.assertIn("test ./internal/ota", runner)
        self.assertIn("Synthetic fixtures are contract tests only", runner)


if __name__ == "__main__":
    unittest.main()
