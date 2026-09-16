import base64
import hashlib
import hmac
import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = PROJECT / "tools" / "factory_sku_manifest.py"
SPEC = importlib.util.spec_from_file_location("factory_sku_manifest", MODULE_PATH)
SKU = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(SKU)


class FactorySKUManifestTests(unittest.TestCase):
    def manifest(self):
        return SKU.build_manifest(
            bytes(range(32)),
            base_mac="02:00:00:12:AB:EF",
            sku="VOICE_AGENT_KIT_BOX3",
            board="esp32s3-box3",
            hardware_revision=1,
            chip_revision=1,
            factory_record_version=7,
            manifest_id="00112233445566778899aabbccddeeff",
        )

    def test_manifest_matches_device_wire_contract(self):
        blob, evidence = self.manifest()
        self.assertEqual(len(blob), 70)
        self.assertEqual(blob[:6], b"XSKU\x01\x02")
        self.assertEqual(int.from_bytes(blob[6:8], "little"), 1)
        self.assertEqual(int.from_bytes(blob[8:10], "little"), 1)
        self.assertEqual(blob[10:12], b"\x00\x00")
        self.assertEqual(blob[12:18], bytes.fromhex("02000012abef"))
        self.assertEqual(int.from_bytes(blob[18:22], "little"), 7)
        self.assertEqual(blob[22:38].hex(), evidence["manifest_id"])
        expected = hmac.new(
            bytes(range(32)), SKU.DOMAIN + blob[:38], hashlib.sha256
        ).digest()
        self.assertEqual(blob[38:], expected)
        self.assertEqual(evidence["manifest_sha256"], hashlib.sha256(blob).hexdigest())

    def test_parser_authenticates_and_reconstructs_evidence(self):
        blob, evidence = self.manifest()
        parsed = SKU.parse_and_verify_manifest(bytes(range(32)), blob)
        self.assertEqual(parsed, evidence)
        tampered = bytearray(blob)
        tampered[6] ^= 1
        with self.assertRaisesRegex(SKU.FactorySKUManifestError, "authentication"):
            SKU.parse_and_verify_manifest(bytes(range(32)), bytes(tampered))

    def test_profile_and_identity_inputs_fail_closed(self):
        base = dict(
            base_mac="02:00:00:12:AB:EF",
            sku="VOICE_AGENT_KIT_BOX3",
            board="esp32s3-box3",
            hardware_revision=1,
            chip_revision=1,
            factory_record_version=1,
            manifest_id="00112233445566778899aabbccddeeff",
        )
        cases = (
            (b"short", base),
            (bytes(32), {**base, "base_mac": "03:00:00:12:AB:EF"}),
            (bytes(32), {**base, "board": "wrong-board"}),
            (bytes(32), {**base, "hardware_revision": 2}),
            (bytes(32), {**base, "chip_revision": 1000}),
            (bytes(32), {**base, "factory_record_version": 0}),
            (bytes(32), {**base, "manifest_id": "0" * 32}),
        )
        for key, values in cases:
            with self.subTest(values=values):
                with self.assertRaises(SKU.FactorySKUManifestError):
                    SKU.build_manifest(key, **values)

    def test_combined_factory_nvs_rows_are_binary_only(self):
        onboarding_path = PROJECT / "tools" / "generate_onboarding_bundle.py"
        onboarding_spec = importlib.util.spec_from_file_location(
            "generate_onboarding_bundle_for_sku", onboarding_path
        )
        onboarding = importlib.util.module_from_spec(onboarding_spec)
        assert onboarding_spec and onboarding_spec.loader
        onboarding_spec.loader.exec_module(onboarding)
        manifest, _ = self.manifest()
        csv_data = onboarding.build_nvs_csv(b"material", manifest).decode("ascii")
        self.assertIn("prod_prov,namespace", csv_data)
        self.assertIn("prod_sku,namespace", csv_data)
        self.assertIn(
            "manifest,data,base64," + base64.b64encode(manifest).decode("ascii"),
            csv_data,
        )
        self.assertNotIn("VOICE_AGENT_KIT_BOX3", csv_data)

    def test_cli_outputs_are_private_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            key = root / "identity.key"
            key.write_bytes(bytes(range(32)))
            key.chmod(0o600)
            manifest = root / "manifest.bin"
            evidence = root / "evidence.json"
            command = [
                sys.executable,
                str(PROJECT / "tools" / "generate_factory_sku_manifest.py"),
                "--device-hmac-key", str(key),
                "--base-mac", "02:00:00:12:AB:EF",
                "--sku", "VOICE_AGENT_KIT_BOX3",
                "--board", "esp32s3-box3",
                "--hardware-revision", "1",
                "--chip-revision", "1",
                "--factory-record-version", "7",
                "--manifest-id", "00112233445566778899aabbccddeeff",
                "--manifest-output", str(manifest),
                "--evidence-output", str(evidence),
            ]
            subprocess.run(command, check=True, capture_output=True, text=True)
            before = (manifest.read_bytes(), evidence.read_bytes())
            self.assertEqual(manifest.stat().st_mode & 0o777, 0o600)
            self.assertEqual(evidence.stat().st_mode & 0o777, 0o600)
            second = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(second.returncode, 0)
            self.assertEqual(before, (manifest.read_bytes(), evidence.read_bytes()))


if __name__ == "__main__":
    unittest.main()
