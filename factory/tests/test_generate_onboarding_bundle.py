import base64
import hashlib
import hmac
import importlib.util
import json
import pathlib
import unittest
import zlib


PROJECT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = PROJECT / "tools" / "generate_onboarding_bundle.py"
SPEC = importlib.util.spec_from_file_location("generate_onboarding_bundle", MODULE_PATH)
BUNDLE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(BUNDLE)


class OnboardingBundleTests(unittest.TestCase):
    def test_bundle_matches_device_contract(self):
        key = bytes(range(32))
        salt = bytes(range(1, 17))
        blob, label = BUNDLE.build_bundle(
            key, "02:00:00:12:AB:EF", "xiaozhi", salt=salt
        )
        self.assertEqual(len(blob), BUNDLE.BLOB_SIZE)
        self.assertEqual(blob[:4], b"PS21")
        self.assertEqual(blob[4], 1)
        self.assertEqual(blob[5], 16)
        self.assertEqual(int.from_bytes(blob[6:8], "little"), 384)
        self.assertEqual(blob[8:24], salt)
        self.assertEqual(blob[24:40], bytes(16))
        self.assertEqual(
            int.from_bytes(blob[424:428], "little"),
            zlib.crc32(blob[:424]) & 0xFFFFFFFF,
        )
        derived = hmac.new(
            key,
            BUNDLE.AP_KEY_DOMAIN + b"XA-12ABEF",
            hashlib.sha256,
        ).digest()
        expected_tag = hmac.new(
            derived,
            BUNDLE.MATERIAL_DOMAIN + blob[:428],
            hashlib.sha256,
        ).digest()
        self.assertEqual(blob[428:], expected_tag)
        self.assertEqual(label["service_name"], "XA-12ABEF")
        self.assertEqual(label["material_sha256"], hashlib.sha256(blob).hexdigest())
        qr = json.loads(label["qr_payload"])
        self.assertEqual(qr["security"], 2)
        self.assertEqual(qr["transport"], "softap")
        self.assertEqual(qr["password"], label["softap_password"])
        self.assertEqual(qr["pop"], label["security2_password"])

    def test_combined_nvs_csv_has_onboarding_and_sku_namespaces(self):
        material = bytes(range(32))
        manifest = bytes(range(70))
        csv_text = BUNDLE.build_nvs_csv(material, manifest).decode("ascii")
        self.assertIn("prod_prov,namespace", csv_text)
        self.assertIn("prod_sku,namespace", csv_text)
        self.assertIn(base64.b64encode(material).decode("ascii"), csv_text)
        self.assertIn(base64.b64encode(manifest).decode("ascii"), csv_text)

    def test_input_validation(self):
        with self.assertRaises(BUNDLE.BundleError):
            BUNDLE.build_bundle(b"short", "02:00:00:12:AB:EF", "xiaozhi")
        with self.assertRaises(BUNDLE.BundleError):
            BUNDLE.build_bundle(
                bytes(32), "invalid", "xiaozhi", salt=bytes(range(1, 17))
            )
        with self.assertRaises(BUNDLE.BundleError):
            BUNDLE.build_bundle(
                bytes(32), "02:00:00:12:AB:EF", "bad user", salt=bytes(range(1, 17))
            )


if __name__ == "__main__":
    unittest.main()
