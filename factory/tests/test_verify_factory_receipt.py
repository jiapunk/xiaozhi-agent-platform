import base64
import hashlib
import importlib.util
import json
import pathlib
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


PROJECT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = PROJECT / "tools" / "verify_factory_receipt.py"
SPEC = importlib.util.spec_from_file_location("verify_factory_receipt", MODULE_PATH)
VERIFY = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(VERIFY)
FLASH_MODULE_PATH = PROJECT / "tools" / "factory_flash_manifest.py"
FLASH_SPEC = importlib.util.spec_from_file_location(
    "factory_flash_manifest_for_receipt", FLASH_MODULE_PATH
)
FLASH = importlib.util.module_from_spec(FLASH_SPEC)
assert FLASH_SPEC and FLASH_SPEC.loader
FLASH_SPEC.loader.exec_module(FLASH)
OBS_MODULE_PATH = PROJECT / "tools" / "factory_physical_observation.py"
OBS_SPEC = importlib.util.spec_from_file_location(
    "factory_physical_observation_for_receipt", OBS_MODULE_PATH
)
OBS = importlib.util.module_from_spec(OBS_SPEC)
assert OBS_SPEC and OBS_SPEC.loader
OBS_SPEC.loader.exec_module(OBS)


def encoded(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def receipt_template():
    return {
        "version": 4,
        "receipt_id": "receipt-0001",
        "device_id": "xz-020000000001",
        "serial_number": "SN-0001",
        "chip": {
            "model": "ESP32-S3",
            "base_mac": "02:00:00:00:00:01",
            "softap_mac": "02:00:00:00:00:02",
            "revision": 1,
        },
        "product_identity": {
            "sku": "VOICE_AGENT_KIT_BOX3",
            "board": "esp32s3-box3",
            "hardware_revision": 1,
            "chip_revision": 1,
            "base_mac": "02:00:00:00:00:01",
            "manifest_schema": 1,
            "manifest_id": "00112233445566778899aabbccddeeff",
            "factory_record_version": 1,
            "manifest_sha256": "9a" * 32,
            "manifest_size": 70,
            "nvs_namespace": "prod_sku",
            "nvs_key": "manifest",
            "authentication_domain": "XIAOZHI-PRODUCT-SKU-MANIFEST-V1",
            "identity_hmac_key_slot": 5,
            "runtime_verification_pass": True,
        },
        "station": {
            "id": "station-01",
            "operators": ["operator-a", "operator-b"],
            "espefuse_version": "5.3.1",
            "fixture_version": "fixture-1.0",
            "signing_key_id": "factory-signing-2026-01",
        },
        "identity_key": {
            "slot": 5,
            "purpose": "HMAC_UP",
            "read_protected": True,
            "write_protected": True,
            "purpose_write_protected": True,
            "confirmation_b64url": encoded(bytes(range(32))),
        },
        "secure_storage": {
            "key": {
                "slot": 4,
                "purpose": "HMAC_UP",
                "read_protected": True,
                "write_protected": True,
                "purpose_write_protected": True,
                "confirmation_b64url": encoded(bytes(range(31, -1, -1))),
            },
            "credential_partition": "nvs",
            "encryption_scheme": "HMAC_XTS_AES",
            "factory_partition": "nvs_factory",
            "factory_material_public_only": True,
        },
        "boot_security": {
            "secure_boot_scheme": "RSA-3072",
            "secure_boot_digests": [
                {
                    "slot": slot,
                    "purpose": f"SECURE_BOOT_DIGEST{slot}",
                    "key_id": f"boot-signing-{slot}",
                    "digest_sha256": f"0{slot + 1}" * 32,
                    "read_protected": False,
                    "write_protected": True,
                    "purpose_write_protected": True,
                }
                for slot in range(3)
            ],
            "flash_encryption_key": {
                "slot": 3,
                "purpose": "XTS_AES_128_KEY",
                "read_protected": True,
                "write_protected": True,
                "purpose_write_protected": True,
            },
            "secure_download_mode": True,
            "jtag_disabled": True,
            "read_protect_lock_closed": True,
            "anti_rollback_efuse_version": 1,
            "signing_request_sha256": "12" * 32,
            "signed_artifact_verification_sha256": "56" * 32,
            "encrypted_flash_manifest_sha256": "78" * 32,
            "efuse_summary_sha256": "34" * 32,
        },
        "onboarding": {
            "material_sha256": "cd" * 32,
            "nvs_factory_readback_sha256": "ef" * 32,
            "label_issue_id": "label-0001",
            "security2_transaction_pass": True,
        },
        "registry": {
            "record_version": 1,
            "committed": True,
            "sku": "VOICE_AGENT_KIT_BOX3",
            "board": "esp32s3-box3",
            "hardware_revision": 1,
            "factory_manifest_sha256": "9a" * 32,
        },
        "firmware": {
            "sha256": "ab" * 32,
            "secure_boot_v2": True,
            "flash_encryption_release_mode": True,
            "security_version": 1,
        },
        "tests": {
            "efuse_summary_pass": True,
            "identity_hmac_challenge_pass": True,
            "storage_hmac_challenge_pass": True,
            "encrypted_nvs_roundtrip_pass": True,
            "onboarding_button_gesture_pass": True,
            "factory_sku_identity_pass": True,
            "session_issuance_pass": True,
            "wss_upgrade_pass": True,
            "signed_bootloader_verification_pass": True,
            "signed_app_verification_pass": True,
            "flash_encryption_roundtrip_pass": True,
            "anti_rollback_rejection_pass": True,
            "secure_download_mode_pass": True,
        },
        "started_at": "2026-08-09T12:00:00Z",
        "finished_at": "2026-08-09T12:01:00Z",
        "result": "PASS",
        "signature_algorithm": "Ed25519",
        "receipt_signature_b64url": encoded(bytes(64)),
    }


def complete_flash_manifest(receipt):
    boot_signed = "b1" * 32
    app_signed = "a1" * 32
    partition_source = "c1" * 32
    ota_source = "d1" * 32
    nvs_source = receipt["onboarding"]["nvs_factory_readback_sha256"]
    sources = [boot_signed, partition_source, nvs_source, ota_source, app_signed]
    sizes = [0x3000, 0xC00, 0x6000, 0x2000, 0x11000]
    regions = []
    for index, policy in enumerate(FLASH.REGION_POLICY):
        name, offset, source_treatment, flash_treatment = policy
        programmed = sources[index] if name == "nvs_factory" else f"e{index}" * 32
        regions.append(
            {
                "name": name,
                "offset": offset,
                "size": sizes[index],
                "source_treatment": source_treatment,
                "flash_treatment": flash_treatment,
                "source_sha256": sources[index],
                "programmed_sha256": programmed,
                "readback_sha256": programmed,
            }
        )
    observation_key = Ed25519PrivateKey.generate()
    observation = {
        "schema": OBS.SCHEMA,
        "observation_id": "physical-readback-0001",
        "environment": OBS.ENVIRONMENT,
        "phase": OBS.PHASE,
        "transaction": {
            "transaction_id": "factory-tx-0001",
            "attempt_id": "attempt-0001",
            "device_id": receipt["device_id"],
            "serial_number": receipt["serial_number"],
            "base_mac": receipt["chip"]["base_mac"],
        },
        "product": {
            "sku": receipt["product_identity"]["sku"],
            "board": receipt["product_identity"]["board"],
            "hardware_revision": receipt["product_identity"]["hardware_revision"],
            "chip_model": "ESP32-S3",
            "chip_revision": receipt["product_identity"]["chip_revision"],
        },
        "release": {
            "signing_request_sha256": receipt["boot_security"][
                "signing_request_sha256"
            ],
            "signed_artifact_verification_sha256": receipt["boot_security"][
                "signed_artifact_verification_sha256"
            ],
            "anti_rollback_secure_version": receipt["firmware"]["security_version"],
        },
        "station": {
            "id": "station-01",
            "operators": ["operator-a", "operator-b"],
            "fixture_id": "fixture-01",
            "fixture_version": "1.0.0",
            "fixture_calibration_sha256": "41" * 32,
            "signing_key_id": "physical-observation-key-2026",
            "esptool_version": "5.3.1",
        },
        "capture": {
            "transport": "UART_ROM_DOWNLOAD",
            "port_fingerprint_sha256": "42" * 32,
            "chip_probe_log_sha256": "43" * 32,
            "efuse_summary_before_sha256": "44" * 32,
            "efuse_summary_after_sha256": "44" * 32,
            "flash_encryption_enabled": True,
            "download_manual_encrypt_disabled": True,
            "secure_download_lock_pending": True,
            "raw_readback_pass": True,
            "regions": [
                {
                    "name": item["name"],
                    "offset": item["offset"],
                    "size": item["size"],
                    "readback_sha256": item["readback_sha256"],
                }
                for item in regions
            ],
        },
        "started_at": "2026-08-09T11:50:00Z",
        "finished_at": "2026-08-09T11:55:00Z",
        "result": OBS.RESULT,
        "signature_algorithm": "Ed25519",
    }
    observation["signature_b64url"] = encoded(
        observation_key.sign(OBS.canonical_json(observation))
    )
    observation_raw = OBS.canonical_json(observation)
    observation_public_key = observation_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    manifest = {
        "version": 2,
        "format": FLASH.FORMAT,
        "profile": FLASH.PROFILE,
        "complete": True,
        "transaction": {
            "transaction_id": "factory-tx-0001",
            "attempt_id": "attempt-0001",
            "device_id": receipt["device_id"],
            "serial_number": receipt["serial_number"],
            "base_mac": receipt["chip"]["base_mac"],
            "sku": receipt["product_identity"]["sku"],
            "board": receipt["product_identity"]["board"],
            "hardware_revision": receipt["product_identity"]["hardware_revision"],
            "chip_revision": receipt["product_identity"]["chip_revision"],
            "factory_record_version": receipt["product_identity"][
                "factory_record_version"
            ],
            "factory_manifest_id": receipt["product_identity"]["manifest_id"],
            "factory_manifest_sha256": receipt["product_identity"][
                "manifest_sha256"
            ],
        },
        "release": {
            "signing_request_sha256": receipt["boot_security"][
                "signing_request_sha256"
            ],
            "signed_artifact_verification_sha256": receipt["boot_security"][
                "signed_artifact_verification_sha256"
            ],
            "anti_rollback_secure_version": receipt["firmware"]["security_version"],
            "application_unsigned_sha256": receipt["firmware"]["sha256"],
            "application_signed_sha256": app_signed,
            "bootloader_signed_sha256": boot_signed,
            "secure_boot_digests": [
                {
                    "slot": item["slot"],
                    "digest_sha256": item["digest_sha256"],
                }
                for item in receipt["boot_security"]["secure_boot_digests"]
            ],
            "application_signing_slot": 0,
        },
        "factory_material": {
            "onboarding_material_sha256": receipt["onboarding"][
                "material_sha256"
            ],
            "factory_sku_manifest_sha256": receipt["product_identity"][
                "manifest_sha256"
            ],
            "nvs_factory_image_sha256": nvs_source,
            "nvs_factory_readback_sha256": nvs_source,
            "nvs_factory_size": 0x6000,
            "exact_public_entries": ["prod_prov/sec2", "prod_sku/manifest"],
        },
        "physical_flash_observation": {
            "schema": observation["schema"],
            "observation_id": observation["observation_id"],
            "environment": observation["environment"],
            "phase": observation["phase"],
            "station_id": observation["station"]["id"],
            "signing_key_id": observation["station"]["signing_key_id"],
            "receipt_sha256": hashlib.sha256(observation_raw).hexdigest(),
        },
        "programmed_regions": regions,
        "partition_initial_state": FLASH.PARTITIONS,
        "tools": {
            "espsecure_version": "5.3.1",
            "nvs_partition_tool_bundle_sha256": "71" * 32,
            "factory_manifest_builder_bundle_sha256": "72" * 32,
        },
    }
    raw = FLASH.canonical_json(manifest)
    receipt["boot_security"]["encrypted_flash_manifest_sha256"] = (
        hashlib.sha256(raw).hexdigest()
    )
    return manifest, raw, observation, observation_raw, observation_public_key


class FactoryReceiptTests(unittest.TestCase):
    def setUp(self):
        self.private_key = Ed25519PrivateKey.generate()
        self.public_pem = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def signed_receipt(self):
        receipt = receipt_template()
        signature = self.private_key.sign(VERIFY.canonical_payload(receipt))
        receipt["receipt_signature_b64url"] = encoded(signature)
        return receipt

    def test_valid_signed_receipt(self):
        receipt = self.signed_receipt()
        VERIFY.verify_receipt(receipt, self.public_pem)

    def test_tampering_breaks_signature(self):
        receipt = self.signed_receipt()
        receipt["serial_number"] = "SN-0002"
        with self.assertRaisesRegex(VERIFY.ReceiptError, "signature"):
            VERIFY.verify_receipt(receipt, self.public_pem)

    def test_duplicate_and_unknown_fields_fail_closed(self):
        with self.assertRaisesRegex(VERIFY.ReceiptError, "duplicate"):
            VERIFY.parse_receipt_bytes(b'{"version":1,"version":1}')
        receipt = self.signed_receipt()
        receipt["bootstrap_secret"] = "forbidden"
        with self.assertRaisesRegex(VERIFY.ReceiptError, "extra"):
            VERIFY.validate_receipt(receipt)
        receipt = self.signed_receipt()
        receipt["version"] = 4.0
        with self.assertRaisesRegex(VERIFY.ReceiptError, "integer"):
            VERIFY.validate_receipt(receipt)

    def test_security_and_two_person_gates_are_required(self):
        receipt = self.signed_receipt()
        receipt["firmware"]["secure_boot_v2"] = False
        with self.assertRaisesRegex(VERIFY.ReceiptError, "must be true"):
            VERIFY.validate_receipt(receipt)
        receipt = self.signed_receipt()
        receipt["station"]["operators"] = ["operator-a", "operator-a"]
        with self.assertRaises(VERIFY.ReceiptError):
            VERIFY.validate_receipt(receipt)

    def test_noncanonical_base64_and_time_order_are_rejected(self):
        receipt = self.signed_receipt()
        receipt["identity_key"]["confirmation_b64url"] += "="
        with self.assertRaisesRegex(VERIFY.ReceiptError, "base64url"):
            VERIFY.validate_receipt(receipt)
        receipt = self.signed_receipt()
        receipt["finished_at"] = "2026-08-09T11:59:59Z"
        with self.assertRaisesRegex(VERIFY.ReceiptError, "precedes"):
            VERIFY.validate_receipt(receipt)

    def test_identity_and_storage_slots_are_frozen(self):
        receipt = self.signed_receipt()
        receipt["secure_storage"]["key"]["slot"] = 3
        with self.assertRaisesRegex(VERIFY.ReceiptError, "block 4"):
            VERIFY.validate_receipt(receipt)
        receipt = self.signed_receipt()
        receipt["identity_key"]["slot"] = 4
        with self.assertRaisesRegex(VERIFY.ReceiptError, "block 5"):
            VERIFY.validate_receipt(receipt)

    def test_device_id_is_derived_from_base_mac(self):
        receipt = self.signed_receipt()
        receipt["device_id"] = "xz-020000000002"
        with self.assertRaisesRegex(VERIFY.ReceiptError, "base MAC"):
            VERIFY.validate_receipt(receipt)

    def test_factory_sku_identity_is_bound_to_observed_device(self):
        receipt = self.signed_receipt()
        receipt["product_identity"]["base_mac"] = "02:00:00:00:00:02"
        with self.assertRaisesRegex(VERIFY.ReceiptError, "base MAC"):
            VERIFY.validate_receipt(receipt)
        receipt = self.signed_receipt()
        receipt["product_identity"]["chip_revision"] = 2
        with self.assertRaisesRegex(VERIFY.ReceiptError, "chip revision"):
            VERIFY.validate_receipt(receipt)

    def test_registry_must_match_authenticated_factory_manifest(self):
        for field, value in (
            ("record_version", 2),
            ("sku", "OTHER_SKU"),
            ("board", "other-board"),
            ("hardware_revision", 2),
            ("factory_manifest_sha256", "00" * 32),
        ):
            receipt = self.signed_receipt()
            receipt["registry"][field] = value
            with self.assertRaises(VERIFY.ReceiptError):
                VERIFY.validate_receipt(receipt)

    def test_factory_sku_runtime_verification_is_required(self):
        receipt = self.signed_receipt()
        receipt["product_identity"]["runtime_verification_pass"] = False
        with self.assertRaisesRegex(VERIFY.ReceiptError, "must be true"):
            VERIFY.validate_receipt(receipt)

    def test_complete_encrypted_flash_manifest_is_bound_to_signed_receipt(self):
        receipt = receipt_template()
        manifest, raw, observation, observation_raw, _ = complete_flash_manifest(
            receipt
        )
        FLASH.validate_manifest(manifest)
        VERIFY.validate_encrypted_flash_manifest_binding(
            receipt, manifest, raw, observation, observation_raw
        )

    def test_resigned_cross_transaction_flash_manifest_is_rejected(self):
        mutations = (
            lambda manifest: manifest["transaction"].update(
                {"serial_number": "SN-OTHER"}
            ),
            lambda manifest: manifest["release"].update(
                {"signing_request_sha256": "91" * 32}
            ),
            lambda manifest: manifest["factory_material"].update(
                {"onboarding_material_sha256": "92" * 32}
            ),
            lambda manifest: manifest["release"]["secure_boot_digests"][0].update(
                {"digest_sha256": "93" * 32}
            ),
        )
        for mutate in mutations:
            receipt = receipt_template()
            manifest, _, observation, observation_raw, _ = complete_flash_manifest(
                receipt
            )
            mutate(manifest)
            raw = FLASH.canonical_json(manifest)
            receipt["boot_security"]["encrypted_flash_manifest_sha256"] = (
                hashlib.sha256(raw).hexdigest()
            )
            with self.assertRaises(VERIFY.ReceiptError):
                VERIFY.validate_encrypted_flash_manifest_binding(
                    receipt, manifest, raw, observation, observation_raw
                )
        receipt = self.signed_receipt()
        receipt["tests"]["factory_sku_identity_pass"] = False
        with self.assertRaisesRegex(VERIFY.ReceiptError, "must be true"):
            VERIFY.validate_receipt(receipt)

    def test_storage_and_onboarding_gates_are_required(self):
        receipt = self.signed_receipt()
        receipt["tests"]["encrypted_nvs_roundtrip_pass"] = False
        with self.assertRaisesRegex(VERIFY.ReceiptError, "must be true"):
            VERIFY.validate_receipt(receipt)
        receipt = self.signed_receipt()
        receipt["onboarding"]["security2_transaction_pass"] = False
        with self.assertRaisesRegex(VERIFY.ReceiptError, "must be true"):
            VERIFY.validate_receipt(receipt)

    def test_physical_onboarding_gesture_gate_is_required(self):
        receipt = self.signed_receipt()
        receipt["tests"]["onboarding_button_gesture_pass"] = False
        with self.assertRaisesRegex(VERIFY.ReceiptError, "must be true"):
            VERIFY.validate_receipt(receipt)
        receipt = self.signed_receipt()
        del receipt["tests"]["onboarding_button_gesture_pass"]
        with self.assertRaisesRegex(VERIFY.ReceiptError, "missing"):
            VERIFY.validate_receipt(receipt)

    def test_boot_security_map_and_anti_rollback_are_required(self):
        receipt = self.signed_receipt()
        receipt["boot_security"]["secure_boot_digests"][1]["slot"] = 2
        with self.assertRaisesRegex(VERIFY.ReceiptError, "sequential"):
            VERIFY.validate_receipt(receipt)
        receipt = self.signed_receipt()
        receipt["boot_security"]["flash_encryption_key"]["purpose"] = (
            "XTS_AES_256_KEY_1"
        )
        with self.assertRaisesRegex(VERIFY.ReceiptError, "XTS_AES_128_KEY"):
            VERIFY.validate_receipt(receipt)
        receipt = self.signed_receipt()
        receipt["firmware"]["security_version"] = 2
        with self.assertRaisesRegex(VERIFY.ReceiptError, "anti-rollback"):
            VERIFY.validate_receipt(receipt)

    def test_boot_security_physical_gates_are_required(self):
        for field in (
            "signed_bootloader_verification_pass",
            "signed_app_verification_pass",
            "flash_encryption_roundtrip_pass",
            "anti_rollback_rejection_pass",
            "secure_download_mode_pass",
        ):
            receipt = self.signed_receipt()
            receipt["tests"][field] = False
            with self.assertRaisesRegex(VERIFY.ReceiptError, "must be true"):
                VERIFY.validate_receipt(receipt)

    def test_signed_artifact_receipt_binding_is_required(self):
        receipt = self.signed_receipt()
        del receipt["boot_security"]["signed_artifact_verification_sha256"]
        with self.assertRaisesRegex(VERIFY.ReceiptError, "missing"):
            VERIFY.validate_receipt(receipt)
        receipt = self.signed_receipt()
        receipt["boot_security"]["signed_artifact_verification_sha256"] = "0" * 63
        with self.assertRaisesRegex(VERIFY.ReceiptError, "invalid format"):
            VERIFY.validate_receipt(receipt)


if __name__ == "__main__":
    unittest.main()
