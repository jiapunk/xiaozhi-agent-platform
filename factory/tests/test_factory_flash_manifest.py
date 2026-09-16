import base64
import copy
import hashlib
import importlib.util
import json
import pathlib
import struct
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


PROJECT = pathlib.Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


FLASH = load("factory_flash_manifest", PROJECT / "tools" / "factory_flash_manifest.py")
OBSERVATION = load(
    "factory_physical_observation_for_flash",
    PROJECT / "tools" / "factory_physical_observation.py",
)
SKU = load("factory_sku_manifest_for_flash", PROJECT / "tools" / "factory_sku_manifest.py")


def partition_table():
    data = bytearray([0xFF]) * 0xC00
    for index, (label, values) in enumerate(FLASH.EXPECTED_PARTITIONS.items()):
        kind, subtype, address, size, flags = values
        struct.pack_into(
            "<HBBII16sI",
            data,
            index * 32,
            0x50AA,
            kind,
            subtype,
            address,
            size,
            label.encode("ascii").ljust(16, b"\0"),
            flags,
        )
    return bytes(data)


class FactoryFlashManifestTests(unittest.TestCase):
    def fixture(self):
        unsigned_bootloader = bytes([0x42]) * 0x2000
        unsigned_application = bytes([0x41]) * 0x10000
        signed_bootloader = unsigned_bootloader + bytes([0xE7]) + bytes(0xFFF)
        signed_application = unsigned_application + bytes([0xE7]) + bytes(0xFFF)
        table = partition_table()
        ota = bytes([0x4F]) * 0x2000
        request = {
            "version": 1,
            "profile": FLASH.PROFILE,
            "target": "esp32s3",
            "idf_version": "6.0.2",
            "upstream_commits": {},
            "secure_boot": {},
            "efuse_key_block_map": [],
            "flash_encryption": {"mode": "release", "scheme": "XTS-AES-128"},
            "anti_rollback_secure_version": 1,
            "partition_table_offset": 0x10000,
            "artifacts": {
                "bootloader": {
                    "size": len(unsigned_bootloader),
                    "sha256": hashlib.sha256(unsigned_bootloader).hexdigest(),
                },
                "application": {
                    "size": len(unsigned_application),
                    "sha256": hashlib.sha256(unsigned_application).hexdigest(),
                    "project": "xiaozhi_agent_platform",
                    "project_version": "0.24.0-security-gate",
                    "secure_version": 1,
                },
                "partition_table": {
                    "size": len(table),
                    "sha256": hashlib.sha256(table).hexdigest(),
                },
                "ota_data_initial": {
                    "size": len(ota),
                    "sha256": hashlib.sha256(ota).hexdigest(),
                },
            },
        }
        request_sha = hashlib.sha256(FLASH.canonical_json(request)).hexdigest()
        signed_receipt = {
            "version": 1,
            "profile": FLASH.PROFILE,
            "signing_request_sha256": request_sha,
            "anti_rollback_secure_version": 1,
            "bootloader": {
                "size": len(signed_bootloader),
                "sha256": hashlib.sha256(signed_bootloader).hexdigest(),
            },
            "application": {
                "size": len(signed_application),
                "sha256": hashlib.sha256(signed_application).hexdigest(),
            },
            "secure_boot_digests": [
                {"slot": slot, "digest_sha256": f"0{slot + 1}" * 32}
                for slot in range(3)
            ],
            "application_signing_slot": 0,
        }
        signed_receipt_raw = FLASH.canonical_json(signed_receipt)
        sku_manifest, sku_evidence = SKU.build_manifest(
            bytes(range(32)),
            base_mac="02:00:00:00:00:01",
            sku="VOICE_AGENT_KIT_BOX3",
            board="esp32s3-box3",
            hardware_revision=1,
            chip_revision=1,
            factory_record_version=7,
            manifest_id="00112233445566778899aabbccddeeff",
        )
        material = bytes(index % 251 for index in range(460))
        nvs_csv = (
            "key,type,encoding,value\n"
            "prod_prov,namespace,,\n"
            f"sec2,data,base64,{base64.b64encode(material).decode('ascii')}\n"
            "prod_sku,namespace,,\n"
            f"manifest,data,base64,{base64.b64encode(sku_manifest).decode('ascii')}\n"
        ).encode("ascii")
        nvs_image = bytes([0xFF]) * 0x6000
        nvs_entries = [
            {
                "namespace": "prod_prov",
                "key": "sec2",
                "encoding": "blob_data",
                "data": base64.b64encode(material).decode("ascii"),
                "state": "Written",
                "is_empty": False,
            },
            {
                "namespace": "prod_sku",
                "key": "manifest",
                "encoding": "blob_data",
                "data": base64.b64encode(sku_manifest).decode("ascii"),
                "state": "Written",
                "is_empty": False,
            },
        ]
        sources = {
            "bootloader": signed_bootloader,
            "partition_table": table,
            "ota_data_initial": ota,
            "application": signed_application,
        }
        encrypted = {
            name: bytes(byte ^ 0xA5 for byte in data) for name, data in sources.items()
        }
        readback = {**encrypted, "nvs_factory": nvs_image}
        efuse_summary = (
            "espefuse v5.3.1\n"
            "MAC (BLOCK1) MAC address\n"
            " = 02:00:00:00:00:01 (OK) R/W\n"
            "DIS_DOWNLOAD_MODE (BLOCK0) download mode = False R/W (0b0)\n"
            "DIS_DOWNLOAD_MANUAL_ENCRYPT (BLOCK0) manual encrypt = True R/W (0b1)\n"
            "SPI_BOOT_CRYPT_CNT (BLOCK0) flash encryption = Enable R/W (0b111)\n"
            "SECURE_BOOT_EN (BLOCK0) secure boot = True R/W (0b1)\n"
            "ENABLE_SECURITY_DOWNLOAD (BLOCK0) secure download = False R/W (0b0)\n"
            "SECURE_VERSION (BLOCK0) anti rollback = 1 R/W (0x0001)\n"
        ).encode("ascii")
        observation_key = Ed25519PrivateKey.generate()
        observation = OBSERVATION.build_request(
            observation_id="physical-readback-0001",
            transaction_id="factory-tx-0001",
            attempt_id="attempt-0001",
            device_id="xz-020000000001",
            serial_number="SN-0001",
            base_mac="02:00:00:00:00:01",
            chip_revision=1,
            signing_request_sha256=request_sha,
            signed_artifact_verification_sha256=hashlib.sha256(
                signed_receipt_raw
            ).hexdigest(),
            anti_rollback_secure_version=1,
            station_id="factory-station-01",
            operators=["operator-a", "operator-b"],
            fixture_id="fixture-01",
            fixture_version="1.0.0",
            fixture_calibration_sha256="31" * 32,
            signing_key_id="physical-observation-key-2026",
            port_fingerprint_sha256="32" * 32,
            chip_probe_log_sha256="33" * 32,
            efuse_summary_before=efuse_summary,
            efuse_summary_after=efuse_summary,
            readbacks=readback,
            started_at="2026-08-10T10:00:00Z",
            finished_at="2026-08-10T10:05:00Z",
        )
        observation["signature_b64url"] = base64.urlsafe_b64encode(
            observation_key.sign(OBSERVATION.canonical_json(observation))
        ).rstrip(b"=").decode("ascii")
        observation_raw = OBSERVATION.canonical_json(observation)
        observation_public_key = observation_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return {
            "transaction_id": "factory-tx-0001",
            "attempt_id": "attempt-0001",
            "device_id": "xz-020000000001",
            "serial_number": "SN-0001",
            "base_mac": "02:00:00:00:00:01",
            "chip_revision": 1,
            "request": request,
            "request_sha256": request_sha,
            "signed_artifact_receipt": signed_receipt,
            "signed_artifact_receipt_raw": signed_receipt_raw,
            "factory_sku_evidence": sku_evidence,
            "signed_bootloader": signed_bootloader,
            "signed_application": signed_application,
            "partition_table": table,
            "ota_data_initial": ota,
            "factory_sku_manifest": sku_manifest,
            "onboarding_material": material,
            "nvs_csv": nvs_csv,
            "nvs_factory_image": nvs_image,
            "nvs_entries": nvs_entries,
            "encrypted": encrypted,
            "encryption_reference": copy.deepcopy(encrypted),
            "readback": readback,
            "physical_observation_receipt": observation,
            "physical_observation_receipt_raw": observation_raw,
            "physical_observation_public_key_pem": observation_public_key,
            "espsecure_version": "5.3.1",
            "nvs_tool_bundle_sha256": "11" * 32,
            "builder_tool_bundle_sha256": "22" * 32,
        }

    def build(self, fixture=None):
        return FLASH.build_manifest(**(fixture or self.fixture()))

    def test_complete_manifest_is_canonical_and_strict(self):
        manifest = self.build()
        payload = FLASH.canonical_json(manifest)
        self.assertEqual(FLASH.parse_manifest_bytes(payload), manifest)
        self.assertTrue(manifest["complete"])
        self.assertEqual(
            [item["offset"] for item in manifest["programmed_regions"]],
            [0, 0x10000, 0x11000, 0x21000, 0x40000],
        )
        self.assertEqual(
            manifest["transaction"]["factory_record_version"], 7
        )
        self.assertEqual(
            manifest["physical_flash_observation"]["observation_id"],
            "physical-readback-0001",
        )

    def test_cross_device_and_cross_release_mix_are_rejected(self):
        for mutate in (
            lambda item: item.update({"device_id": "xz-020000000002"}),
            lambda item: item["signed_artifact_receipt"].update(
                {"signing_request_sha256": "00" * 32}
            ),
            lambda item: item["factory_sku_evidence"].update(
                {"base_mac": "02:00:00:00:00:02"}
            ),
            lambda item: item.update({"signed_application": bytes(0x11000)}),
        ):
            fixture = self.fixture()
            mutate(fixture)
            with self.assertRaises(FLASH.FactoryFlashManifestError):
                self.build(fixture)

    def test_ciphertext_reproduction_and_raw_readback_are_required(self):
        fixture = self.fixture()
        fixture["encrypted"]["application"] = fixture["signed_application"]
        fixture["encryption_reference"]["application"] = fixture[
            "signed_application"
        ]
        fixture["readback"]["application"] = fixture["signed_application"]
        with self.assertRaisesRegex(
            FLASH.FactoryFlashManifestError, "readback|not encrypted"
        ):
            self.build(fixture)

        fixture = self.fixture()
        fixture["readback"]["bootloader"] = bytes(
            [fixture["readback"]["bootloader"][0] ^ 1]
        ) + fixture["readback"]["bootloader"][1:]
        with self.assertRaisesRegex(FLASH.FactoryFlashManifestError, "readback"):
            self.build(fixture)

        fixture = self.fixture()
        fixture["encryption_reference"]["partition_table"] = bytes(
            len(fixture["encrypted"]["partition_table"])
        )
        with self.assertRaisesRegex(FLASH.FactoryFlashManifestError, "reproducible"):
            self.build(fixture)

        fixture = self.fixture()
        fixture["physical_observation_receipt"]["transaction"]["attempt_id"] = (
            "attempt-other"
        )
        with self.assertRaisesRegex(FLASH.FactoryFlashManifestError, "signature"):
            self.build(fixture)

    def test_nvs_csv_image_and_exact_public_entry_set_are_required(self):
        fixture = self.fixture()
        fixture["nvs_entries"].append(
            {
                "namespace": "secret",
                "key": "token",
                "encoding": "blob_data",
                "data": base64.b64encode(b"forbidden").decode("ascii"),
                "state": "Written",
                "is_empty": False,
            }
        )
        with self.assertRaisesRegex(FLASH.FactoryFlashManifestError, "unexpected"):
            self.build(fixture)

        fixture = self.fixture()
        fixture["nvs_csv"] += b"extra,namespace,,\n"
        with self.assertRaisesRegex(FLASH.FactoryFlashManifestError, "CSV"):
            self.build(fixture)

        fixture = self.fixture()
        fixture["readback"]["nvs_factory"] = bytes(0x6000)
        with self.assertRaisesRegex(FLASH.FactoryFlashManifestError, "readback"):
            self.build(fixture)

    def test_incomplete_noncanonical_and_overwrite_are_rejected(self):
        manifest = self.build()
        manifest["complete"] = False
        with self.assertRaisesRegex(FLASH.FactoryFlashManifestError, "completion"):
            FLASH.parse_manifest_bytes(FLASH.canonical_json(manifest))

        manifest = self.build()
        pretty = (json.dumps(manifest, indent=2) + "\n").encode()
        with self.assertRaisesRegex(FLASH.FactoryFlashManifestError, "canonical"):
            FLASH.parse_manifest_bytes(pretty)

        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "manifest.json"
            payload = FLASH.canonical_json(self.build())
            FLASH.write_new(output, payload)
            FLASH.write_new(output, payload)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            output.write_bytes(b"{}\n")
            with self.assertRaisesRegex(FLASH.FactoryFlashManifestError, "differs"):
                FLASH.write_new(output, payload)


if __name__ == "__main__":
    unittest.main()
