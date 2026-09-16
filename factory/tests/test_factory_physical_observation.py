import base64
import copy
import importlib.util
import json
import pathlib
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


PROJECT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = PROJECT / "tools" / "factory_physical_observation.py"
SPEC = importlib.util.spec_from_file_location(
    "factory_physical_observation_test", MODULE_PATH
)
OBS = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(OBS)


def readbacks():
    return {
        "bootloader": b"B" * 0x3000,
        "partition_table": b"P" * 0xC00,
        "nvs_factory": b"N" * 0x6000,
        "ota_data_initial": b"O" * 0x2000,
        "application": b"A" * 0x11000,
    }


def efuse_summary():
    return (
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


def request():
    return OBS.build_request(
        observation_id="physical-readback-0001",
        transaction_id="factory-tx-0001",
        attempt_id="attempt-0001",
        device_id="xz-020000000001",
        serial_number="SN-0001",
        base_mac="02:00:00:00:00:01",
        chip_revision=1,
        signing_request_sha256="11" * 32,
        signed_artifact_verification_sha256="12" * 32,
        anti_rollback_secure_version=1,
        station_id="station-01",
        operators=["operator-a", "operator-b"],
        fixture_id="fixture-01",
        fixture_version="1.0.0",
        fixture_calibration_sha256="13" * 32,
        signing_key_id="factory-readback-authority-2026",
        port_fingerprint_sha256="14" * 32,
        chip_probe_log_sha256="15" * 32,
        efuse_summary_before=efuse_summary(),
        efuse_summary_after=efuse_summary(),
        readbacks=readbacks(),
        started_at="2026-08-10T10:00:00Z",
        finished_at="2026-08-10T10:05:00Z",
    )


def signed():
    key = Ed25519PrivateKey.generate()
    receipt = request()
    receipt["signature_b64url"] = base64.urlsafe_b64encode(
        key.sign(OBS.canonical_json(receipt))
    ).rstrip(b"=").decode("ascii")
    public_key = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return receipt, public_key, key


class FactoryPhysicalObservationTests(unittest.TestCase):
    def test_canonical_signed_physical_observation_verifies(self):
        receipt, public_key, _ = signed()
        raw = OBS.canonical_json(receipt)
        self.assertEqual(OBS.parse_canonical(raw, signed=True), receipt)
        OBS.verify_receipt(receipt, public_key)
        self.assertEqual(
            [item["offset"] for item in receipt["capture"]["regions"]],
            [0, 0x10000, 0x11000, 0x21000, 0x40000],
        )

    def test_test_environment_unknown_fields_and_noncanonical_json_fail_closed(self):
        receipt, _, _ = signed()
        receipt["environment"] = "TEST_ONLY"
        with self.assertRaisesRegex(OBS.PhysicalObservationError, "production"):
            OBS.validate(receipt, signed=True)
        receipt, _, _ = signed()
        receipt["simulated"] = True
        with self.assertRaisesRegex(OBS.PhysicalObservationError, "extra"):
            OBS.validate(receipt, signed=True)
        pretty = (json.dumps(signed()[0], indent=2) + "\n").encode()
        with self.assertRaisesRegex(OBS.PhysicalObservationError, "canonical"):
            OBS.parse_canonical(pretty, signed=True)

    def test_signature_tampering_and_private_key_input_are_rejected(self):
        receipt, public_key, private_key = signed()
        receipt["transaction"]["serial_number"] = "SN-OTHER"
        with self.assertRaisesRegex(OBS.PhysicalObservationError, "signature"):
            OBS.verify_receipt(receipt, public_key)
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        value, _, _ = signed()
        with self.assertRaisesRegex(OBS.PhysicalObservationError, "public key"):
            OBS.verify_receipt(value, private_pem)

    def test_two_person_fixture_and_frozen_tool_are_required(self):
        for mutate, message in (
            (
                lambda value: value["station"].update(
                    {"operators": ["operator-a"]}
                ),
                "operators",
            ),
            (
                lambda value: value["station"].update({"esptool_version": "5.3.2"}),
                "version",
            ),
            (
                lambda value: value["station"].update(
                    {"fixture_calibration_sha256": "bad"}
                ),
                "format",
            ),
        ):
            value = request()
            mutate(value)
            with self.assertRaisesRegex(OBS.PhysicalObservationError, message):
                OBS.validate(value, signed=False)

    def test_efuse_state_phase_and_security_assertions_are_frozen(self):
        value = request()
        value["capture"]["efuse_summary_after_sha256"] = "17" * 32
        with self.assertRaisesRegex(OBS.PhysicalObservationError, "eFuse state changed"):
            OBS.validate(value, signed=False)
        value = request()
        value["phase"] = "POST_SECURE_DOWNLOAD_LOCK"
        with self.assertRaisesRegex(OBS.PhysicalObservationError, "phase"):
            OBS.validate(value, signed=False)
        value = request()
        value["capture"]["secure_download_lock_pending"] = False
        with self.assertRaisesRegex(OBS.PhysicalObservationError, "must be true"):
            OBS.validate(value, signed=False)
        with self.assertRaisesRegex(OBS.PhysicalObservationError, "SECURE_BOOT_EN"):
            OBS.validate_efuse_summary(
                efuse_summary().replace(b"SECURE_BOOT_EN", b"SECURE_BOOT_NO"),
                base_mac="02:00:00:00:00:01",
                secure_version=1,
            )

    def test_transaction_release_and_each_readback_are_bound(self):
        receipt, _, _ = signed()
        arguments = {
            "receipt": receipt,
            "transaction_id": "factory-tx-0001",
            "attempt_id": "attempt-0001",
            "device_id": "xz-020000000001",
            "serial_number": "SN-0001",
            "base_mac": "02:00:00:00:00:01",
            "chip_revision": 1,
            "signing_request_sha256": "11" * 32,
            "signed_artifact_verification_sha256": "12" * 32,
            "anti_rollback_secure_version": 1,
            "readbacks": readbacks(),
        }
        OBS.bind_receipt(**arguments)
        changed = copy.deepcopy(arguments)
        changed["attempt_id"] = "attempt-other"
        with self.assertRaises(OBS.PhysicalObservationError):
            OBS.bind_receipt(**changed)
        changed = copy.deepcopy(arguments)
        changed["signing_request_sha256"] = "99" * 32
        with self.assertRaises(OBS.PhysicalObservationError):
            OBS.bind_receipt(**changed)
        changed = copy.deepcopy(arguments)
        changed["readbacks"]["application"] = b"wrong"
        with self.assertRaises(OBS.PhysicalObservationError):
            OBS.bind_receipt(**changed)

    def test_region_order_and_time_window_are_strict(self):
        value = request()
        value["capture"]["regions"].reverse()
        with self.assertRaisesRegex(OBS.PhysicalObservationError, "order"):
            OBS.validate(value, signed=False)
        value = request()
        value["finished_at"] = "2026-08-10T11:00:01Z"
        with self.assertRaisesRegex(OBS.PhysicalObservationError, "time window"):
            OBS.validate(value, signed=False)


if __name__ == "__main__":
    unittest.main()
