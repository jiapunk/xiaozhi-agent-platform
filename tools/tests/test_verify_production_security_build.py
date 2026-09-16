import importlib.util
import pathlib
import struct
import tempfile
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = PROJECT / "tools" / "verify_production_security_build.py"
SPEC = importlib.util.spec_from_file_location(
    "verify_production_security_build", MODULE_PATH
)
VERIFY = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(VERIFY)


class ProductionSecurityBuildVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.build = pathlib.Path(self.temp.name)
        (self.build / "partition_table").mkdir()
        (self.build / "bootloader").mkdir()
        self._write_config()
        self._write_partition_table()
        self._write_app()
        self._write_bootloader()
        (self.build / "ota_data_initial.bin").write_bytes(bytes(0x2000))

    def tearDown(self):
        self.temp.cleanup()

    def _write_config(self):
        lines = [f"{name}=y" for name in sorted(VERIFY.REQUIRED_TRUE)]
        lines.extend(
            f"# {name} is not set" for name in sorted(VERIFY.REQUIRED_FALSE)
        )
        lines.extend(
            f"{name}={value}" for name, value in VERIFY.EXPECTED_CONFIG.items()
        )
        lines.extend(
            [
                "CONFIG_BOOTLOADER_APP_SECURE_VERSION=1",
                'CONFIG_APP_PROJECT_VER="0.24.0-security-gate"',
            ]
        )
        (self.build / "sdkconfig").write_text("\n".join(lines) + "\n")

    def _write_partition_table(self):
        data = bytearray(b"\xff" * 0xC00)
        for index, (name, values) in enumerate(
            VERIFY.EXPECTED_PARTITIONS.items()
        ):
            part_type, subtype, address, size, flags = values
            label = name.encode("ascii").ljust(16, b"\0")
            struct.pack_into(
                "<HBBII16sI",
                data,
                index * 32,
                VERIFY.PARTITION_MAGIC,
                part_type,
                subtype,
                address,
                size,
                label,
                flags,
            )
        struct.pack_into(
            "<H", data, len(VERIFY.EXPECTED_PARTITIONS) * 32,
            VERIFY.PARTITION_MD5_MAGIC,
        )
        (self.build / "partition_table" / "partition-table.bin").write_bytes(data)

    def _write_app(self, secure_version=1, build_time=b"", build_date=b""):
        data = bytearray(b"\xff" * 0x10000)
        data[0] = 0xE9
        data[32:288] = bytes(256)
        struct.pack_into(
            "<II", data, 32, VERIFY.APP_DESCRIPTION_MAGIC, secure_version
        )
        data[48:80] = b"0.24.0-security-gate".ljust(32, b"\0")
        data[80:112] = b"xiaozhi_agent_platform".ljust(32, b"\0")
        data[112:128] = build_time.ljust(16, b"\0")
        data[128:144] = build_date.ljust(16, b"\0")
        (self.build / "xiaozhi_agent_platform.bin").write_bytes(data)

    def _write_bootloader(self):
        data = bytearray(b"\xff" * 0x2000)
        data[0] = 0xE9
        (self.build / "bootloader" / "bootloader.bin").write_bytes(data)

    def request(self):
        config = VERIFY.parse_sdkconfig(self.build / "sdkconfig")
        return VERIFY.make_request(self.build, config)

    def test_valid_inputs_bind_all_six_key_blocks(self):
        request = self.request()
        self.assertEqual(request["anti_rollback_secure_version"], 1)
        self.assertEqual(
            [entry["block"] for entry in request["efuse_key_block_map"]],
            list(range(6)),
        )
        self.assertEqual(
            request["secure_boot"]["bootloader_required_signatures"], 3
        )

    def test_insecure_or_internal_signing_config_is_rejected(self):
        config = VERIFY.parse_sdkconfig(self.build / "sdkconfig")
        config["CONFIG_SECURE_BOOT_INSECURE"] = "y"
        with self.assertRaisesRegex(VERIFY.VerificationError, "explicitly disabled"):
            VERIFY.verify_config(config)
        config["CONFIG_SECURE_BOOT_INSECURE"] = None
        config["CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES"] = "y"
        with self.assertRaisesRegex(VERIFY.VerificationError, "explicitly disabled"):
            VERIFY.verify_config(config)

    def test_partition_drift_is_rejected(self):
        path = self.build / "partition_table" / "partition-table.bin"
        data = bytearray(path.read_bytes())
        struct.pack_into("<I", data, 8, 0x5000)
        path.write_bytes(data)
        with self.assertRaisesRegex(VERIFY.VerificationError, "frozen layout"):
            self.request()

    def test_nonreproducible_timestamp_is_rejected(self):
        self._write_app(build_time=b"12:00:00", build_date=b"Aug  9 2026")
        with self.assertRaisesRegex(VERIFY.VerificationError, "time/date"):
            self.request()

    def test_app_and_efuse_secure_versions_must_match(self):
        self._write_app(secure_version=2)
        with self.assertRaisesRegex(VERIFY.VerificationError, "differs"):
            self.request()

    def test_signed_shaped_app_is_not_accepted_as_signing_input(self):
        path = self.build / "xiaozhi_agent_platform.bin"
        path.write_bytes(path.read_bytes() + bytes(0x1000))
        with self.assertRaisesRegex(VERIFY.VerificationError, "64 KiB padded"):
            self.request()

    def test_private_key_in_build_output_is_rejected(self):
        (self.build / "accidental.pem").write_text(
            "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n"
        )
        with self.assertRaisesRegex(VERIFY.VerificationError, "private key"):
            self.request()

    def test_signing_request_write_is_idempotent_but_not_overwritable(self):
        request = self.request()
        path = self.build / "request.json"
        VERIFY.write_request(path, request)
        VERIFY.write_request(path, request)
        path.write_text("{}\n")
        with self.assertRaisesRegex(VERIFY.VerificationError, "differs"):
            VERIFY.write_request(path, request)
        target = self.build / "request-target.json"
        target.write_bytes(VERIFY.canonical_json(request))
        link = self.build / "request-link.json"
        link.symlink_to(target)
        with self.assertRaisesRegex(VERIFY.VerificationError, "symlink"):
            VERIFY.write_request(link, request)


if __name__ == "__main__":
    unittest.main()
