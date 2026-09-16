import importlib.util
import pathlib
import stat
import tempfile
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = PROJECT / "tools" / "generate_factory_hmac_key.py"
SPEC = importlib.util.spec_from_file_location(
    "generate_factory_hmac_key", MODULE_PATH
)
KEY_TOOL = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(KEY_TOOL)


class FactoryHmacKeyTests(unittest.TestCase):
    def test_new_key_has_exact_size_and_private_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "nvs.key"
            KEY_TOOL.write_new_key(output)
            self.assertEqual(len(output.read_bytes()), 32)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_existing_file_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "identity.key"
            output.write_bytes(b"keep")
            with self.assertRaises(KEY_TOOL.KeyGenerationError):
                KEY_TOOL.write_new_key(output)
            self.assertEqual(output.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main()
