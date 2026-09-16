import importlib.util
import pathlib
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = PROJECT / "tools" / "verify_indicator_action_build.py"
SPEC = importlib.util.spec_from_file_location(
    "verify_indicator_action_build", MODULE_PATH
)
VERIFY = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(VERIFY)


class IndicatorActionBuildVerifierTests(unittest.TestCase):
    def test_config_must_be_exactly_enabled_or_explicitly_disabled(self):
        self.assertTrue(VERIFY.parse_enabled(f"{VERIFY.CONFIG_NAME}=y\n"))
        self.assertFalse(
            VERIFY.parse_enabled(f"# {VERIFY.CONFIG_NAME} is not set\n")
        )
        with self.assertRaisesRegex(VERIFY.VerificationError, "exactly once"):
            VERIFY.parse_enabled("")
        with self.assertRaisesRegex(VERIFY.VerificationError, "exactly once"):
            VERIFY.parse_enabled(
                f"{VERIFY.CONFIG_NAME}=y\n# {VERIFY.CONFIG_NAME} is not set\n"
            )

    def test_enabled_build_requires_complete_adapter_symbols(self):
        VERIFY.verify_boundary(
            enabled=True,
            symbols=set(VERIFY.REQUIRED_ENABLED_SYMBOLS),
            expect="enabled",
        )
        incomplete = set(VERIFY.REQUIRED_ENABLED_SYMBOLS)
        incomplete.remove("product_status_indicator_set")
        with self.assertRaisesRegex(VERIFY.VerificationError, "missing"):
            VERIFY.verify_boundary(
                enabled=True, symbols=incomplete, expect="enabled"
            )

    def test_disabled_build_rejects_config_or_symbol_leakage(self):
        VERIFY.verify_boundary(enabled=False, symbols={"app_main"}, expect="disabled")
        with self.assertRaisesRegex(VERIFY.VerificationError, "enabled"):
            VERIFY.verify_boundary(
                enabled=True, symbols={"app_main"}, expect="disabled"
            )
        with self.assertRaisesRegex(VERIFY.VerificationError, "contains"):
            VERIFY.verify_boundary(
                enabled=False,
                symbols={"product_status_indicator_create"},
                expect="disabled",
            )

    def test_nm_parser_uses_symbol_column(self):
        symbols = VERIFY.parse_defined_symbols(
            "42000000 T app_main\n42000020 t product_agent_set_indicator\n"
        )
        self.assertEqual(symbols, {"app_main", "product_agent_set_indicator"})


if __name__ == "__main__":
    unittest.main()
