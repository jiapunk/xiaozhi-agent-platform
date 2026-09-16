import importlib.util
import json
import pathlib
import shutil
import tempfile
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = PROJECT / "tools" / "verify_companion_app_policy.py"
SPEC = importlib.util.spec_from_file_location("verify_companion_app_policy", MODULE_PATH)
POLICY = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(POLICY)


class CompanionAppPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.project = pathlib.Path(self.temporary.name)
        shutil.copytree(
            PROJECT / "companion-app",
            self.project / "companion-app",
            ignore=shutil.ignore_patterns(".build"),
        )

    def tearDown(self):
        self.temporary.cleanup()

    def test_reviewed_tree_passes_without_materialized_checkouts(self):
        self.assertEqual(POLICY.verify(self.project, require_checkouts=False), [])

    def test_resolution_drift_is_rejected(self):
        path = self.project / "companion-app" / "Package.resolved"
        document = json.loads(path.read_text())
        document["pins"][0]["state"]["revision"] = "0" * 40
        path.write_text(json.dumps(document))
        errors = POLICY.verify(self.project, require_checkouts=False)
        self.assertTrue(any("resolution drifted" in error for error in errors))

    def test_sensitive_logging_is_rejected(self):
        path = (
            self.project
            / "companion-app/Sources/ProductOnboardingESPProvision/ESPProvisionTransport.swift"
        )
        path.write_text(path.read_text() + "\n// enableLogs(true)\n")
        errors = POLICY.verify(self.project, require_checkouts=False)
        self.assertTrue(any("forbidden logging" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
