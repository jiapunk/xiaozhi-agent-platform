import json
from pathlib import Path
import unittest


PROJECT = Path(__file__).resolve().parents[2]


class ManagedTokenTransitionPolicyTests(unittest.TestCase):
    def read(self, name: str) -> str:
        return (PROJECT / name).read_text()

    def test_transition_is_forward_only_and_preserves_current_material(self) -> None:
        source = self.read("gateway/internal/auth/managed_transition.go")
        for marker in (
            "target.revision <= current.revision",
            "sameManagedSecret",
            "subtle.ConstantTimeCompare",
            "cutover.After(now.Add(managedTokenTransitionSkew))",
            "len(target.keys) != len(current.keys)+1",
            "dropped or replaced a current key",
            "cannot alter legacy migration",
        ):
            self.assertIn(marker, source)

    def test_forward_recovery_cannot_restore_a_document_or_legacy_key(self) -> None:
        source = self.read("gateway/internal/auth/managed_transition.go")
        self.assertIn('ManagedTokenTransitionForwardRecover = "forward-recovery"',
                      source)
        self.assertIn("current.legacyUnkeyedKeyID == target.activeKeyID", source)
        self.assertIn("len(target.keys) != len(current.keys)", source)
        self.assertNotIn("current.revision -", source)

    def test_receipt_is_exact_nonsecret_and_explicitly_software_only(self) -> None:
        source = self.read(
            "gateway/cmd/validatemanagedtokenrotation/main.go")
        for marker in (
            "expected-current-revision",
            "expected-target-revision",
            "expected-current-active-key-id",
            "expected-target-active-key-id",
            "currentFloor != *expectedCurrentRevision",
            "targetFloor != *expectedTargetRevision",
            'Result: "SOFTWARE_PREFLIGHT_PASS"',
            "SoftwareOnly: true",
            "os.O_EXCL",
            "file.Chmod(0o444)",
        ):
            self.assertIn(marker, source)
        self.assertNotIn("HMACKeyB64URL", source)
        self.assertNotIn("currentFile,", source.split("receipt :=", 1)[1])
        self.assertNotIn("targetFile,", source.split("receipt :=", 1)[1])

    def test_schema_and_runbook_cannot_claim_live_evidence(self) -> None:
        schema = json.loads(self.read(
            "gateway/managed-token-rotation-preflight.schema.json"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["software_only"], {"const": True})
        self.assertEqual(schema["properties"]["result"],
                         {"const": "SOFTWARE_PREFLIGHT_PASS"})
        self.assertEqual(schema["properties"]["transition"]["enum"],
                         ["rotate", "forward-recovery"])
        runbook = self.read("MANAGED_TOKEN_KEY_ROTATION_RUNBOOK.md")
        normalized_runbook = " ".join(runbook.split())
        self.assertIn("cannot satisfy live or market-release evidence",
                      normalized_runbook)
        self.assertIn("verifier Secret", runbook)
        deployment = self.read("tools/oci_release.py")
        self.assertIn('"factorytimeauthority"', deployment)
        self.assertEqual(deployment.count('"factorytimeauthority"'), 1)


if __name__ == "__main__":
    unittest.main()
