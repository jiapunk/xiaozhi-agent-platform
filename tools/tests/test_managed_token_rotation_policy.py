import ast
import json
from pathlib import Path
import unittest


PROJECT = Path(__file__).resolve().parents[2]


class ManagedTokenRotationPolicyTests(unittest.TestCase):
    def read(self, name: str) -> str:
        return (PROJECT / name).read_text()

    def test_keyring_is_private_canonical_revision_fenced_and_bounded(self) -> None:
        source = self.read("gateway/internal/auth/managed_keyring.go")
        for marker in (
            "xz-hmac-token-keyring-v1",
            "minimumRevision",
            "JSON is not canonical",
            "private bounded regular file",
            "maximumManagedTokenKeys      = 3",
            'json:"legacy_unkeyed_verify_until_unix"',
            "ManagedTokenKeyringsDisjointFromSecrets",
        ):
            self.assertIn(marker, source)
        self.assertIn("status.Mode().Perm()&0o077", source)

    def test_keyed_tokens_bind_key_id_and_do_not_fallback(self) -> None:
        issuer = self.read("gateway/internal/auth/issuer.go")
        verifier = self.read("gateway/internal/auth/token.go")
        self.assertIn('version = "v4"', issuer)
        self.assertIn('version = "v2"', issuer)
        self.assertIn('issuer.keyID + "." + encoded', issuer)
        self.assertIn("key, found := v.managed.keys[parts[1]]", verifier)
        self.assertIn("claims.SigningKeyID = verificationKey.id", verifier)
        self.assertIn("claims.IssuedAt >= verificationKey.issueBefore.Unix()", verifier)
        self.assertIn("ErrKeyRetired", verifier)

    def test_schema_fixes_the_bounded_rotation_contract(self) -> None:
        schema = json.loads(self.read("gateway/managed-token-keyring.schema.json"))
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["schema"]["const"],
                         "xz-hmac-token-keyring-v1")
        self.assertEqual(schema["properties"]["keys"]["maxItems"], 3)
        key = schema["$defs"]["key"]
        self.assertFalse(key["additionalProperties"])
        self.assertEqual(key["properties"]["state"]["enum"],
                         ["active", "retiring"])

    def test_production_services_require_managed_keyrings(self) -> None:
        markers = {
            "gateway/internal/config/config.go": "production Gateway requires a managed voice token keyring",
            "gateway/internal/controlplane/config.go": "production control plane requires a managed",
            "gateway/internal/agentproxy/config.go": "production Agent Proxy requires a managed token keyring",
            "gateway/internal/firmwareorigin/config.go": "production Firmware Origin requires a managed OTA token keyring",
        }
        for path, marker in markers.items():
            self.assertIn(marker, self.read(path))
        for path in (
            "gateway/cmd/gateway/main.go", "gateway/cmd/controlplane/main.go",
            "gateway/cmd/agentproxy/main.go", "gateway/cmd/firmwareorigin/main.go",
        ):
            self.assertIn("Managed", self.read(path))

    def test_kubernetes_uses_files_and_keeps_seven_workloads(self) -> None:
        deployment = self.read("tools/kubernetes_deployment.py")
        for filename in (
            "voice-token-keyring.json", "agent-token-keyring.json",
            "ota-token-keyring.json",
        ):
            self.assertIn(filename, deployment)
        for legacy in (
            '"DEVICE_TOKEN_HMAC_KEYS_B64"', '"VOICE_TOKEN_HMAC_KEY_B64"',
            '"AGENT_TOKEN_HMAC_KEYS_B64"', '"OTA_TOKEN_HMAC_KEYS_B64"',
        ):
            self.assertNotIn(legacy, deployment)
        release = ast.parse(self.read("tools/oci_release.py"))
        assignment = next(
            node for node in release.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "SERVICES"
                    for target in node.targets)
        )
        self.assertEqual(len(ast.literal_eval(assignment.value)), 7)

    def test_firmware_treats_tokens_as_opaque_and_receives_no_hmac_key(self) -> None:
        protocol = self.read(
            "components/box3_agent_credentials_client/box3_agent_credentials_protocol.c")
        self.assertIn("safe_ascii", protocol)
        self.assertNotIn("HMAC", protocol)
        self.assertNotIn("hmac", protocol)
        deployment = self.read("tools/kubernetes_deployment.py")
        self.assertNotIn("voice-token-keyring.json\"", self.read(
            "components/box3_agent_credentials_client/box3_agent_credentials_protocol.c"))
        self.assertIn("voice-token-keyring.json", deployment)


if __name__ == "__main__":
    unittest.main()
