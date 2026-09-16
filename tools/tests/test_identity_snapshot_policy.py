import json
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[2]


class IdentitySnapshotPolicyTest(unittest.TestCase):
    def test_schema_is_strict_signed_version_two(self):
        schema = json.loads(
            (PROJECT / "gateway/device-identity-snapshot.schema.json").read_text()
        )
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["version"]["const"], 2)
        self.assertIn("revision", schema["required"])
        self.assertIn("purpose", schema["required"])
        self.assertIn("valid_until", schema["required"])
        self.assertIn("signature", schema["required"])

    def test_signature_domain_and_rollback_errors_are_fixed(self):
        source = (
            PROJECT / "gateway/internal/provisioning/identity_snapshot.go"
        ).read_text()
        self.assertIn("xiaozhi-device-identity-snapshot-v1", source)
        self.assertIn("ErrSnapshotRollback", source)
        self.assertIn("ErrSnapshotEquivocation", source)
        self.assertIn("maximumSnapshotValidity = 24 * time.Hour", source)
        self.assertIn("AccessSnapshotPurpose", source)
        self.assertIn("ProofSnapshotPurpose", source)

    def test_production_services_require_revision_floor(self):
        common = (PROJECT / "gateway/internal/identityconfig/config.go").read_text()
        self.assertIn("DEVICE_REGISTRY_MIN_REVISION", common)
        self.assertIn("DEVICE_REGISTRY_SIGNING_PUBLIC_KEY_FILE", common)
        self.assertIn("DEVICE_REGISTRY_RELOAD_INTERVAL_SECONDS", common)
        for path in (
            "gateway/internal/config/config.go",
            "gateway/internal/controlplane/config.go",
        ):
            self.assertIn("identityconfig.Load", (PROJECT / path).read_text())

    def test_gateway_rechecks_and_actively_closes_revoked_devices(self):
        source = (PROJECT / "gateway/internal/gateway/handler.go").read_text()
        self.assertGreaterEqual(source.count("IdentityRegistry.DeviceAllowed"), 3)
        self.assertIn("func (server *Server) ReconcileIdentity()", source)
        self.assertIn("device access revoked", source)
        self.assertIn("StatusPolicyViolation", source)

    def test_access_snapshot_cannot_become_proof_authority(self):
        registry = (PROJECT / "gateway/internal/provisioning/registry.go").read_text()
        proof = (PROJECT / "gateway/internal/provisioning/proof.go").read_text()
        self.assertIn("func (registry *Registry) ProofReady() bool", registry)
        self.assertIn("!registry.ProofReady()", proof)
        self.assertIn("WithDeviceAllowed", proof)

    def test_downstream_services_require_production_access_snapshot(self):
        agent = (PROJECT / "gateway/internal/agentproxy/config.go").read_text()
        origin = (PROJECT / "gateway/internal/firmwareorigin/config.go").read_text()
        for source in (agent, origin):
            self.assertIn("identityconfig.Load", source)

    def test_remote_identity_requires_mtls_and_signed_response_contract(self):
        config = (PROJECT / "gateway/internal/identityconfig/config.go").read_text()
        remote = (
            PROJECT / "gateway/internal/provisioning/identity_remote.go"
        ).read_text()
        runtime = (PROJECT / "gateway/internal/identityruntime/load.go").read_text()
        for setting in (
            "DEVICE_REGISTRY_URL",
            "DEVICE_REGISTRY_TLS_CA_FILE",
            "DEVICE_REGISTRY_TLS_CERT_FILE",
            "DEVICE_REGISTRY_TLS_KEY_FILE",
        ):
            self.assertIn(setting, config)
        self.assertIn("IdentitySnapshotMediaType", remote)
        self.assertIn("tls.VersionTLS12", remote)
        self.assertIn("If-None-Match", remote)
        self.assertIn("no-store", remote)
        self.assertIn("LoadRemoteReloadableRegistry", runtime)

    def test_agent_proxy_cancels_provider_requests_on_revoke(self):
        source = (PROJECT / "gateway/internal/agentproxy/proxy.go").read_text()
        self.assertIn("identityaccess.New", source)
        self.assertIn("identity.Start", source)
        self.assertIn("func (proxy *Proxy) ReconcileIdentity()", source)
        self.assertIn("xiaozhi_agent_proxy_identity_canceled_total", source)

    def test_firmware_origin_revocation_sets_write_deadline(self):
        source = (PROJECT / "gateway/internal/firmwareorigin/server.go").read_text()
        self.assertIn("http.NewResponseController", source)
        self.assertIn("SetWriteDeadline(time.Now())", source)
        self.assertIn("copyExactContext", source)
        self.assertIn("xiaozhi_firmware_origin_identity_canceled_total", source)


if __name__ == "__main__":
    unittest.main()
