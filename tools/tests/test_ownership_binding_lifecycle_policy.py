import pathlib
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class OwnershipBindingLifecyclePolicyTests(unittest.TestCase):
    def read(self, relative):
        return (PROJECT / relative).read_text(encoding="utf-8")

    def test_release_is_action_and_device_bound(self):
        token = self.read("gateway/internal/auth/token.go")
        jwt = self.read("gateway/internal/auth/companion_jwt.go")
        control = self.read("gateway/internal/controlplane/server.go")
        self.assertIn('CompanionReleaseAction = "device:release"', token)
        self.assertIn("validCompanionActionDevice", token)
        self.assertIn("IssueRelease(subject, tenantID", jwt)
        self.assertIn('"POST /v1/device-ownership/release"', control)
        self.assertIn("claims.DeviceID != deviceID", control)
        self.assertIn("ClaimStore.Release(", control)

    def test_lifecycle_uses_monotonic_revision_and_new_binding(self):
        memory = self.read("gateway/internal/deviceclaim/store.go")
        postgres = self.read("gateway/internal/deviceclaim/postgres.go")
        schema = self.read("gateway/migrations/ownership/0001_ownership.sql")
        self.assertIn("entry.BindingRevision++", memory)
        self.assertIn("revision = owner.BindingRevision + 1", memory)
        self.assertIn("owner.BindingRevision++", postgres)
        self.assertIn("auth.MaximumBindingRevision", postgres)
        self.assertIn("bindingRevision = owner.BindingRevision + 1", postgres)
        self.assertIn("status = 'released'", postgres)
        self.assertIn("status = 'active'", postgres)
        self.assertIn("xz-owner-v3-20260809-lifecycle", schema)
        self.assertIn("BETWEEN 1 AND 4294967295", schema)

    def test_service_consumers_resolve_live_binding(self):
        gateway = self.read("gateway/internal/gateway/handler.go")
        gateway_main = self.read("gateway/cmd/gateway/main.go")
        proxy = self.read("gateway/internal/agentproxy/proxy.go")
        for source in (gateway, proxy):
            self.assertIn("config.Ownership.Owner(claims.DeviceID)", source)
            self.assertIn("ownership.Matches(claims.OwnerID, claims.TenantID", source)
        self.assertIn("func (server *Server) ReconcileOwnership() int", gateway)
        self.assertIn("deviceclaim.BatchOwnershipResolver", gateway)
        self.assertIn("batch.Owners(deviceIDs)", gateway)
        self.assertIn("time.NewTicker(5 * time.Second)", gateway_main)
        self.assertIn("xiaozhi_gateway_ownership_revocations_total", self.read(
            "gateway/internal/gateway/metrics.go"
        ))

    def test_firmware_memory_is_locked_to_authenticated_binding(self):
        core = self.read(
            "components/product_agent_memory/product_agent_memory_core.c"
        )
        memory = self.read("components/product_agent_memory/product_agent_memory.c")
        supervisor = self.read(
            "components/box3_agent_supervisor/box3_agent_supervisor.c"
        )
        self.assertIn("static const uint8_t FORMAT_MAGIC[4] = {'X', 'A', 'M', '2'}", core)
        self.assertIn("LEGACY_FORMAT_MAGIC", core)
        self.assertIn("discard all unscoped values", core)
        self.assertIn("PRODUCT_AGENT_MEMORY_CORE_BINDING_STALE", core)
        self.assertIn("product_agent_memory_reconcile_binding", memory)
        self.assertIn("product_agent_memory_reconcile_binding(", supervisor)

    def test_companion_client_exposes_exact_release_contract(self):
        client = self.read(
            "companion-app/Sources/ProductOnboardingCore/DeviceClaimAPI.swift"
        )
        tests = self.read(
            "companion-app/Tests/ProductOnboardingCoreTests/DeviceClaimTests.swift"
        )
        self.assertIn("high-assurance user reauthentication", client)
        self.assertIn('release?.path = "/v1/device-ownership/release"', client)
        self.assertIn('request.setValue(deviceID, forHTTPHeaderField: "Device-Id")', client)
        self.assertIn("parseReleaseResponse", client)
        self.assertIn("ownershipReleaseRequiresExactActionBoundRequest", tests)


if __name__ == "__main__":
    unittest.main()
