import pathlib
import re
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class OwnerAuthorizationPolicyTests(unittest.TestCase):
    def read(self, relative):
        return (PROJECT / relative).read_text(encoding="utf-8")

    def test_voice_and_agent_tokens_require_v3_binding_owner_tenant_and_jti(self):
        token = self.read("gateway/internal/auth/token.go")
        issuer = self.read("gateway/internal/auth/issuer.go")
        self.assertIn('case VoiceAudience, AgentAudience:', token)
        self.assertIn('version != "v3"', token)
        self.assertIn('!ValidIdentifier(claims.OwnerID, 128)', token)
        self.assertIn('!ValidIdentifier(claims.TenantID, 128)', token)
        self.assertIn('!ValidBindingID(claims.BindingID)', token)
        self.assertIn('!ValidBindingRevision(claims.BindingRevision)', token)
        self.assertIn('MaximumBindingRevision = uint64(1<<32 - 1)', token)
        self.assertIn('claims.TokenID == ""', token)
        self.assertIn('func (issuer *Issuer) IssueOwned(', issuer)
        self.assertIn('version = "v3"', issuer)

    def test_control_plane_cannot_issue_without_current_ownership(self):
        control = self.read("gateway/internal/controlplane/server.go")
        self.assertIn("deviceclaim.OwnershipResolver", control)
        self.assertIn("config.Ownership == nil", control)
        self.assertIn("config.Ownership.Owner(deviceID)", control)
        self.assertIn("device ownership required", control)
        self.assertIn("issuer.IssueOwned(", control)

    def test_tenant_is_explicit_at_account_and_claim_boundaries(self):
        issuer = self.read("gateway/internal/auth/issuer.go")
        claim = self.read("gateway/internal/deviceclaim/store.go")
        control = self.read("gateway/internal/controlplane/server.go")
        self.assertIn("IssueCompanion(subject, tenantID string)", issuer)
        self.assertIn("Begin(userID, tenantID, deviceID", claim)
        self.assertIn("Lookup(userID, tenantID, requestID", claim)
        self.assertIn("OwnerID", claim)
        self.assertIn("TenantID", claim)
        self.assertGreaterEqual(
            control.count("claims.Subject, claims.TenantID"), 2
        )

    def test_voice_replay_and_agent_limits_use_opaque_binding_scope(self):
        replay = self.read("gateway/internal/gateway/token_replay.go")
        proxy = self.read("gateway/internal/agentproxy/proxy.go")
        token = self.read("gateway/internal/auth/token.go")
        self.assertIn('return claims.BindingID + "\\x00"', token)
        self.assertIn('strconv.FormatUint(claims.BindingRevision, 10)', token)
        self.assertIn("auth.OwnedDeviceScope(claims)", replay)
        self.assertIn('key := scope + "\\x00" + claims.TokenID', replay)
        self.assertIn("ownedScope, ok := auth.OwnedDeviceScope(claims)", proxy)
        self.assertIn("proxy.acquireDevice(ownedScope)", proxy)

    def test_voice_runtime_carries_scope_but_speech_adapter_does_not_forward_it(self):
        handler = self.read("gateway/internal/gateway/handler.go")
        voice = self.read("gateway/internal/gateway/voice.go")
        stt = self.read("gateway/internal/gateway/stt_websocket.go")
        self.assertIn("ownerID: claims.OwnerID", handler)
        self.assertIn("tenantID: claims.TenantID", handler)
        self.assertIn("OwnerID: connection.ownerID", handler)
        self.assertIn("TenantID: connection.tenantID", handler)
        self.assertIn("Backends must not forward them", voice)
        self.assertNotIn("config.OwnerID", stt)
        self.assertNotIn("config.TenantID", stt)

    def test_standalone_ownerless_session_issuance_is_disabled(self):
        gateway = self.read("gateway/internal/gateway/handler.go")
        main = self.read("gateway/cmd/gateway/main.go")
        self.assertRegex(
            gateway,
            re.compile(r"\bOwnership\s+deviceclaim\.OwnershipResolver\b"),
        )
        self.assertIn("sessionParts != 3", gateway)
        self.assertIn("standalone session issuance is disabled", main)
        self.assertIn("ownership_resolver_required", main)

    def test_vertical_slice_checks_provider_identity_non_disclosure(self):
        integration = self.read(
            "gateway/internal/integration/vertical_slice_test.go"
        )
        self.assertIn('issuedClaims.OwnerID != "user-1"', integration)
        self.assertIn('issuedClaims.TenantID != "tenant-1"', integration)
        self.assertIn('providerRequest.Header.Get("Owner-Id")', integration)
        self.assertIn('providerRequest.Header.Get("Tenant-Id")', integration)


if __name__ == "__main__":
    unittest.main()
