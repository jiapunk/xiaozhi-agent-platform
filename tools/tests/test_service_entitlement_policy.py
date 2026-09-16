from __future__ import annotations

import pathlib
import sys
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT / "tools"))
import kubernetes_deployment as K8S


class ServiceEntitlementPolicyTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (PROJECT / relative).read_text(encoding="utf-8")

    def test_ledger_is_ordered_idempotent_and_content_minimized(self) -> None:
        migration = self.read(
            "gateway/migrations/account/0004_service_entitlements.sql")
        ledger = self.read("gateway/internal/accountauth/entitlement_postgres.go")
        postgres = self.read("gateway/internal/accountauth/postgres.go")
        for required in (
            "xz-service-entitlement-db-v1-20260811",
            "service_entitlement_events",
            "service_entitlements",
            "revision = previous_revision + 1",
            "update_digest bytea",
            "voice_enabled boolean",
            "agent_enabled boolean",
            "access_until timestamptz",
        ):
            self.assertIn(required, migration)
        ddl = "\n".join(
            line for line in migration.lower().splitlines()
            if not line.lstrip().startswith("--")
        )
        for forbidden in (
            "provider_customer_id", "payment_method", "invoice",
            "webhook_payload", "raw_payload", "card_number",
        ):
            self.assertNotIn(forbidden, ddl)
        self.assertIn("sql.LevelSerializable", postgres)
        for required in (
            "postgresTime", "FOR UPDATE",
            "selectEntitlementEvent", "subtle.ConstantTimeCompare",
            "ErrStaleEntitlement", "AccessUntil.After(now)",
        ):
            self.assertIn(required, ledger)

    def test_internal_read_path_is_strict_mtls_and_fails_closed(self) -> None:
        endpoint = self.read("gateway/internal/accountauth/entitlement_http.go")
        main = self.read("gateway/cmd/accountauthorization/main.go")
        for required in (
            'ServiceEntitlementAuthorizationPath = "/v1/service-entitlements/authorize"',
            "verifiedWorkloadTLS(request)", "DisallowUnknownFields",
            "bytes.Equal(canonical, body)", "http.StatusNoContent",
            "http.StatusServiceUnavailable", "TLS.Version < tls.VersionTLS12",
            "service entitlement redirects are forbidden",
        ):
            self.assertIn(required, endpoint)
        self.assertIn(
            'mux.Handle("POST "+accountauth.ServiceEntitlementAuthorizationPath',
            main,
        )

    def test_signed_update_path_is_minimized_rotatable_and_replay_bounded(self) -> None:
        endpoint = self.read(
            "gateway/internal/accountauth/entitlement_update_http.go")
        keyring = self.read(
            "gateway/internal/accountauth/entitlement_update_keyring.go")
        main = self.read("gateway/cmd/accountauthorization/main.go")
        deployment = self.read("tools/kubernetes_deployment.py")
        for required in (
            '"/v1/service-entitlements/apply"',
            '"xiaozhi-service-entitlement-update-v1\\x00"',
            "http.StatusUnauthorized",
            "http.StatusConflict", "authorizationExpiresAt.After(now)",
            "ValidServiceEntitlementUpdate(update, authorizedAt)",
        ):
            self.assertIn(required, endpoint)
        request_struct = endpoint[
            endpoint.index("type serviceEntitlementUpdateRequest struct"):
            endpoint.index("type serviceEntitlementUpdateResponse struct")
        ]
        for forbidden in (
            "provider_customer_id", "payment_method", "invoice",
            "webhook", "receipt", "card_number", "price",
        ):
            self.assertNotIn(forbidden, request_struct.lower())
        for required in (
            "xz-service-entitlement-update-keyring-v1", "os.Lstat",
            "os.ModeSymlink", "Mode().Perm()&0o077", "minimumRevision",
            'case "active"', 'case "retiring"',
            "subtle.ConstantTimeCompare", "ed25519.Verify",
            "ed25519.SignatureSize",
        ):
            self.assertIn(required, keyring)
        self.assertIn(
            'mux.Handle("POST "+accountauth.ServiceEntitlementUpdatePath',
            main,
        )
        for required in (
            "SCHEMA_VERSION = 7", '"entitlement_update_trust"',
            '"entitlement-update-keyring.json"',
            '"ENTITLEMENT_UPDATE_KEYRING_MIN_REVISION"',
            '"ENTITLEMENT_UPDATE_AUTHORIZATION_TTL_SECONDS"',
            'profile["release_operator_namespace"]',
        ):
            self.assertIn(required, deployment)

    def test_token_issuance_is_entitlement_first_and_expiry_bounded(self) -> None:
        server = self.read("gateway/internal/controlplane/server.go")
        issuer = self.read("gateway/internal/auth/issuer.go")
        gateway = self.read("gateway/internal/gateway/handler.go")
        gateway_test = self.read("gateway/internal/gateway/handler_test.go")
        authorize = server.index("ServiceEntitlements.AuthorizeService")
        issue = server.index("issuer.IssueOwnedUntil", authorize)
        self.assertLess(authorize, issue)
        for required in (
            "http.StatusPaymentRequired", "http.StatusServiceUnavailable",
            "entitlementDenied", "entitlementUnavailable",
            "entitlementGrace", "grant.ValidUntil",
        ):
            self.assertIn(required, server)
        for required in (
            "IssueOwnedUntil", "validUntil.Before(expiresAt)",
            "minimumIssuedTTL", "validUntil.Location() != time.UTC",
        ):
            self.assertIn(required, issuer)
        for required in (
            "enforceTokenExpiry", "voiceTokenExpirations",
            '"voice token expired"', "sessionExpiresAt",
        ):
            self.assertIn(required, gateway)
        self.assertIn("TestVoiceTokenExpiryClosesActiveWebSocket", gateway_test)

    def test_device_maps_402_to_non_retrying_product_state(self) -> None:
        voice = self.read(
            "components/box3_agent_credentials_client/box3_agent_credentials_client.c")
        agent = self.read(
            "components/agent_control_plane_client/agent_control_plane_client.c")
        supervisor = self.read(
            "components/box3_agent_supervisor/box3_agent_supervisor.c")
        core = self.read(
            "components/box3_agent_supervisor/box3_agent_supervisor_core.c")
        runtime = self.read(
            "components/box3_product_runtime/box3_product_runtime.c")
        core_test = self.read("tests/host/test_box3_agent_supervisor_core.c")
        self.assertIn("status_code == 402", voice)
        self.assertIn("get_status_code(client->agent_http) == 402", agent)
        self.assertIn("ESP_ERR_NOT_ALLOWED", voice + agent + supervisor)
        self.assertIn("box3_agent_supervisor_core_entitlement_denied", supervisor)
        self.assertIn("BOX3_AGENT_SUPERVISOR_ENTITLEMENT_BLOCKED", core)
        self.assertIn("BOX3_PRODUCT_RUNTIME_ENTITLEMENT_REQUIRED", runtime)
        self.assertIn("UINT64_MAX", core_test)
        blocked = core.index("box3_agent_supervisor_core_entitlement_denied")
        changed = core.index("box3_agent_supervisor_core_entitlement_changed")
        self.assertNotIn("retry_target", core[blocked:changed])

    def test_signed_deployment_v7_keeps_seven_workloads(self) -> None:
        profile, _ = K8S.load_profile(
            PROJECT / "deployment/kubernetes-deployment-profile.example.json")
        self.assertEqual(K8S.SCHEMA_VERSION, 7)
        self.assertEqual(len(K8S.SERVICES), 7)
        self.assertEqual(len(K8S.build_prerequisites(profile)["objects"]), 30)
        control = {
            item["name"]: item.get("value")
            for item in K8S._fixed_env(profile, "controlplane")
        }
        self.assertIn("SERVICE_ENTITLEMENT_AUTHORIZATION_URL", control)
        self.assertEqual(
            control["VOICE_TOKEN_TTL_SECONDS"],
            str(profile["service_entitlement"]["voice_token_ttl_seconds"]),
        )
        self.assertEqual(
            control["AGENT_TOKEN_TTL_SECONDS"],
            str(profile["service_entitlement"]["agent_token_ttl_seconds"]),
        )

    def test_runbook_keeps_external_billing_and_market_evidence_open(self) -> None:
        docs = self.read("SERVICE_ENTITLEMENT_RUNBOOK.md") + self.read(
            "M83_SERVICE_ENTITLEMENT_REPORT.md") + self.read(
            "PRODUCT_MARKET_RELEASE_RUNBOOK.md")
        for required in (
            "NO-GO", "MARKET_RELEASE_PASS", "真實 billing",
            "managed PostgreSQL", "簽章 App", "WORM", "取消",
            "寬限", "402", "七個",
        ):
            self.assertIn(required, docs)


if __name__ == "__main__":
    unittest.main()
