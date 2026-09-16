import pathlib
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class AgentActionConsentPolicyTests(unittest.TestCase):
    def read(self, path):
        return (PROJECT / path).read_text(encoding="utf-8")

    def test_device_runtime_consents_only_after_exact_action_is_known(self):
        runtime = self.read("components/esp_claw_runtime/esp_claw_runtime.c")
        header = self.read(
            "components/esp_claw_runtime/include/esp_claw_runtime.h"
        )
        start = runtime.index("static esp_err_t set_indicator_execute")
        end = runtime.index("static bool parse_exact_object", start)
        action = runtime[start:end]
        self.assertLess(action.index("parse_exact_object"),
                        action.index("capability_consent"))
        self.assertIn("indicator_on", action)
        self.assertIn("execute_approved_indicator_action", action)
        self.assertIn("indicator_on ? 1U : 0U", runtime)
        self.assertIn("Voice text is never passed", header)

    def test_companion_ticket_is_short_lived_exact_and_one_use(self):
        source = self.read(
            "companion-app/Sources/ProductOnboardingCore/AgentActionConsent.swift"
        )
        for required in (
            'contract = "xz-action-consent-v1"',
            "maximumLifetime: TimeInterval = 30",
            "ownerRevision <= UInt64(UInt32.max)",
            'capability == "device.set_indicator"',
            'Set(arguments.keys) == ["on"]',
            "canonical == data",
            "guard !consumed",
        ):
            self.assertIn(required, source)

    def test_companion_decision_rebinds_every_action_field(self):
        source = self.read(
            "companion-app/Sources/ProductOnboardingCore/AgentActionConsent.swift"
        )
        body = source[source.index("let body = Data("):]
        for field in (
            "challenge_id", "device_id", "owner_revision", "session_id",
            "request_id", "capability", "arguments", "decision",
        ):
            self.assertIn(field, body)

    def test_companion_transport_is_https_no_store_and_device_scoped(self):
        source = self.read(
            "companion-app/Sources/ProductOnboardingCore/AgentActionConsentAPI.swift"
        )
        for required in (
            'authority.scheme == "https"',
            '"/v1/devices/\\(device)/action-consents/\\(challenge)/decision"',
            'forHTTPHeaderField: "Content-Length"',
            'forHTTPHeaderField: "Cache-Control"',
            'forHTTPHeaderField: "X-Xiaozhi-Action-Consent"',
            'response.statusCode == 200',
        ):
            self.assertIn(required, source)

    def test_companion_fetches_only_exact_owner_inbox_contract(self):
        source = self.read(
            "companion-app/Sources/ProductOnboardingCore/AgentActionConsentAPI.swift"
        )
        for required in (
            "func fetchPending(",
            '"/v1/devices/\\(device)/action-consents/pending"',
            "ownerRevision <= UInt64(UInt32.max)",
            "response.statusCode == 204",
            "guard data.isEmpty",
            "expectedOwnerRevision: ownerRevision",
        ):
            self.assertIn(required, source)

    def test_companion_foreground_session_is_ephemeral_and_fail_closed(self):
        session = self.read(
            "companion-app/Sources/ProductOnboardingCore/"
            "AgentActionConsentSession.swift"
        )
        for required in (
            "maximumLifetime: TimeInterval = 5 * 60",
            "acquireActionConsentAccess",
            "discardActionConsentAccess",
            "func enterForeground(",
            "func leaveForeground()",
            "func signOut()",
            "generation == flow && !Task.isCancelled",
            "currentTicket === ticket",
            "decisionDeliveryUnknown",
            "ticket.invalidate()",
        ):
            self.assertIn(required, session)

    def test_product_ui_displays_only_exact_typed_action_and_safe_outcomes(self):
        package = self.read("companion-app/Package.swift")
        ui = self.read(
            "companion-app/Sources/ProductActionConsentUI/"
            "AgentActionConsentGateView.swift"
        )
        self.assertIn('name: "ProductActionConsentUI"', package)
        for required in (
            "AgentActionConsentSceneGateView",
            "@Environment(\\.scenePhase)",
            ".onChange(of: scenePhase)",
            ".onChange(of: desiredBinding)",
            ".onChange(of: accountSignedIn)",
            "viewModel.leaveForeground()",
            "viewModel.signOut()",
            'Text("Device")',
            "Text(verbatim: presentation.deviceID)",
            'Text("Exact action")',
            '"Turn the indicator ON"',
            '"Turn the indicator OFF"',
            'Button("Deny", role: .cancel',
            'Button("Approve"',
            ".interactiveDismissDisabled(true)",
            '"The decision result is unknown. Do not submit it again."',
        ):
            self.assertIn(required, ui)

    def test_app_access_provider_is_jit_bound_and_non_caching(self):
        source = self.read(
            "companion-app/Sources/ProductOnboardingCore/"
            "AgentActionConsentAccessAPI.swift"
        )
        gate = self.read("tools/run_companion_app_gate.sh")
        for required in (
            "CompanionSessionAuthorizationProviding",
            "HTTPSAgentActionConsentAccessProvider",
            '"/v1/companion/action-consent-access"',
            '"purpose":"action-consent"',
            '"X-Xiaozhi-Companion-Access"',
            "authorization.invalidate()",
            "discardCompanionSessionAuthorization()",
            "AgentActionConsentAccess.maximumLifetime",
        ):
            self.assertIn(required, source)
        self.assertNotIn("private var bearer", source)
        self.assertIn("--target ProductActionConsentUI", gate)

    def test_backend_store_serializes_exact_decision_and_replay(self):
        source = self.read("gateway/internal/actionconsent/store.go")
        for required in (
            "MaximumLifetime = 30 * time.Second",
            "type DecisionStore interface",
            "re-read the current ownership row inside the same serializable",
            "actor.OwnerID != challenge.OwnerID",
            "request.SessionID != challenge.SessionID",
            "request.RequestID != challenge.RequestID",
            "request.Action != challenge.Action",
            "record.decision != \"\"",
            "return Record{}, ErrReplay",
        ):
            self.assertIn(required, source)

    def test_bff_issuance_requires_idp_ownership_and_durable_registration(self):
        handler = self.read(
            "gateway/internal/accountauth/access_handler.go"
        )
        service = self.read("gateway/internal/accountauth/service.go")
        private_reader = self.read(
            "gateway/cmd/accountauthorization/main.go"
        )
        gate = self.read("tools/run_agent_action_consent_gate.sh")
        for required in (
            "ActionConsentAccessAuthenticator",
            '"/v1/companion/action-consent-access"',
            '"xz-companion-access-v1"',
            "request.TLS.Version < tls.VersionTLS12",
            "AuthenticateActionConsentAccess(",
            "PurposeActionConsent, input.DeviceID",
            "issued.Authorization.Binding.TokenID",
            "MaximumActionConsentTokenLifetime",
            'header.Set("Cache-Control", "no-store")',
        ):
            self.assertIn(required, handler)
        self.assertIn("MaximumActionConsentTokenLifetime", service)
        self.assertIn("= 5 * time.Minute", service)
        self.assertLess(
            service.index("service.ledger.RegisterToken"),
            service.index("return IssuedToken{Bearer: bearer"),
        )
        self.assertIn("./internal/accountauth", gate)
        self.assertNotIn("ActionConsentAccessPath", private_reader)
        self.assertNotIn("NewActionConsentAccessHandler", private_reader)

    def test_control_plane_requires_scope_current_owner_and_canonical_json(self):
        source = self.read("gateway/internal/controlplane/server.go")
        for required in (
            "auth.CompanionConsentAction",
            "claims.DeviceID != deviceID",
            "bytes.Equal(canonical, body)",
            "owner.OwnerID != claims.Subject",
            "owner.TenantID != claims.TenantID",
            "owner.BindingRevision != decision.OwnerRevision",
            "X-Xiaozhi-Action-Consent",
        ):
            self.assertIn(required, source)

    def test_durable_store_shares_atomic_ownership_ordering_domain(self):
        postgres = self.read("gateway/internal/actionconsent/postgres.go")
        migration = self.read(
            "gateway/migrations/ownership/0002_action_consent.sql"
        )
        for required in (
            "sql.LevelSerializable",
            "selectCurrentOwner",
            "FOR UPDATE",
            "func (store *PostgresStore) Register",
            "func (store *PostgresStore) Decide",
            "func (store *PostgresStore) Consume",
            "record.Challenge.OwnerRevision",
            "consumed_at = $2",
            "postgresRetryable",
        ):
            self.assertIn(required, postgres)
        for required in (
            "xz_action_consent_schema",
            "xz-action-consent-db-v1-20260810",
            "REFERENCES device_owners",
            "UNIQUE (device_id, session_id, request_id)",
            "expires_at <= created_at + INTERVAL '30 seconds'",
            "consumed_at IS NULL OR decision IS NOT NULL",
        ):
            self.assertIn(required, migration)

    def test_owner_inbox_is_durable_current_epoch_and_undecided_only(self):
        store = self.read("gateway/internal/actionconsent/store.go")
        postgres = self.read("gateway/internal/actionconsent/postgres.go")
        server = self.read("gateway/internal/controlplane/server.go")
        self.assertIn("Pending(actor Actor", store)
        for required in (
            "func (store *PostgresStore) Pending",
            "selectCurrentOwner(ctx, tx, actor.DeviceID)",
            "decision IS NULL AND consumed_at IS NULL",
            "ORDER BY expires_at, challenge_id",
            "LIMIT 1 FOR UPDATE",
        ):
            self.assertIn(required, postgres)
        for required in (
            '"GET /v1/devices/{device_id}/action-consents/pending"',
            "pendingActionConsent",
            "owner.OwnerID != claims.Subject",
            "ActionConsents.Pending",
            "http.StatusNoContent",
        ):
            self.assertIn(required, server)

    def test_wake_payload_is_content_free_and_foreground_fetch_only(self):
        swift_wake = self.read(
            "companion-app/Sources/ProductOnboardingCore/"
            "AgentActionConsentWake.swift"
        )
        session = self.read(
            "companion-app/Sources/ProductOnboardingCore/"
            "AgentActionConsentSession.swift"
        )
        ui = self.read(
            "companion-app/Sources/ProductActionConsentUI/"
            "AgentActionConsentGateView.swift"
        )
        self.assertIn(
            '#"{"version":1,"kind":"action-consent-wake"}"#',
            swift_wake,
        )
        for forbidden in (
            "challenge_id", "device_id", "owner_revision", "indicator_on",
            "approve", "deny", "access_token", "http",
        ):
            self.assertNotIn(forbidden, swift_wake)
        for required in (
            "public func receiveWake(_ data: Data) throws",
            "AgentActionConsentWake.parse(data)",
            "private func signalWake()",
            "guard foreground, currentTicket == nil",
            "case .noPending, .inboxUnavailable, .completed, .expired",
            "await self?.poll(",
        ):
            self.assertIn(required, session)
        self.assertIn("try session.receiveWake(data)", ui)
        self.assertNotIn("session.signalWake()", ui)

    def test_wake_outbox_is_atomic_leased_and_not_a_decision_channel(self):
        store = self.read("gateway/internal/actionconsent/store.go")
        postgres = self.read("gateway/internal/actionconsent/postgres.go")
        wake = self.read("gateway/internal/actionconsent/wake.go")
        postgres_wake = self.read(
            "gateway/internal/actionconsent/postgres_wake.go"
        )
        notifier = self.read(
            "gateway/internal/actionconsent/notifier.go"
        )
        migration = self.read(
            "gateway/migrations/ownership/"
            "0003_action_consent_wake_outbox.sql"
        )
        self.assertIn("store.records[challenge.ChallengeID]", store)
        self.assertIn("store.wakes[challenge.ChallengeID]", store)
        for required in (
            "INSERT INTO action_consent_challenges",
            "INSERT INTO action_consent_wake_outbox",
        ):
            self.assertIn(required, postgres)
        self.assertLess(
            postgres.index("INSERT INTO action_consent_challenges"),
            postgres.index("INSERT INTO action_consent_wake_outbox"),
        )
        self.assertIn(
            '`{"version":1,"kind":"action-consent-wake"}`', wake
        )
        payload_line = next(
            line for line in wake.splitlines() if "var wakePayload" in line
        )
        for forbidden in (
            "challenge_id", "device_id", "indicator_on", "decision",
            "approve", "deny", "access_token",
        ):
            self.assertNotIn(forbidden, payload_line)
        for required in (
            "FOR UPDATE OF wake SKIP LOCKED",
            "claimed_by = $2",
            "attempts = attempts + 1",
            "claimed_by = NULL, lease_until = NULL",
        ):
            self.assertIn(required, postgres_wake)
        for required in (
            "WakeSender interface",
            "CanonicalWakePayload()",
            "AcknowledgeWake(",
            "RetryWake(",
            "worker deliberately has no challenge-reading API",
        ):
            self.assertIn(required, notifier)
        for required in (
            "xz_action_consent_wake_schema",
            "xz-action-consent-wake-db-v1-20260810",
            "action_consent_wake_outbox",
            "REFERENCES action_consent_challenges",
            "CHECK ((claimed_by IS NULL) = (lease_until IS NULL))",
            "expires_at <= created_at + INTERVAL '30 seconds'",
        ):
            self.assertIn(required, migration)

    def test_device_relay_proofs_bind_canonical_body_and_separate_paths(self):
        proof = self.read("gateway/internal/provisioning/proof.go")
        server = self.read("gateway/internal/controlplane/server.go")
        for required in (
            "xiaozhi-action-consent-challenge-proof-v1",
            "xiaozhi-action-consent-result-proof-v1",
            "/v1/action-consents/device/challenge",
            "/v1/action-consents/device/result",
            "HeaderActionConsentBodySHA256",
            "AuthorizeBody",
            "sha256.Sum256(body)",
        ):
            self.assertIn(required, proof)
        for required in (
            "registerDeviceActionConsent",
            "consumeDeviceActionConsent",
            "readCanonicalActionConsentBody",
            "actionconsent.ValidChallenge(challenge, now)",
            "actionconsent.ErrPending",
            "RetryAfterSeconds: 1",
            "ActionConsents.Consume",
        ):
            self.assertIn(required, server)

    def test_firmware_relay_has_typed_body_and_scoped_efuse_signers(self):
        protocol = self.read(
            "components/agent_control_plane_client/"
            "agent_control_plane_protocol.c"
        )
        client = self.read(
            "components/agent_control_plane_client/"
            "agent_control_plane_client.c"
        )
        identity = self.read(
            "components/agent_device_identity/agent_device_identity.c"
        )
        for required in (
            "agent_control_plane_build_action_challenge_body",
            "agent_control_plane_build_action_result_body",
            '"arguments\\\":{\\\"on\\\":%s}',
            "agent_control_plane_build_action_canonical",
            "agent_control_plane_parse_action_challenge_response",
            "agent_control_plane_parse_action_result_response",
        ):
            self.assertIn(required, protocol)
        for required in (
            "agent_control_plane_client_register_action_consent",
            "agent_control_plane_client_poll_action_consent",
            "mbedtls_md_info_from_type(MBEDTLS_MD_SHA256)",
            '"X-Action-Consent-Body-SHA256"',
            "expires_at_unix - unix_seconds > 30",
            "AGENT_CONTROL_PLANE_ACTION_PENDING",
        ):
            self.assertIn(required, client)
        self.assertIn(
            "AGENT_DEVICE_PROOF_SCOPE_ACTION_CONSENT_CHALLENGE", identity
        )
        self.assertIn(
            "AGENT_DEVICE_PROOF_SCOPE_ACTION_CONSENT_RESULT", identity
        )

    def test_runtime_callback_is_bounded_cancelable_and_product_owned(self):
        client = self.read(
            "components/agent_control_plane_client/agent_control_plane_client.c"
        )
        runtime = self.read(
            "components/box3_product_runtime/box3_product_runtime.c"
        )
        core = self.read(
            "components/box3_product_runtime/box3_product_runtime_core.c"
        )
        claw = self.read("components/esp_claw_runtime/esp_claw_runtime.c")
        main = self.read("main/app_main.c")
        for required in (
            "register_action_consent_bounded",
            "poll_action_consent_bounded",
            "esp_http_client_set_timeout_ms",
            "client->get_unix_time",
        ):
            self.assertIn(required, client)
        for required in (
            "product_action_consent",
            "box3_action_consent_core_run",
            "action_consent_cancel_epoch",
            "product.agent.capability_consent = product_action_consent",
            "config->product.agent.capability_consent",
        ):
            self.assertIn(required, runtime)
        for required in (
            "maximum_request_timeout_ms",
            "BOX3_ACTION_CONSENT_OUTCOME_CANCELED",
            "BOX3_ACTION_CONSENT_OUTCOME_EXPIRED",
            "ops->available(ctx)",
        ):
            self.assertIn(required, core)
        self.assertLess(
            claw.index("canceled_request_id"),
            claw.index("device_ops.set_indicator(")
        )
        self.assertIn("committed_action_request_id", claw)
        self.assertIn("ESP_CLAW_CAPABILITY_DEVICE_GET_STATUS", main)
        self.assertNotIn(
            "ESP_CLAW_CAPABILITY_DEVICE_SET_INDICATOR", main[main.index(
                ".enabled_capabilities ="
            ):main.index(".device_ops =", main.index(
                ".enabled_capabilities ="
            ))]
        )

    def test_companion_tokens_require_online_mtls_revocation_in_production(self):
        status = self.read("gateway/internal/auth/companion_status.go")
        server = self.read("gateway/internal/controlplane/server.go")
        config = self.read("gateway/internal/controlplane/config.go")
        main = self.read("gateway/cmd/controlplane/main.go")
        for required in (
            'CompanionAuthorizationContract = "xz-companion-authorization-v1"',
            '"/v1/companion-tokens/introspect"',
            "TokenID: claims.TokenID",
            "Subject: claims.Subject",
            "TenantID: claims.TenantID",
            "Action: claims.Action",
            "DeviceID: claims.DeviceID",
            "Proxy:               nil",
            "MinVersion:   tls.VersionTLS12",
            "ErrCompanionInactive",
            "ErrCompanionUnavailable",
        ):
            self.assertIn(required, status)
        for required in (
            "CompanionStatus",
            "server.config.CompanionStatus.Authorize",
            "auth.ErrCompanionInactive",
            "http.StatusServiceUnavailable",
        ):
            self.assertIn(required, server)
        self.assertIn(
            "production Companion authorization requires online mTLS token introspection",
            config,
        )
        self.assertIn("LoadCompanionIntrospectionMTLSClient", main)

    def test_reference_store_cannot_be_enabled_in_production(self):
        config = self.read("gateway/internal/controlplane/config.go")
        main = self.read("gateway/cmd/controlplane/main.go")
        self.assertIn("settings.ActionConsentReference && !settings.AllowInsecure",
                      config)
        self.assertIn("durable multi-replica adapter", config)
        self.assertIn("actionconsent.NewStore", main)
        self.assertIn("settings.ActionConsentEnabled", config)
        self.assertIn("actionconsent.NewPostgresStore", main)

    def test_release_runbook_keeps_missing_physical_delivery_gates_explicit(self):
        runbook = self.read("AGENT_ACTION_CONSENT_RUNBOOK.md")
        gate = self.read("tools/run_agent_action_consent_gate.sh")
        for required in (
            "不得自行建立 challenge",
            "authenticated device challenge ingress",
            "PostgreSQL",
            "pending inbox",
            "不得啟用",
            "真機",
        ):
            self.assertIn(required, runbook)
        self.assertIn("run_companion_app_gate.sh", gate)
        self.assertIn("./internal/actionconsent", gate)


if __name__ == "__main__":
    unittest.main()
