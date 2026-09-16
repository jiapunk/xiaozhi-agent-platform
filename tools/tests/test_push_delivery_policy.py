import pathlib
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class PushDeliveryPolicyTests(unittest.TestCase):
    def read(self, path):
        return (PROJECT / path).read_text(encoding="utf-8")

    def test_installation_registry_is_encrypted_revision_fenced_and_bounded(self):
        types = self.read("gateway/internal/accountauth/push_installation.go")
        protector = self.read(
            "gateway/internal/accountauth/push_token_protector.go"
        )
        postgres = self.read(
            "gateway/internal/accountauth/push_installation_postgres.go"
        )
        migration = self.read(
            "gateway/migrations/account/0002_companion_push_installations.sql"
        )
        for required in (
            "MaximumPushInstallationsPerAccount = 16",
            "MaximumPushInstallationLifetime",
            "= 35 * 24 * time.Hour",
            "ProtectedPushToken",
            "InvalidatePushInstallation",
        ):
            self.assertIn(required, types)
        for required in (
            "aes.NewCipher", "cipher.NewGCM", "hmac.New(sha256.New",
            "pushTokenAAD", "subtle.ConstantTimeCompare",
        ):
            self.assertIn(required, protector)
        for required in (
            "selectAccount(ctx, tx, session.Principal)",
            "account.Revision != session.AccountRevision",
            "token_digest = $5", "MaximumPushInstallationsPerAccount",
        ):
            self.assertIn(required, postgres)
        for required in (
            "xz-companion-push-db-v1-20260810",
            "token_ciphertext bytea", "token_key_id varchar(64)",
            "token_digest bytea", "UNIQUE (platform, token_digest)",
            "valid_until <= refreshed_at + INTERVAL '840 hours'",
        ):
            self.assertIn(required, migration)
        self.assertNotIn("provider_token", migration)

    def test_registration_is_selected_idp_bff_only_and_app_is_ephemeral(self):
        handler = self.read(
            "gateway/internal/accountauth/push_installation_handler.go"
        )
        private_reader = self.read("gateway/cmd/accountauthorization/main.go")
        swift = self.read(
            "companion-app/Sources/ProductOnboardingCore/PushInstallationAPI.swift"
        )
        for required in (
            "PushInstallationAuthenticator", "request.TLS.Version < tls.VersionTLS12",
            "AuthenticatePushInstallation", "handler.protector.Seal",
            "UpsertPushInstallation", "RemovePushInstallation",
        ):
            self.assertIn(required, handler)
        self.assertNotIn("NewPushInstallationHandler", private_reader)
        for required in (
            "HTTPSPushInstallationClient", 'accountAuthority.scheme == "https"',
            '"X-Xiaozhi-Companion-Push"', "authorization.invalidate()",
            "discardCompanionSessionAuthorization()", "canonicalAPNsToken",
        ):
            self.assertIn(required, swift)
        self.assertNotIn("private var providerToken", swift)

    def test_apns_and_fcm_envelopes_are_fixed_content_free_and_fail_closed(self):
        apns = self.read("gateway/internal/pushdelivery/apns.go")
        fcm = self.read("gateway/internal/pushdelivery/fcm.go")
        for required in (
            '"content-available":1', '"kind":"action-consent-wake"',
            '"version":1', 'request.Header.Set("apns-push-type", "background")',
            'request.Header.Set("apns-priority", "5")',
            'request.Header.Set("apns-expiration", "0")',
            "response.ProtoMajor != 2", 'reason == "Unregistered"',
        ):
            self.assertIn(required, apns)
        for required in (
            '"kind": "action-consent-wake"', '"version": "1"',
            'Priority = "normal"', 'TTL = "0s"',
            'detail.ErrorCode == "UNREGISTERED"',
            'detail.ErrorCode == "INVALID_ARGUMENT"',
        ):
            self.assertIn(required, fcm)
        for forbidden in (
            "challenge_id", "indicator_on", "decision", "approve", "deny",
            "prompt", "access_token",
        ):
            self.assertNotIn(forbidden, apns)
            self.assertNotIn(forbidden, fcm)

    def test_private_dispatch_stays_inside_existing_seven_service_boundary(self):
        private = self.read("gateway/internal/pushdelivery/private_wake.go")
        sender = self.read("gateway/internal/pushdelivery/sender.go")
        release = self.read("tools/oci_release.py")
        for required in (
            "len(request.TLS.VerifiedChains) == 0",
            "len(request.TLS.PeerCertificates) == 0",
            "PrivateWakeContract", "MTLSWakeClient",
            "actionconsent.CanonicalWakePayload()",
        ):
            self.assertIn(required, private)
        for required in (
            "ActivePushInstallations", "protector.Open", "provider.Send",
            "InvalidatePushInstallation", "WakeSendNoInstallation",
        ):
            self.assertIn(required, sender)
        self.assertIn('"factorytimeauthority",', release)
        self.assertNotIn('"pushnotification",', release)

    def test_m68_credentials_wiring_and_deployment_are_fail_closed(self):
        apns_auth = self.read("gateway/internal/pushdelivery/apns_auth.go")
        google_auth = self.read("gateway/internal/pushdelivery/google_oauth.go")
        account_main = self.read("gateway/cmd/accountauthorization/main.go")
        control_main = self.read("gateway/cmd/controlplane/main.go")
        deployment = self.read("tools/kubernetes_deployment.py")
        for required in (
            'Algorithm: "ES256"', "apnsTokenRefreshAge = 40 * time.Minute",
            "apnsTokenMaximumAge = 50 * time.Minute", "ecdsa.Verify",
        ):
            self.assertIn(required, apns_auth)
        for required in (
            'Algorithm: "RS256"', "googleFCMScope",
            'request.Header.Set("Metadata-Flavor", "Google")',
            "transport.Proxy != nil", "maximumGoogleTokenResponse",
        ):
            self.assertIn(required, google_auth)
        for required in (
            "buildPushWakeHandler", "LoadPushTokenProtector",
            "NewPrivateWakeHandler", 'mux.Handle("POST "+pushdelivery.PrivateWakePath',
        ):
            self.assertIn(required, account_main)
        for required in (
            "actionConsentStore.(actionconsent.WakeOutbox)",
            "NewMTLSWakeClient", "NewWakeNotifier", ".Run(ctx",
        ):
            self.assertIn(required, control_main)
        for required in (
            "SCHEMA_VERSION = 7", '"companion_push"',
            '"ACTION_CONSENT_PUSH_WORKER_ID"', '"push-token-keyring.json"',
            '"accountauthorization": (("database", 5432),) +',
        ):
            self.assertIn(required, deployment)
        self.assertNotIn('"pushnotification",', deployment)

    def test_release_docs_keep_live_provider_and_signed_app_gates(self):
        account = self.read("COMPANION_ACCOUNT_AUTHORIZATION_RUNBOOK.md")
        consent = self.read("AGENT_ACTION_CONSENT_RUNBOOK.md")
        report = self.read("M68_PUSH_CREDENTIAL_WIRING_REPORT.md")
        for required in ("APNs", "FCM", "installation"):
            self.assertIn(required, account)
            self.assertIn(required, report)
        self.assertIn("簽章 App", account)
        self.assertIn("managed account database", account)
        self.assertIn("signed App", report)
        self.assertIn("managed PostgreSQL", report)
        self.assertIn("不得啟用", consent)
        self.assertIn("NO-GO", report)


if __name__ == "__main__":
    unittest.main()
