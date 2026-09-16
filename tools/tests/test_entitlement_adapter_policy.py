from __future__ import annotations

import pathlib
import sys
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT / "tools"))
import kubernetes_deployment as K8S


class EntitlementAdapterPolicyTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (PROJECT / relative).read_text(encoding="utf-8")

    def test_sdk_has_hsm_boundary_and_product_owned_mtls_transport(self) -> None:
        client = self.read(
            "gateway/internal/accountauth/entitlement_update_client.go")
        transport = self.read("gateway/internal/auth/companion_status.go")
        signer = client[
            client.index("type EntitlementUpdateSigner interface"):
            client.index("type HTTPServiceEntitlementUpdater struct")
        ]
        for required in (
            "KeyID() string",
            "Sign(context.Context, []byte) ([]byte, error)",
            "auth.NewCompanionIntrospectionMTLSClient",
            "type EntitlementUpdateMTLSClient struct",
            "client *http.Client",
        ):
            self.assertIn(required, client)
        for forbidden in (
            "ed25519.PrivateKey", "os.ReadFile", "client: http.DefaultClient",
            "client = http.DefaultClient", "ProxyFromEnvironment",
            "WrapTransport",
        ):
            self.assertNotIn(forbidden, client)
        self.assertNotIn("PrivateKey", signer)
        for required in (
            "Proxy:               nil",
            "DisableCompression:  true",
            "MinVersion:   tls.VersionTLS12",
        ):
            self.assertIn(required, transport)

    def test_sdk_is_canonical_single_delivery_without_hidden_retry(self) -> None:
        client = self.read(
            "gateway/internal/accountauth/entitlement_update_client.go")
        tests = self.read(
            "gateway/internal/accountauth/entitlement_update_client_test.go")
        self.assertEqual(client.count("updater.client.Do(request)"), 1)
        self.assertNotIn("for {", client)
        self.assertNotIn("time.Sleep", client)
        for required in (
            "serviceEntitlementUpdateSigningMessage(body)",
            "json.Marshal(input)",
            "base64.RawURLEncoding.EncodeToString(signature)",
            "TestHTTPServiceEntitlementUpdaterSignsCanonicalSingleDelivery",
            "TestHTTPServiceEntitlementUpdaterClassifiesExactFailuresWithoutRetry",
            "requestCount != 1", "calls != 1",
            "ErrEntitlementUpdateUnauthorized", "ErrConflict",
            "ErrUnavailable",
        ):
            self.assertIn(required, client + tests)

    def test_adapter_cannot_send_provider_or_payment_evidence(self) -> None:
        contract = self.read("gateway/internal/accountauth/entitlement.go")
        wire = self.read(
            "gateway/internal/accountauth/entitlement_update_http.go")
        sdk = self.read(
            "gateway/internal/accountauth/entitlement_update_client.go")
        public_update = contract[
            contract.index("type ServiceEntitlementUpdate struct"):
            contract.index("type ServiceEntitlementGrant struct")
        ]
        wire_request = wire[
            wire.index("type serviceEntitlementUpdateRequest struct"):
            wire.index("type serviceEntitlementUpdateResponse struct")
        ]
        minimized = (public_update + wire_request + sdk).lower()
        for forbidden in (
            "provider_customer", "payment_method", "invoice", "currency",
            "receipt", "card_number", "raw_webhook", "webhook_payload",
        ):
            self.assertNotIn(forbidden, minimized)

    def test_adapter_sdk_does_not_change_signed_seven_workload_graph(self) -> None:
        profile, _ = K8S.load_profile(
            PROJECT / "deployment/kubernetes-deployment-profile.example.json")
        fake_receipt = {
            "release_id": "m85-policy-fixture",
            "services": [
                {"name": service,
                 "image_index_digest": "sha256:" + "0" * 64}
                for service in K8S.SERVICES
            ],
        }
        resources = K8S.build_kubernetes_list(profile, fake_receipt)["items"]
        workloads = [item for item in resources
                     if item["kind"] in {"Deployment", "StatefulSet"}]
        self.assertEqual(K8S.SCHEMA_VERSION, 7)
        self.assertEqual(len(K8S.SERVICES), 7)
        self.assertEqual(len(resources), 44)
        self.assertEqual(len(workloads), 7)
        self.assertEqual(len(K8S.build_prerequisites(profile)["objects"]), 30)

    def test_runbook_requires_real_provider_reconciliation_and_no_go(self) -> None:
        docs = self.read("ENTITLEMENT_ADAPTER_CONFORMANCE_RUNBOOK.md") + self.read(
            "SIGNED_ENTITLEMENT_INGESTION_RUNBOOK.md") + self.read(
            "PRODUCT_MARKET_RELEASE_RUNBOOK.md")
        for required in (
            "provider 原生簽章", "HSM／KMS", "不自動重試", "dead-letter",
            "401", "404", "409", "503", "WORM", "七個", "NO-GO",
            "MARKET_RELEASE_PASS", "真實 provider",
        ):
            self.assertIn(required, docs)


if __name__ == "__main__":
    unittest.main()
