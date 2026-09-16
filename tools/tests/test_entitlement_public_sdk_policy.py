from __future__ import annotations

import pathlib
import re
import sys
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT / "tools"))
import kubernetes_deployment as K8S


class EntitlementPublicSDKPolicyTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (PROJECT / relative).read_text(encoding="utf-8")

    def test_public_api_is_versioned_and_does_not_expose_internal_types(self) -> None:
        source = self.read("gateway/entitlementadapter/client.go")
        for required in (
            "package entitlementadapter",
            "APIVersion      = 1",
            "type State string", "type Principal struct", "type Update struct",
            "type Result struct", "type Signer interface",
            "type MTLSClient struct", "type Client struct",
            "func NewMTLSClient(", "func NewClient(",
            "func (client *Client) Apply(",
        ):
            self.assertIn(required, source)
        exported_types = source[
            source.index("type State string"):
            source.index("func NewMTLSClient(")
        ]
        for public_block in re.findall(
                r"type (?:Principal|Update|Result|Signer) .*?(?=\n}\n|\n\ntype)",
                exported_types, flags=re.DOTALL):
            self.assertNotIn("accountauth.", public_block)
        self.assertNotRegex(
            source,
            r"func (?:NewMTLSClient|NewClient|ValidEndpoint).*accountauth\.",
        )

    def test_public_update_is_minimized_and_signer_is_hsm_shaped(self) -> None:
        source = self.read("gateway/entitlementadapter/client.go")
        update = source[
            source.index("type Update struct"):
            source.index("type Disposition string")
        ].lower()
        for forbidden in (
            "provider_customer", "payment_method", "invoice", "currency",
            "receipt", "card_number", "raw_webhook", "webhook_payload",
        ):
            self.assertNotIn(forbidden, update)
        signer = source[
            source.index("type Signer interface"):
            source.index("type MTLSClient struct")
        ]
        self.assertIn("KeyID() string", signer)
        self.assertIn("Sign(context.Context, []byte) ([]byte, error)", signer)
        self.assertNotIn("PrivateKey", signer)
        self.assertNotIn("http.RoundTripper", source)
        self.assertNotIn("func (client *MTLSClient) Set", source)
        self.assertNotIn("http.DefaultClient", source)

    def test_public_errors_are_stable_and_hide_internal_details(self) -> None:
        source = self.read("gateway/entitlementadapter/client.go")
        tests = self.read("gateway/entitlementadapter/error_test.go")
        for required in (
            "ErrInvalid", "ErrUnauthorized", "ErrNotFound", "ErrConflict",
            "ErrUnavailable", "func publicError(err error) error",
            'errors.New("private provider detail")',
            '"unknown":',
        ):
            self.assertIn(required, source + tests)
        self.assertNotIn("err.Error()", source)

    def test_separate_module_compiles_only_against_public_import(self) -> None:
        consumer = self.read(
            "gateway/entitlementadapter/external_consumer_test.go")
        for required in (
            "module example.com/selected-provider-adapter",
            'sdk "xiaozhi-agent-platform/gateway/entitlementadapter"',
            "var _ sdk.Signer = kmsSigner{}",
            'exec.Command(goBinary, "test", "-mod=mod", "./...")',
            '"GOWORK=off"',
        ):
            self.assertIn(required, consumer)
        self.assertNotIn("gateway/internal/", consumer)

    def test_public_sdk_preserves_deployment_and_live_evidence_boundary(self) -> None:
        profile, _ = K8S.load_profile(
            PROJECT / "deployment/kubernetes-deployment-profile.example.json")
        fake_receipt = {
            "release_id": "m86-policy-fixture",
            "services": [
                {"name": service,
                 "image_index_digest": "sha256:" + "0" * 64}
                for service in K8S.SERVICES
            ],
        }
        resources = K8S.build_kubernetes_list(profile, fake_receipt)["items"]
        self.assertEqual(K8S.SCHEMA_VERSION, 7)
        self.assertEqual(len(K8S.SERVICES), 7)
        self.assertEqual(len(resources), 44)
        self.assertEqual(len(K8S.build_prerequisites(profile)["objects"]), 30)
        docs = self.read("ENTITLEMENT_ADAPTER_CONFORMANCE_RUNBOOK.md") + self.read(
            "PRODUCT_MARKET_RELEASE_RUNBOOK.md")
        for required in (
            "entitlementadapter", "public SDK", "private Go proxy",
            "真實 provider", "HSM／KMS", "NO-GO", "MARKET_RELEASE_PASS",
            "七個",
        ):
            self.assertIn(required, docs)


if __name__ == "__main__":
    unittest.main()
