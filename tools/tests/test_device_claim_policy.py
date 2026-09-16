import pathlib
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class DeviceClaimPolicyTests(unittest.TestCase):
    def read(self, relative):
        return (PROJECT / relative).read_text(encoding="utf-8")

    def test_device_proof_has_a_distinct_fixed_scope(self):
        proof = self.read(
            "components/agent_device_identity/agent_device_proof_core.c"
        )
        identity = self.read(
            "components/agent_device_identity/agent_device_identity.c"
        )
        self.assertIn("xiaozhi-device-claim-proof-v1", proof)
        self.assertIn("/v1/device-claim/device", proof)
        self.assertIn("DEVICE_CLAIM_BASE64URL_SIZE = 43", proof)
        self.assertIn("AGENT_DEVICE_PROOF_SCOPE_DEVICE_CLAIM", identity)

    def test_security2_claim_must_precede_wifi_apply_and_cloud_success(self):
        provisioning = self.read(
            "components/product_provisioning/product_provisioning.c"
        )
        core = self.read(
            "components/product_provisioning/product_provisioning_core.c"
        )
        for contract in (
            '"xz-claim"', "xz_claim_v1",
            "pending_valid && claim_disclosed",
            "PRODUCT_PROVISIONING_ACTION_PUBLISH_CLAIM",
        ):
            self.assertIn(contract, provisioning)
        self.assertIn("claim_required && !core->claim_published", core)
        self.assertIn("product_provisioning_core_claim_result", core)

    def test_control_plane_pairs_app_and_device_without_raw_claim_storage(self):
        server = self.read("gateway/internal/controlplane/server.go")
        store = self.read("gateway/internal/deviceclaim/store.go")
        for route in (
            "/v1/device-claim/app",
            "/v1/device-claim/device",
            "/v1/device-claim/status",
        ):
            self.assertIn(route, server)
        self.assertIn("type OwnershipStore interface", store)
        self.assertIn("digest    [sha256.Size]byte", store)
        stored_record = store.split("type storedRecord struct", 1)[1].split(
            "}", 1
        )[0]
        self.assertNotIn("claim", stored_record.lower())
        self.assertIn("device ownership required", server)

    def test_reference_memory_store_is_not_a_production_configuration(self):
        config = self.read("gateway/internal/controlplane/config.go")
        self.assertIn("ALLOW_INSECURE_DEVELOPMENT", config)
        self.assertIn("durable transactional adapter", config)
        self.assertIn("reference device claim store", config)

    def test_companion_success_requires_matching_bound_request(self):
        flow = self.read(
            "companion-app/Sources/ProductOnboardingCore/OnboardingFlow.swift"
        )
        adapter = self.read(
            "companion-app/Sources/ProductOnboardingESPProvision/"
            "ESPProvisionTransport.swift"
        )
        api = self.read(
            "companion-app/Sources/ProductOnboardingCore/DeviceClaimAPI.swift"
        )
        self.assertIn('sendData(path: "xz-claim", data: Data())', adapter)
        self.assertIn("case beginDeviceClaim", flow)
        self.assertIn("case scheduleOwnershipStatusPoll", flow)
        self.assertIn("status.requestID == claimRequest?.requestID", flow)
        self.assertIn("status.status == .pending", flow)
        self.assertIn('strcmp(status->valuestring, "bound") == 0', self.read(
            "components/agent_control_plane_client/"
            "agent_control_plane_protocol.c"
        ))
        self.assertIn("disable_auto_redirect = true", self.read(
            "components/agent_control_plane_client/"
            "agent_control_plane_client.c"
        ))
        self.assertIn("URLSessionConfiguration.ephemeral", api)


if __name__ == "__main__":
    unittest.main()
