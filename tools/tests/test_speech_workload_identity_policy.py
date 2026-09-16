import ast
from pathlib import Path
import unittest


PROJECT = Path(__file__).resolve().parents[2]


class SpeechWorkloadIdentityPolicyTests(unittest.TestCase):
    def read(self, name: str) -> str:
        return (PROJECT / name).read_text()

    def test_transport_is_private_tls13_mtls_without_proxy_or_redirects(self) -> None:
        client = self.read("gateway/internal/speechidentity/client.go")
        for marker in (
            "MinVersion:             tls.VersionTLS13",
            "MaxVersion:             tls.VersionTLS13",
            "Certificates:           []tls.Certificate{identity}",
            "SessionTicketsDisabled: true",
            "Proxy:                 nil",
            "speech workload redirects are disabled",
        ):
            self.assertIn(marker, client)
        self.assertIn("ExtKeyUsageClientAuth", client)
        self.assertIn("private key permissions must be 0600 or stricter", client)

    def test_stt_and_tts_are_content_isolated(self) -> None:
        client = self.read("gateway/internal/speechidentity/client.go")
        self.assertIn("STT and TTS must not share a CA trust set", client)
        self.assertIn("STT and TTS must not share a CA certificate", client)
        self.assertIn("STT and TTS must not share a client identity", client)
        self.assertIn("XIAOZHI-SPEECH-WORKLOAD-BINDINGS-V1", client)
        self.assertIn("XIAOZHI-SPEECH-CA-TRUST-SET-V1", client)

    def test_production_gateway_requires_and_wires_both_identities(self) -> None:
        configuration = self.read("gateway/internal/config/config.go")
        gateway = self.read("gateway/cmd/gateway/main.go")
        for variable in (
            "STT_TLS_CA_FILE", "STT_TLS_CLIENT_CERT_FILE", "STT_TLS_CLIENT_KEY_FILE",
            "TTS_TLS_CA_FILE", "TTS_TLS_CLIENT_CERT_FILE", "TTS_TLS_CLIENT_KEY_FILE",
        ):
            self.assertIn(variable, configuration)
        self.assertIn("isolated STT and TTS mTLS credentials are required", configuration)
        self.assertIn("STT and TTS bearer tokens must be isolated", configuration)
        self.assertIn("speechidentity.ValidateIsolation", gateway)
        self.assertIn("HTTPClient: sttHTTPClient", gateway)
        self.assertRegex(gateway, r"Client:\s+ttsHTTPClient")

    def test_live_qualification_uses_same_isolated_boundary(self) -> None:
        command = self.read("gateway/cmd/qualifyspeechadapter/main.go")
        for flag in (
            "stt-bearer-token-file", "tts-bearer-token-file",
            "stt-ca-bundle", "stt-client-certificate", "stt-client-key",
            "tts-ca-bundle", "tts-client-certificate", "tts-client-key",
        ):
            self.assertIn(flag, command)
        self.assertIn("speechidentity.BindingSetDigest", command)
        self.assertIn("legacy shared speech flags cannot be combined", command)

    def test_deployment_mounts_six_files_without_an_eighth_workload(self) -> None:
        deployment = self.read("tools/kubernetes_deployment.py")
        for name in (
            "stt-ca.pem", "stt-client.crt", "stt-client.key",
            "tts-ca.pem", "tts-client.crt", "tts-client.key",
        ):
            self.assertIn(name, deployment)
        self.assertIn('SERVICES = oci.SERVICES', deployment)
        release = self.read("tools/oci_release.py")
        module = ast.parse(release)
        assignment = next(
            node for node in module.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "SERVICES"
                    for target in node.targets)
        )
        self.assertEqual(ast.literal_eval(assignment.value), (
            "gateway", "controlplane", "agentproxy", "firmwareorigin",
            "generationcoordinator", "accountauthorization", "factorytimeauthority",
        ))


if __name__ == "__main__":
    unittest.main()
