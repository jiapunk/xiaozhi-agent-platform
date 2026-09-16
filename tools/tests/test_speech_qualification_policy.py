from pathlib import Path
import unittest


PROJECT = Path(__file__).resolve().parents[2]


class SpeechQualificationPolicyTests(unittest.TestCase):
    def test_receipt_cannot_claim_production_ready_or_store_text_hashes(self):
        runner = (PROJECT / "gateway/internal/speechqualification/run.go").read_text()
        verifier = (PROJECT / "gateway/internal/speechqualification/receipt.go").read_text()
        self.assertIn('ProductionReady:', runner)
        self.assertIn('false,', runner)
        self.assertIn('UnresolvedProductionGates', runner)
        self.assertIn('TranscriptExactMatch', runner)
        self.assertIn('SingleFinalObserved', runner)
        self.assertNotIn('text_sha256', runner)
        self.assertIn('qualification receipt overstates production readiness', verifier)
        self.assertIn('RequireProductionTransport', verifier)

    def test_receipt_binds_candidate_endpoint_corpus_and_reference_codec(self):
        runner = (PROJECT / "gateway/internal/speechqualification/run.go").read_text()
        receipt = (PROJECT / "gateway/internal/speechqualification/receipt.go").read_text()
        for marker in (
            'candidate_config_sha256',
            'adapter_endpoint_set_sha256',
            'qualification_tool_sha256',
            'transport_trust_sha256',
            'corpus_sha256',
            'reference_codec',
            'signature_b64url',
        ):
            self.assertIn(marker, runner)
        self.assertIn('XIAOZHI-SPEECH-QUALIFICATION-V1', receipt)
        self.assertIn('Ed25519', receipt)
        self.assertIn('refusing to overwrite qualification receipt', receipt)
        self.assertIn('ExpectedCorpusSHA256', receipt)
        self.assertIn('ExpectedFixtureManifest', receipt)
        self.assertIn('RequireExpectedThresholds', receipt)

    def test_live_gate_uses_real_codec_and_private_secret_file(self):
        command = (PROJECT / "gateway/cmd/qualifyspeechadapter/main.go").read_text()
        decoder = (PROJECT / "gateway/internal/speechqualification/codec.go").read_text()
        gate = (PROJECT / "tools/run_speech_adapter_harness_gate.sh").read_text()
        self.assertIn('bearer-token-file', command)
        self.assertIn('signing-private-key', command)
        self.assertIn('NewReferenceDecoder', command)
        self.assertIn('ffmpeg-native-opus', decoder)
        self.assertIn('XIAOZHI_FFMPEG', gate)

    def test_qualification_tools_are_not_backend_release_services(self):
        python_release = (PROJECT / "tools/oci_release.py").read_text()
        go_release = (PROJECT / "gateway/internal/ocirelease/validate.go").read_text()
        for command in ('qualifyspeechadapter', 'validatespeechqualification'):
            self.assertNotIn(f'"{command}"', python_release)
            self.assertNotIn(f'"{command}"', go_release)

    def test_private_adapter_urls_reject_query_credentials(self):
        stt = (PROJECT / "gateway/internal/gateway/stt_websocket.go").read_text()
        tts = (PROJECT / "gateway/internal/tts/framed_http.go").read_text()
        self.assertIn('parsed.RawQuery != ""', stt)
        self.assertIn('parsed.RawQuery != ""', tts)


if __name__ == "__main__":
    unittest.main()
