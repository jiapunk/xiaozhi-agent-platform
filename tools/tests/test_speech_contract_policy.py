import pathlib
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[2]


class SpeechContractPolicyTests(unittest.TestCase):
    def test_contract_versions_are_product_owned_and_explicit(self):
        source = (
            PROJECT / "gateway" / "internal" / "speechcontract" / "contract.go"
        ).read_text()
        self.assertIn('Header     = "X-Xiaozhi-Speech-Contract"', source)
        self.assertIn('STTVersion = "xiaozhi-private-stt-v1"', source)
        self.assertIn('TTSVersion = "xiaozhi-private-tts-v1"', source)

    def test_both_live_and_health_paths_require_contract_versions(self):
        stt = (
            PROJECT / "gateway" / "internal" / "gateway" / "stt_websocket.go"
        ).read_text()
        tts = (
            PROJECT / "gateway" / "internal" / "tts" / "framed_http.go"
        ).read_text()
        self.assertGreaterEqual(stt.count("speechcontract.STTVersion"), 5)
        self.assertGreaterEqual(tts.count("speechcontract.TTSVersion"), 5)
        self.assertIn("STT health contract mismatch", stt)
        self.assertIn("TTS health contract mismatch", tts)

    def test_uplink_and_downlink_apply_opus_policy_before_emission(self):
        stt = (
            PROJECT / "gateway" / "internal" / "gateway" / "stt_websocket.go"
        ).read_text()
        tts = (
            PROJECT / "gateway" / "internal" / "tts" / "framed_http.go"
        ).read_text()
        parser = (
            PROJECT / "gateway" / "internal" / "opuspacket" / "packet.go"
        ).read_text()
        self.assertIn("ValidateMonoDuration(opus, session.frameDuration)", stt)
        self.assertIn("ValidateMonoDuration(frame, client.frameDuration)", tts)
        for contract in (
            "stereo Opus is not allowed",
            "Opus packet duration exceeds 120 ms",
            "Opus CBR packet has unequal frame sizes",
            "Opus VBR frame lengths exceed payload",
        ):
            self.assertIn(contract, parser)

    def test_acceptance_runbook_keeps_real_decode_and_provider_gates_open(self):
        runbook = (PROJECT / "SPEECH_PROVIDER_ACCEPTANCE.md").read_text()
        self.assertIn("does not decode the Opus payload", runbook)
        self.assertIn("privacy, latency, cancellation", runbook)
        self.assertIn("real-BOX3 canary", runbook)


if __name__ == "__main__":
    unittest.main()
