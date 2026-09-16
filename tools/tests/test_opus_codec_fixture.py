from __future__ import annotations

import base64
import sys
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT / "tools"))

from opus_codec_fixture import CodecFixtureError, parse_ogg_packets, wrap_raw_opus  # noqa: E402


class OpusCodecFixturePolicyTests(unittest.TestCase):
    def test_ogg_wrapper_round_trips_raw_packet(self):
        packet = bytes([0x18]) + bytes(range(1, 181))
        packets = parse_ogg_packets(wrap_raw_opus(packet, 16000))
        self.assertEqual(packets[0][:8], b"OpusHead")
        self.assertEqual(packets[1][:8], b"OpusTags")
        self.assertEqual(packets[2], packet)

    def test_ogg_wrapper_handles_255_byte_lacing_boundary(self):
        packet = bytes([0x18]) + b"a" * 509
        self.assertEqual(parse_ogg_packets(wrap_raw_opus(packet, 24000))[2], packet)

    def test_wrapper_rejects_non_product_rate_and_duration(self):
        with self.assertRaises(CodecFixtureError):
            wrap_raw_opus(b"packet", 48000)
        with self.assertRaises(CodecFixtureError):
            wrap_raw_opus(b"packet", 16000, 20)

    def test_checked_in_manifest_uses_canonical_base64_and_exact_profiles(self):
        import json

        manifest = json.loads(
            (PROJECT / "gateway/testdata/speech/opus-codec-fixtures.json").read_text()
        )
        self.assertTrue(manifest["qualification_only"])
        self.assertEqual(
            {fixture["name"] for fixture in manifest["fixtures"]},
            {"stt-16k-mono-60ms", "tts-24k-mono-60ms"},
        )
        for fixture in manifest["fixtures"]:
            packet = base64.b64decode(fixture["packet_base64"], validate=True)
            self.assertEqual(base64.b64encode(packet).decode(), fixture["packet_base64"])
            self.assertEqual(fixture["duration_ms"], 60)
            self.assertEqual(fixture["channels"], 1)


if __name__ == "__main__":
    unittest.main()
