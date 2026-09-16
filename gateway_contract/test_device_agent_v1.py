import unittest

from device_agent_v1 import (
    GatewaySession,
    ProtocolViolation,
    TtsState,
    acknowledge_client_hello,
)


class HelloTests(unittest.TestCase):
    def test_acknowledges_exact_v1_feature(self) -> None:
        result = acknowledge_client_hello(
            {
                "type": "hello",
                "features": {
                    "mcp": True,
                    "device_agent": {
                        "version": 1,
                        "request_correlation": True,
                    },
                },
            },
            {"type": "hello", "session_id": "voice:d1:c1", "features": {}},
        )
        self.assertEqual(
            result["features"]["device_agent"],
            {"version": 1, "request_correlation": True},
        )

    def test_rejects_legacy_or_ambiguous_features(self) -> None:
        cases = [
            {"type": "hello", "features": {}},
            {
                "type": "hello",
                "features": {
                    "device_agent": {
                        "version": 2,
                        "request_correlation": True,
                    }
                },
            },
            {
                "type": "hello",
                "features": {
                    "device_agent": {
                        "version": True,
                        "request_correlation": True,
                    }
                },
            },
            {
                "type": "hello",
                "features": {
                    "device_agent": {
                        "version": 1,
                        "request_correlation": 1,
                    }
                },
            },
        ]
        for client in cases:
            with self.subTest(client=client):
                with self.assertRaises(ProtocolViolation):
                    acknowledge_client_hello(
                        client, {"type": "hello", "session_id": "s"}
                    )


class SessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.session = GatewaySession("voice:d1:c1")

    def request(self, request_id: object = 42, text: object = "Done") -> dict:
        return {
            "session_id": "voice:d1:c1",
            "type": "tts_request",
            "request_id": request_id,
            "text": text,
        }

    def test_happy_path_events_are_correlated(self) -> None:
        self.session.accept_device_message(self.request())
        self.assertEqual(self.session.state, TtsState.PENDING)
        self.assertEqual(self.session.tts_start(42)["request_id"], 42)
        caption = self.session.sentence_start(42, "Done")
        self.assertEqual(caption["session_id"], "voice:d1:c1")
        self.assertEqual(caption["state"], "sentence_start")
        terminal = self.session.tts_stop(42)
        self.assertEqual(terminal["state"], "stop")
        self.assertEqual(self.session.state, TtsState.IDLE)
        self.assertIsNone(self.session.active_request_id)

    def test_error_is_terminal(self) -> None:
        self.session.accept_device_message(self.request())
        error = self.session.tts_error(42, "synthesis_failed")
        self.assertEqual(error["code"], "synthesis_failed")
        self.assertEqual(self.session.state, TtsState.IDLE)

    def test_abort_clears_request(self) -> None:
        self.session.accept_device_message(self.request())
        self.session.accept_device_message(
            {
                "session_id": "voice:d1:c1",
                "type": "tts_abort",
                "request_id": 42,
                "reason": "barge_in",
            }
        )
        self.assertEqual(self.session.state, TtsState.IDLE)
        with self.assertRaisesRegex(ProtocolViolation, "stale_request"):
            self.session.tts_stop(42)

    def test_rejects_stale_session_request_and_overlap(self) -> None:
        stale_session = self.request()
        stale_session["session_id"] = "old"
        with self.assertRaisesRegex(ProtocolViolation, "stale_session"):
            self.session.accept_device_message(stale_session)

        self.session.accept_device_message(self.request())
        with self.assertRaisesRegex(ProtocolViolation, "request_in_progress"):
            self.session.accept_device_message(self.request(43))
        with self.assertRaisesRegex(ProtocolViolation, "stale_request"):
            self.session.tts_start(43)

    def test_rejects_invalid_ids_reasons_and_limits(self) -> None:
        for invalid in (0, -1, 4_294_967_296, 1.5, "1", True, None):
            with self.subTest(request_id=invalid):
                with self.assertRaisesRegex(ProtocolViolation, "invalid_request_id"):
                    self.session.accept_device_message(self.request(invalid))

        with self.assertRaisesRegex(ProtocolViolation, "field_too_large"):
            self.session.accept_device_message(self.request(text="a" * 513))

        self.session.accept_device_message(self.request())
        for reason in ("unknown", {"not": "a string"}):
            with self.subTest(reason=reason):
                with self.assertRaises(ProtocolViolation):
                    self.session.accept_device_message(
                        {
                            "session_id": "voice:d1:c1",
                            "type": "tts_abort",
                            "request_id": 42,
                            "reason": reason,
                        }
                    )


if __name__ == "__main__":
    unittest.main()
