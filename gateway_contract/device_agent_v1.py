"""Executable reference contract for the Device Agent Voice Protocol v1.

This module deliberately contains no networking, TTS provider, or cloud SDK.
Production gateways can use any implementation language; their protocol tests
must exhibit the same externally observable behavior.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from enum import Enum
from typing import Any


PROTOCOL_VERSION = 1
MAX_REQUEST_ID = 0xFFFFFFFF
MAX_SESSION_ID_BYTES = 63
MAX_TTS_TEXT_BYTES = 512
ABORT_REASONS = frozenset(
    {"barge_in", "button", "network_lost", "session_closed"}
)


class ProtocolViolation(ValueError):
    """A stable error class suitable for mapping to gateway metrics."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


class TtsState(str, Enum):
    IDLE = "idle"
    PENDING = "pending"
    PLAYING = "playing"


def _require_object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProtocolViolation("invalid_field", f"{field} must be an object")
    return value


def _require_nonempty_string(value: Any, field: str, max_bytes: int) -> str:
    if not isinstance(value, str) or not value:
        raise ProtocolViolation("invalid_field", f"{field} must be a non-empty string")
    try:
        length = len(value.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise ProtocolViolation("invalid_utf8", f"{field} is not valid UTF-8") from error
    if length > max_bytes:
        raise ProtocolViolation("field_too_large", f"{field} exceeds {max_bytes} bytes")
    return value


def _require_request_id(value: Any) -> int:
    # bool is a subclass of int in Python but is not a JSON protocol integer.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProtocolViolation("invalid_request_id", "request_id must be an integer")
    if value < 1 or value > MAX_REQUEST_ID:
        raise ProtocolViolation("invalid_request_id", "request_id is out of range")
    return value


def acknowledge_client_hello(
    client_hello: dict[str, Any], server_hello: dict[str, Any]
) -> dict[str, Any]:
    """Validate a client claim and return a server hello with an exact v1 echo."""

    if client_hello.get("type") != "hello":
        raise ProtocolViolation("invalid_hello", "client type must be hello")
    client_features = _require_object(client_hello.get("features"), "features")
    device_agent = _require_object(
        client_features.get("device_agent"), "features.device_agent"
    )
    if device_agent.get("version") != PROTOCOL_VERSION or isinstance(
        device_agent.get("version"), bool
    ):
        raise ProtocolViolation("unsupported_version", "Device Agent v1 is required")
    if device_agent.get("request_correlation") is not True:
        raise ProtocolViolation(
            "missing_correlation", "request correlation must be explicitly true"
        )

    response = deepcopy(server_hello)
    if response.get("type") != "hello":
        raise ProtocolViolation("invalid_hello", "server type must be hello")
    _require_nonempty_string(
        response.get("session_id"), "session_id", MAX_SESSION_ID_BYTES
    )
    features = response.setdefault("features", {})
    _require_object(features, "features")
    features["device_agent"] = {
        "version": PROTOCOL_VERSION,
        "request_correlation": True,
    }
    return response


@dataclass
class GatewaySession:
    """Single-active-request gateway state used by conformance tests."""

    session_id: str
    state: TtsState = TtsState.IDLE
    active_request_id: int | None = None
    active_text: str | None = None

    def __post_init__(self) -> None:
        self.session_id = _require_nonempty_string(
            self.session_id, "session_id", MAX_SESSION_ID_BYTES
        )

    def _require_session(self, message: dict[str, Any]) -> None:
        incoming = _require_nonempty_string(
            message.get("session_id"), "session_id", MAX_SESSION_ID_BYTES
        )
        if incoming != self.session_id:
            raise ProtocolViolation("stale_session", "session_id does not match")

    def _require_active(self, request_id: Any) -> int:
        parsed = _require_request_id(request_id)
        if self.active_request_id != parsed:
            raise ProtocolViolation("stale_request", "request_id is not active")
        return parsed

    def accept_device_message(self, message: dict[str, Any]) -> None:
        _require_object(message, "message")
        self._require_session(message)
        message_type = message.get("type")

        if message_type == "tts_request":
            request_id = _require_request_id(message.get("request_id"))
            text = _require_nonempty_string(
                message.get("text"), "text", MAX_TTS_TEXT_BYTES
            )
            if self.state is not TtsState.IDLE:
                raise ProtocolViolation(
                    "request_in_progress", "only one TTS request may be active"
                )
            self.active_request_id = request_id
            self.active_text = text
            self.state = TtsState.PENDING
            return

        if message_type == "tts_abort":
            self._require_active(message.get("request_id"))
            reason = _require_nonempty_string(message.get("reason"), "reason", 32)
            if reason not in ABORT_REASONS:
                raise ProtocolViolation("invalid_abort_reason", "unsupported reason")
            self._clear()
            return

        raise ProtocolViolation("unsupported_message", "unsupported device message type")

    def tts_start(self, request_id: int) -> dict[str, Any]:
        request_id = self._require_active(request_id)
        if self.state is not TtsState.PENDING:
            raise ProtocolViolation("invalid_state", "TTS is not pending")
        self.state = TtsState.PLAYING
        return self._event("start", request_id)

    def sentence_start(self, request_id: int, text: str) -> dict[str, Any]:
        request_id = self._require_active(request_id)
        if self.state is not TtsState.PLAYING:
            raise ProtocolViolation("invalid_state", "TTS is not playing")
        text = _require_nonempty_string(text, "text", MAX_TTS_TEXT_BYTES)
        return self._event("sentence_start", request_id, text=text)

    def tts_stop(self, request_id: int) -> dict[str, Any]:
        request_id = self._require_active(request_id)
        if self.state not in (TtsState.PENDING, TtsState.PLAYING):
            raise ProtocolViolation("invalid_state", "TTS is not active")
        event = self._event("stop", request_id)
        self._clear()
        return event

    def tts_error(self, request_id: int, code: str) -> dict[str, Any]:
        request_id = self._require_active(request_id)
        if self.state not in (TtsState.PENDING, TtsState.PLAYING):
            raise ProtocolViolation("invalid_state", "TTS is not active")
        code = _require_nonempty_string(code, "code", 64)
        event = self._event("error", request_id, code=code)
        self._clear()
        return event

    def _event(self, state: str, request_id: int, **fields: Any) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "type": "tts",
            "state": state,
            "request_id": request_id,
            **fields,
        }

    def _clear(self) -> None:
        self.state = TtsState.IDLE
        self.active_request_id = None
        self.active_text = None
