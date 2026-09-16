#!/usr/bin/env python3
"""M60 signed online trusted-time contract for sacrificial attempt consumption."""

from __future__ import annotations

import base64
import binascii
import hashlib
import http.client
import json
import re
import secrets
import ssl
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


REQUEST_SCHEMA = "xz-sacrificial-trusted-time-request-v1"
RECEIPT_SCHEMA = "xz-sacrificial-trusted-time-receipt-v1"
ENVIRONMENT = "SACRIFICIAL_HARDWARE_AUTHORIZATION"
SCOPE = "SACRIFICIAL_ATTEMPT_CONSUMPTION_TIME"
REQUEST_RESULT = "TRUSTED_TIME_REQUESTED"
RECEIPT_RESULT = "TRUSTED_TIME_ATTESTED"
SIGNATURE_DOMAIN = b"xz-sacrificial-trusted-time-receipt-v1\x00"
ENDPOINT_PATH = "/v1/factory/trusted-time"
TIMEOUT_MS = 5000
MAX_RESPONSE_BYTES = 16 * 1024
MAX_RECEIPT_LIFETIME_SECONDS = 10
MAX_JSON_BYTES = 64 * 1024
MAX_PUBLIC_KEY_BYTES = 16 * 1024
IDENTIFIER = re.compile(r"^[A-Za-z0-9:_.-]{1,128}$")
DEVICE_ID = re.compile(r"^xz-[0-9a-f]{12}$")
MAC_ADDRESS = re.compile(r"^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$")
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
NONCE = re.compile(r"^[A-Za-z0-9_-]{43}$")
SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class TrustedTimeError(ValueError):
    pass


def canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise TrustedTimeError(f"duplicate JSON member: {key}")
        value[key] = item
    return value


def _parse_json(data: bytes, label: str) -> dict[str, Any]:
    if not data or len(data) > MAX_JSON_BYTES:
        raise TrustedTimeError(f"{label} is empty or too large")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TrustedTimeError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise TrustedTimeError(f"{label} must be an object")
    return value


def _exact(value: Any, members: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != members:
        raise TrustedTimeError(f"{label} members differ")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise TrustedTimeError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_HEX.fullmatch(value) is None:
        raise TrustedTimeError(f"{label} must be a lowercase SHA-256")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or TIMESTAMP.fullmatch(value) is None:
        raise TrustedTimeError(f"{label} must be whole-second UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise TrustedTimeError(f"{label} is invalid") from error
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise TrustedTimeError(f"{label} is not canonical")
    return parsed


def _public_key(data: bytes) -> Ed25519PublicKey:
    if not data or len(data) > MAX_PUBLIC_KEY_BYTES or b"PRIVATE KEY" in data:
        raise TrustedTimeError("trusted-time public key input is invalid")
    try:
        key = serialization.load_pem_public_key(data)
    except (TypeError, ValueError) as error:
        raise TrustedTimeError("trusted-time public key is invalid") from error
    if not isinstance(key, Ed25519PublicKey):
        raise TrustedTimeError("trusted-time public key must be Ed25519")
    return key


def public_key_sha256(data: bytes) -> str:
    key = _public_key(data)
    der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256(der)


def validate_endpoint(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 512:
        raise TrustedTimeError("trusted-time endpoint is invalid")
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != ENDPOINT_PATH
        or parsed.query
        or parsed.fragment
    ):
        raise TrustedTimeError("trusted-time endpoint must be an exact HTTPS URL")
    try:
        port = parsed.port
    except ValueError as error:
        raise TrustedTimeError("trusted-time endpoint port is invalid") from error
    if port is not None and not 1 <= port <= 65535:
        raise TrustedTimeError("trusted-time endpoint port is invalid")
    return value


def _subject(policy: dict[str, Any], policy_data: bytes, plan: dict[str, Any], plan_data: bytes) -> dict[str, Any]:
    return {
        "ledger": {
            "policy_sha256": sha256(policy_data),
            "policy_id": policy["policy_id"],
            "ledger_id": policy["ledger_id"],
        },
        "authorization": {
            "plan_sha256": sha256(plan_data),
            "plan_id": plan["plan_id"],
            "issued_at": plan["authorization"]["issued_at"],
            "expires_at": plan["authorization"]["expires_at"],
        },
        "transaction": {
            "attempt_id": plan["transaction"]["attempt_id"],
            "device_id": plan["transaction"]["device_id"],
            "base_mac": plan["transaction"]["base_mac"],
        },
        "station": {
            "id": plan["station"]["id"],
            "fixture_id": plan["station"]["fixture_id"],
            "fixture_version": plan["station"]["fixture_version"],
        },
    }


def build_request(
    *,
    policy: dict[str, Any],
    policy_data: bytes,
    plan: dict[str, Any],
    plan_data: bytes,
    request_id: str | None = None,
    nonce: bytes | None = None,
) -> dict[str, Any]:
    request_identifier = request_id or "time-" + secrets.token_hex(16)
    raw_nonce = nonce if nonce is not None else secrets.token_bytes(32)
    if len(raw_nonce) != 32:
        raise TrustedTimeError("trusted-time request nonce must be 32 bytes")
    subject = _subject(policy, policy_data, plan, plan_data)
    request = {
        "schema": REQUEST_SCHEMA,
        "environment": ENVIRONMENT,
        "scope": SCOPE,
        "request_id": request_identifier,
        "nonce_b64url": base64.urlsafe_b64encode(raw_nonce).rstrip(b"=").decode("ascii"),
        **subject,
        "result": REQUEST_RESULT,
    }
    validate_request(request)
    return request


def _validate_subject(root: dict[str, Any]) -> None:
    ledger = _exact(
        root["ledger"], {"policy_sha256", "policy_id", "ledger_id"}, "time ledger"
    )
    _digest(ledger["policy_sha256"], "time policy hash")
    _identifier(ledger["policy_id"], "time policy ID")
    _identifier(ledger["ledger_id"], "time ledger ID")
    authorization = _exact(
        root["authorization"],
        {"plan_sha256", "plan_id", "issued_at", "expires_at"},
        "time authorization",
    )
    _digest(authorization["plan_sha256"], "time plan hash")
    _identifier(authorization["plan_id"], "time plan ID")
    issued = _timestamp(authorization["issued_at"], "time plan issue")
    expires = _timestamp(authorization["expires_at"], "time plan expiry")
    if issued >= expires:
        raise TrustedTimeError("time plan window is invalid")
    transaction = _exact(
        root["transaction"], {"attempt_id", "device_id", "base_mac"}, "time transaction"
    )
    _identifier(transaction["attempt_id"], "time attempt ID")
    if (
        not isinstance(transaction["device_id"], str)
        or DEVICE_ID.fullmatch(transaction["device_id"]) is None
        or not isinstance(transaction["base_mac"], str)
        or MAC_ADDRESS.fullmatch(transaction["base_mac"]) is None
        or transaction["device_id"]
        != "xz-" + transaction["base_mac"].replace(":", "").lower()
    ):
        raise TrustedTimeError("time device subject is invalid")
    station = _exact(
        root["station"], {"id", "fixture_id", "fixture_version"}, "time station"
    )
    for name in ("id", "fixture_id", "fixture_version"):
        _identifier(station[name], f"time station {name}")


def validate_request(value: dict[str, Any]) -> None:
    root = _exact(
        value,
        {
            "schema",
            "environment",
            "scope",
            "request_id",
            "nonce_b64url",
            "ledger",
            "authorization",
            "transaction",
            "station",
            "result",
        },
        "trusted-time request",
    )
    if (
        root["schema"] != REQUEST_SCHEMA
        or root["environment"] != ENVIRONMENT
        or root["scope"] != SCOPE
        or root["result"] != REQUEST_RESULT
    ):
        raise TrustedTimeError("trusted-time request constants differ")
    _identifier(root["request_id"], "trusted-time request ID")
    if not isinstance(root["nonce_b64url"], str) or NONCE.fullmatch(root["nonce_b64url"]) is None:
        raise TrustedTimeError("trusted-time nonce is invalid")
    try:
        decoded = base64.urlsafe_b64decode(root["nonce_b64url"] + "=")
    except (ValueError, binascii.Error) as error:
        raise TrustedTimeError("trusted-time nonce encoding is invalid") from error
    if len(decoded) != 32:
        raise TrustedTimeError("trusted-time nonce length is invalid")
    _validate_subject(root)


def parse_request(data: bytes) -> dict[str, Any]:
    value = _parse_json(data, "trusted-time request")
    if canonical_json(value) != data:
        raise TrustedTimeError("trusted-time request is not canonical JSON")
    validate_request(value)
    return value


def build_receipt(
    *, request: dict[str, Any], authority_key_id: str, observed_at: str, expires_at: str
) -> dict[str, Any]:
    validate_request(request)
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "environment": ENVIRONMENT,
        "scope": SCOPE,
        "request_sha256": sha256(canonical_json(request)),
        "request_id": request["request_id"],
        "nonce_b64url": request["nonce_b64url"],
        "ledger": copy_object(request["ledger"]),
        "authorization": copy_object(request["authorization"]),
        "transaction": copy_object(request["transaction"]),
        "station": copy_object(request["station"]),
        "authority_key_id": authority_key_id,
        "observed_at": observed_at,
        "expires_at": expires_at,
        "result": RECEIPT_RESULT,
        "signature_algorithm": "Ed25519",
    }
    validate_receipt(receipt, signed=False)
    return receipt


def copy_object(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items()}


def validate_receipt(value: dict[str, Any], *, signed: bool) -> None:
    members = {
        "schema",
        "environment",
        "scope",
        "request_sha256",
        "request_id",
        "nonce_b64url",
        "ledger",
        "authorization",
        "transaction",
        "station",
        "authority_key_id",
        "observed_at",
        "expires_at",
        "result",
        "signature_algorithm",
    }
    if signed:
        members.add("signature_b64url")
    root = _exact(value, members, "trusted-time receipt")
    if (
        root["schema"] != RECEIPT_SCHEMA
        or root["environment"] != ENVIRONMENT
        or root["scope"] != SCOPE
        or root["result"] != RECEIPT_RESULT
        or root["signature_algorithm"] != "Ed25519"
    ):
        raise TrustedTimeError("trusted-time receipt constants differ")
    _digest(root["request_sha256"], "trusted-time request hash")
    _identifier(root["request_id"], "trusted-time request ID")
    _identifier(root["authority_key_id"], "trusted-time authority key ID")
    if not isinstance(root["nonce_b64url"], str) or NONCE.fullmatch(root["nonce_b64url"]) is None:
        raise TrustedTimeError("trusted-time receipt nonce is invalid")
    _validate_subject(root)
    observed = _timestamp(root["observed_at"], "trusted-time observation")
    expires = _timestamp(root["expires_at"], "trusted-time expiry")
    if not observed < expires <= observed + timedelta(seconds=MAX_RECEIPT_LIFETIME_SECONDS):
        raise TrustedTimeError("trusted-time receipt lifetime exceeds ten seconds")
    plan_issued = _timestamp(root["authorization"]["issued_at"], "plan issue")
    plan_expires = _timestamp(root["authorization"]["expires_at"], "plan expiry")
    if not plan_issued <= observed <= plan_expires:
        raise TrustedTimeError("trusted-time observation is outside plan window")
    if signed and (
        not isinstance(root["signature_b64url"], str)
        or SIGNATURE.fullmatch(root["signature_b64url"]) is None
    ):
        raise TrustedTimeError("trusted-time signature is invalid")


def parse_receipt(data: bytes) -> dict[str, Any]:
    value = _parse_json(data, "trusted-time receipt")
    if canonical_json(value) != data:
        raise TrustedTimeError("trusted-time receipt is not canonical JSON")
    validate_receipt(value, signed=True)
    return value


def verify_receipt(
    *,
    receipt: dict[str, Any],
    request: dict[str, Any],
    public_key_data: bytes,
    expected_authority_key_id: str,
) -> None:
    validate_request(request)
    validate_receipt(receipt, signed=True)
    expected_subject = {
        "request_sha256": sha256(canonical_json(request)),
        "request_id": request["request_id"],
        "nonce_b64url": request["nonce_b64url"],
        "ledger": request["ledger"],
        "authorization": request["authorization"],
        "transaction": request["transaction"],
        "station": request["station"],
    }
    for name, expected in expected_subject.items():
        if receipt[name] != expected:
            raise TrustedTimeError("trusted-time receipt request binding differs")
    if receipt["authority_key_id"] != expected_authority_key_id:
        raise TrustedTimeError("trusted-time authority key ID differs")
    unsigned = dict(receipt)
    encoded = unsigned.pop("signature_b64url")
    try:
        signature = base64.urlsafe_b64decode(encoded + "==")
    except (ValueError, binascii.Error) as error:
        raise TrustedTimeError("trusted-time signature encoding is invalid") from error
    if len(signature) != 64:
        raise TrustedTimeError("trusted-time signature length is invalid")
    try:
        _public_key(public_key_data).verify(
            signature, SIGNATURE_DOMAIN + canonical_json(unsigned)
        )
    except InvalidSignature as error:
        raise TrustedTimeError("trusted-time signature verification failed") from error


def fetch_receipt(
    *,
    endpoint: str,
    request_data: bytes,
    ca_certificate: Path,
    client_certificate: Path,
    client_private_key: Path,
    timeout_ms: int = TIMEOUT_MS,
    maximum_response_bytes: int = MAX_RESPONSE_BYTES,
) -> tuple[bytes, int]:
    validate_endpoint(endpoint)
    if timeout_ms != TIMEOUT_MS or maximum_response_bytes != MAX_RESPONSE_BYTES:
        raise TrustedTimeError("trusted-time transport bounds differ")
    parsed = urllib.parse.urlsplit(endpoint)
    context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH, cafile=str(ca_certificate)
    )
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = True
    try:
        context.load_cert_chain(
            certfile=str(client_certificate), keyfile=str(client_private_key)
        )
    except (OSError, ssl.SSLError) as error:
        raise TrustedTimeError("trusted-time mTLS client material is invalid") from error
    started = time.monotonic_ns()
    connection = http.client.HTTPSConnection(
        parsed.hostname,
        port=parsed.port or 443,
        timeout=timeout_ms / 1000,
        context=context,
    )
    try:
        connection.request(
            "POST",
            ENDPOINT_PATH,
            body=request_data,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Content-Length": str(len(request_data)),
                "Cache-Control": "no-store",
            },
        )
        response = connection.getresponse()
        if response.status != 200:
            raise TrustedTimeError("trusted-time endpoint rejected request")
        if response.getheader("Content-Type") != "application/json":
            raise TrustedTimeError("trusted-time response content type differs")
        if (
            response.getheader("Transfer-Encoding") is not None
            or response.getheader("Content-Encoding") is not None
            or response.getheader("Location") is not None
            or response.getheader("Cache-Control") != "no-store"
        ):
            raise TrustedTimeError("trusted-time response transport headers differ")
        raw_length = response.getheader("Content-Length")
        try:
            length = int(raw_length) if raw_length is not None else -1
        except ValueError as error:
            raise TrustedTimeError("trusted-time content length is invalid") from error
        if not 1 <= length <= maximum_response_bytes:
            raise TrustedTimeError("trusted-time response length is outside bounds")
        data = response.read(maximum_response_bytes + 1)
        if len(data) != length or len(data) > maximum_response_bytes:
            raise TrustedTimeError("trusted-time response body length differs")
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        raise TrustedTimeError("trusted-time HTTPS request failed") from error
    finally:
        connection.close()
    elapsed_ms = (time.monotonic_ns() - started + 999_999) // 1_000_000
    if elapsed_ms < 0 or elapsed_ms > timeout_ms:
        raise TrustedTimeError("trusted-time HTTPS round trip exceeded five seconds")
    return data, elapsed_ms
