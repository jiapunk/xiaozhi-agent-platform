#!/usr/bin/env python3
"""M59 local, durable, non-executing sacrificial-attempt consumption ledger."""

from __future__ import annotations

import base64
import binascii
import copy
import errno
import hashlib
import json
import os
import re
import secrets
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

try:
    import sacrificial_provisioning_plan as plan_contract
except ModuleNotFoundError:  # Package import in host tests.
    from . import sacrificial_provisioning_plan as plan_contract
try:
    import sacrificial_trusted_time as time_contract
except ModuleNotFoundError:  # Package import in host tests.
    from . import sacrificial_trusted_time as time_contract


POLICY_SCHEMA = "xz-sacrificial-attempt-ledger-policy-v2"
RECORD_SCHEMA = "xz-sacrificial-attempt-consumption-v2"
ENVIRONMENT = "SACRIFICIAL_HARDWARE_AUTHORIZATION"
SCOPE = "ONE_UNIT_ONE_ATTEMPT_DESTRUCTIVE_QUALIFICATION"
POLICY_RESULT = "SACRIFICIAL_ATTEMPT_LEDGER_POLICY"
RECORD_RESULT = "SACRIFICIAL_ATTEMPT_CONSUMED"
POLICY_SIGNATURE_DOMAIN = b"xz-sacrificial-attempt-ledger-policy-v2\x00"
POLICY_FILE = "ledger-policy.json"
CLAIMS_DIRECTORY = "claims"
ROOT_MODE = 0o700
CLAIMS_MODE = 0o700
POLICY_MODE = 0o400
RECORD_MODE = 0o400
MAX_POLICY_BYTES = 128 * 1024
MAX_RECORD_BYTES = 256 * 1024
MAX_PUBLIC_KEY_BYTES = 16 * 1024
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")
FINAL_RECORD_NAME = re.compile(r"^[0-9a-f]{64}\.json$")
TEMPORARY_RECORD_NAME = re.compile(r"^\.claim-[0-9a-f]{32}\.tmp$")


class AttemptLedgerError(ValueError):
    pass


class AttemptAlreadyConsumed(AttemptLedgerError):
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
            raise AttemptLedgerError(f"duplicate JSON member: {key}")
        value[key] = item
    return value


def _parse_json(data: bytes, label: str, maximum: int) -> dict[str, Any]:
    if not data or len(data) > maximum:
        raise AttemptLedgerError(f"{label} is empty or too large")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AttemptLedgerError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise AttemptLedgerError(f"{label} must be an object")
    return value


def _exact(value: Any, members: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != members:
        raise AttemptLedgerError(f"{label} members differ")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or plan_contract.IDENTIFIER.fullmatch(value) is None:
        raise AttemptLedgerError(f"{label} is invalid")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_HEX.fullmatch(value) is None:
        raise AttemptLedgerError(f"{label} must be a lowercase SHA-256")
    return value


def _integer(value: Any, minimum: int, maximum: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise AttemptLedgerError(f"{label} is outside bounds")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or TIMESTAMP.fullmatch(value) is None:
        raise AttemptLedgerError(f"{label} must be whole-second UTC")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise AttemptLedgerError(f"{label} is invalid") from error
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise AttemptLedgerError(f"{label} is not canonical")
    return parsed


def _mode(info: os.stat_result) -> int:
    return stat.S_IMODE(info.st_mode)


def _open_directory(path: Path) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise AttemptLedgerError("ledger root is unavailable or unsafe") from error
    info = os.fstat(descriptor)
    if not stat.S_ISDIR(info.st_mode):
        os.close(descriptor)
        raise AttemptLedgerError("ledger root is not a directory")
    return descriptor, info


def _open_child_directory(parent: int, name: str) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent)
    except OSError as error:
        raise AttemptLedgerError(f"ledger {name} directory is unavailable or unsafe") from error
    info = os.fstat(descriptor)
    if not stat.S_ISDIR(info.st_mode):
        os.close(descriptor)
        raise AttemptLedgerError(f"ledger {name} is not a directory")
    return descriptor, info


def _read_regular_at(
    parent: int, name: str, maximum: int, required_mode: int, label: str
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent)
    except OSError as error:
        raise AttemptLedgerError(f"{label} is unavailable or unsafe") from error
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_size < 1
            or info.st_size > maximum
            or _mode(info) != required_mode
        ):
            raise AttemptLedgerError(f"{label} type, size or mode differs")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > maximum:
            raise AttemptLedgerError(f"{label} is too large")
        return data
    finally:
        os.close(descriptor)


def _write_synced_exclusive_at(
    parent: int, name: str, payload: bytes, mode: int
) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, 0o600, dir_fd=parent)
    remove = True
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        remove = False
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if remove:
            try:
                os.unlink(name, dir_fd=parent)
            except FileNotFoundError:
                pass


def initialize_root(root: Path) -> os.stat_result:
    absolute = Path(os.path.abspath(root))
    parent = absolute.parent
    if absolute.name in ("", ".", ".."):
        raise AttemptLedgerError("ledger root name is invalid")
    parent_descriptor, _ = _open_directory(parent)
    try:
        try:
            os.mkdir(absolute.name, ROOT_MODE, dir_fd=parent_descriptor)
        except FileExistsError as error:
            raise AttemptLedgerError("ledger root already exists") from error
        root_descriptor = -1
        try:
            root_descriptor, info = _open_child_directory(
                parent_descriptor, absolute.name
            )
            if _mode(info) != ROOT_MODE:
                raise AttemptLedgerError("ledger root mode differs")
            os.mkdir(CLAIMS_DIRECTORY, CLAIMS_MODE, dir_fd=root_descriptor)
            os.fsync(root_descriptor)
            os.fsync(parent_descriptor)
            return info
        except Exception:
            # Fail closed. An incomplete root is retained for explicit operator
            # disposition instead of being recursively deleted by this tool.
            raise
        finally:
            if root_descriptor >= 0:
                os.close(root_descriptor)
    finally:
        os.close(parent_descriptor)


def build_policy_request(
    *,
    policy_id: str,
    ledger_id: str,
    station_id: str,
    fixture_id: str,
    fixture_version: str,
    authorization_key_id: str,
    trusted_time_endpoint: str,
    trusted_time_authority_key_id: str,
    trusted_time_authority_public_key_sha256: str,
    trusted_time_ca_certificate_sha256: str,
    trusted_time_client_certificate_sha256: str,
    filesystem_device: int,
    directory_inode: int,
    created_at: str,
    expires_at: str,
) -> dict[str, Any]:
    request = {
        "schema": POLICY_SCHEMA,
        "environment": ENVIRONMENT,
        "policy_id": policy_id,
        "ledger_id": ledger_id,
        "station": {
            "id": station_id,
            "fixture_id": fixture_id,
            "fixture_version": fixture_version,
        },
        "authorization_key_id": authorization_key_id,
        "trusted_time": {
            "endpoint": trusted_time_endpoint,
            "authority_key_id": trusted_time_authority_key_id,
            "authority_public_key_sha256": trusted_time_authority_public_key_sha256,
            "ca_certificate_sha256": trusted_time_ca_certificate_sha256,
            "client_certificate_sha256": trusted_time_client_certificate_sha256,
            "timeout_ms": time_contract.TIMEOUT_MS,
            "maximum_response_bytes": time_contract.MAX_RESPONSE_BYTES,
            "tls_minimum_version": "1.3",
            "mtls_required": True,
            "redirects_allowed": False,
            "proxies_allowed": False,
        },
        "storage": {
            "kind": "LOCAL_DURABLE_SINGLE_STATION",
            "filesystem_device": filesystem_device,
            "directory_inode": directory_inode,
            "claims_directory": CLAIMS_DIRECTORY,
            "root_mode": "0700",
            "record_mode": "0400",
            "multi_station_supported": False,
        },
        "safety": {
            "executor_included": False,
            "executor_invoked": False,
            "hardware_touched": False,
            "production_inventory_eligible": False,
            "deletion_api_included": False,
            "failure_disposition": "QUARANTINE_OR_DESTROY",
        },
        "created_at": created_at,
        "expires_at": expires_at,
        "result": POLICY_RESULT,
        "signature_algorithm": "Ed25519",
    }
    validate_policy(request, signed=False)
    return request


def validate_policy(value: dict[str, Any], *, signed: bool) -> None:
    members = {
        "schema",
        "environment",
        "policy_id",
        "ledger_id",
        "station",
        "authorization_key_id",
        "trusted_time",
        "storage",
        "safety",
        "created_at",
        "expires_at",
        "result",
        "signature_algorithm",
    }
    if signed:
        members.add("signature_b64url")
    root = _exact(value, members, "ledger policy")
    if (
        root["schema"] != POLICY_SCHEMA
        or root["environment"] != ENVIRONMENT
        or root["result"] != POLICY_RESULT
        or root["signature_algorithm"] != "Ed25519"
    ):
        raise AttemptLedgerError("ledger policy frozen constants differ")
    _identifier(root["policy_id"], "policy ID")
    _identifier(root["ledger_id"], "ledger ID")
    _identifier(root["authorization_key_id"], "authorization key ID")
    if signed and (
        not isinstance(root["signature_b64url"], str)
        or SIGNATURE.fullmatch(root["signature_b64url"]) is None
    ):
        raise AttemptLedgerError("ledger policy signature is invalid")

    station = _exact(
        root["station"], {"id", "fixture_id", "fixture_version"}, "ledger station"
    )
    for name in ("id", "fixture_id", "fixture_version"):
        _identifier(station[name], f"ledger station {name}")

    trusted_time = _exact(
        root["trusted_time"],
        {
            "endpoint",
            "authority_key_id",
            "authority_public_key_sha256",
            "ca_certificate_sha256",
            "client_certificate_sha256",
            "timeout_ms",
            "maximum_response_bytes",
            "tls_minimum_version",
            "mtls_required",
            "redirects_allowed",
            "proxies_allowed",
        },
        "ledger trusted-time policy",
    )
    try:
        time_contract.validate_endpoint(trusted_time["endpoint"])
    except time_contract.TrustedTimeError as error:
        raise AttemptLedgerError(f"ledger trusted-time endpoint rejected: {error}") from error
    _identifier(trusted_time["authority_key_id"], "trusted-time authority key ID")
    for name in (
        "authority_public_key_sha256",
        "ca_certificate_sha256",
        "client_certificate_sha256",
    ):
        _digest(trusted_time[name], f"trusted-time {name}")
    if trusted_time != {
        "endpoint": trusted_time["endpoint"],
        "authority_key_id": trusted_time["authority_key_id"],
        "authority_public_key_sha256": trusted_time[
            "authority_public_key_sha256"
        ],
        "ca_certificate_sha256": trusted_time["ca_certificate_sha256"],
        "client_certificate_sha256": trusted_time[
            "client_certificate_sha256"
        ],
        "timeout_ms": time_contract.TIMEOUT_MS,
        "maximum_response_bytes": time_contract.MAX_RESPONSE_BYTES,
        "tls_minimum_version": "1.3",
        "mtls_required": True,
        "redirects_allowed": False,
        "proxies_allowed": False,
    }:
        raise AttemptLedgerError("ledger trusted-time transport boundary differs")

    storage = _exact(
        root["storage"],
        {
            "kind",
            "filesystem_device",
            "directory_inode",
            "claims_directory",
            "root_mode",
            "record_mode",
            "multi_station_supported",
        },
        "ledger storage",
    )
    expected_storage = {
        "kind": "LOCAL_DURABLE_SINGLE_STATION",
        "filesystem_device": storage["filesystem_device"],
        "directory_inode": storage["directory_inode"],
        "claims_directory": CLAIMS_DIRECTORY,
        "root_mode": "0700",
        "record_mode": "0400",
        "multi_station_supported": False,
    }
    if storage != expected_storage:
        raise AttemptLedgerError("ledger storage boundary differs")
    _integer(storage["filesystem_device"], 0, (1 << 63) - 1, "filesystem device")
    _integer(storage["directory_inode"], 1, (1 << 64) - 1, "directory inode")

    safety = _exact(
        root["safety"],
        {
            "executor_included",
            "executor_invoked",
            "hardware_touched",
            "production_inventory_eligible",
            "deletion_api_included",
            "failure_disposition",
        },
        "ledger safety",
    )
    if safety != {
        "executor_included": False,
        "executor_invoked": False,
        "hardware_touched": False,
        "production_inventory_eligible": False,
        "deletion_api_included": False,
        "failure_disposition": "QUARANTINE_OR_DESTROY",
    }:
        raise AttemptLedgerError("ledger safety boundary differs")
    created = _timestamp(root["created_at"], "policy creation time")
    expires = _timestamp(root["expires_at"], "policy expiry time")
    if not created < expires <= created + timedelta(days=30):
        raise AttemptLedgerError("ledger policy lifetime exceeds thirty days")


def parse_policy(data: bytes, *, signed: bool) -> dict[str, Any]:
    value = _parse_json(data, "ledger policy", MAX_POLICY_BYTES)
    if canonical_json(value) != data:
        raise AttemptLedgerError("ledger policy is not canonical JSON")
    validate_policy(value, signed=signed)
    return value


def _public_key(data: bytes) -> Ed25519PublicKey:
    if not data or len(data) > MAX_PUBLIC_KEY_BYTES or b"PRIVATE KEY" in data:
        raise AttemptLedgerError("ledger authorization public key input is invalid")
    try:
        key = serialization.load_pem_public_key(data)
    except (TypeError, ValueError) as error:
        raise AttemptLedgerError("ledger authorization public key is invalid") from error
    if not isinstance(key, Ed25519PublicKey):
        raise AttemptLedgerError("ledger authorization public key must be Ed25519")
    return key


def verify_policy(receipt: dict[str, Any], public_key_data: bytes) -> None:
    validate_policy(receipt, signed=True)
    unsigned = dict(receipt)
    encoded = unsigned.pop("signature_b64url")
    try:
        signature = base64.urlsafe_b64decode(encoded + "==")
    except (ValueError, binascii.Error) as error:
        raise AttemptLedgerError("ledger policy signature encoding is invalid") from error
    if len(signature) != 64:
        raise AttemptLedgerError("ledger policy signature length is invalid")
    try:
        _public_key(public_key_data).verify(
            signature, POLICY_SIGNATURE_DOMAIN + canonical_json(unsigned)
        )
    except InvalidSignature as error:
        raise AttemptLedgerError("ledger policy signature verification failed") from error


def require_policy_active(policy: dict[str, Any], verification_time: str) -> None:
    now = _timestamp(verification_time, "verification time")
    created = _timestamp(policy["created_at"], "policy creation time")
    expires = _timestamp(policy["expires_at"], "policy expiry time")
    if not created <= now <= expires:
        raise AttemptLedgerError("sacrificial attempt ledger policy is not active")


def _verify_root_state(
    root: Path, policy: dict[str, Any], *, policy_required: bool
) -> tuple[int, int]:
    root_descriptor, root_info = _open_directory(Path(os.path.abspath(root)))
    try:
        if _mode(root_info) != ROOT_MODE:
            raise AttemptLedgerError("ledger root mode differs")
        storage = policy["storage"]
        if (
            root_info.st_dev != storage["filesystem_device"]
            or root_info.st_ino != storage["directory_inode"]
        ):
            raise AttemptLedgerError("ledger root filesystem identity differs")
        expected = {CLAIMS_DIRECTORY, POLICY_FILE} if policy_required else {CLAIMS_DIRECTORY}
        if set(os.listdir(root_descriptor)) != expected:
            raise AttemptLedgerError("ledger root file set differs")
        claims_descriptor, claims_info = _open_child_directory(
            root_descriptor, CLAIMS_DIRECTORY
        )
        if _mode(claims_info) != CLAIMS_MODE:
            os.close(claims_descriptor)
            raise AttemptLedgerError("ledger claims directory mode differs")
        for name in os.listdir(claims_descriptor):
            is_final = FINAL_RECORD_NAME.fullmatch(name) is not None
            is_temporary = TEMPORARY_RECORD_NAME.fullmatch(name) is not None
            if not is_final and not is_temporary:
                os.close(claims_descriptor)
                raise AttemptLedgerError("ledger claims file set contains an unknown name")
            try:
                entry = os.stat(name, dir_fd=claims_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                if is_temporary:
                    # A concurrent successful publisher may remove its completed
                    # temporary hard-link name after listdir. The final name is
                    # still checked by the exclusive publication operation.
                    continue
                os.close(claims_descriptor)
                raise AttemptLedgerError("ledger final claim disappeared")
            except OSError as error:
                os.close(claims_descriptor)
                raise AttemptLedgerError("ledger claim is unavailable") from error
            entry_mode = _mode(entry)
            if not stat.S_ISREG(entry.st_mode) or (
                is_final and entry_mode != RECORD_MODE
            ) or (
                is_temporary and entry_mode not in (0o600, RECORD_MODE)
            ):
                os.close(claims_descriptor)
                raise AttemptLedgerError("ledger claim type or mode differs")
        return root_descriptor, claims_descriptor
    except Exception:
        os.close(root_descriptor)
        raise


def publish_policy(
    root: Path, signed_policy_data: bytes, public_key_data: bytes
) -> dict[str, Any]:
    policy = parse_policy(signed_policy_data, signed=True)
    verify_policy(policy, public_key_data)
    root_descriptor, claims_descriptor = _verify_root_state(
        root, policy, policy_required=False
    )
    try:
        if os.listdir(claims_descriptor):
            raise AttemptLedgerError("new ledger claims directory is not empty")
        _write_synced_exclusive_at(
            root_descriptor, POLICY_FILE, signed_policy_data, POLICY_MODE
        )
        os.fsync(root_descriptor)
    finally:
        os.close(claims_descriptor)
        os.close(root_descriptor)
    return policy


def load_policy(root: Path, public_key_data: bytes) -> tuple[dict[str, Any], bytes]:
    root_descriptor, _ = _open_directory(Path(os.path.abspath(root)))
    try:
        data = _read_regular_at(
            root_descriptor, POLICY_FILE, MAX_POLICY_BYTES, POLICY_MODE, "ledger policy"
        )
    finally:
        os.close(root_descriptor)
    policy = parse_policy(data, signed=True)
    verify_policy(policy, public_key_data)
    return policy, data


def attempt_key(attempt_id: str) -> str:
    _identifier(attempt_id, "attempt ID")
    return sha256(("xz-sacrificial-attempt-v1\x00" + attempt_id).encode("ascii"))


def build_consumption_record(
    *,
    policy: dict[str, Any],
    policy_data: bytes,
    plan: dict[str, Any],
    plan_data: bytes,
    trusted_time_receipt: dict[str, Any],
    https_round_trip_ms: int,
) -> dict[str, Any]:
    transaction = plan["transaction"]
    station = plan["station"]
    record = {
        "schema": RECORD_SCHEMA,
        "environment": ENVIRONMENT,
        "scope": SCOPE,
        "attempt_key_sha256": attempt_key(transaction["attempt_id"]),
        "ledger": {
            "policy_sha256": sha256(policy_data),
            "policy_id": policy["policy_id"],
            "ledger_id": policy["ledger_id"],
            "filesystem_device": policy["storage"]["filesystem_device"],
            "directory_inode": policy["storage"]["directory_inode"],
        },
        "authorization": {
            "plan_sha256": sha256(plan_data),
            "plan_id": plan["plan_id"],
            "authorization_key_id": plan["authorization"]["key_id"],
            "issued_at": plan["authorization"]["issued_at"],
            "expires_at": plan["authorization"]["expires_at"],
        },
        "transaction": copy.deepcopy(transaction),
        "release": copy.deepcopy(plan["release"]),
        "station": {
            "id": station["id"],
            "operators": list(station["operators"]),
            "fixture_id": station["fixture_id"],
            "fixture_version": station["fixture_version"],
        },
        "trusted_time": {
            "receipt": copy.deepcopy(trusted_time_receipt),
            "https_round_trip_ms": https_round_trip_ms,
        },
        "consumed_at": trusted_time_receipt["observed_at"],
        "safety": {
            "one_time_handoff": True,
            "reusable": False,
            "executor_included": False,
            "executor_invoked": False,
            "hardware_touched": False,
            "production_inventory_eligible": False,
            "deletion_api_included": False,
            "failure_disposition": "QUARANTINE_OR_DESTROY",
        },
        "result": RECORD_RESULT,
    }
    validate_record(record)
    return record


def validate_record(value: dict[str, Any]) -> None:
    root = _exact(
        value,
        {
            "schema",
            "environment",
            "scope",
            "attempt_key_sha256",
            "ledger",
            "authorization",
            "transaction",
            "release",
            "station",
            "trusted_time",
            "consumed_at",
            "safety",
            "result",
        },
        "attempt consumption record",
    )
    if (
        root["schema"] != RECORD_SCHEMA
        or root["environment"] != ENVIRONMENT
        or root["scope"] != SCOPE
        or root["result"] != RECORD_RESULT
    ):
        raise AttemptLedgerError("attempt record frozen constants differ")
    _digest(root["attempt_key_sha256"], "attempt key")
    ledger = _exact(
        root["ledger"],
        {
            "policy_sha256",
            "policy_id",
            "ledger_id",
            "filesystem_device",
            "directory_inode",
        },
        "attempt ledger binding",
    )
    _digest(ledger["policy_sha256"], "ledger policy hash")
    _identifier(ledger["policy_id"], "ledger policy ID")
    _identifier(ledger["ledger_id"], "ledger ID")
    _integer(ledger["filesystem_device"], 0, (1 << 63) - 1, "filesystem device")
    _integer(ledger["directory_inode"], 1, (1 << 64) - 1, "directory inode")

    authorization = _exact(
        root["authorization"],
        {
            "plan_sha256",
            "plan_id",
            "authorization_key_id",
            "issued_at",
            "expires_at",
        },
        "attempt authorization binding",
    )
    _digest(authorization["plan_sha256"], "plan hash")
    _identifier(authorization["plan_id"], "plan ID")
    _identifier(authorization["authorization_key_id"], "authorization key ID")
    issued = _timestamp(authorization["issued_at"], "plan issue time")
    expires = _timestamp(authorization["expires_at"], "plan expiry time")
    consumed = _timestamp(root["consumed_at"], "attempt consumption time")
    if not issued <= consumed <= expires:
        raise AttemptLedgerError("attempt was not consumed while authorization was active")

    transaction = _exact(
        root["transaction"],
        {"transaction_id", "attempt_id", "device_id", "serial_number", "base_mac"},
        "attempt transaction",
    )
    for name in ("transaction_id", "attempt_id", "serial_number"):
        _identifier(transaction[name], name)
    if (
        not isinstance(transaction["device_id"], str)
        or plan_contract.DEVICE_ID.fullmatch(transaction["device_id"]) is None
        or not isinstance(transaction["base_mac"], str)
        or plan_contract.MAC_ADDRESS.fullmatch(transaction["base_mac"]) is None
    ):
        raise AttemptLedgerError("attempt device or base MAC is invalid")
    if transaction["device_id"] != "xz-" + transaction["base_mac"].replace(
        ":", ""
    ).lower():
        raise AttemptLedgerError("attempt device ID does not derive from base MAC")
    if root["attempt_key_sha256"] != attempt_key(transaction["attempt_id"]):
        raise AttemptLedgerError("attempt key does not derive from attempt ID")

    if not isinstance(root["release"], dict):
        raise AttemptLedgerError("attempt release binding must be an object")
    station = _exact(
        root["station"],
        {"id", "operators", "fixture_id", "fixture_version"},
        "attempt station",
    )
    for name in ("id", "fixture_id", "fixture_version"):
        _identifier(station[name], f"attempt station {name}")
    operators = station["operators"]
    if (
        not isinstance(operators, list)
        or not 2 <= len(operators) <= 4
        or len(set(operators)) != len(operators)
    ):
        raise AttemptLedgerError("attempt operators differ")
    for operator in operators:
        _identifier(operator, "attempt operator")

    trusted_time = _exact(
        root["trusted_time"],
        {"receipt", "https_round_trip_ms"},
        "attempt trusted time",
    )
    try:
        time_contract.validate_receipt(trusted_time["receipt"], signed=True)
    except time_contract.TrustedTimeError as error:
        raise AttemptLedgerError(f"trusted-time receipt rejected: {error}") from error
    _integer(
        trusted_time["https_round_trip_ms"],
        0,
        time_contract.TIMEOUT_MS,
        "trusted-time HTTPS round trip",
    )
    if root["consumed_at"] != trusted_time["receipt"]["observed_at"]:
        raise AttemptLedgerError("attempt consumption time differs from trusted time")

    safety = _exact(
        root["safety"],
        {
            "one_time_handoff",
            "reusable",
            "executor_included",
            "executor_invoked",
            "hardware_touched",
            "production_inventory_eligible",
            "deletion_api_included",
            "failure_disposition",
        },
        "attempt safety",
    )
    if safety != {
        "one_time_handoff": True,
        "reusable": False,
        "executor_included": False,
        "executor_invoked": False,
        "hardware_touched": False,
        "production_inventory_eligible": False,
        "deletion_api_included": False,
        "failure_disposition": "QUARANTINE_OR_DESTROY",
    }:
        raise AttemptLedgerError("attempt record safety boundary differs")


def parse_record(data: bytes) -> dict[str, Any]:
    value = _parse_json(data, "attempt consumption record", MAX_RECORD_BYTES)
    if canonical_json(value) != data:
        raise AttemptLedgerError("attempt consumption record is not canonical JSON")
    validate_record(value)
    return value


def _validate_bindings(policy: dict[str, Any], plan: dict[str, Any]) -> None:
    station = policy["station"]
    plan_station = plan["station"]
    if (
        station["id"] != plan_station["id"]
        or station["fixture_id"] != plan_station["fixture_id"]
        or station["fixture_version"] != plan_station["fixture_version"]
        or policy["authorization_key_id"] != plan["authorization"]["key_id"]
    ):
        raise AttemptLedgerError("ledger policy does not bind the plan station")


def _load_verified_inputs(
    *,
    root: Path,
    plan_data: bytes,
    authorization_public_key: bytes,
    signing_request_data: bytes,
    signed_artifact_data: bytes,
) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    policy, policy_data = load_policy(root, authorization_public_key)
    try:
        plan = plan_contract.parse_canonical(plan_data, signed=True)
        plan_contract.verify_receipt(plan, authorization_public_key)
        plan_contract.bind_release(plan, signing_request_data, signed_artifact_data)
    except plan_contract.SacrificialPlanError as error:
        raise AttemptLedgerError(f"sacrificial plan rejected: {error}") from error
    _validate_bindings(policy, plan)
    return policy, policy_data, plan


def _publish_record(claims_descriptor: int, final_name: str, payload: bytes) -> None:
    temporary_name = f".claim-{secrets.token_hex(16)}.tmp"
    _write_synced_exclusive_at(
        claims_descriptor, temporary_name, payload, RECORD_MODE
    )
    linked = False
    try:
        try:
            os.link(
                temporary_name,
                final_name,
                src_dir_fd=claims_descriptor,
                dst_dir_fd=claims_descriptor,
                follow_symlinks=False,
            )
            linked = True
        except FileExistsError as error:
            raise AttemptAlreadyConsumed("sacrificial attempt is already consumed") from error
        os.fsync(claims_descriptor)
    finally:
        try:
            os.unlink(temporary_name, dir_fd=claims_descriptor)
            os.fsync(claims_descriptor)
        except FileNotFoundError:
            pass
        if not linked:
            # The exclusive final name was not published. No executor is called
            # by this library, so retry remains safe after the orphan is removed.
            pass


def _trusted_time_request_for_receipt(
    *,
    policy: dict[str, Any],
    policy_data: bytes,
    plan: dict[str, Any],
    plan_data: bytes,
    receipt: dict[str, Any],
) -> dict[str, Any]:
    try:
        nonce = base64.urlsafe_b64decode(receipt["nonce_b64url"] + "=")
        return time_contract.build_request(
            policy=policy,
            policy_data=policy_data,
            plan=plan,
            plan_data=plan_data,
            request_id=receipt["request_id"],
            nonce=nonce,
        )
    except (KeyError, ValueError, time_contract.TrustedTimeError) as error:
        raise AttemptLedgerError(f"trusted-time request rejected: {error}") from error


def _verify_trusted_time(
    *,
    policy: dict[str, Any],
    policy_data: bytes,
    plan: dict[str, Any],
    plan_data: bytes,
    receipt: dict[str, Any],
    trusted_time_public_key: bytes,
) -> None:
    trusted_policy = policy["trusted_time"]
    try:
        if (
            time_contract.public_key_sha256(trusted_time_public_key)
            != trusted_policy["authority_public_key_sha256"]
        ):
            raise AttemptLedgerError("trusted-time public key fingerprint differs")
        request = _trusted_time_request_for_receipt(
            policy=policy,
            policy_data=policy_data,
            plan=plan,
            plan_data=plan_data,
            receipt=receipt,
        )
        time_contract.verify_receipt(
            receipt=receipt,
            request=request,
            public_key_data=trusted_time_public_key,
            expected_authority_key_id=trusted_policy["authority_key_id"],
        )
    except time_contract.TrustedTimeError as error:
        raise AttemptLedgerError(f"trusted-time receipt rejected: {error}") from error
    observed_at = receipt["observed_at"]
    require_policy_active(policy, observed_at)
    try:
        plan_contract.require_active(plan, observed_at)
    except plan_contract.SacrificialPlanError as error:
        raise AttemptLedgerError(f"sacrificial plan rejected: {error}") from error


def _consume_loaded(
    *,
    root: Path,
    policy: dict[str, Any],
    policy_data: bytes,
    plan: dict[str, Any],
    plan_data: bytes,
    trusted_time_receipt: dict[str, Any],
    https_round_trip_ms: int,
) -> tuple[dict[str, Any], Path]:
    record = build_consumption_record(
        policy=policy,
        policy_data=policy_data,
        plan=plan,
        plan_data=plan_data,
        trusted_time_receipt=trusted_time_receipt,
        https_round_trip_ms=https_round_trip_ms,
    )
    payload = canonical_json(record)
    root_descriptor, claims_descriptor = _verify_root_state(
        root, policy, policy_required=True
    )
    try:
        final_name = record["attempt_key_sha256"] + ".json"
        _publish_record(claims_descriptor, final_name, payload)
    finally:
        os.close(claims_descriptor)
        os.close(root_descriptor)
    return record, Path(os.path.abspath(root)) / CLAIMS_DIRECTORY / final_name


def _consume_attempt_with_receipt_for_test(
    *,
    root: Path,
    plan_data: bytes,
    authorization_public_key: bytes,
    signing_request_data: bytes,
    signed_artifact_data: bytes,
    trusted_time_receipt_data: bytes,
    trusted_time_public_key: bytes,
    https_round_trip_ms: int,
) -> tuple[dict[str, Any], Path]:
    policy, policy_data, plan = _load_verified_inputs(
        root=root,
        plan_data=plan_data,
        authorization_public_key=authorization_public_key,
        signing_request_data=signing_request_data,
        signed_artifact_data=signed_artifact_data,
    )
    try:
        receipt = time_contract.parse_receipt(trusted_time_receipt_data)
    except time_contract.TrustedTimeError as error:
        raise AttemptLedgerError(f"trusted-time receipt rejected: {error}") from error
    _verify_trusted_time(
        policy=policy,
        policy_data=policy_data,
        plan=plan,
        plan_data=plan_data,
        receipt=receipt,
        trusted_time_public_key=trusted_time_public_key,
    )
    return _consume_loaded(
        root=root,
        policy=policy,
        policy_data=policy_data,
        plan=plan,
        plan_data=plan_data,
        trusted_time_receipt=receipt,
        https_round_trip_ms=https_round_trip_ms,
    )


def consume_attempt_online(
    *,
    root: Path,
    plan_data: bytes,
    authorization_public_key: bytes,
    signing_request_data: bytes,
    signed_artifact_data: bytes,
    trusted_time_public_key: bytes,
    ca_certificate: Path,
    ca_certificate_data: bytes,
    client_certificate: Path,
    client_certificate_data: bytes,
    client_private_key: Path,
) -> tuple[dict[str, Any], Path]:
    policy, policy_data, plan = _load_verified_inputs(
        root=root,
        plan_data=plan_data,
        authorization_public_key=authorization_public_key,
        signing_request_data=signing_request_data,
        signed_artifact_data=signed_artifact_data,
    )
    trusted_policy = policy["trusted_time"]
    try:
        key_fingerprint = time_contract.public_key_sha256(trusted_time_public_key)
    except time_contract.TrustedTimeError as error:
        raise AttemptLedgerError(f"trusted-time key rejected: {error}") from error
    if (
        key_fingerprint != trusted_policy["authority_public_key_sha256"]
        or sha256(ca_certificate_data) != trusted_policy["ca_certificate_sha256"]
        or sha256(client_certificate_data)
        != trusted_policy["client_certificate_sha256"]
    ):
        raise AttemptLedgerError("trusted-time TLS or signing material differs from policy")
    try:
        request = time_contract.build_request(
            policy=policy,
            policy_data=policy_data,
            plan=plan,
            plan_data=plan_data,
        )
        receipt_data, elapsed_ms = time_contract.fetch_receipt(
            endpoint=trusted_policy["endpoint"],
            request_data=time_contract.canonical_json(request),
            ca_certificate=ca_certificate,
            client_certificate=client_certificate,
            client_private_key=client_private_key,
            timeout_ms=trusted_policy["timeout_ms"],
            maximum_response_bytes=trusted_policy["maximum_response_bytes"],
        )
        receipt = time_contract.parse_receipt(receipt_data)
    except time_contract.TrustedTimeError as error:
        raise AttemptLedgerError(f"trusted-time online exchange rejected: {error}") from error
    _verify_trusted_time(
        policy=policy,
        policy_data=policy_data,
        plan=plan,
        plan_data=plan_data,
        receipt=receipt,
        trusted_time_public_key=trusted_time_public_key,
    )
    return _consume_loaded(
        root=root,
        policy=policy,
        policy_data=policy_data,
        plan=plan,
        plan_data=plan_data,
        trusted_time_receipt=receipt,
        https_round_trip_ms=elapsed_ms,
    )


def verify_consumption(
    *,
    root: Path,
    plan_data: bytes,
    authorization_public_key: bytes,
    signing_request_data: bytes,
    signed_artifact_data: bytes,
    trusted_time_public_key: bytes,
) -> tuple[dict[str, Any], Path]:
    policy, policy_data, plan = _load_verified_inputs(
        root=root,
        plan_data=plan_data,
        authorization_public_key=authorization_public_key,
        signing_request_data=signing_request_data,
        signed_artifact_data=signed_artifact_data,
    )
    final_name = attempt_key(plan["transaction"]["attempt_id"]) + ".json"
    root_descriptor, claims_descriptor = _verify_root_state(
        root, policy, policy_required=True
    )
    try:
        data = _read_regular_at(
            claims_descriptor,
            final_name,
            MAX_RECORD_BYTES,
            RECORD_MODE,
            "attempt consumption record",
        )
    finally:
        os.close(claims_descriptor)
        os.close(root_descriptor)
    record = parse_record(data)
    receipt = record["trusted_time"]["receipt"]
    _verify_trusted_time(
        policy=policy,
        policy_data=policy_data,
        plan=plan,
        plan_data=plan_data,
        receipt=receipt,
        trusted_time_public_key=trusted_time_public_key,
    )
    expected = build_consumption_record(
        policy=policy,
        policy_data=policy_data,
        plan=plan,
        plan_data=plan_data,
        trusted_time_receipt=receipt,
        https_round_trip_ms=record["trusted_time"]["https_round_trip_ms"],
    )
    if record != expected:
        raise AttemptLedgerError("attempt consumption record binding differs")
    consumed = _timestamp(record["consumed_at"], "attempt consumption time")
    policy_created = _timestamp(policy["created_at"], "policy creation time")
    policy_expires = _timestamp(policy["expires_at"], "policy expiry time")
    if not policy_created <= consumed <= policy_expires:
        raise AttemptLedgerError("attempt was consumed outside ledger policy lifetime")
    return record, Path(os.path.abspath(root)) / CLAIMS_DIRECTORY / final_name
