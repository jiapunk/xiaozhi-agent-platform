#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any


IDENTIFIER = re.compile(r"^[A-Za-z0-9:_.-]{1,64}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
STATE_NAME = re.compile(r"^state-([0-9]{20})\.json$")
PHASES = {"STABLE", "PREPARING", "DRAINING", "COMMITTING"}
ROLES = {"controlplane", "firmwareorigin"}
STAGES = {"PREPARED", "ACTIVE"}
ZERO_SHA256 = "0" * 64
MIN_TIME = 1609459200
MAX_TIME = 4102444800
MAX_STATE_BYTES = 1024 * 1024
STATE_FIELDS = {
    "schema", "revision", "previous_record_sha256", "phase", "active",
    "pending", "required_replicas", "acknowledgements", "prepare_deadline",
    "drain_until", "commit_deadline", "updated_at", "record_hmac_b64url",
}
GENERATION_FIELDS = {"generation_id", "generation_sequence", "receipt_sha256"}
REPLICA_FIELDS = {"replica_id", "role"}
ACK_FIELDS = {
    "replica_id", "role", "stage", "generation_id", "receipt_sha256",
    "acknowledged_at",
}


class StateError(ValueError):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StateError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, separators=(",", ":")) + "\n").encode()


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise StateError(f"{label} fields are not exact")
    return value


def _integer(value: Any, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise StateError(f"{label} is outside range")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise StateError(f"{label} is invalid")
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise StateError(f"{label} is not canonical SHA-256")
    return value


def _generation(value: Any, label: str) -> dict[str, Any]:
    result = _exact(value, GENERATION_FIELDS, label)
    _identifier(result["generation_id"], f"{label} ID")
    _integer(result["generation_sequence"], 0, 2**32 - 1, f"{label} sequence")
    _sha(result["receipt_sha256"], f"{label} receipt")
    return result


def _same_generation(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return left == right


def _replicas(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not 2 <= len(value) <= 64:
        raise StateError("required replica count is invalid")
    prior = ""
    roles: set[str] = set()
    result: list[dict[str, Any]] = []
    for raw in value:
        replica = _exact(raw, REPLICA_FIELDS, "replica")
        replica_id = _identifier(replica["replica_id"], "replica ID")
        role = replica["role"]
        if role not in ROLES or replica_id <= prior:
            raise StateError("replicas are not uniquely sorted or have invalid roles")
        prior = replica_id
        roles.add(role)
        result.append(replica)
    if roles != ROLES:
        raise StateError("both replica roles are required")
    return result


def _acks(value: Any, replicas: list[dict[str, Any]], updated_at: int,
          generation: dict[str, Any] | None = None,
          required_stage: str | None = None) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > len(replicas):
        raise StateError("acknowledgement count is invalid")
    by_id = {item["replica_id"]: item for item in replicas}
    prior = ""
    result: list[dict[str, Any]] = []
    for raw in value:
        ack = _exact(raw, ACK_FIELDS, "acknowledgement")
        replica_id = _identifier(ack["replica_id"], "ack replica ID")
        role = ack["role"]
        stage = ack["stage"]
        if (replica_id <= prior or replica_id not in by_id or
                by_id[replica_id]["role"] != role or stage not in STAGES):
            raise StateError("acknowledgement identity/order is invalid")
        if required_stage is not None and stage != required_stage:
            raise StateError("acknowledgement stage is invalid for phase")
        _identifier(ack["generation_id"], "ack generation ID")
        _sha(ack["receipt_sha256"], "ack receipt")
        _integer(ack["acknowledged_at"], MIN_TIME, updated_at, "ack time")
        if generation is not None and (
            ack["generation_id"] != generation["generation_id"] or
            ack["receipt_sha256"] != generation["receipt_sha256"]
        ):
            raise StateError("acknowledgement generation is invalid")
        prior = replica_id
        result.append(ack)
    return result


def _all_stage(state: dict[str, Any], stage: str) -> bool:
    replicas = state["required_replicas"]
    acks = state["acknowledgements"]
    return len(replicas) == len(acks) and all(
        ack["replica_id"] == replica["replica_id"] and
        ack["role"] == replica["role"] and ack["stage"] == stage
        for replica, ack in zip(replicas, acks)
    )


def _validate_state(state: dict[str, Any]) -> None:
    _exact(state, STATE_FIELDS, "state")
    if state["schema"] != 1:
        raise StateError("state schema is unsupported")
    _integer(state["revision"], 1, 2**64 - 1, "revision")
    _sha(state["previous_record_sha256"], "previous record")
    if state["phase"] not in PHASES:
        raise StateError("state phase is invalid")
    active = _generation(state["active"], "active generation")
    pending = state["pending"]
    if pending is not None:
        pending = _generation(pending, "pending generation")
    replicas = _replicas(state["required_replicas"])
    updated_at = _integer(state["updated_at"], MIN_TIME, MAX_TIME, "updated_at")
    phase = state["phase"]
    if phase == "STABLE":
        if (pending is not None or state["acknowledgements"] != [] or
                any(state[name] != 0 for name in (
                    "prepare_deadline", "drain_until", "commit_deadline"))):
            raise StateError("STABLE state contains transition data")
        _acks(state["acknowledgements"], replicas, updated_at)
    elif phase in {"PREPARING", "DRAINING"}:
        if (pending is None or pending["generation_sequence"] !=
                active["generation_sequence"] + 1 or
                pending["generation_id"] == active["generation_id"]):
            raise StateError("pending generation does not follow active")
        if phase == "PREPARING":
            _integer(state["prepare_deadline"], updated_at + 1, MAX_TIME,
                     "prepare deadline")
            if state["drain_until"] != 0:
                raise StateError("PREPARING has a drain deadline")
        else:
            if state["prepare_deadline"] != 0 or state["drain_until"] != updated_at + 10:
                raise StateError("DRAINING deadline is invalid")
        _integer(state["commit_deadline"], 30, 86400, "commit duration")
        _acks(state["acknowledgements"], replicas, updated_at, pending, "PREPARED")
        if phase == "DRAINING" and not _all_stage(state, "PREPARED"):
            raise StateError("DRAINING lacks every PREPARED acknowledgement")
    else:
        if pending is None or not _same_generation(active, pending):
            raise StateError("COMMITTING active/pending mismatch")
        if state["prepare_deadline"] != 0 or state["drain_until"] != 0:
            raise StateError("COMMITTING contains old deadlines")
        _integer(state["commit_deadline"], updated_at + 1, MAX_TIME,
                 "commit deadline")
        acks = _acks(state["acknowledgements"], replicas, updated_at, active)
        if len(acks) != len(replicas):
            raise StateError("COMMITTING lacks replica acknowledgements")


def _ack_progress(prior: list[dict[str, Any]], current: list[dict[str, Any]],
                  target: str) -> bool:
    old = {ack["replica_id"]: ack for ack in prior}
    changes = 0
    if not len(prior) <= len(current) <= len(prior) + 1:
        return False
    for ack in current:
        previous = old.get(ack["replica_id"])
        if previous is None:
            if target != "PREPARED" or ack["stage"] != "PREPARED":
                return False
            changes += 1
        elif previous == ack:
            continue
        elif (target == "ACTIVE" and previous["stage"] == "PREPARED" and
              ack["stage"] == "ACTIVE" and
              all(ack[name] == previous[name] for name in (
                  "replica_id", "role", "generation_id", "receipt_sha256"))):
            changes += 1
        else:
            return False
    return changes == 1


def _validate_transition(prior: dict[str, Any], current: dict[str, Any],
                         prior_digest: str) -> None:
    if (current["revision"] != prior["revision"] + 1 or
            current["previous_record_sha256"] != prior_digest or
            current["updated_at"] < prior["updated_at"] or
            current["required_replicas"] != prior["required_replicas"]):
        raise StateError("state chain metadata changed")
    phase = prior["phase"]
    if phase == "STABLE":
        if (current["phase"] != "PREPARING" or
                current["active"] != prior["active"]):
            raise StateError("STABLE did not enter PREPARING")
    elif phase == "PREPARING":
        if current["active"] != prior["active"]:
            raise StateError("PREPARING changed active")
        if current["phase"] == "STABLE":
            return
        if (current["phase"] not in {"PREPARING", "DRAINING"} or
                current["pending"] != prior["pending"] or
                not _ack_progress(prior["acknowledgements"],
                                  current["acknowledgements"], "PREPARED")):
            raise StateError("PREPARED acknowledgements did not progress")
    elif phase == "DRAINING":
        if (current["phase"] != "COMMITTING" or
                current["pending"] != prior["pending"] or
                current["active"] != current["pending"] or
                current["acknowledgements"] != prior["acknowledgements"]):
            raise StateError("DRAINING did not atomically commit pending")
    else:
        if current["phase"] == "STABLE":
            if current["active"] != prior["active"] or not _all_stage(prior, "ACTIVE"):
                raise StateError("COMMITTING converged without every ACTIVE ack")
            return
        if (current["phase"] != "COMMITTING" or
                current["active"] != prior["active"] or
                current["pending"] != prior["pending"] or
                not _ack_progress(prior["acknowledgements"],
                                  current["acknowledgements"], "ACTIVE")):
            raise StateError("ACTIVE acknowledgements did not progress")


def _read_regular(path: Path, maximum: int) -> bytes:
    metadata = path.lstat()
    if (not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or
            not 1 <= metadata.st_size <= maximum or metadata.st_nlink != 1 or
            metadata.st_mode & 0o222):
        raise StateError(f"unsafe or oversized file: {path.name}")
    return path.read_bytes()


def _key() -> bytes:
    value = os.environ.get("GENERATION_STATE_HMAC_KEY_B64", "")
    if not value or "=" in value:
        raise StateError("GENERATION_STATE_HMAC_KEY_B64 is missing or noncanonical")
    try:
        key = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except (ValueError, binascii.Error) as error:
        raise StateError("generation state key is not base64url") from error
    if not 32 <= len(key) <= 128 or base64.urlsafe_b64encode(key).rstrip(b"=").decode() != value:
        raise StateError("generation state key must encode 32 through 128 bytes")
    return key


def validate(directory: Path, key: bytes) -> tuple[dict[str, Any], str]:
    root = directory.resolve(strict=True)
    metadata = directory.lstat()
    if directory.is_symlink() or not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o077:
        raise StateError("state directory must be private and non-symlink")
    entries = sorted(path.name for path in root.iterdir())
    if "CURRENT" not in entries or any(
        name != "CURRENT" and STATE_NAME.fullmatch(name) is None for name in entries
    ):
        raise StateError("state directory contains missing or unexpected entries")
    record_names = [name for name in entries if name != "CURRENT"]
    if not record_names:
        raise StateError("state directory has no records")
    prior: dict[str, Any] | None = None
    prior_digest = ""
    for expected, name in enumerate(record_names, 1):
        match = STATE_NAME.fullmatch(name)
        assert match is not None
        if int(match.group(1)) != expected:
            raise StateError("state record sequence has a gap")
        payload = _read_regular(root / name, MAX_STATE_BYTES)
        try:
            state = json.loads(payload, object_pairs_hook=_pairs)
        except (json.JSONDecodeError, StateError) as error:
            raise StateError(f"invalid state JSON in {name}: {error}") from error
        if _canonical(state) != payload:
            raise StateError(f"noncanonical state JSON in {name}")
        _validate_state(state)
        signature = state["record_hmac_b64url"]
        if not isinstance(signature, str) or "=" in signature:
            raise StateError(f"invalid state HMAC encoding in {name}")
        try:
            provided = base64.urlsafe_b64decode(signature + "=")
        except (ValueError, binascii.Error) as error:
            raise StateError(f"invalid state HMAC encoding in {name}") from error
        if base64.urlsafe_b64encode(provided).rstrip(b"=").decode() != signature:
            raise StateError(f"noncanonical state HMAC encoding in {name}")
        unsigned = dict(state)
        del unsigned["record_hmac_b64url"]
        expected_hmac = hmac.new(key, _canonical(unsigned)[:-1], hashlib.sha256).digest()
        if len(provided) != 32 or not hmac.compare_digest(provided, expected_hmac):
            raise StateError(f"invalid state HMAC in {name}")
        digest = hashlib.sha256(payload).hexdigest()
        if prior is None:
            if state["revision"] != 1 or state["phase"] != "STABLE" or state[
                "previous_record_sha256"] != ZERO_SHA256:
                raise StateError("state genesis is invalid")
        else:
            _validate_transition(prior, state, prior_digest)
        prior = state
        prior_digest = digest
    current_payload = _read_regular(root / "CURRENT", 256)
    try:
        current = json.loads(current_payload, object_pairs_hook=_pairs)
    except (json.JSONDecodeError, StateError) as error:
        raise StateError("CURRENT is invalid") from error
    if (_canonical(current) != current_payload or set(current) != {"revision", "record_sha256"} or
            current.get("revision") != prior["revision"] or
            current.get("record_sha256") != prior_digest):
        raise StateError("CURRENT does not identify the latest authoritative record")
    return prior, prior_digest


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Independently verify a durable OTA generation state chain"
    )
    parser.add_argument("--state-directory", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        state, digest = validate(arguments.state_directory, _key())
    except (OSError, StateError) as error:
        print(f"generation state rejected: {error}", file=sys.stderr)
        return 1
    print(
        "generation state verified: "
        f"revision={state['revision']} phase={state['phase']} "
        f"active={state['active']['generation_id']} record_sha256={digest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
