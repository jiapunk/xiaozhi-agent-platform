#!/usr/bin/env python3
"""Two-person, immutable OTA rollout-generation primitives."""

from __future__ import annotations

import base64
import binascii
import os
import re
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import build_ota_deployment_bundle as bundle
from sign_release_manifest import MAX_IMAGE_SIZE, load_manifest_json


MAX_JSON_BYTES = 64 * 1024
MAX_KEY_BYTES = 4096
MAX_APPROVERS = 32
MAX_APPROVAL_WINDOW_SECONDS = 24 * 60 * 60
IDENTIFIER = re.compile(r"^[A-Za-z0-9:_.-]{1,64}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ACTIONS = {"EXPAND", "EMERGENCY_STOP", "RESUME"}

KEYRING_FIELDS = {"version", "approvers"}
KEYRING_ENTRY_FIELDS = {
    "approver_id",
    "approval_key_id",
    "public_key_file",
    "enabled",
}
REQUEST_FIELDS = {
    "schema",
    "generation_id",
    "generation_sequence",
    "parent_generation_id",
    "parent_generation_sequence",
    "parent_receipt_sha256",
    "parent_rollout_enabled",
    "parent_rollout_basis_points",
    "release_id",
    "release_sequence",
    "image_sha256",
    "promotion_action",
    "rollout_enabled",
    "rollout_basis_points",
    "retry_after_seconds",
    "created_at",
    "expires_at",
    "approval_keyring_sha256",
}
APPROVAL_FIELDS = {
    "schema",
    "request_sha256",
    "approver_id",
    "approval_key_id",
    "decision",
    "signed_at",
    "signature_algorithm",
    "signature_b64url",
}
APPROVAL_EVIDENCE_FIELDS = {
    "approver_id",
    "approval_key_id",
    "approval_sha256",
}
RECEIPT_V2_FIELDS = bundle.RECEIPT_FIELDS | {
    "generation_id",
    "generation_sequence",
    "parent_generation_id",
    "parent_generation_sequence",
    "parent_receipt_sha256",
    "promotion_action",
    "approval_keyring_sha256",
    "rollout_request_sha256",
    "approval_evidence",
    "promoted_at",
}


class RolloutError(ValueError):
    pass


@dataclass(frozen=True)
class TrustedApprover:
    approver_id: str
    approval_key_id: str
    public_key: Ed25519PublicKey
    enabled: bool


@dataclass(frozen=True)
class Keyring:
    by_key_id: dict[str, TrustedApprover]
    canonical_bytes: bytes
    sha256: str


def _exact_object(value: object, fields: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise RolloutError(f"{label} fields do not match its schema")
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise RolloutError(f"{label} has invalid format")
    return value


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise RolloutError(f"{label} is not a canonical SHA-256")
    return value


def _integer(value: object, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise RolloutError(f"{label} is outside range")
    return value


def _boolean(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise RolloutError(f"{label} must be a boolean")
    return value


def _canonical_object(data: bytes, fields: set[str], label: str) -> dict[str, object]:
    if not 1 <= len(data) <= MAX_JSON_BYTES:
        raise RolloutError(f"{label} size is outside range")
    value = bundle._strict_json(data, label)
    result = _exact_object(value, fields, label)
    if bundle._json_bytes(result) != data:
        raise RolloutError(f"{label} JSON is not canonical")
    return result


def _base64url(value: object, size: int, label: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise RolloutError(f"{label} is not unpadded base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except (ValueError, binascii.Error) as error:
        raise RolloutError(f"{label} is not base64url") from error
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if len(decoded) != size or canonical != value:
        raise RolloutError(f"{label} has noncanonical encoding or size")
    return decoded


def _validate_relative_file(root: Path, value: object, label: str) -> Path:
    if not isinstance(value, str) or not 1 <= len(value) <= 4096:
        raise RolloutError(f"{label} has invalid format")
    if value.startswith("/") or "\\" in value:
        raise RolloutError(f"{label} must be relative")
    path = Path(value)
    if path.is_absolute() or path == Path(".") or path.parts.count(".."):
        raise RolloutError(f"{label} escapes the keyring root")
    if str(path) != value:
        raise RolloutError(f"{label} is not canonical")
    try:
        resolved_root = root.resolve(strict=True)
        candidate = root / path
        if candidate.is_symlink():
            raise RolloutError(f"{label} must not be a symlink")
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(resolved_root)
    except (OSError, ValueError) as error:
        raise RolloutError(f"{label} is unavailable or escapes the keyring root") from error
    return resolved


def load_approver_keyring(path: Path) -> Keyring:
    data = bundle._read_regular(path, MAX_JSON_BYTES, "approver keyring")
    document = _canonical_object(data, KEYRING_FIELDS, "approver keyring")
    if document.get("version") != 1:
        raise RolloutError("approver keyring version is unsupported")
    entries = document.get("approvers")
    if not isinstance(entries, list) or not 2 <= len(entries) <= MAX_APPROVERS:
        raise RolloutError("approver keyring must contain 2 through 32 entries")
    by_key_id: dict[str, TrustedApprover] = {}
    seen_approvers: set[str] = set()
    seen_public_keys: set[bytes] = set()
    for index, raw in enumerate(entries):
        entry = _exact_object(
            raw, KEYRING_ENTRY_FIELDS, f"approver keyring entry {index}"
        )
        approver_id = _identifier(entry["approver_id"], "approver_id")
        key_id = _identifier(entry["approval_key_id"], "approval_key_id")
        enabled = _boolean(entry["enabled"], "approver enabled")
        if approver_id in seen_approvers or key_id in by_key_id:
            raise RolloutError("approver or approval key ID is duplicated")
        key_path = _validate_relative_file(
            path.parent, entry["public_key_file"], "approver public key path"
        )
        pem = bundle._read_regular(key_path, MAX_KEY_BYTES, "approver public key")
        try:
            public_key = serialization.load_pem_public_key(pem)
        except (TypeError, ValueError) as error:
            raise RolloutError("approver public key PEM is invalid") from error
        if not isinstance(public_key, Ed25519PublicKey):
            raise RolloutError("approver public key must be Ed25519")
        raw_key = public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        if raw_key in seen_public_keys:
            raise RolloutError("approver public keys must be cryptographically distinct")
        seen_approvers.add(approver_id)
        seen_public_keys.add(raw_key)
        by_key_id[key_id] = TrustedApprover(
            approver_id=approver_id,
            approval_key_id=key_id,
            public_key=public_key,
            enabled=enabled,
        )
    return Keyring(by_key_id=by_key_id, canonical_bytes=data, sha256=bundle._sha256(data))


def parse_rollout_request(data: bytes) -> dict[str, object]:
    request = _canonical_object(data, REQUEST_FIELDS, "rollout request")
    if request.get("schema") != 1:
        raise RolloutError("rollout request schema is unsupported")
    for name in (
        "generation_id",
        "parent_generation_id",
        "release_id",
    ):
        _identifier(request[name], name)
    for name in (
        "parent_receipt_sha256",
        "image_sha256",
        "approval_keyring_sha256",
    ):
        _sha(request[name], name)
    generation_sequence = _integer(
        request["generation_sequence"], 1, 2**31 - 1, "generation_sequence"
    )
    parent_sequence = _integer(
        request["parent_generation_sequence"],
        0,
        2**31 - 2,
        "parent_generation_sequence",
    )
    if generation_sequence != parent_sequence + 1:
        raise RolloutError("generation sequence is not parent plus one")
    _integer(request["release_sequence"], 1, 2**31 - 1, "release_sequence")
    parent_enabled = _boolean(
        request["parent_rollout_enabled"], "parent_rollout_enabled"
    )
    parent_basis = _integer(
        request["parent_rollout_basis_points"],
        0,
        10000,
        "parent_rollout_basis_points",
    )
    enabled = _boolean(request["rollout_enabled"], "rollout_enabled")
    basis = _integer(
        request["rollout_basis_points"], 0, 10000, "rollout_basis_points"
    )
    retry = _integer(
        request["retry_after_seconds"], 60, 86400, "retry_after_seconds"
    )
    assert retry >= 60
    created = _integer(request["created_at"], 1609459200, 4102444800, "created_at")
    expires = _integer(request["expires_at"], 1609459200, 4102444800, "expires_at")
    if expires <= created or expires - created > MAX_APPROVAL_WINDOW_SECONDS:
        raise RolloutError("rollout request approval window is invalid")
    action = request.get("promotion_action")
    if action not in ACTIONS:
        raise RolloutError("promotion action is unsupported")
    if action == "EXPAND":
        if not enabled or basis <= parent_basis or (not parent_enabled and parent_sequence != 0):
            raise RolloutError("EXPAND must monotonically grow an active or staging cohort")
    elif action == "EMERGENCY_STOP":
        if not parent_enabled or enabled or basis != 0:
            raise RolloutError("EMERGENCY_STOP must stop an active cohort")
    elif action == "RESUME":
        if parent_enabled or parent_sequence == 0 or not enabled:
            raise RolloutError("RESUME must restart a promoted stopped generation")
    if parent_enabled != (parent_basis > 0) or enabled != (basis > 0):
        raise RolloutError("rollout enabled/cohort state is inconsistent")
    return request


def approval_signature_payload(approval: dict[str, object]) -> bytes:
    return (
        "xiaozhi-ota-rollout-approval-v1\n"
        f"approval_key_id={approval['approval_key_id']}\n"
        f"approver_id={approval['approver_id']}\n"
        f"decision={approval['decision']}\n"
        f"request_sha256={approval['request_sha256']}\n"
        f"schema={approval['schema']}\n"
        f"signature_algorithm={approval['signature_algorithm']}\n"
        f"signed_at={approval['signed_at']}\n"
    ).encode("ascii")


def parse_rollout_approval(data: bytes) -> dict[str, object]:
    approval = _canonical_object(data, APPROVAL_FIELDS, "rollout approval")
    if approval.get("schema") != 1 or approval.get("decision") != "APPROVE":
        raise RolloutError("rollout approval schema or decision is invalid")
    if approval.get("signature_algorithm") != "Ed25519":
        raise RolloutError("rollout approval signature algorithm is unsupported")
    _sha(approval["request_sha256"], "approval request_sha256")
    _identifier(approval["approver_id"], "approval approver_id")
    _identifier(approval["approval_key_id"], "approval_key_id")
    _integer(approval["signed_at"], 1609459200, 4102444800, "approval signed_at")
    _base64url(approval["signature_b64url"], 64, "approval signature")
    return approval


def verify_rollout_approvals(
    request_data: bytes,
    approval_data: list[bytes],
    keyring: Keyring,
) -> list[tuple[dict[str, object], bytes]]:
    request = parse_rollout_request(request_data)
    if request["approval_keyring_sha256"] != keyring.sha256:
        raise RolloutError("rollout request does not bind the trusted keyring")
    if len(approval_data) != 2:
        raise RolloutError("exactly two rollout approvals are required")
    request_hash = bundle._sha256(request_data)
    verified: list[tuple[dict[str, object], bytes]] = []
    seen_approvers: set[str] = set()
    seen_keys: set[str] = set()
    for data in approval_data:
        approval = parse_rollout_approval(data)
        if approval["request_sha256"] != request_hash:
            raise RolloutError("approval is for another rollout request")
        signed_at = approval["signed_at"]
        assert isinstance(signed_at, int)
        if not request["created_at"] <= signed_at <= request["expires_at"]:
            raise RolloutError("approval signed_at is outside the request window")
        key_id = approval["approval_key_id"]
        approver_id = approval["approver_id"]
        assert isinstance(key_id, str) and isinstance(approver_id, str)
        trusted = keyring.by_key_id.get(key_id)
        if (
            trusted is None
            or not trusted.enabled
            or trusted.approver_id != approver_id
        ):
            raise RolloutError("approval signer is not enabled in the trusted keyring")
        if approver_id in seen_approvers or key_id in seen_keys:
            raise RolloutError("rollout approvals must come from two distinct approvers")
        signature = _base64url(
            approval["signature_b64url"], 64, "approval signature"
        )
        try:
            trusted.public_key.verify(signature, approval_signature_payload(approval))
        except InvalidSignature as error:
            raise RolloutError("rollout approval signature verification failed") from error
        seen_approvers.add(approver_id)
        seen_keys.add(key_id)
        verified.append((approval, data))
    verified.sort(key=lambda item: str(item[0]["approver_id"]))
    return verified


def _parent_state(receipt: dict[str, object]) -> dict[str, object]:
    schema = receipt.get("schema")
    if schema == 1:
        generation_id = "staging"
        generation_sequence = 0
    elif schema == 2:
        generation_id = receipt.get("generation_id")
        generation_sequence = receipt.get("generation_sequence")
        _identifier(generation_id, "parent generation_id")
        _integer(
            generation_sequence, 1, 2**31 - 2, "parent generation_sequence"
        )
    else:
        raise RolloutError("parent bundle receipt schema is unsupported")
    enabled = _boolean(receipt.get("rollout_enabled"), "parent rollout_enabled")
    basis = _integer(
        receipt.get("rollout_basis_points"),
        0,
        10000,
        "parent rollout_basis_points",
    )
    if enabled != (basis > 0):
        raise RolloutError("parent rollout state is inconsistent")
    return {
        "generation_id": generation_id,
        "generation_sequence": generation_sequence,
        "rollout_enabled": enabled,
        "rollout_basis_points": basis,
    }


def _read_receipt(root: Path) -> tuple[dict[str, object], bytes]:
    data = bundle._read_regular(
        root / "deployment-receipt.json", MAX_JSON_BYTES, "parent bundle receipt"
    )
    value = bundle._strict_json(data, "parent bundle receipt")
    if not isinstance(value, dict):
        raise RolloutError("parent bundle receipt must be an object")
    return value, data


def validate_parent_bundle(
    root: Path,
    *,
    expected_authority: str,
    approver_keyring_paths: list[Path] | None,
    parent_roots: list[Path] | None = None,
) -> tuple[dict[str, object], bytes]:
    receipt, data = _read_receipt(root)
    if receipt.get("schema") == 1:
        validated = bundle.validate_deployment_bundle(
            root, expected_authority=expected_authority, require_read_only=True
        )
        return validated, data
    if receipt.get("schema") != 2:
        raise RolloutError("parent bundle receipt schema is unsupported")
    if not approver_keyring_paths or not parent_roots:
        raise RolloutError(
            "a promoted parent requires its complete lineage and trusted keyrings"
        )
    validated = validate_rollout_chain(
        root,
        expected_authority=expected_authority,
        approver_keyring_paths=approver_keyring_paths,
        parent_roots=parent_roots,
    )
    return validated, data


def create_rollout_request(
    *,
    parent_bundle: Path,
    parent_lineage: list[Path] | None,
    parent_approver_keyring_paths: list[Path] | None,
    approver_keyring_path: Path,
    expected_authority: str,
    generation_id: str,
    action: str,
    rollout_basis_points: int,
    created_at: int,
    expires_at: int,
) -> dict[str, object]:
    receipt, receipt_data = validate_parent_bundle(
        parent_bundle,
        expected_authority=expected_authority,
        approver_keyring_paths=parent_approver_keyring_paths,
        parent_roots=parent_lineage,
    )
    state = _parent_state(receipt)
    keyring = load_approver_keyring(approver_keyring_path)
    _identifier(generation_id, "generation_id")
    if action not in ACTIONS:
        raise RolloutError("promotion action is unsupported")
    enabled = action != "EMERGENCY_STOP"
    request: dict[str, object] = {
        "schema": 1,
        "generation_id": generation_id,
        "generation_sequence": int(state["generation_sequence"]) + 1,
        "parent_generation_id": state["generation_id"],
        "parent_generation_sequence": state["generation_sequence"],
        "parent_receipt_sha256": bundle._sha256(receipt_data),
        "parent_rollout_enabled": state["rollout_enabled"],
        "parent_rollout_basis_points": state["rollout_basis_points"],
        "release_id": receipt["release_id"],
        "release_sequence": receipt["release_sequence"],
        "image_sha256": receipt["image_sha256"],
        "promotion_action": action,
        "rollout_enabled": enabled,
        "rollout_basis_points": rollout_basis_points,
        "retry_after_seconds": receipt["retry_after_seconds"],
        "created_at": created_at,
        "expires_at": expires_at,
        "approval_keyring_sha256": keyring.sha256,
    }
    parse_rollout_request(bundle._json_bytes(request))
    _request_within_manifest(request, parent_bundle)
    return request


def sign_rollout_approval(
    request_data: bytes,
    private_key_pem: bytes,
    *,
    approver_id: str,
    approval_key_id: str,
    signed_at: int,
) -> dict[str, object]:
    request = parse_rollout_request(request_data)
    _identifier(approver_id, "approver_id")
    _identifier(approval_key_id, "approval_key_id")
    if not request["created_at"] <= signed_at <= request["expires_at"]:
        raise RolloutError("approval signed_at is outside the request window")
    try:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    except (TypeError, ValueError) as error:
        raise RolloutError("approval private key PEM is invalid or encrypted") from error
    if not isinstance(private_key, Ed25519PrivateKey):
        raise RolloutError("approval private key must be Ed25519")
    approval: dict[str, object] = {
        "schema": 1,
        "request_sha256": bundle._sha256(request_data),
        "approver_id": approver_id,
        "approval_key_id": approval_key_id,
        "decision": "APPROVE",
        "signed_at": signed_at,
        "signature_algorithm": "Ed25519",
    }
    signature = private_key.sign(approval_signature_payload(approval))
    approval["signature_b64url"] = (
        base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    )
    parse_rollout_approval(bundle._json_bytes(approval))
    return approval


def _promotion_receipt(
    *,
    manifest: dict[str, object],
    authority: str,
    url_path: str,
    request: dict[str, object],
    request_data: bytes,
    approval_pairs: list[tuple[dict[str, object], bytes]],
    promoted_at: int,
    manifest_data: bytes,
    public_key_data: bytes,
    sdkconfig_data: bytes,
    control_data: bytes,
    origin_data: bytes,
) -> dict[str, object]:
    evidence = [
        {
            "approver_id": approval["approver_id"],
            "approval_key_id": approval["approval_key_id"],
            "approval_sha256": bundle._sha256(data),
        }
        for approval, data in approval_pairs
    ]
    return {
        "schema": 2,
        "generation_id": request["generation_id"],
        "generation_sequence": request["generation_sequence"],
        "parent_generation_id": request["parent_generation_id"],
        "parent_generation_sequence": request["parent_generation_sequence"],
        "parent_receipt_sha256": request["parent_receipt_sha256"],
        "promotion_action": request["promotion_action"],
        "approval_keyring_sha256": request["approval_keyring_sha256"],
        "rollout_request_sha256": bundle._sha256(request_data),
        "approval_evidence": evidence,
        "promoted_at": promoted_at,
        "release_id": manifest["release_id"],
        "signing_key_id": manifest["signing_key_id"],
        "project": manifest["project"],
        "board": manifest["board"],
        "channel": manifest["channel"],
        "version": manifest["version"],
        "release_sequence": manifest["release_sequence"],
        "secure_version": manifest["secure_version"],
        "image_authority": authority,
        "image_url_path": url_path,
        "image_size": manifest["image_size"],
        "image_sha256": manifest["image_sha256"],
        "manifest_sha256": bundle._sha256(manifest_data),
        "public_key_sha256": bundle._sha256(public_key_data),
        "sdkconfig_sha256": bundle._sha256(sdkconfig_data),
        "control_registry_sha256": bundle._sha256(control_data),
        "origin_catalog_sha256": bundle._sha256(origin_data),
        "rollout_enabled": request["rollout_enabled"],
        "rollout_basis_points": request["rollout_basis_points"],
        "retry_after_seconds": request["retry_after_seconds"],
    }


def _validate_receipt_v2(receipt: dict[str, object]) -> None:
    _exact_object(receipt, RECEIPT_V2_FIELDS, "rollout receipt")
    if receipt.get("schema") != 2:
        raise RolloutError("rollout receipt schema is unsupported")
    for name in (
        "generation_id",
        "parent_generation_id",
        "release_id",
        "signing_key_id",
        "project",
        "board",
        "channel",
    ):
        _identifier(receipt[name], f"receipt {name}")
    for name in (
        "parent_receipt_sha256",
        "approval_keyring_sha256",
        "rollout_request_sha256",
        "image_sha256",
        "manifest_sha256",
        "public_key_sha256",
        "sdkconfig_sha256",
        "control_registry_sha256",
        "origin_catalog_sha256",
    ):
        _sha(receipt[name], f"receipt {name}")
    sequence = _integer(
        receipt["generation_sequence"], 1, 2**31 - 1, "receipt generation_sequence"
    )
    parent_sequence = _integer(
        receipt["parent_generation_sequence"],
        0,
        2**31 - 2,
        "receipt parent_generation_sequence",
    )
    if sequence != parent_sequence + 1:
        raise RolloutError("receipt generation sequence is invalid")
    if receipt.get("promotion_action") not in ACTIONS:
        raise RolloutError("receipt promotion action is unsupported")
    _integer(receipt["promoted_at"], 1609459200, 4102444800, "promoted_at")
    enabled = _boolean(receipt["rollout_enabled"], "receipt rollout_enabled")
    basis = _integer(
        receipt["rollout_basis_points"], 0, 10000, "receipt rollout_basis_points"
    )
    if enabled != (basis > 0):
        raise RolloutError("receipt rollout state is inconsistent")
    _integer(
        receipt["retry_after_seconds"], 60, 86400, "receipt retry_after_seconds"
    )
    evidence = receipt.get("approval_evidence")
    if not isinstance(evidence, list) or len(evidence) != 2:
        raise RolloutError("receipt must contain exactly two approval digests")
    prior_id = ""
    for item in evidence:
        entry = _exact_object(item, APPROVAL_EVIDENCE_FIELDS, "approval evidence")
        approver_id = _identifier(entry["approver_id"], "evidence approver_id")
        _identifier(entry["approval_key_id"], "evidence approval_key_id")
        _sha(entry["approval_sha256"], "approval evidence SHA-256")
        if approver_id <= prior_id:
            raise RolloutError("approval evidence is not uniquely sorted")
        prior_id = approver_id


def _read_rollout_artifacts(root: Path) -> dict[str, object]:
    manifest_data = bundle._read_regular(
        root / "control/release-manifest.json", 8192, "rollout manifest"
    )
    public_key_data = bundle._read_regular(
        root / "control/release-public.pem", bundle.MAX_PUBLIC_KEY_BYTES, "rollout public key"
    )
    sdkconfig_data = bundle._read_regular(
        root / "evidence/sdkconfig", bundle.MAX_SDKCONFIG_BYTES, "rollout sdkconfig"
    )
    manifest = load_manifest_json(manifest_data)
    image_url = manifest["image_url"]
    assert isinstance(image_url, str)
    url_path = urlsplit(image_url).path
    bundle._validate_url_path(url_path)
    image_relative = Path("origin") / ("objects" + url_path).lstrip("/")
    image_data = bundle._read_regular(
        root / image_relative, MAX_IMAGE_SIZE, "rollout image"
    )
    return {
        "manifest": manifest,
        "manifest_data": manifest_data,
        "public_key_data": public_key_data,
        "sdkconfig_data": sdkconfig_data,
        "image_data": image_data,
        "url_path": url_path,
        "image_relative": image_relative,
    }


def _request_matches_parent(
    request: dict[str, object],
    parent_receipt: dict[str, object],
    parent_receipt_data: bytes,
) -> None:
    state = _parent_state(parent_receipt)
    expected = {
        "parent_generation_id": state["generation_id"],
        "parent_generation_sequence": state["generation_sequence"],
        "parent_receipt_sha256": bundle._sha256(parent_receipt_data),
        "parent_rollout_enabled": state["rollout_enabled"],
        "parent_rollout_basis_points": state["rollout_basis_points"],
        "generation_sequence": int(state["generation_sequence"]) + 1,
        "release_id": parent_receipt["release_id"],
        "release_sequence": parent_receipt["release_sequence"],
        "image_sha256": parent_receipt["image_sha256"],
        "retry_after_seconds": parent_receipt["retry_after_seconds"],
    }
    for name, value in expected.items():
        if request.get(name) != value:
            raise RolloutError(f"rollout request {name} does not match parent bundle")


def _request_within_manifest(request: dict[str, object], bundle_root: Path) -> None:
    manifest_data = bundle._read_regular(
        bundle_root / "control/release-manifest.json", 8192, "rollout manifest"
    )
    manifest = load_manifest_json(manifest_data)
    if (
        request.get("release_id") != manifest.get("release_id")
        or int(request["created_at"]) < int(manifest["not_before"])
        or int(request["expires_at"]) > int(manifest["expires_at"])
    ):
        raise RolloutError("rollout approval window is outside manifest validity")


def validate_rollout_bundle(
    root: Path,
    *,
    expected_authority: str,
    approver_keyring_path: Path,
    parent_root: Path,
    require_read_only: bool = True,
) -> dict[str, object]:
    try:
        root_info = root.lstat()
    except OSError as error:
        raise RolloutError("rollout bundle does not exist") from error
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise RolloutError("rollout bundle must be a non-symlink directory")
    parent_receipt, parent_receipt_data = _read_receipt(parent_root)
    receipt_data = bundle._read_regular(
        root / "deployment-receipt.json", MAX_JSON_BYTES, "rollout receipt"
    )
    receipt = _canonical_object(receipt_data, RECEIPT_V2_FIELDS, "rollout receipt")
    _validate_receipt_v2(receipt)
    request_data = bundle._read_regular(
        root / "promotion/rollout-request.json", MAX_JSON_BYTES, "rollout request"
    )
    request = parse_rollout_request(request_data)
    approval_paths = [
        root / "promotion/approval-1.json",
        root / "promotion/approval-2.json",
    ]
    approval_data = [
        bundle._read_regular(path, MAX_JSON_BYTES, "rollout approval")
        for path in approval_paths
    ]
    keyring = load_approver_keyring(approver_keyring_path)
    approvals = verify_rollout_approvals(request_data, approval_data, keyring)
    _request_matches_parent(request, parent_receipt, parent_receipt_data)
    _request_within_manifest(request, root)
    if request["generation_id"] == request["parent_generation_id"]:
        raise RolloutError("rollout generation ID must differ from its parent")
    promoted_at = receipt["promoted_at"]
    assert isinstance(promoted_at, int)
    signed_times = [int(item[0]["signed_at"]) for item in approvals]
    if (
        promoted_at < max(signed_times)
        or promoted_at < int(request["created_at"])
        or promoted_at > int(request["expires_at"])
    ):
        raise RolloutError("promoted_at is outside the approved execution window")

    artifacts = _read_rollout_artifacts(root)
    manifest = artifacts["manifest"]
    assert isinstance(manifest, dict)
    bundle.verify_release_artifacts(
        manifest,
        artifacts["public_key_data"],
        artifacts["image_data"],
        artifacts["sdkconfig_data"].decode("utf-8"),
        expected_authority=expected_authority,
    )
    image_url = manifest["image_url"]
    assert isinstance(image_url, str)
    if urlsplit(image_url).netloc != expected_authority:
        raise RolloutError("rollout manifest authority is not canonical")
    control, origin = bundle._expected_documents(
        manifest,
        str(artifacts["url_path"]),
        int(request["retry_after_seconds"]),
        rollout_enabled=bool(request["rollout_enabled"]),
        rollout_basis_points=int(request["rollout_basis_points"]),
    )
    control_data = bundle._json_bytes(control)
    origin_data = bundle._json_bytes(origin)
    expected_receipt = _promotion_receipt(
        manifest=manifest,
        authority=expected_authority,
        url_path=str(artifacts["url_path"]),
        request=request,
        request_data=request_data,
        approval_pairs=approvals,
        promoted_at=promoted_at,
        manifest_data=artifacts["manifest_data"],
        public_key_data=artifacts["public_key_data"],
        sdkconfig_data=artifacts["sdkconfig_data"],
        control_data=control_data,
        origin_data=origin_data,
    )
    if receipt != expected_receipt or receipt_data != bundle._json_bytes(expected_receipt):
        raise RolloutError("rollout receipt does not match approved artifacts")
    actual_control = bundle._read_regular(
        root / "control/ota-release-registry.json", MAX_JSON_BYTES, "control registry"
    )
    actual_origin = bundle._read_regular(
        root / "origin/firmware-origin-catalog.json", MAX_JSON_BYTES, "origin catalog"
    )
    if actual_control != control_data or actual_origin != origin_data:
        raise RolloutError("rollout catalogs are not canonical or consistent")
    ready = bundle._read_regular(root / "READY", 128, "rollout READY marker")
    if ready != (bundle._sha256(receipt_data) + "\n").encode("ascii"):
        raise RolloutError("rollout READY marker is invalid")
    expected_files = {
        Path("control/release-public.pem"),
        Path("control/release-manifest.json"),
        Path("control/ota-release-registry.json"),
        Path("origin/firmware-origin-catalog.json"),
        artifacts["image_relative"],
        Path("evidence/sdkconfig"),
        Path("promotion/rollout-request.json"),
        Path("promotion/approval-1.json"),
        Path("promotion/approval-2.json"),
        Path("deployment-receipt.json"),
        Path("READY"),
    }
    if require_read_only:
        bundle._require_read_only_tree(root, expected_files)
    return expected_receipt


def validate_rollout_chain(
    root: Path,
    *,
    expected_authority: str,
    parent_roots: list[Path],
    approver_keyring_paths: list[Path],
) -> dict[str, object]:
    if not parent_roots:
        raise RolloutError("rollout lineage must include the immediate parent")
    keyrings: dict[str, Path] = {}
    for path in approver_keyring_paths:
        loaded = load_approver_keyring(path)
        existing = keyrings.get(loaded.sha256)
        if existing is not None and existing != path:
            raise RolloutError("duplicate approver keyring snapshot digest")
        keyrings[loaded.sha256] = path
    if not keyrings:
        raise RolloutError("at least one trusted approver keyring is required")

    current = root
    first_receipt: dict[str, object] | None = None
    seen_generations: set[str] = set()
    for parent in parent_roots:
        current_receipt, _ = _read_receipt(current)
        if current_receipt.get("schema") != 2:
            raise RolloutError("rollout lineage contains an extra parent")
        generation_id = str(current_receipt.get("generation_id"))
        if generation_id in seen_generations:
            raise RolloutError("rollout lineage generation ID is duplicated")
        seen_generations.add(generation_id)
        keyring_hash = current_receipt.get("approval_keyring_sha256")
        keyring_path = keyrings.get(str(keyring_hash))
        if keyring_path is None:
            raise RolloutError("rollout lineage is missing a trusted keyring snapshot")
        validated = validate_rollout_bundle(
            current,
            expected_authority=expected_authority,
            approver_keyring_path=keyring_path,
            parent_root=parent,
            require_read_only=True,
        )
        if first_receipt is None:
            first_receipt = validated
        current = parent
    final_receipt, _ = _read_receipt(current)
    if final_receipt.get("schema") != 1:
        raise RolloutError("rollout lineage does not terminate at a staging bundle")
    bundle.validate_deployment_bundle(
        current, expected_authority=expected_authority, require_read_only=True
    )
    assert first_receipt is not None
    return first_receipt


def promote_rollout_bundle(
    *,
    parent_bundle: Path,
    parent_lineage: list[Path] | None,
    parent_approver_keyring_paths: list[Path] | None,
    request_path: Path,
    approval_paths: list[Path],
    approver_keyring_path: Path,
    expected_authority: str,
    verification_time: int,
    output_path: Path,
) -> dict[str, object]:
    parent_receipt, parent_receipt_data = validate_parent_bundle(
        parent_bundle,
        expected_authority=expected_authority,
        approver_keyring_paths=parent_approver_keyring_paths,
        parent_roots=parent_lineage,
    )
    request_data = bundle._read_regular(request_path, MAX_JSON_BYTES, "rollout request")
    request = parse_rollout_request(request_data)
    _request_matches_parent(request, parent_receipt, parent_receipt_data)
    _request_within_manifest(request, parent_bundle)
    if request["generation_id"] == request["parent_generation_id"]:
        raise RolloutError("rollout generation ID must differ from its parent")
    keyring = load_approver_keyring(approver_keyring_path)
    approval_data = [
        bundle._read_regular(path, MAX_JSON_BYTES, "rollout approval")
        for path in approval_paths
    ]
    approvals = verify_rollout_approvals(request_data, approval_data, keyring)
    signed_times = [int(item[0]["signed_at"]) for item in approvals]
    if (
        verification_time < max(signed_times)
        or verification_time < int(request["created_at"])
        or verification_time > int(request["expires_at"])
    ):
        raise RolloutError("verification time is outside the approved request window")

    artifacts = _read_rollout_artifacts(parent_bundle)
    manifest = artifacts["manifest"]
    assert isinstance(manifest, dict)
    control, origin = bundle._expected_documents(
        manifest,
        str(artifacts["url_path"]),
        int(request["retry_after_seconds"]),
        rollout_enabled=bool(request["rollout_enabled"]),
        rollout_basis_points=int(request["rollout_basis_points"]),
    )
    control_data = bundle._json_bytes(control)
    origin_data = bundle._json_bytes(origin)
    receipt = _promotion_receipt(
        manifest=manifest,
        authority=expected_authority,
        url_path=str(artifacts["url_path"]),
        request=request,
        request_data=request_data,
        approval_pairs=approvals,
        promoted_at=verification_time,
        manifest_data=artifacts["manifest_data"],
        public_key_data=artifacts["public_key_data"],
        sdkconfig_data=artifacts["sdkconfig_data"],
        control_data=control_data,
        origin_data=origin_data,
    )
    receipt_data = bundle._json_bytes(receipt)
    if output_path.exists() or output_path.is_symlink():
        raise RolloutError("output rollout bundle already exists")
    if not output_path.parent.is_dir():
        raise RolloutError("output rollout bundle parent does not exist")

    created = False
    try:
        output_path.mkdir(mode=0o700)
        created = True
        control_dir = output_path / "control"
        origin_dir = output_path / "origin"
        evidence_dir = output_path / "evidence"
        promotion_dir = output_path / "promotion"
        object_path = origin_dir / ("objects" + str(artifacts["url_path"])).lstrip("/")
        for directory in (control_dir, origin_dir, evidence_dir, promotion_dir):
            directory.mkdir(mode=0o700)
        object_path.parent.mkdir(mode=0o700, parents=True)
        bundle._write_new(control_dir / "release-public.pem", artifacts["public_key_data"])
        bundle._write_new(control_dir / "release-manifest.json", artifacts["manifest_data"])
        bundle._write_new(control_dir / "ota-release-registry.json", control_data)
        bundle._write_new(origin_dir / "firmware-origin-catalog.json", origin_data)
        bundle._write_new(object_path, artifacts["image_data"])
        bundle._write_new(evidence_dir / "sdkconfig", artifacts["sdkconfig_data"])
        bundle._write_new(promotion_dir / "rollout-request.json", request_data)
        for index, (_, data) in enumerate(approvals, start=1):
            bundle._write_new(promotion_dir / f"approval-{index}.json", data)
        bundle._write_new(output_path / "deployment-receipt.json", receipt_data)
        bundle._write_new(
            output_path / "READY",
            (bundle._sha256(receipt_data) + "\n").encode("ascii"),
        )
        for directory in sorted(
            (path for path in output_path.rglob("*") if path.is_dir()),
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            bundle._fsync_directory(directory)
        bundle._fsync_directory(output_path)
        bundle._lock_bundle_tree(output_path)
        validate_rollout_bundle(
            output_path,
            expected_authority=expected_authority,
            approver_keyring_path=approver_keyring_path,
            parent_root=parent_bundle,
            require_read_only=True,
        )
    except BaseException:
        if created:
            os.chmod(output_path, 0o700)
            for path in output_path.rglob("*"):
                if path.is_dir():
                    os.chmod(path, 0o700)
                else:
                    os.chmod(path, 0o600)
            shutil.rmtree(output_path)
        raise
    return receipt
