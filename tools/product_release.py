#!/usr/bin/env python3
"""Fail-closed M79 product market-release evidence record.

This module does not manufacture hardware, provider, legal, or live-service
evidence.  It verifies independently signed production attestations, prevents
cross-release mixing, directly validates the signed 28-day backend SLO proof,
and signs one deterministic release record only after the fixed market-release
evidence set is complete.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import hashlib
import ipaddress
import json
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import validate_backend_slo_observation as backend_slo


SCHEMA_VERSION = 2
EVIDENCE_SIGNATURE_DOMAIN = b"XIAOZHI-AGENT-PRODUCT-EVIDENCE-V2\x00"
RECORD_SIGNATURE_DOMAIN = b"XIAOZHI-AGENT-PRODUCT-RELEASE-V2\x00"
RESULT = "MARKET_RELEASE_PASS"
ENVIRONMENT = "PRODUCTION"
MAX_JSON_BYTES = 1024 * 1024
MAX_KEY_BYTES = 4096
MAX_EVIDENCE_BYTES = 1024 * 1024 * 1024
ZERO_SHA256 = "0" * 64
SHA256 = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
SKU = re.compile(r"^[A-Z0-9][A-Z0-9_.-]{0,63}$")
VERSION = re.compile(r"^[0-9][A-Za-z0-9._+-]{0,63}$")
REGION = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
RESERVED_PARTS = {"dev", "demo", "fixture", "local", "mock", "test"}

EVIDENCE_TYPES = (
    "agent_security_privacy",
    "alpha_fleet",
    "backend_supply_chain",
    "companion_apps",
    "device_soak_power_acoustic",
    "factory_boot_storage_onboarding",
    "firmware_supply_chain",
    "kubernetes_live_admission",
    "legal_market",
    "managed_postgresql_resilience",
    "ota_release_chain",
    "push_provider_delivery",
    "reset_resale_hardware",
    "speech_backup_adapter",
    "speech_primary_adapter",
)

SUBJECT_FIELDS = {
    "product_release_id",
    "sku",
    "product_version",
    "firmware_sha256",
    "firmware_security_version",
    "ota_release_id",
    "oci_release_id",
    "deployment_id",
    "qualification_id",
}
POLICY_FIELDS = {
    "schema_version",
    "policy_id",
    "record_id",
    "release_sequence",
    "previous_record_sha256",
    "subject",
    "valid_from",
    "valid_until",
    "tool_sha256",
    "required_evidence",
    "backend_slo",
    "release_signing_key_id",
    "release_public_key_sha256",
}
BACKEND_SLO_TRUST_FIELDS = {
    "collector_id",
    "signing_key_id",
    "public_key_sha256",
    "policy_sha256",
}
TRUST_FIELDS = {
    "evidence_type",
    "signing_key_id",
    "public_key_sha256",
    "max_age_seconds",
}
ATTESTATION_FIELDS = {
    "schema_version",
    "evidence_id",
    "evidence_type",
    "subject",
    "environment",
    "region",
    "observed_at",
    "valid_until",
    "evidence_uri",
    "evidence_sha256",
    "result",
    "signing_key_id",
    "signature_algorithm",
    "signature_b64url",
}
EVIDENCE_SUMMARY_FIELDS = {
    "evidence_type",
    "evidence_id",
    "attestation_sha256",
    "evidence_uri",
    "evidence_sha256",
    "region",
    "observed_at",
    "valid_until",
    "authority_key_id",
    "authority_public_key_sha256",
}
RECORD_FIELDS = {
    "schema_version",
    "record_type",
    "record_id",
    "policy_sha256",
    "release_sequence",
    "previous_record_sha256",
    "subject",
    "issued_at",
    "valid_until",
    "evidence",
    "backend_slo",
    "result",
    "signing_key_id",
    "signature_algorithm",
    "signature_b64url",
}
BACKEND_SLO_SUMMARY_FIELDS = {
    "observation_id",
    "observation_sha256",
    "policy_sha256",
    "collector_id",
    "window_start",
    "window_end",
    "generated_at",
    "authority_key_id",
    "authority_public_key_sha256",
}


class ProductReleaseError(ValueError):
    pass


def _exact_keys(value: Mapping[str, Any], expected: Iterable[str], label: str) -> None:
    actual = set(value)
    wanted = set(expected)
    if actual != wanted:
        raise ProductReleaseError(
            f"{label} fields mismatch; missing={sorted(wanted - actual)}, "
            f"unexpected={sorted(actual - wanted)}"
        )


def _strict_json(data: bytes, label: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ProductReleaseError(f"{label} contains duplicate fields")
            result[key] = value
        return result

    def reject_constant(value: str) -> Any:
        raise ProductReleaseError(f"{label} contains non-standard constant {value}")

    try:
        return json.loads(
            data.decode("utf-8"), object_pairs_hook=pairs, parse_constant=reject_constant
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProductReleaseError(f"{label} is not strict UTF-8 JSON") from error


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_regular(path: Path, maximum: int, label: str) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ProductReleaseError(f"cannot open {label}") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not 1 <= info.st_size <= maximum:
            raise ProductReleaseError(f"{label} must be a bounded regular file")
        chunks: list[bytes] = []
        remaining = info.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65536))
            if not chunk:
                raise ProductReleaseError(f"{label} changed while being read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ProductReleaseError(f"{label} changed while being read")
        return b"".join(chunks)
    except OSError as error:
        raise ProductReleaseError(f"cannot read {label}") from error
    finally:
        os.close(descriptor)


def _load_canonical(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular(path, MAX_JSON_BYTES, label)
    value = _strict_json(raw, label)
    if not isinstance(value, dict):
        raise ProductReleaseError(f"{label} must be one object")
    if raw != _canonical(value):
        raise ProductReleaseError(f"{label} is not canonical JSON")
    return value, raw


def _hash_regular(path: Path, maximum: int, label: str) -> str:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ProductReleaseError(f"cannot open {label}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= maximum:
            raise ProductReleaseError(f"{label} must be a bounded regular file")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise ProductReleaseError(f"{label} changed while being hashed")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ProductReleaseError(f"{label} changed while being hashed")
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ):
            raise ProductReleaseError(f"{label} changed while being hashed")
        return digest.hexdigest()
    except OSError as error:
        raise ProductReleaseError(f"cannot hash {label}") from error
    finally:
        os.close(descriptor)


def _write_new(path: Path, data: bytes, mode: int = 0o400) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as error:
        raise ProductReleaseError(f"cannot create {path.name}") from error
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _lock_tree(root: Path) -> None:
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        if path.is_symlink():
            raise ProductReleaseError("release record bundle contains a symlink")
        os.chmod(path, 0o555 if path.is_dir() else 0o444)
    os.chmod(root, 0o555)


def _reject_nonproduction_marker(value: str, label: str) -> None:
    parts = {part for part in re.split(r"[^a-z0-9]+", value.lower()) if part}
    if parts & RESERVED_PARTS:
        raise ProductReleaseError(f"{label} contains a non-production marker")


def _require_identifier(value: Any, label: str, *, production: bool = True) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ProductReleaseError(f"{label} has invalid format")
    if production:
        _reject_nonproduction_marker(value, label)
    return value


def _require_sha(value: Any, label: str, *, allow_zero: bool = False) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise ProductReleaseError(f"{label} is not canonical SHA-256")
    if value == ZERO_SHA256 and not allow_zero:
        raise ProductReleaseError(f"{label} cannot be the zero SHA-256")
    return value


def _parse_timestamp(value: Any, label: str) -> datetime.datetime:
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value
    ):
        raise ProductReleaseError(f"{label} is not canonical UTC time")
    try:
        parsed = datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc
        )
    except ValueError as error:
        raise ProductReleaseError(f"{label} is invalid") from error
    if not datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc) <= parsed <= datetime.datetime(
        2100, 1, 1, tzinfo=datetime.timezone.utc
    ):
        raise ProductReleaseError(f"{label} is outside the supported range")
    return parsed


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_b64url(value: Any, size: int, label: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise ProductReleaseError(f"{label} is not canonical base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except (ValueError, binascii.Error) as error:
        raise ProductReleaseError(f"{label} is not base64url") from error
    if len(decoded) != size or _b64url(decoded) != value:
        raise ProductReleaseError(f"{label} is not canonical base64url")
    return decoded


def _parse_public_key(raw: bytes) -> tuple[Ed25519PublicKey, str]:
    try:
        key = serialization.load_pem_public_key(raw)
    except (TypeError, ValueError) as error:
        raise ProductReleaseError("invalid public key PEM") from error
    if not isinstance(key, Ed25519PublicKey):
        raise ProductReleaseError("public key must be Ed25519")
    canonical = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return key, _sha256(canonical)


def _load_public_key(path: Path) -> tuple[Ed25519PublicKey, str]:
    raw = _read_regular(path, MAX_KEY_BYTES, "Ed25519 public key")
    return _parse_public_key(raw)


def _load_private_key(path: Path) -> tuple[Ed25519PrivateKey, str]:
    raw = _read_regular(path, MAX_KEY_BYTES, "Ed25519 private key")
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except (TypeError, ValueError) as error:
        raise ProductReleaseError("invalid private key PEM") from error
    if not isinstance(key, Ed25519PrivateKey):
        raise ProductReleaseError("private key must be Ed25519")
    public_raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return key, _sha256(public_raw)


def _validate_subject(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProductReleaseError("subject must be an object")
    _exact_keys(value, SUBJECT_FIELDS, "subject")
    _require_identifier(value["product_release_id"], "subject product release ID")
    if not isinstance(value["sku"], str) or not SKU.fullmatch(value["sku"]):
        raise ProductReleaseError("subject SKU has invalid format")
    _reject_nonproduction_marker(value["sku"], "subject SKU")
    if not isinstance(value["product_version"], str) or not VERSION.fullmatch(
        value["product_version"]
    ):
        raise ProductReleaseError("subject product version has invalid format")
    _reject_nonproduction_marker(value["product_version"], "subject product version")
    _require_sha(value["firmware_sha256"], "subject firmware SHA-256")
    security_version = value["firmware_security_version"]
    if type(security_version) is not int or not 1 <= security_version <= 16:
        raise ProductReleaseError("firmware security version is outside 1..16")
    for field in ("ota_release_id", "oci_release_id", "deployment_id", "qualification_id"):
        _require_identifier(value[field], f"subject {field}")
    return dict(value)


def validate_policy(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProductReleaseError("release policy must be an object")
    _exact_keys(value, POLICY_FIELDS, "release policy")
    if value["schema_version"] != SCHEMA_VERSION:
        raise ProductReleaseError("unsupported release policy schema")
    _require_identifier(value["policy_id"], "policy ID")
    _require_identifier(value["record_id"], "record ID")
    sequence = value["release_sequence"]
    if type(sequence) is not int or not 1 <= sequence <= 2147483647:
        raise ProductReleaseError("release sequence is outside range")
    previous = _require_sha(
        value["previous_record_sha256"], "previous record SHA-256", allow_zero=True
    )
    if (sequence == 1) != (previous == ZERO_SHA256):
        raise ProductReleaseError("genesis/previous record continuity is invalid")
    _validate_subject(value["subject"])
    valid_from = _parse_timestamp(value["valid_from"], "policy valid_from")
    valid_until = _parse_timestamp(value["valid_until"], "policy valid_until")
    if not valid_from < valid_until or valid_until - valid_from > datetime.timedelta(days=90):
        raise ProductReleaseError("policy validity must be positive and at most 90 days")
    required = value["required_evidence"]
    if not isinstance(required, list) or len(required) != len(EVIDENCE_TYPES):
        raise ProductReleaseError("release policy must contain the complete evidence set")
    seen: list[str] = []
    for index, entry in enumerate(required):
        if not isinstance(entry, dict):
            raise ProductReleaseError(f"required evidence {index} must be an object")
        _exact_keys(entry, TRUST_FIELDS, f"required evidence {index}")
        evidence_type = entry["evidence_type"]
        if evidence_type not in EVIDENCE_TYPES:
            raise ProductReleaseError(f"required evidence {index} has unknown type")
        seen.append(evidence_type)
        _require_identifier(entry["signing_key_id"], f"required evidence {index} key ID")
        _require_sha(entry["public_key_sha256"], f"required evidence {index} public key")
        maximum_age = entry["max_age_seconds"]
        if type(maximum_age) is not int or not 3600 <= maximum_age <= 180 * 86400:
            raise ProductReleaseError(f"required evidence {index} max age is outside range")
    if tuple(seen) != EVIDENCE_TYPES:
        raise ProductReleaseError("required evidence must be complete, unique, and sorted")
    slo_trust = value["backend_slo"]
    if not isinstance(slo_trust, dict):
        raise ProductReleaseError("backend SLO trust must be an object")
    _exact_keys(slo_trust, BACKEND_SLO_TRUST_FIELDS, "backend SLO trust")
    for field, label in (
        ("collector_id", "backend SLO collector ID"),
        ("signing_key_id", "backend SLO signing key ID"),
    ):
        _require_identifier(slo_trust[field], label)
        if not backend_slo.IDENTIFIER.fullmatch(slo_trust[field]):
            raise ProductReleaseError(f"{label} is outside the subordinate contract")
    _require_sha(slo_trust["public_key_sha256"], "backend SLO public key")
    _require_sha(slo_trust["policy_sha256"], "backend SLO policy SHA-256")
    if not backend_slo.IDENTIFIER.fullmatch(value["subject"]["deployment_id"]):
        raise ProductReleaseError(
            "subject deployment ID is outside the backend SLO contract"
        )
    _require_sha(value["tool_sha256"], "product release core SHA-256")
    _require_identifier(value["release_signing_key_id"], "release signing key ID")
    _require_sha(value["release_public_key_sha256"], "release public key SHA-256")
    return dict(value)


def load_policy(path: Path) -> tuple[dict[str, Any], bytes]:
    value, raw = _load_canonical(path, "product release policy")
    return validate_policy(value), raw


def _verify_tool_hash(policy: Mapping[str, Any]) -> None:
    source = _read_regular(Path(__file__).resolve(), MAX_JSON_BYTES, "product release core")
    if _sha256(source) != policy["tool_sha256"]:
        raise ProductReleaseError("product release core hash does not match policy")


def _validate_uri(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise ProductReleaseError("evidence URI has invalid format")
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower()
    address = None
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    if (
        parsed.scheme != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.query
        or host == "localhost"
        or host in {"example.com", "example.net", "example.org"}
        or host.endswith((".example", ".invalid", ".localhost", ".test"))
        or (
            address is not None
            and (
                address.is_private
                or address.is_loopback
                or address.is_link_local
                or address.is_multicast
                or address.is_reserved
                or address.is_unspecified
            )
        )
        or not parsed.path.startswith("/")
    ):
        raise ProductReleaseError("evidence URI must be a production HTTPS object reference")
    return value


def _unsigned_attestation(value: Mapping[str, Any]) -> bytes:
    unsigned = dict(value)
    unsigned.pop("signature_b64url", None)
    return EVIDENCE_SIGNATURE_DOMAIN + _canonical(unsigned)


def validate_attestation(
    value: Any,
    *,
    policy: Mapping[str, Any],
    trust: Mapping[str, Any],
    public_key_path: Path,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProductReleaseError("evidence attestation must be an object")
    _exact_keys(value, ATTESTATION_FIELDS, "evidence attestation")
    if value["schema_version"] != SCHEMA_VERSION:
        raise ProductReleaseError("unsupported evidence attestation schema")
    _require_identifier(value["evidence_id"], "evidence ID")
    evidence_type = value["evidence_type"]
    if evidence_type != trust["evidence_type"]:
        raise ProductReleaseError("evidence type does not match its policy slot")
    if value["subject"] != policy["subject"]:
        raise ProductReleaseError("evidence subject does not match the release")
    _validate_subject(value["subject"])
    if value["environment"] != ENVIRONMENT:
        raise ProductReleaseError("evidence is not from the production environment")
    if not isinstance(value["region"], str) or not REGION.fullmatch(value["region"]):
        raise ProductReleaseError("evidence region has invalid format")
    _reject_nonproduction_marker(value["region"], "evidence region")
    observed = _parse_timestamp(value["observed_at"], "evidence observed_at")
    evidence_until = _parse_timestamp(value["valid_until"], "evidence valid_until")
    release_start = _parse_timestamp(policy["valid_from"], "policy valid_from")
    release_until = _parse_timestamp(policy["valid_until"], "policy valid_until")
    if observed > release_start:
        raise ProductReleaseError("evidence was observed after release issuance")
    if release_start - observed > datetime.timedelta(seconds=trust["max_age_seconds"]):
        raise ProductReleaseError("evidence is older than its policy maximum")
    if evidence_until < release_until:
        raise ProductReleaseError("evidence expires before the release record")
    _validate_uri(value["evidence_uri"])
    _require_sha(value["evidence_sha256"], "evidence object SHA-256")
    if value["result"] != "PASS":
        raise ProductReleaseError("evidence result is not PASS")
    if value["signing_key_id"] != trust["signing_key_id"]:
        raise ProductReleaseError("evidence signing key ID does not match policy")
    if value["signature_algorithm"] != "Ed25519":
        raise ProductReleaseError("evidence signature algorithm is not Ed25519")
    public_key, fingerprint = _load_public_key(public_key_path)
    if fingerprint != trust["public_key_sha256"]:
        raise ProductReleaseError("evidence public key fingerprint does not match policy")
    signature = _decode_b64url(value["signature_b64url"], 64, "evidence signature")
    try:
        public_key.verify(signature, _unsigned_attestation(value))
    except InvalidSignature as error:
        raise ProductReleaseError("evidence signature is invalid") from error
    return dict(value)


def sign_attestation(
    unsigned: Mapping[str, Any], *, private_key_path: Path, expected_key_id: str
) -> dict[str, Any]:
    value = dict(unsigned)
    if "signature_b64url" in value:
        raise ProductReleaseError("unsigned evidence already contains a signature")
    value["signature_b64url"] = "A" * 86
    _exact_keys(value, ATTESTATION_FIELDS, "unsigned evidence")
    if value["signing_key_id"] != expected_key_id:
        raise ProductReleaseError("evidence signing key ID mismatch")
    key, _ = _load_private_key(private_key_path)
    value["signature_b64url"] = _b64url(key.sign(_unsigned_attestation(value)))
    return value


def _trust_index(policy: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    return {entry["evidence_type"]: entry for entry in policy["required_evidence"]}


def _summary(
    attestation: Mapping[str, Any], raw: bytes, trust: Mapping[str, Any]
) -> dict[str, Any]:
    return {
        "evidence_type": attestation["evidence_type"],
        "evidence_id": attestation["evidence_id"],
        "attestation_sha256": _sha256(raw),
        "evidence_uri": attestation["evidence_uri"],
        "evidence_sha256": attestation["evidence_sha256"],
        "region": attestation["region"],
        "observed_at": attestation["observed_at"],
        "valid_until": attestation["valid_until"],
        "authority_key_id": trust["signing_key_id"],
        "authority_public_key_sha256": trust["public_key_sha256"],
    }


def _validate_backend_slo_proof(
    *,
    policy: Mapping[str, Any],
    observation_path: Path,
    slo_policy_path: Path,
    public_key_path: Path,
) -> tuple[dict[str, Any], bytes, bytes]:
    trust = policy["backend_slo"]
    observation_raw = _read_regular(
        observation_path, MAX_JSON_BYTES, "backend SLO observation"
    )
    slo_policy_raw = _read_regular(
        slo_policy_path, MAX_JSON_BYTES, "trusted backend SLO policy"
    )
    if _sha256(slo_policy_raw) != trust["policy_sha256"]:
        raise ProductReleaseError("backend SLO policy digest does not match release policy")
    public_key_raw = _read_regular(
        public_key_path, MAX_KEY_BYTES, "backend SLO public key"
    )
    _, fingerprint = _parse_public_key(public_key_raw)
    if fingerprint != trust["public_key_sha256"]:
        raise ProductReleaseError(
            "backend SLO public key fingerprint does not match release policy"
        )
    release_start = _parse_timestamp(policy["valid_from"], "policy valid_from")
    try:
        with tempfile.TemporaryDirectory(prefix="xiaozhi-market-slo-") as raw_snapshot:
            snapshot = Path(raw_snapshot)
            snapshot_observation = snapshot / "observation.json"
            snapshot_policy = snapshot / "policy.json"
            snapshot_public_key = snapshot / "authority.pem"
            _write_new(snapshot_observation, observation_raw)
            _write_new(snapshot_policy, slo_policy_raw)
            _write_new(snapshot_public_key, public_key_raw)
            observation = backend_slo.validate_observation(
                snapshot_observation,
                snapshot_policy,
                snapshot_public_key,
                expected_signing_key_id=trust["signing_key_id"],
                expected_deployment_id=policy["subject"]["deployment_id"],
                expected_collector_id=trust["collector_id"],
                now=release_start,
            )
    except backend_slo.SLOError as error:
        raise ProductReleaseError(f"backend SLO proof rejected: {error}") from error
    generated = _parse_timestamp(observation["generated_at"], "backend SLO generated_at")
    if generated > release_start:
        raise ProductReleaseError("backend SLO proof was generated after release issuance")
    summary = {
        "observation_id": observation["observation_id"],
        "observation_sha256": _sha256(observation_raw),
        "policy_sha256": trust["policy_sha256"],
        "collector_id": observation["collector_id"],
        "window_start": observation["window_start"],
        "window_end": observation["window_end"],
        "generated_at": observation["generated_at"],
        "authority_key_id": trust["signing_key_id"],
        "authority_public_key_sha256": trust["public_key_sha256"],
    }
    _exact_keys(summary, BACKEND_SLO_SUMMARY_FIELDS, "backend SLO summary")
    return summary, observation_raw, slo_policy_raw


def _unsigned_record(value: Mapping[str, Any]) -> bytes:
    unsigned = dict(value)
    unsigned.pop("signature_b64url", None)
    return RECORD_SIGNATURE_DOMAIN + _canonical(unsigned)


def _record_from(
    policy: Mapping[str, Any],
    policy_raw: bytes,
    summaries: Sequence[Mapping[str, Any]],
    slo_summary: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "record_type": "PRODUCT_MARKET_RELEASE",
        "record_id": policy["record_id"],
        "policy_sha256": _sha256(policy_raw),
        "release_sequence": policy["release_sequence"],
        "previous_record_sha256": policy["previous_record_sha256"],
        "subject": policy["subject"],
        "issued_at": policy["valid_from"],
        "valid_until": policy["valid_until"],
        "evidence": list(summaries),
        "backend_slo": dict(slo_summary),
        "result": RESULT,
        "signing_key_id": policy["release_signing_key_id"],
        "signature_algorithm": "Ed25519",
    }


def _check_previous(policy: Mapping[str, Any], previous_record_path: Path | None) -> None:
    if policy["release_sequence"] == 1:
        if previous_record_path is not None:
            raise ProductReleaseError("genesis release must not provide a previous record")
        return
    if previous_record_path is None:
        raise ProductReleaseError("non-genesis release requires the exact previous record")
    previous, raw = _load_canonical(previous_record_path, "previous product release record")
    _exact_keys(previous, RECORD_FIELDS, "previous product release record")
    if _sha256(raw) != policy["previous_record_sha256"]:
        raise ProductReleaseError("previous product release record hash mismatch")
    if previous["schema_version"] != SCHEMA_VERSION or \
            previous["result"] != RESULT or \
            previous["record_type"] != "PRODUCT_MARKET_RELEASE":
        raise ProductReleaseError("previous product release record is not a market PASS")
    if previous["release_sequence"] + 1 != policy["release_sequence"]:
        raise ProductReleaseError("release sequence is not contiguous")


def _collect_attestations(
    *,
    policy: Mapping[str, Any],
    attestation_paths: Sequence[Path],
    evidence_public_keys: Mapping[str, Path],
    evidence_objects: Mapping[str, Path],
) -> tuple[list[dict[str, Any]], dict[str, bytes]]:
    if len(attestation_paths) != len(EVIDENCE_TYPES):
        raise ProductReleaseError("exactly one attestation per required evidence type is required")
    if set(evidence_public_keys) != set(EVIDENCE_TYPES):
        raise ProductReleaseError("evidence public-key map is incomplete or has extra types")
    if set(evidence_objects) != set(EVIDENCE_TYPES):
        raise ProductReleaseError("evidence object map is incomplete or has extra types")
    trust = _trust_index(policy)
    values: dict[str, dict[str, Any]] = {}
    raws: dict[str, bytes] = {}
    for path in attestation_paths:
        value, raw = _load_canonical(path, "product release evidence attestation")
        evidence_type = value.get("evidence_type")
        if evidence_type not in EVIDENCE_TYPES:
            raise ProductReleaseError("evidence attestation has unknown type")
        if evidence_type in values:
            raise ProductReleaseError("duplicate product release evidence type")
        values[evidence_type] = validate_attestation(
            value,
            policy=policy,
            trust=trust[evidence_type],
            public_key_path=evidence_public_keys[evidence_type],
        )
        if _hash_regular(
            evidence_objects[evidence_type],
            MAX_EVIDENCE_BYTES,
            f"{evidence_type} detailed evidence object",
        ) != value["evidence_sha256"]:
            raise ProductReleaseError(
                f"{evidence_type} detailed evidence object SHA-256 mismatch"
            )
        raws[evidence_type] = raw
    if tuple(sorted(values)) != EVIDENCE_TYPES:
        raise ProductReleaseError("product release evidence set is incomplete")
    summaries = [_summary(values[kind], raws[kind], trust[kind]) for kind in EVIDENCE_TYPES]
    return summaries, raws


def build_bundle(
    *,
    policy_path: Path,
    attestation_paths: Sequence[Path],
    evidence_public_keys: Mapping[str, Path],
    evidence_objects: Mapping[str, Path],
    backend_slo_observation_path: Path,
    backend_slo_policy_path: Path,
    backend_slo_public_key_path: Path,
    release_private_key_path: Path,
    output_path: Path,
    previous_record_path: Path | None = None,
) -> dict[str, Any]:
    policy, policy_raw = load_policy(policy_path)
    _verify_tool_hash(policy)
    _check_previous(policy, previous_record_path)
    summaries, attestation_raws = _collect_attestations(
        policy=policy,
        attestation_paths=attestation_paths,
        evidence_public_keys=evidence_public_keys,
        evidence_objects=evidence_objects,
    )
    slo_summary, slo_observation_raw, slo_policy_raw = _validate_backend_slo_proof(
        policy=policy,
        observation_path=backend_slo_observation_path,
        slo_policy_path=backend_slo_policy_path,
        public_key_path=backend_slo_public_key_path,
    )
    release_key, fingerprint = _load_private_key(release_private_key_path)
    if fingerprint != policy["release_public_key_sha256"]:
        raise ProductReleaseError("release private key does not match policy fingerprint")
    record = _record_from(policy, policy_raw, summaries, slo_summary)
    record["signature_b64url"] = _b64url(release_key.sign(_unsigned_record(record)))
    record_raw = _canonical(record)

    output = output_path.absolute()
    if output.exists() or output.is_symlink():
        raise ProductReleaseError("output path already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.parent.is_symlink() or not output.parent.is_dir():
        raise ProductReleaseError("output parent must be a non-symlink directory")
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    claimed = False
    try:
        evidence_dir = temporary / "evidence"
        evidence_dir.mkdir(mode=0o700)
        _write_new(temporary / "policy.json", policy_raw)
        _write_new(temporary / "backend-slo-policy.json", slo_policy_raw)
        _write_new(temporary / "backend-slo-observation.json", slo_observation_raw)
        for evidence_type in EVIDENCE_TYPES:
            _write_new(evidence_dir / f"{evidence_type}.json", attestation_raws[evidence_type])
        _write_new(temporary / "product-release-record.json", record_raw)
        _write_new(temporary / "READY", f"sha256:{_sha256(record_raw)}\n".encode("ascii"))
        _fsync_directory(evidence_dir)
        _fsync_directory(temporary)
        try:
            output.mkdir(mode=0o700)
            claimed = True
        except FileExistsError as error:
            raise ProductReleaseError("output path was claimed concurrently") from error
        os.rename(temporary / "policy.json", output / "policy.json")
        os.rename(
            temporary / "backend-slo-policy.json",
            output / "backend-slo-policy.json",
        )
        os.rename(
            temporary / "backend-slo-observation.json",
            output / "backend-slo-observation.json",
        )
        os.rename(temporary / "evidence", output / "evidence")
        os.rename(
            temporary / "product-release-record.json",
            output / "product-release-record.json",
        )
        _fsync_directory(output)
        os.rename(temporary / "READY", output / "READY")
        _fsync_directory(output)
        temporary.rmdir()
        _fsync_directory(output.parent)
        _lock_tree(output)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        if claimed:
            shutil.rmtree(output, ignore_errors=True)
        raise
    return record


def validate_bundle(
    root: Path,
    *,
    trusted_policy_path: Path,
    evidence_public_keys: Mapping[str, Path],
    evidence_objects: Mapping[str, Path],
    backend_slo_observation_path: Path,
    backend_slo_policy_path: Path,
    backend_slo_public_key_path: Path,
    release_public_key_path: Path,
    evaluation_time: str,
    previous_record_path: Path | None = None,
) -> dict[str, Any]:
    bundle = root.absolute()
    if bundle.is_symlink() or not bundle.is_dir():
        raise ProductReleaseError("product release bundle must be a non-symlink directory")
    policy, policy_raw = load_policy(trusted_policy_path)
    _verify_tool_hash(policy)
    bundled_policy, bundled_policy_raw = _load_canonical(
        bundle / "policy.json", "bundled product release policy"
    )
    if bundled_policy_raw != policy_raw or bundled_policy != policy:
        raise ProductReleaseError("bundled policy does not match the trusted policy")
    _check_previous(policy, previous_record_path)
    evaluation = _parse_timestamp(evaluation_time, "evaluation time")
    valid_from = _parse_timestamp(policy["valid_from"], "policy valid_from")
    valid_until = _parse_timestamp(policy["valid_until"], "policy valid_until")
    if not valid_from <= evaluation <= valid_until:
        raise ProductReleaseError("product release record is not valid at evaluation time")

    attestation_paths = [bundle / "evidence" / f"{kind}.json" for kind in EVIDENCE_TYPES]
    summaries, _ = _collect_attestations(
        policy=policy,
        attestation_paths=attestation_paths,
        evidence_public_keys=evidence_public_keys,
        evidence_objects=evidence_objects,
    )
    slo_summary, external_slo_raw, external_slo_policy_raw = _validate_backend_slo_proof(
        policy=policy,
        observation_path=backend_slo_observation_path,
        slo_policy_path=backend_slo_policy_path,
        public_key_path=backend_slo_public_key_path,
    )
    bundled_slo_raw = _read_regular(
        bundle / "backend-slo-observation.json",
        MAX_JSON_BYTES,
        "bundled backend SLO observation",
    )
    bundled_slo_policy_raw = _read_regular(
        bundle / "backend-slo-policy.json",
        MAX_JSON_BYTES,
        "bundled backend SLO policy",
    )
    if bundled_slo_raw != external_slo_raw or \
            bundled_slo_policy_raw != external_slo_policy_raw:
        raise ProductReleaseError(
            "bundled backend SLO proof does not match independent inputs"
        )
    record, record_raw = _load_canonical(
        bundle / "product-release-record.json", "product release record"
    )
    _exact_keys(record, RECORD_FIELDS, "product release record")
    expected = _record_from(policy, policy_raw, summaries, slo_summary)
    for key, expected_value in expected.items():
        if record.get(key) != expected_value:
            raise ProductReleaseError(f"product release record {key} does not match evidence")
    if record["signature_algorithm"] != "Ed25519":
        raise ProductReleaseError("product release signature algorithm is invalid")
    release_key, fingerprint = _load_public_key(release_public_key_path)
    if fingerprint != policy["release_public_key_sha256"]:
        raise ProductReleaseError("release public key does not match policy fingerprint")
    signature = _decode_b64url(record["signature_b64url"], 64, "product release signature")
    try:
        release_key.verify(signature, _unsigned_record(record))
    except InvalidSignature as error:
        raise ProductReleaseError("product release signature is invalid") from error
    ready = _read_regular(bundle / "READY", 128, "product release READY marker")
    if ready != f"sha256:{_sha256(record_raw)}\n".encode("ascii"):
        raise ProductReleaseError("product release READY marker is invalid")
    expected_files = {
        "READY",
        "policy.json",
        "backend-slo-policy.json",
        "backend-slo-observation.json",
        "product-release-record.json",
        *{f"evidence/{kind}.json" for kind in EVIDENCE_TYPES},
    }
    actual_files = {
        path.relative_to(bundle).as_posix()
        for path in bundle.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    if actual_files != expected_files:
        raise ProductReleaseError(
            f"product release file set mismatch; missing={sorted(expected_files - actual_files)}, "
            f"unexpected={sorted(actual_files - expected_files)}"
        )
    return record


def _parse_assignments(values: Sequence[str], label: str) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise ProductReleaseError(f"{label} must use TYPE=PATH")
        evidence_type, raw_path = value.split("=", 1)
        if evidence_type not in EVIDENCE_TYPES or not raw_path:
            raise ProductReleaseError(f"{label} has unknown type or empty path")
        if evidence_type in result:
            raise ProductReleaseError(f"duplicate {label} assignment")
        result[evidence_type] = Path(raw_path)
    if set(result) != set(EVIDENCE_TYPES):
        raise ProductReleaseError(f"{label} assignments must cover the fixed evidence set")
    return result


def parse_key_assignments(values: Sequence[str]) -> dict[str, Path]:
    return _parse_assignments(values, "evidence key")


def parse_object_assignments(values: Sequence[str]) -> dict[str, Path]:
    return _parse_assignments(values, "evidence object")
