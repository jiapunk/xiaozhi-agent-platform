#!/usr/bin/env python3
"""Build and verify a signed Companion App source supply-chain bundle."""

from __future__ import annotations

import base64
import binascii
import datetime
import hashlib
import json
import os
import plistlib
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


SCHEMA_VERSION = 1
SIGNATURE_DOMAIN = b"XIAOZHI-AGENT-COMPANION-SUPPLY-CHAIN-V1\x00"
RESULT = "SOURCE_SUPPLY_CHAIN_PASS"
RECEIPT_TYPE = "COMPANION_APP_SOURCE_SUPPLY_CHAIN"
BUILD_TYPE = "https://xiaozhi-agent.local/buildtypes/companion-source-supply-chain/v1"
BUILDER_ID = "https://xiaozhi-agent.local/builders/companion-source-supply-chain/v1"
SPDX_VERSION = "SPDX-2.3"
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 64 * 1024 * 1024
MAX_LICENSE_BYTES = 1024 * 1024
MAX_KEY_BYTES = 4096
ZERO_SHA256 = "0" * 64
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_REVISION = re.compile(r"^[0-9a-f]{40}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
VERSION = re.compile(r"^[0-9][A-Za-z0-9._+-]{0,63}$")
RESERVED_PARTS = {"dev", "demo", "fixture", "local", "mock", "test"}
PLATFORMS = ("ios15", "macos13")
TARGETS = (
    "ProductActionConsentUI",
    "ProductOnboardingCore",
    "ProductOnboardingESPProvision",
)
DEPENDENCY_IDENTITIES = (
    "esp-idf-provisioning-ios",
    "swift-protobuf",
)
LIMITATIONS = (
    "not_a_source_review_or_functional_test",
    "not_a_distribution_signed_app",
    "not_an_app_store_or_testflight_receipt",
    "not_apple_app_attest_or_device_evidence",
    "not_android_implementation_or_play_integrity_evidence",
    "not_a_release_day_vulnerability_or_legal_conclusion",
)
POLICY_FIELDS = {
    "schema_version",
    "policy_id",
    "release_id",
    "package_name",
    "package_version",
    "source_date_epoch",
    "platforms",
    "production_targets",
    "source_paths",
    "package_resolved_sha256",
    "upstream_lock_sha256",
    "privacy_manifest_path",
    "privacy_manifest_sha256",
    "dependencies",
    "tool_sha256",
    "signing_key_id",
    "signing_public_key_sha256",
}
DEPENDENCY_FIELDS = {
    "identity",
    "url",
    "version",
    "revision",
    "role",
    "license",
    "license_sha256",
    "checkout_path",
    "license_path",
    "bundle_path",
}
SOURCE_MANIFEST_FIELDS = {
    "schema_version",
    "release_id",
    "package_name",
    "package_version",
    "files",
}
SOURCE_FILE_FIELDS = {"path", "size", "sha1", "sha256"}
RECEIPT_FIELDS = {
    "schema_version",
    "receipt_type",
    "release_id",
    "policy_sha256",
    "package_name",
    "package_version",
    "source_date",
    "platforms",
    "production_targets",
    "package_resolved_sha256",
    "upstream_lock_sha256",
    "privacy_manifest_sha256",
    "source_manifest_sha256",
    "spdx_sha256",
    "provenance_sha256",
    "source_file_count",
    "dependencies",
    "license_files",
    "result",
    "production_ready",
    "limitations",
    "signing_key_id",
    "signature_algorithm",
    "signature_b64url",
}


class CompanionSupplyChainError(ValueError):
    pass


def _exact_keys(value: Mapping[str, Any], expected: Iterable[str], label: str) -> None:
    actual = set(value)
    wanted = set(expected)
    if actual != wanted:
        raise CompanionSupplyChainError(
            f"{label} fields mismatch; missing={sorted(wanted - actual)}, "
            f"unexpected={sorted(actual - wanted)}"
        )


def _strict_json(data: bytes, label: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise CompanionSupplyChainError(f"{label} contains duplicate fields")
            result[key] = value
        return result

    def reject_constant(value: str) -> Any:
        raise CompanionSupplyChainError(
            f"{label} contains non-standard constant {value}"
        )

    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CompanionSupplyChainError(f"{label} is not strict UTF-8 JSON") from error


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _compact_bytes(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()  # nosec: required by SPDX verificationCode


def _read_regular(path: Path, maximum: int, label: str) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise CompanionSupplyChainError(f"cannot open {label}") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise CompanionSupplyChainError(f"{label} must be a regular file")
        if not 1 <= info.st_size <= maximum:
            raise CompanionSupplyChainError(f"{label} size is outside range")
        chunks: list[bytes] = []
        remaining = info.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise CompanionSupplyChainError(f"{label} changed while being read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise CompanionSupplyChainError(f"{label} changed while being read")
        return b"".join(chunks)
    except OSError as error:
        raise CompanionSupplyChainError(f"cannot read {label}") from error
    finally:
        os.close(descriptor)


def _write_new(path: Path, data: bytes, mode: int = 0o400) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as error:
        raise CompanionSupplyChainError(f"cannot create {path.name}") from error
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
            raise CompanionSupplyChainError("supply-chain bundle contains a symlink")
        os.chmod(path, 0o555 if path.is_dir() else 0o444)
    os.chmod(root, 0o555)


def _safe_relative(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise CompanionSupplyChainError(f"{label} has invalid format")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(
        part in ("", ".", "..") for part in path.parts
    ):
        raise CompanionSupplyChainError(f"{label} must be a canonical relative path")
    return value


def _require_identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise CompanionSupplyChainError(f"{label} has invalid format")
    parts = {part for part in re.split(r"[^a-z0-9]+", value.lower()) if part}
    if parts & RESERVED_PARTS:
        raise CompanionSupplyChainError(f"{label} contains a non-production marker")
    return value


def _require_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value) or value == ZERO_SHA256:
        raise CompanionSupplyChainError(f"{label} is not a nonzero canonical SHA-256")
    return value


def _timestamp(epoch: int) -> str:
    if type(epoch) is not int or not 1_577_836_800 <= epoch <= 4_102_444_800:
        raise CompanionSupplyChainError("source_date_epoch is outside supported range")
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_b64url(value: Any, size: int, label: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise CompanionSupplyChainError(f"{label} is not canonical base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except (ValueError, binascii.Error) as error:
        raise CompanionSupplyChainError(f"{label} is not base64url") from error
    if len(decoded) != size or _b64url(decoded) != value:
        raise CompanionSupplyChainError(f"{label} is not canonical base64url")
    return decoded


def _parse_public_key(raw: bytes) -> tuple[Ed25519PublicKey, str]:
    try:
        key = serialization.load_pem_public_key(raw)
    except (TypeError, ValueError) as error:
        raise CompanionSupplyChainError("invalid Ed25519 public key PEM") from error
    if not isinstance(key, Ed25519PublicKey):
        raise CompanionSupplyChainError("public key must be Ed25519")
    public_raw = key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return key, _sha256(public_raw)


def _load_public_key(path: Path) -> tuple[Ed25519PublicKey, str]:
    return _parse_public_key(_read_regular(path, MAX_KEY_BYTES, "trusted public key"))


def _load_private_key(path: Path) -> tuple[Ed25519PrivateKey, str]:
    raw = _read_regular(path, MAX_KEY_BYTES, "signing private key")
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except (TypeError, ValueError) as error:
        raise CompanionSupplyChainError("invalid Ed25519 private key PEM") from error
    if not isinstance(key, Ed25519PrivateKey):
        raise CompanionSupplyChainError("private key must be Ed25519")
    public_raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return key, _sha256(public_raw)


def validate_policy(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CompanionSupplyChainError("supply-chain policy must be an object")
    _exact_keys(value, POLICY_FIELDS, "supply-chain policy")
    if value["schema_version"] != SCHEMA_VERSION:
        raise CompanionSupplyChainError("unsupported supply-chain policy schema")
    _require_identifier(value["policy_id"], "policy ID")
    _require_identifier(value["release_id"], "release ID")
    _require_identifier(value["package_name"], "package name")
    if not isinstance(value["package_version"], str) or not VERSION.fullmatch(
        value["package_version"]
    ):
        raise CompanionSupplyChainError("package version has invalid format")
    _timestamp(value["source_date_epoch"])
    if value["platforms"] != list(PLATFORMS):
        raise CompanionSupplyChainError("platform inventory differs")
    if value["production_targets"] != list(TARGETS):
        raise CompanionSupplyChainError("production target inventory differs")
    source_paths = value["source_paths"]
    if not isinstance(source_paths, list) or not 4 <= len(source_paths) <= 256:
        raise CompanionSupplyChainError("source path inventory size is invalid")
    checked_sources = [_safe_relative(path, "source path") for path in source_paths]
    if checked_sources != sorted(set(checked_sources)):
        raise CompanionSupplyChainError("source paths must be unique and sorted")
    required_sources = {"Package.swift", "Package.resolved", "upstream-lock.json"}
    if not required_sources.issubset(checked_sources):
        raise CompanionSupplyChainError("source inventory omits package metadata")
    for path in checked_sources:
        if path in required_sources:
            continue
        if not path.startswith("Sources/") or not path.endswith((".swift", ".xcprivacy")):
            raise CompanionSupplyChainError("source inventory contains unsupported path")
    privacy_path = _safe_relative(value["privacy_manifest_path"], "privacy manifest path")
    if not privacy_path.endswith("/PrivacyInfo.xcprivacy") or privacy_path not in checked_sources:
        raise CompanionSupplyChainError("privacy manifest is absent from source inventory")
    for field, label in (
        ("package_resolved_sha256", "Package.resolved SHA-256"),
        ("upstream_lock_sha256", "upstream lock SHA-256"),
        ("privacy_manifest_sha256", "privacy manifest SHA-256"),
        ("tool_sha256", "supply-chain tool SHA-256"),
        ("signing_public_key_sha256", "signing public key SHA-256"),
    ):
        _require_sha(value[field], label)
    dependencies = value["dependencies"]
    if not isinstance(dependencies, list) or len(dependencies) != len(
        DEPENDENCY_IDENTITIES
    ):
        raise CompanionSupplyChainError("dependency inventory is incomplete")
    identities: list[str] = []
    bundle_paths: list[str] = []
    for index, dependency in enumerate(dependencies):
        if not isinstance(dependency, dict):
            raise CompanionSupplyChainError(f"dependency {index} must be an object")
        _exact_keys(dependency, DEPENDENCY_FIELDS, f"dependency {index}")
        identity = dependency["identity"]
        if identity not in DEPENDENCY_IDENTITIES:
            raise CompanionSupplyChainError(f"dependency {index} identity differs")
        identities.append(identity)
        parsed = urlparse(dependency["url"] if isinstance(dependency["url"], str) else "")
        if (
            parsed.scheme != "https"
            or parsed.hostname != "github.com"
            or parsed.query
            or parsed.fragment
            or not parsed.path.endswith(".git")
        ):
            raise CompanionSupplyChainError(f"dependency {index} URL is not approved HTTPS git")
        if not isinstance(dependency["version"], str) or not VERSION.fullmatch(
            dependency["version"]
        ):
            raise CompanionSupplyChainError(f"dependency {index} version is invalid")
        if not isinstance(dependency["revision"], str) or not GIT_REVISION.fullmatch(
            dependency["revision"]
        ):
            raise CompanionSupplyChainError(f"dependency {index} revision is invalid")
        _require_identifier(dependency["role"], f"dependency {index} role")
        if dependency["license"] != "Apache-2.0":
            raise CompanionSupplyChainError(f"dependency {index} license differs")
        _require_sha(dependency["license_sha256"], f"dependency {index} license SHA-256")
        checkout = _safe_relative(dependency["checkout_path"], f"dependency {index} checkout")
        if checkout != f".build/checkouts/{identity}":
            raise CompanionSupplyChainError(f"dependency {index} checkout path differs")
        license_path = _safe_relative(
            dependency["license_path"], f"dependency {index} license path"
        )
        if len(PurePosixPath(license_path).parts) != 1:
            raise CompanionSupplyChainError(f"dependency {index} license path differs")
        bundle_path = _safe_relative(
            dependency["bundle_path"], f"dependency {index} bundle path"
        )
        if not bundle_path.startswith("licenses/") or not bundle_path.endswith(".txt"):
            raise CompanionSupplyChainError(f"dependency {index} bundle path differs")
        bundle_paths.append(bundle_path)
    if tuple(identities) != DEPENDENCY_IDENTITIES:
        raise CompanionSupplyChainError("dependencies must be complete, unique and sorted")
    if len(bundle_paths) != len(set(bundle_paths)):
        raise CompanionSupplyChainError("dependency license bundle paths are duplicated")
    _require_identifier(value["signing_key_id"], "signing key ID")
    return dict(value)


def load_policy(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = _read_regular(path, MAX_JSON_BYTES, "Companion supply-chain policy")
    value = _strict_json(raw, "Companion supply-chain policy")
    if _json_bytes(value) != raw:
        raise CompanionSupplyChainError("Companion supply-chain policy is not canonical")
    return validate_policy(value), raw


def _verify_tool_hash(policy: Mapping[str, Any]) -> None:
    raw = _read_regular(Path(__file__).resolve(), MAX_JSON_BYTES, "supply-chain tool")
    if _sha256(raw) != policy["tool_sha256"]:
        raise CompanionSupplyChainError("supply-chain tool hash does not match policy")


def _source_inventory(app: Path, policy: Mapping[str, Any]) -> tuple[dict[str, Any], bytes]:
    if app.is_symlink() or not app.is_dir():
        raise CompanionSupplyChainError("Companion App root must be a non-symlink directory")
    discovered = {"Package.swift", "Package.resolved", "upstream-lock.json"}
    sources = app / "Sources"
    if sources.is_symlink() or not sources.is_dir():
        raise CompanionSupplyChainError("Companion Sources must be a non-symlink directory")
    for path in sources.rglob("*"):
        if path.is_symlink():
            raise CompanionSupplyChainError("Companion source tree contains a symlink")
        if path.is_file():
            relative = path.relative_to(app).as_posix()
            if not relative.endswith((".swift", ".xcprivacy")):
                raise CompanionSupplyChainError(
                    f"Companion source tree contains unsupported file {relative}"
                )
            discovered.add(relative)
    expected = set(policy["source_paths"])
    if discovered != expected:
        raise CompanionSupplyChainError(
            f"Companion source inventory differs; missing={sorted(expected - discovered)}, "
            f"unexpected={sorted(discovered - expected)}"
        )
    entries: list[dict[str, Any]] = []
    total = 0
    raws: dict[str, bytes] = {}
    for relative in policy["source_paths"]:
        raw = _read_regular(app / relative, MAX_SOURCE_BYTES, f"Companion source {relative}")
        total += len(raw)
        if total > MAX_TOTAL_SOURCE_BYTES:
            raise CompanionSupplyChainError("Companion source inventory is too large")
        raws[relative] = raw
        entries.append(
            {
                "path": relative,
                "size": len(raw),
                "sha1": _sha1(raw),
                "sha256": _sha256(raw),
            }
        )
    for entry in entries:
        _exact_keys(entry, SOURCE_FILE_FIELDS, "source file")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "release_id": policy["release_id"],
        "package_name": policy["package_name"],
        "package_version": policy["package_version"],
        "files": entries,
    }
    _exact_keys(manifest, SOURCE_MANIFEST_FIELDS, "source manifest")
    if _sha256(raws["Package.resolved"]) != policy["package_resolved_sha256"]:
        raise CompanionSupplyChainError("Package.resolved digest differs from policy")
    if _sha256(raws["upstream-lock.json"]) != policy["upstream_lock_sha256"]:
        raise CompanionSupplyChainError("upstream lock digest differs from policy")
    privacy_raw = raws[policy["privacy_manifest_path"]]
    if _sha256(privacy_raw) != policy["privacy_manifest_sha256"]:
        raise CompanionSupplyChainError("privacy manifest digest differs from policy")
    try:
        privacy = plistlib.loads(privacy_raw)
    except plistlib.InvalidFileException as error:
        raise CompanionSupplyChainError("privacy manifest is not a valid plist") from error
    if privacy != {
        "NSPrivacyAccessedAPITypes": [],
        "NSPrivacyCollectedDataTypes": [],
        "NSPrivacyTracking": False,
        "NSPrivacyTrackingDomains": [],
    }:
        raise CompanionSupplyChainError("privacy manifest exceeds reviewed package boundary")
    _validate_package_resolved(raws["Package.resolved"], policy)
    return manifest, _json_bytes(manifest)


def _validate_package_resolved(raw: bytes, policy: Mapping[str, Any]) -> None:
    value = _strict_json(raw, "Package.resolved")
    if not isinstance(value, dict) or set(value) != {"originHash", "pins", "version"}:
        raise CompanionSupplyChainError("Package.resolved structure differs")
    if value["version"] != 3 or not isinstance(value["originHash"], str) or not SHA256.fullmatch(
        value["originHash"]
    ):
        raise CompanionSupplyChainError("Package.resolved metadata differs")
    pins = value["pins"]
    if not isinstance(pins, list) or len(pins) != len(policy["dependencies"]):
        raise CompanionSupplyChainError("Package.resolved dependency set differs")
    expected = {entry["identity"]: entry for entry in policy["dependencies"]}
    seen: list[str] = []
    for pin in pins:
        if not isinstance(pin, dict) or set(pin) != {"identity", "kind", "location", "state"}:
            raise CompanionSupplyChainError("Package.resolved pin fields differ")
        identity = pin["identity"]
        if identity not in expected or identity in seen:
            raise CompanionSupplyChainError("Package.resolved pin identity differs")
        seen.append(identity)
        dependency = expected[identity]
        if pin["kind"] != "remoteSourceControl" or pin["location"] != dependency["url"]:
            raise CompanionSupplyChainError("Package.resolved pin source differs")
        state = pin["state"]
        if not isinstance(state, dict) or set(state) != {"revision", "version"}:
            raise CompanionSupplyChainError("Package.resolved pin state differs")
        if state["revision"] != dependency["revision"] or state["version"] != dependency["version"]:
            raise CompanionSupplyChainError("Package.resolved pin revision differs")
    if tuple(sorted(seen)) != DEPENDENCY_IDENTITIES:
        raise CompanionSupplyChainError("Package.resolved dependency order/set differs")


def _git(checkout: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    return subprocess.run(
        ["git", "-C", str(checkout), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        env=environment,
    )


def _dependency_licenses(
    app: Path, policy: Mapping[str, Any]
) -> tuple[dict[str, bytes], list[dict[str, Any]]]:
    raw_by_bundle: dict[str, bytes] = {}
    records: list[dict[str, Any]] = []
    for dependency in policy["dependencies"]:
        checkout = app / dependency["checkout_path"]
        if checkout.is_symlink() or not checkout.is_dir():
            raise CompanionSupplyChainError(
                f"dependency checkout {dependency['identity']} is unavailable"
            )
        head = _git(checkout, "rev-parse", "HEAD")
        if head.returncode or head.stdout.strip() != dependency["revision"]:
            raise CompanionSupplyChainError(
                f"dependency checkout {dependency['identity']} revision differs"
            )
        status = _git(checkout, "status", "--porcelain=v1", "--untracked-files=all")
        if status.returncode or status.stdout:
            raise CompanionSupplyChainError(
                f"dependency checkout {dependency['identity']} is dirty"
            )
        raw = _read_regular(
            checkout / dependency["license_path"],
            MAX_LICENSE_BYTES,
            f"{dependency['identity']} license",
        )
        if _sha256(raw) != dependency["license_sha256"]:
            raise CompanionSupplyChainError(
                f"dependency {dependency['identity']} license digest differs"
            )
        bundle_path = dependency["bundle_path"]
        raw_by_bundle[bundle_path] = raw
        records.append(
            {
                "path": bundle_path,
                "sha256": _sha256(raw),
                "size": len(raw),
            }
        )
    return raw_by_bundle, records


def _spdx(
    policy: Mapping[str, Any], source_manifest: Mapping[str, Any], manifest_raw: bytes
) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    relationships: list[dict[str, str]] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-Package-CompanionApp",
        }
    ]
    for index, source in enumerate(source_manifest["files"], start=1):
        file_id = f"SPDXRef-File-{index:04d}"
        files.append(
            {
                "SPDXID": file_id,
                "checksums": [
                    {"algorithm": "SHA1", "checksumValue": source["sha1"]},
                    {"algorithm": "SHA256", "checksumValue": source["sha256"]},
                ],
                "copyrightText": "NOASSERTION",
                "fileName": f"./{source['path']}",
                "licenseConcluded": "NOASSERTION",
                "licenseInfoInFiles": ["NOASSERTION"],
            }
        )
        relationships.append(
            {
                "spdxElementId": "SPDXRef-Package-CompanionApp",
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": file_id,
            }
        )
    verification_code = _sha1(
        "".join(sorted(source["sha1"] for source in source_manifest["files"])).encode(
            "ascii"
        )
    )
    packages: list[dict[str, Any]] = [
        {
            "SPDXID": "SPDXRef-Package-CompanionApp",
            "copyrightText": "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": True,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "name": policy["package_name"],
            "packageVerificationCode": {
                "packageVerificationCodeValue": verification_code
            },
            "versionInfo": policy["package_version"],
        }
    ]
    for index, dependency in enumerate(policy["dependencies"], start=1):
        package_id = f"SPDXRef-Package-Dependency-{index:02d}"
        packages.append(
            {
                "SPDXID": package_id,
                "copyrightText": "NOASSERTION",
                "downloadLocation": f"{dependency['url']}@{dependency['revision']}",
                "filesAnalyzed": False,
                "licenseConcluded": dependency["license"],
                "licenseDeclared": dependency["license"],
                "name": dependency["identity"],
                "versionInfo": dependency["version"],
            }
        )
        relationships.append(
            {
                "spdxElementId": "SPDXRef-Package-CompanionApp",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": package_id,
            }
        )
    return {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": _timestamp(policy["source_date_epoch"]),
            "creators": ["Tool: xiaozhi-companion-supply-chain-v1"],
        },
        "dataLicense": "CC0-1.0",
        "documentDescribes": ["SPDXRef-Package-CompanionApp"],
        "documentNamespace": (
            "https://xiaozhi-agent.local/spdx/companion-app/"
            f"{policy['release_id']}/{_sha256(manifest_raw)}"
        ),
        "files": files,
        "name": f"{policy['package_name']}-{policy['release_id']}",
        "packages": packages,
        "relationships": relationships,
        "spdxVersion": SPDX_VERSION,
    }


def _provenance(
    policy: Mapping[str, Any], manifest_raw: bytes, spdx_raw: bytes
) -> dict[str, Any]:
    dependencies = [
        {
            "uri": f"git+{dependency['url']}@{dependency['revision']}",
            "digest": {"gitCommit": dependency["revision"]},
        }
        for dependency in policy["dependencies"]
    ]
    dependencies.extend(
        [
            {
                "uri": "file:Package.resolved",
                "digest": {"sha256": policy["package_resolved_sha256"]},
            },
            {
                "uri": "file:upstream-lock.json",
                "digest": {"sha256": policy["upstream_lock_sha256"]},
            },
        ]
    )
    timestamp = _timestamp(policy["source_date_epoch"])
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": "source-manifest.json",
                "digest": {"sha256": _sha256(manifest_raw)},
            },
            {
                "name": "companion-app.spdx.json",
                "digest": {"sha256": _sha256(spdx_raw)},
            },
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": BUILD_TYPE,
                "externalParameters": {
                    "release_id": policy["release_id"],
                    "package_name": policy["package_name"],
                    "package_version": policy["package_version"],
                    "platforms": policy["platforms"],
                    "production_targets": policy["production_targets"],
                    "source_date_epoch": policy["source_date_epoch"],
                },
                "internalParameters": {},
                "resolvedDependencies": dependencies,
            },
            "runDetails": {
                "builder": {"id": BUILDER_ID},
                "metadata": {
                    "finishedOn": timestamp,
                    "invocationId": policy["release_id"],
                    "startedOn": timestamp,
                },
            },
        },
    }


def _dependency_summary(policy: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "identity": dependency["identity"],
            "license": dependency["license"],
            "license_sha256": dependency["license_sha256"],
            "revision": dependency["revision"],
            "version": dependency["version"],
        }
        for dependency in policy["dependencies"]
    ]


def _unsigned_receipt(value: Mapping[str, Any]) -> bytes:
    unsigned = dict(value)
    unsigned.pop("signature_b64url", None)
    return SIGNATURE_DOMAIN + _compact_bytes(unsigned)


def _receipt(
    policy: Mapping[str, Any],
    policy_raw: bytes,
    manifest_raw: bytes,
    spdx_raw: bytes,
    provenance_raw: bytes,
    license_records: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "receipt_type": RECEIPT_TYPE,
        "release_id": policy["release_id"],
        "policy_sha256": _sha256(policy_raw),
        "package_name": policy["package_name"],
        "package_version": policy["package_version"],
        "source_date": _timestamp(policy["source_date_epoch"]),
        "platforms": list(policy["platforms"]),
        "production_targets": list(policy["production_targets"]),
        "package_resolved_sha256": policy["package_resolved_sha256"],
        "upstream_lock_sha256": policy["upstream_lock_sha256"],
        "privacy_manifest_sha256": policy["privacy_manifest_sha256"],
        "source_manifest_sha256": _sha256(manifest_raw),
        "spdx_sha256": _sha256(spdx_raw),
        "provenance_sha256": _sha256(provenance_raw),
        "source_file_count": len(policy["source_paths"]),
        "dependencies": _dependency_summary(policy),
        "license_files": [dict(record) for record in license_records],
        "result": RESULT,
        "production_ready": False,
        "limitations": list(LIMITATIONS),
        "signing_key_id": policy["signing_key_id"],
        "signature_algorithm": "Ed25519",
    }


def _derive(
    app: Path, policy: Mapping[str, Any], policy_raw: bytes
) -> tuple[dict[str, bytes], dict[str, Any]]:
    manifest, manifest_raw = _source_inventory(app, policy)
    license_raws, license_records = _dependency_licenses(app, policy)
    spdx_raw = _json_bytes(_spdx(policy, manifest, manifest_raw))
    provenance_raw = _json_bytes(_provenance(policy, manifest_raw, spdx_raw))
    receipt = _receipt(
        policy,
        policy_raw,
        manifest_raw,
        spdx_raw,
        provenance_raw,
        license_records,
    )
    artifacts = {
        "policy.json": policy_raw,
        "source-manifest.json": manifest_raw,
        "companion-app.spdx.json": spdx_raw,
        "companion-app.provenance.json": provenance_raw,
        **license_raws,
    }
    return artifacts, receipt


def build_bundle(
    *,
    project_root: Path,
    policy_path: Path,
    signing_private_key_path: Path,
    output_path: Path,
) -> dict[str, Any]:
    policy, policy_raw = load_policy(policy_path)
    _verify_tool_hash(policy)
    app = project_root.resolve() / "companion-app"
    artifacts, receipt = _derive(app, policy, policy_raw)
    key, fingerprint = _load_private_key(signing_private_key_path)
    if fingerprint != policy["signing_public_key_sha256"]:
        raise CompanionSupplyChainError("signing private key fingerprint differs from policy")
    receipt["signature_b64url"] = _b64url(key.sign(_unsigned_receipt(receipt)))
    receipt_raw = _json_bytes(receipt)
    artifacts["receipt.json"] = receipt_raw
    artifacts["READY"] = f"sha256:{_sha256(receipt_raw)}\n".encode("ascii")

    output = output_path.absolute()
    if output.exists() or output.is_symlink():
        raise CompanionSupplyChainError("output path already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.parent.is_symlink() or not output.parent.is_dir():
        raise CompanionSupplyChainError("output parent must be a non-symlink directory")
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    claimed = False
    try:
        licenses = temporary / "licenses"
        licenses.mkdir(mode=0o700)
        for relative, raw in sorted(artifacts.items()):
            _write_new(temporary / relative, raw)
        _fsync_directory(licenses)
        _fsync_directory(temporary)
        try:
            output.mkdir(mode=0o700)
            claimed = True
        except FileExistsError as error:
            raise CompanionSupplyChainError("output path was claimed concurrently") from error
        for relative in sorted(artifacts):
            if relative == "READY" or relative.startswith("licenses/"):
                continue
            os.rename(temporary / relative, output / relative)
        os.rename(temporary / "licenses", output / "licenses")
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
    return receipt


def validate_bundle(
    root: Path,
    *,
    project_root: Path,
    trusted_policy_path: Path,
    trusted_public_key_path: Path,
) -> dict[str, Any]:
    bundle = root.absolute()
    if bundle.is_symlink() or not bundle.is_dir():
        raise CompanionSupplyChainError("supply-chain bundle must be a non-symlink directory")
    policy, policy_raw = load_policy(trusted_policy_path)
    _verify_tool_hash(policy)
    bundled_policy = _read_regular(bundle / "policy.json", MAX_JSON_BYTES, "bundled policy")
    if bundled_policy != policy_raw:
        raise CompanionSupplyChainError("bundled policy differs from trusted policy")
    expected_artifacts, expected_receipt = _derive(
        project_root.resolve() / "companion-app", policy, policy_raw
    )
    for relative, expected_raw in expected_artifacts.items():
        actual = _read_regular(
            bundle / relative,
            MAX_LICENSE_BYTES if relative.startswith("licenses/") else MAX_JSON_BYTES,
            f"bundled {relative}",
        )
        if actual != expected_raw:
            raise CompanionSupplyChainError(f"bundled {relative} differs from independent input")
    receipt_raw = _read_regular(bundle / "receipt.json", MAX_JSON_BYTES, "signed receipt")
    receipt = _strict_json(receipt_raw, "signed receipt")
    if _json_bytes(receipt) != receipt_raw or not isinstance(receipt, dict):
        raise CompanionSupplyChainError("signed receipt is not canonical")
    _exact_keys(receipt, RECEIPT_FIELDS, "signed receipt")
    for key, expected_value in expected_receipt.items():
        if receipt.get(key) != expected_value:
            raise CompanionSupplyChainError(f"signed receipt {key} differs")
    if receipt["signature_algorithm"] != "Ed25519":
        raise CompanionSupplyChainError("signed receipt algorithm differs")
    key, fingerprint = _load_public_key(trusted_public_key_path)
    if fingerprint != policy["signing_public_key_sha256"]:
        raise CompanionSupplyChainError("trusted public key fingerprint differs from policy")
    signature = _decode_b64url(receipt["signature_b64url"], 64, "receipt signature")
    try:
        key.verify(signature, _unsigned_receipt(receipt))
    except InvalidSignature as error:
        raise CompanionSupplyChainError("receipt signature is invalid") from error
    ready = _read_regular(bundle / "READY", 128, "READY marker")
    if ready != f"sha256:{_sha256(receipt_raw)}\n".encode("ascii"):
        raise CompanionSupplyChainError("READY marker does not bind signed receipt")
    expected_files = {
        "READY",
        "policy.json",
        "source-manifest.json",
        "companion-app.spdx.json",
        "companion-app.provenance.json",
        "receipt.json",
        *{dependency["bundle_path"] for dependency in policy["dependencies"]},
    }
    actual_files = {
        path.relative_to(bundle).as_posix()
        for path in bundle.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    if actual_files != expected_files:
        raise CompanionSupplyChainError(
            f"bundle file set differs; missing={sorted(expected_files - actual_files)}, "
            f"unexpected={sorted(actual_files - expected_files)}"
        )
    return receipt
