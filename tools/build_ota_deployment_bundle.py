#!/usr/bin/env python3
"""Build one fail-closed OTA deployment bundle from signed release artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import posixpath
import shutil
import stat
from pathlib import Path
from urllib.parse import urlsplit

from sign_release_manifest import (
    MAX_IMAGE_SIZE,
    ManifestError,
    load_manifest_json,
    validate_authority,
    verify_release_artifacts,
)


MAX_PUBLIC_KEY_BYTES = 4096
MAX_SDKCONFIG_BYTES = 1024 * 1024
RECEIPT_FIELDS = {
    "schema",
    "release_id",
    "signing_key_id",
    "project",
    "board",
    "channel",
    "version",
    "release_sequence",
    "secure_version",
    "image_authority",
    "image_url_path",
    "image_size",
    "image_sha256",
    "manifest_sha256",
    "public_key_sha256",
    "sdkconfig_sha256",
    "control_registry_sha256",
    "origin_catalog_sha256",
    "rollout_enabled",
    "rollout_basis_points",
    "retry_after_seconds",
}


class DeploymentBundleError(ValueError):
    pass


def _read_regular(path: Path, maximum: int, label: str) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise DeploymentBundleError(f"cannot open {label}") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise DeploymentBundleError(f"{label} must be a regular file")
        if not 1 <= info.st_size <= maximum:
            raise DeploymentBundleError(f"{label} size is outside range")
        chunks: list[bytes] = []
        remaining = info.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise DeploymentBundleError(f"{label} changed while being read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise DeploymentBundleError(f"{label} changed while being read")
        return b"".join(chunks)
    except OSError as error:
        raise DeploymentBundleError(f"cannot read {label}") from error
    finally:
        os.close(descriptor)


def _strict_json(data: bytes, label: str) -> object:
    def exact_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise DeploymentBundleError(f"{label} contains duplicate fields")
            result[key] = value
        return result

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=exact_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DeploymentBundleError(f"{label} is not strict UTF-8 JSON") from error


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_url_path(value: str) -> None:
    if (
        not 2 <= len(value) <= 512
        or not value.startswith("/")
        or posixpath.normpath(value) != value
        or value.endswith("/")
        or "//" in value
        or any(character in value for character in "%\\?#")
        or not value.endswith(".bin")
    ):
        raise DeploymentBundleError("manifest image URL path is not origin-safe")
    for character in value:
        if character.isascii() and (character.isalnum() or character in "/-_."):
            continue
        raise DeploymentBundleError("manifest image URL path is not origin-safe")


def _expected_documents(
    manifest: dict[str, object],
    url_path: str,
    retry_after_seconds: int,
    *,
    rollout_enabled: bool = False,
    rollout_basis_points: int = 0,
) -> tuple[dict[str, object], dict[str, object]]:
    if type(rollout_enabled) is not bool or type(rollout_basis_points) is not int:
        raise DeploymentBundleError("rollout state has invalid types")
    if rollout_enabled:
        if not 1 <= rollout_basis_points <= 10000:
            raise DeploymentBundleError("enabled rollout must have a nonzero cohort")
    elif rollout_basis_points != 0:
        raise DeploymentBundleError("disabled rollout must have a zero cohort")
    control_registry: dict[str, object] = {
        "version": 1,
        "signing_keys": [
            {
                "key_id": manifest["signing_key_id"],
                "public_key_file": "release-public.pem",
            }
        ],
        "releases": [
            {
                "manifest_file": "release-manifest.json",
                "enabled": rollout_enabled,
                "rollout_basis_points": rollout_basis_points,
                "retry_after_seconds": retry_after_seconds,
            }
        ],
    }
    origin_catalog: dict[str, object] = {
        "version": 1,
        "objects": [
            {
                "release_id": manifest["release_id"],
                "image_sha256": manifest["image_sha256"],
                "image_size": manifest["image_size"],
                "url_path": url_path,
                "image_file": "objects" + url_path,
            }
        ],
    }
    return control_registry, origin_catalog


def _expected_receipt(
    manifest: dict[str, object],
    authority: str,
    url_path: str,
    retry_after_seconds: int,
    manifest_bytes: bytes,
    public_key_bytes: bytes,
    sdkconfig_bytes: bytes,
    control_registry_bytes: bytes,
    origin_catalog_bytes: bytes,
) -> dict[str, object]:
    return {
        "schema": 1,
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
        "manifest_sha256": _sha256(manifest_bytes),
        "public_key_sha256": _sha256(public_key_bytes),
        "sdkconfig_sha256": _sha256(sdkconfig_bytes),
        "control_registry_sha256": _sha256(control_registry_bytes),
        "origin_catalog_sha256": _sha256(origin_catalog_bytes),
        "rollout_enabled": False,
        "rollout_basis_points": 0,
        "retry_after_seconds": retry_after_seconds,
    }


def _write_new(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o400)
    except OSError as error:
        raise DeploymentBundleError(f"cannot create bundle file {path.name}") from error
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


def _lock_bundle_tree(root: Path) -> None:
    paths = sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True)
    for path in paths:
        if path.is_symlink():
            raise DeploymentBundleError("bundle contains a symlink")
        os.chmod(path, 0o555 if path.is_dir() else 0o444)
    os.chmod(root, 0o555)


def _require_read_only_tree(root: Path, expected_files: set[Path]) -> None:
    actual_files: set[Path] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise DeploymentBundleError("bundle contains a symlink")
        relative = path.relative_to(root)
        mode = path.lstat().st_mode
        if mode & 0o222:
            raise DeploymentBundleError("bundle tree must be read-only")
        if path.is_file():
            actual_files.add(relative)
        elif not path.is_dir():
            raise DeploymentBundleError("bundle contains a non-regular object")
    if root.lstat().st_mode & 0o222:
        raise DeploymentBundleError("bundle root must be read-only")
    if actual_files != expected_files:
        raise DeploymentBundleError("bundle file layout is not exact")


def _prepare_artifacts(
    manifest_bytes: bytes,
    public_key_bytes: bytes,
    image_bytes: bytes,
    sdkconfig_bytes: bytes,
    *,
    expected_authority: str,
    retry_after_seconds: int,
    reset_qualification_receipt: bytes | None = None,
    reset_qualification_public_key: bytes | None = None,
    reset_qualification_signing_key_id: str | None = None,
) -> tuple[
    dict[str, object],
    str,
    bytes,
    bytes,
    bytes,
]:
    if not 60 <= retry_after_seconds <= 86400:
        raise DeploymentBundleError("retry-after seconds is outside range")
    validate_authority(expected_authority)
    if expected_authority != expected_authority.lower():
        raise DeploymentBundleError("release authority must be canonical lowercase")
    manifest = load_manifest_json(manifest_bytes)
    try:
        sdkconfig_text = sdkconfig_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise DeploymentBundleError("sdkconfig is not UTF-8") from error
    verify_release_artifacts(
        manifest,
        public_key_bytes,
        image_bytes,
        sdkconfig_text,
        expected_authority=expected_authority,
        reset_qualification_receipt=reset_qualification_receipt,
        reset_qualification_public_key_pem=reset_qualification_public_key,
        reset_qualification_signing_key_id=reset_qualification_signing_key_id,
    )
    image_url = manifest["image_url"]
    assert isinstance(image_url, str)
    parsed = urlsplit(image_url)
    if parsed.netloc != expected_authority:
        raise DeploymentBundleError("manifest authority is not canonical")
    _validate_url_path(parsed.path)
    control_registry, origin_catalog = _expected_documents(
        manifest, parsed.path, retry_after_seconds
    )
    control_registry_bytes = _json_bytes(control_registry)
    origin_catalog_bytes = _json_bytes(origin_catalog)
    receipt = _expected_receipt(
        manifest,
        expected_authority,
        parsed.path,
        retry_after_seconds,
        manifest_bytes,
        public_key_bytes,
        sdkconfig_bytes,
        control_registry_bytes,
        origin_catalog_bytes,
    )
    return (
        receipt,
        parsed.path,
        control_registry_bytes,
        origin_catalog_bytes,
        _json_bytes(receipt),
    )


def validate_deployment_bundle(
    root: Path, *, expected_authority: str, require_read_only: bool = True
) -> dict[str, object]:
    try:
        root_info = root.lstat()
    except OSError as error:
        raise DeploymentBundleError("deployment bundle does not exist") from error
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise DeploymentBundleError("deployment bundle must be a non-symlink directory")

    manifest_path = root / "control" / "release-manifest.json"
    public_key_path = root / "control" / "release-public.pem"
    sdkconfig_path = root / "evidence" / "sdkconfig"
    control_path = root / "control" / "ota-release-registry.json"
    origin_path = root / "origin" / "firmware-origin-catalog.json"
    receipt_path = root / "deployment-receipt.json"
    ready_path = root / "READY"
    manifest_bytes = _read_regular(manifest_path, 8192, "bundle manifest")
    public_key_bytes = _read_regular(
        public_key_path, MAX_PUBLIC_KEY_BYTES, "bundle public key"
    )
    sdkconfig_bytes = _read_regular(
        sdkconfig_path, MAX_SDKCONFIG_BYTES, "bundle sdkconfig"
    )
    receipt_bytes = _read_regular(receipt_path, 8192, "bundle receipt")
    receipt = _strict_json(receipt_bytes, "bundle receipt")
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_FIELDS:
        raise DeploymentBundleError("bundle receipt fields do not match schema v1")
    retry_after_seconds = receipt.get("retry_after_seconds")
    if type(retry_after_seconds) is not int:
        raise DeploymentBundleError("bundle retry-after seconds is invalid")
    manifest = load_manifest_json(manifest_bytes)
    image_url = manifest["image_url"]
    assert isinstance(image_url, str)
    url_path = urlsplit(image_url).path
    _validate_url_path(url_path)
    image_relative = Path("origin") / ("objects" + url_path).lstrip("/")
    image_path = root / image_relative
    image_bytes = _read_regular(image_path, MAX_IMAGE_SIZE, "bundle image")
    expected_receipt, prepared_path, control_bytes, origin_bytes, expected_receipt_bytes = (
        _prepare_artifacts(
            manifest_bytes,
            public_key_bytes,
            image_bytes,
            sdkconfig_bytes,
            expected_authority=expected_authority,
            retry_after_seconds=retry_after_seconds,
        )
    )
    if (
        prepared_path != url_path
        or receipt != expected_receipt
        or receipt_bytes != expected_receipt_bytes
    ):
        raise DeploymentBundleError("bundle receipt does not match release artifacts")
    actual_control = _read_regular(control_path, 1024 * 1024, "control registry")
    actual_origin = _read_regular(origin_path, 1024 * 1024, "origin catalog")
    if actual_control != control_bytes or actual_origin != origin_bytes:
        raise DeploymentBundleError("bundle catalogs are not canonical or consistent")
    expected_ready = (_sha256(expected_receipt_bytes) + "\n").encode("ascii")
    if _read_regular(ready_path, 128, "READY marker") != expected_ready:
        raise DeploymentBundleError("bundle READY marker is invalid")
    expected_files = {
        Path("control/release-public.pem"),
        Path("control/release-manifest.json"),
        Path("control/ota-release-registry.json"),
        Path("origin/firmware-origin-catalog.json"),
        image_relative,
        Path("evidence/sdkconfig"),
        Path("deployment-receipt.json"),
        Path("READY"),
    }
    if require_read_only:
        _require_read_only_tree(root, expected_files)
    return expected_receipt


def build_deployment_bundle(
    *,
    manifest_path: Path,
    public_key_path: Path,
    image_path: Path,
    sdkconfig_path: Path,
    reset_qualification_receipt_path: Path,
    reset_qualification_public_key_path: Path,
    reset_qualification_signing_key_id: str,
    expected_authority: str,
    retry_after_seconds: int,
    output_path: Path,
) -> dict[str, object]:
    manifest_bytes = _read_regular(manifest_path, 8192, "release manifest")
    public_key_bytes = _read_regular(
        public_key_path, MAX_PUBLIC_KEY_BYTES, "release public key"
    )
    image_bytes = _read_regular(image_path, MAX_IMAGE_SIZE, "release image")
    sdkconfig_bytes = _read_regular(
        sdkconfig_path, MAX_SDKCONFIG_BYTES, "release sdkconfig"
    )
    reset_qualification_receipt = _read_regular(
        reset_qualification_receipt_path,
        128 * 1024,
        "reset qualification receipt",
    )
    reset_qualification_public_key = _read_regular(
        reset_qualification_public_key_path,
        16 * 1024,
        "reset qualification public key",
    )
    receipt, url_path, control_bytes, origin_bytes, receipt_bytes = _prepare_artifacts(
        manifest_bytes,
        public_key_bytes,
        image_bytes,
        sdkconfig_bytes,
        expected_authority=expected_authority,
        retry_after_seconds=retry_after_seconds,
        reset_qualification_receipt=reset_qualification_receipt,
        reset_qualification_public_key=reset_qualification_public_key,
        reset_qualification_signing_key_id=reset_qualification_signing_key_id,
    )
    if output_path.exists() or output_path.is_symlink():
        raise DeploymentBundleError("output bundle already exists")
    if not output_path.parent.is_dir():
        raise DeploymentBundleError("output bundle parent does not exist")

    created = False
    try:
        output_path.mkdir(mode=0o700)
        created = True
        control_dir = output_path / "control"
        origin_dir = output_path / "origin"
        evidence_dir = output_path / "evidence"
        object_path = origin_dir / ("objects" + url_path).lstrip("/")
        control_dir.mkdir(mode=0o700)
        origin_dir.mkdir(mode=0o700)
        evidence_dir.mkdir(mode=0o700)
        object_path.parent.mkdir(mode=0o700, parents=True)

        _write_new(control_dir / "release-public.pem", public_key_bytes)
        _write_new(control_dir / "release-manifest.json", manifest_bytes)
        _write_new(control_dir / "ota-release-registry.json", control_bytes)
        _write_new(origin_dir / "firmware-origin-catalog.json", origin_bytes)
        _write_new(object_path, image_bytes)
        _write_new(evidence_dir / "sdkconfig", sdkconfig_bytes)
        _write_new(output_path / "deployment-receipt.json", receipt_bytes)
        _write_new(
            output_path / "READY", (_sha256(receipt_bytes) + "\n").encode("ascii")
        )
        for directory in sorted(
            (path for path in output_path.rglob("*") if path.is_dir()),
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            _fsync_directory(directory)
        _fsync_directory(output_path)
        _lock_bundle_tree(output_path)
        validate_deployment_bundle(
            output_path, expected_authority=expected_authority, require_read_only=True
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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a verified, immutable, fail-closed OTA deployment bundle"
    )
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--sdkconfig", required=True, type=Path)
    parser.add_argument("--reset-qualification-receipt", required=True, type=Path)
    parser.add_argument("--reset-qualification-public-key", required=True, type=Path)
    parser.add_argument("--reset-qualification-signing-key-id", required=True)
    parser.add_argument("--expected-authority", required=True)
    parser.add_argument("--retry-after-seconds", type=int, default=900)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        receipt = build_deployment_bundle(
            manifest_path=arguments.manifest,
            public_key_path=arguments.public_key,
            image_path=arguments.image,
            sdkconfig_path=arguments.sdkconfig,
            reset_qualification_receipt_path=(
                arguments.reset_qualification_receipt
            ),
            reset_qualification_public_key_path=(
                arguments.reset_qualification_public_key
            ),
            reset_qualification_signing_key_id=(
                arguments.reset_qualification_signing_key_id
            ),
            expected_authority=arguments.expected_authority,
            retry_after_seconds=arguments.retry_after_seconds,
            output_path=arguments.output,
        )
    except (OSError, ManifestError, DeploymentBundleError) as error:
        parser.error(str(error))
    print(
        f"OTA deployment bundle ready for {receipt['release_id']} "
        f"sequence={receipt['release_sequence']} rollout=disabled"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
