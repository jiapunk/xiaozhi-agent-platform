#!/usr/bin/env python3
"""Deterministic, daemonless OCI release bundle builder and validator.

The offline Ed25519 signature implemented here authenticates this project's
immutable release bundle.  It is deliberately not represented as a Cosign or
transparency-log signature; production registry policy remains a deployment
gate.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


SCHEMA_VERSION = 3
OCI_LAYOUT_VERSION = "1.0.0"
OCI_IMAGE_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_IMAGE_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_IMAGE_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER_GZIP = "application/vnd.oci.image.layer.v1.tar+gzip"
OCI_EMPTY_CONFIG = "application/vnd.oci.empty.v1+json"
SPDX_MEDIA_TYPE = "application/spdx+json"
INTOTO_MEDIA_TYPE = "application/vnd.in-toto+json"
SPDX_VERSION = "SPDX-2.3"
INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SLSA_PROVENANCE_TYPE = "https://slsa.dev/provenance/v1"
BUILD_TYPE = "https://xiaozhi-agent.local/buildtypes/daemonless-oci/v3"
BUILDER_ID = "https://xiaozhi-agent.local/builders/daemonless-oci/v3"
SIGNATURE_DOMAIN = b"XIAOZHI-AGENT-OCI-RELEASE-V3\x00"
SERVICES = (
    "gateway",
    "controlplane",
    "agentproxy",
    "firmwareorigin",
    "generationcoordinator",
    "accountauthorization",
    "factorytimeauthority",
)
ARCHITECTURES = ("amd64", "arm64")
GO_MACHINES = {"amd64": 62, "arm64": 183}
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_BLOB_BYTES = 128 * 1024 * 1024
MAX_KEY_BYTES = 4096
MAX_SOURCE_INPUTS = 4096
MIN_SOURCE_DATE_EPOCH = 946684800
MAX_SOURCE_DATE_EPOCH = 4102444800


class OCIReleaseError(ValueError):
    pass


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest(data: bytes) -> str:
    return "sha256:" + _sha256(data)


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _compact_bytes(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _strict_json(data: bytes, label: str) -> object:
    def exact_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise OCIReleaseError(f"{label} contains duplicate fields")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise OCIReleaseError(f"{label} contains non-standard JSON constant {value}")

    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=exact_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OCIReleaseError(f"{label} is not strict UTF-8 JSON") from error


def _read_regular(path: Path, maximum: int, label: str, *, allow_empty: bool = False) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise OCIReleaseError(f"cannot open {label}") from error
    try:
        info = os.fstat(descriptor)
        minimum = 0 if allow_empty else 1
        if not stat.S_ISREG(info.st_mode):
            raise OCIReleaseError(f"{label} must be a regular file")
        if not minimum <= info.st_size <= maximum:
            raise OCIReleaseError(f"{label} size is outside range")
        chunks: list[bytes] = []
        remaining = info.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise OCIReleaseError(f"{label} changed while being read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise OCIReleaseError(f"{label} changed while being read")
        return b"".join(chunks)
    except OSError as error:
        raise OCIReleaseError(f"cannot read {label}") from error
    finally:
        os.close(descriptor)


def _write_new(path: Path, data: bytes, mode: int = 0o400) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, mode)
    except OSError as error:
        raise OCIReleaseError(f"cannot create {path.name}") from error
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
    paths = sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True)
    for path in paths:
        if path.is_symlink():
            raise OCIReleaseError("release bundle contains a symlink")
        os.chmod(path, 0o555 if path.is_dir() else 0o444)
    os.chmod(root, 0o555)


def _unlock_tree(root: Path) -> None:
    if not root.exists() or root.is_symlink():
        return
    os.chmod(root, 0o700)
    for path in root.rglob("*"):
        if not path.is_symlink():
            os.chmod(path, 0o700 if path.is_dir() else 0o600)


def _require_identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise OCIReleaseError(f"{label} has invalid format")
    return value


def _require_version(value: object) -> str:
    if not isinstance(value, str) or not VERSION.fullmatch(value):
        raise OCIReleaseError("version has invalid format")
    return value


def _require_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise OCIReleaseError(f"{label} is not a canonical SHA-256")
    return value


def _require_digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not DIGEST.fullmatch(value):
        raise OCIReleaseError(f"{label} is not a canonical OCI digest")
    return value


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_b64url(value: object, size: int, label: str) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise OCIReleaseError(f"{label} is not canonical base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except (ValueError, binascii.Error) as error:
        raise OCIReleaseError(f"{label} is not base64url") from error
    if len(decoded) != size or _b64url(decoded) != value:
        raise OCIReleaseError(f"{label} is not canonical base64url")
    return decoded


def _timestamp(epoch: int) -> str:
    if type(epoch) is not int or not MIN_SOURCE_DATE_EPOCH <= epoch <= MAX_SOURCE_DATE_EPOCH:
        raise OCIReleaseError("SOURCE_DATE_EPOCH is outside the supported range")
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )


def _descriptor(media_type: str, data: bytes, **extra: object) -> dict[str, object]:
    result: dict[str, object] = {
        "mediaType": media_type,
        "digest": _digest(data),
        "size": len(data),
    }
    result.update(extra)
    return result


def _add_blob(layout: Path, data: bytes) -> dict[str, object]:
    digest = _sha256(data)
    path = layout / "blobs" / "sha256" / digest
    if path.exists():
        if _read_regular(path, MAX_BLOB_BYTES, "existing OCI blob", allow_empty=True) != data:
            raise OCIReleaseError("OCI blob digest collision")
    else:
        _write_new(path, data)
    return {"digest": "sha256:" + digest, "size": len(data)}


def _make_layer(
    binary: bytes,
    architecture: str,
    ca_bundle: bytes,
    websocket_license: bytes,
    notices: bytes,
    source_date_epoch: int,
) -> tuple[bytes, bytes]:
    if not _static_elf(binary, architecture):
        raise OCIReleaseError(f"{architecture} service binary is not a static ELF")
    entries: list[tuple[str, bytes | None, int, int, int]] = [
        ("etc", None, 0o555, 0, 0),
        ("etc/ssl", None, 0o555, 0, 0),
        ("etc/ssl/certs", None, 0o555, 0, 0),
        ("licenses", None, 0o555, 0, 0),
        ("service", binary, 0o555, 65532, 65532),
        ("etc/ssl/certs/ca-certificates.crt", ca_bundle, 0o444, 0, 0),
        ("licenses/coder-websocket-LICENSE.txt", websocket_license, 0o444, 0, 0),
        ("licenses/THIRD_PARTY_NOTICES.md", notices, 0o444, 0, 0),
    ]
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, payload, mode, uid, gid in entries:
            info = tarfile.TarInfo(name=name)
            info.mode = mode
            info.uid = uid
            info.gid = gid
            info.uname = ""
            info.gname = ""
            info.mtime = source_date_epoch
            if payload is None:
                info.type = tarfile.DIRTYPE
                info.size = 0
                archive.addfile(info)
            else:
                info.type = tarfile.REGTYPE
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
    uncompressed = raw.getvalue()
    compressed = io.BytesIO()
    with gzip.GzipFile(
        filename="", mode="wb", compresslevel=9, fileobj=compressed, mtime=source_date_epoch
    ) as stream:
        stream.write(uncompressed)
    return compressed.getvalue(), uncompressed


def _static_elf(data: bytes, architecture: str) -> bool:
    if architecture not in GO_MACHINES or len(data) < 64 or data[:4] != b"\x7fELF":
        return False
    elf_class, encoding = data[4], data[5]
    if elf_class not in (1, 2) or encoding not in (1, 2):
        return False
    order = "<" if encoding == 1 else ">"
    machine = struct.unpack_from(order + "H", data, 18)[0]
    if machine != GO_MACHINES[architecture]:
        return False
    if elf_class == 2:
        phoff = struct.unpack_from(order + "Q", data, 32)[0]
        phentsize = struct.unpack_from(order + "H", data, 54)[0]
        phnum = struct.unpack_from(order + "H", data, 56)[0]
    else:
        phoff = struct.unpack_from(order + "I", data, 28)[0]
        phentsize = struct.unpack_from(order + "H", data, 42)[0]
        phnum = struct.unpack_from(order + "H", data, 44)[0]
    if phnum > 256 or phentsize < 4 or phoff + phentsize * phnum > len(data):
        return False
    for index in range(phnum):
        program_type = struct.unpack_from(order + "I", data, phoff + index * phentsize)[0]
        if program_type == 3:  # PT_INTERP means a dynamic loader is required.
            return False
    return True


def _source_input_paths(project_root: Path, services: Iterable[str]) -> list[Path]:
    paths = [
        project_root / "gateway/go.mod",
        project_root / "gateway/go.sum",
        project_root / "gateway/Dockerfile",
        project_root / "gateway/oci-release-receipt.schema.json",
        project_root / "gateway/third_party/coder-websocket-LICENSE.txt",
        project_root / "gateway/cmd/validateocirelease/main.go",
        project_root / "THIRD_PARTY_NOTICES.md",
        project_root / "tools/oci_release.py",
        project_root / "tools/build_oci_release_bundle.py",
        project_root / "tools/smoke_oci_release.py",
        project_root / "tools/validate_oci_release_bundle.py",
    ]
    paths.extend(
        path
        for path in sorted((project_root / "gateway/internal").rglob("*.go"))
        if not path.name.endswith("_test.go")
    )
    paths.extend(sorted((project_root / "gateway/migrations").rglob("*.sql")))
    for service in services:
        paths.extend(
            path
            for path in sorted((project_root / "gateway/cmd" / service).rglob("*.go"))
            if not path.name.endswith("_test.go")
        )
    unique = sorted(set(paths), key=lambda path: path.relative_to(project_root).as_posix())
    if not unique or len(unique) > MAX_SOURCE_INPUTS:
        raise OCIReleaseError("source input count is outside range")
    return unique


def _go_version(go_binary: Path) -> str:
    try:
        completed = subprocess.run(
            [str(go_binary), "version"], check=True, capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise OCIReleaseError("cannot execute the pinned Go toolchain") from error
    match = re.fullmatch(r"go version (go[0-9]+\.[0-9]+(?:\.[0-9]+)?) [^\s]+\s*", completed.stdout)
    if not match:
        raise OCIReleaseError("Go version output is not recognized")
    return match.group(1)


def _compile_service(
    project_root: Path,
    go_binary: Path,
    service: str,
    architecture: str,
    output: Path,
) -> None:
    environment = dict(os.environ)
    environment.update({"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": architecture})
    environment.pop("GOFLAGS", None)
    command = [
        str(go_binary),
        "build",
        "-trimpath",
        "-buildvcs=false",
        "-ldflags=-s -w -buildid=",
        "-o",
        str(output),
        "./cmd/" + service,
    ]
    try:
        subprocess.run(
            command,
            cwd=project_root / "gateway",
            env=environment,
            check=True,
            capture_output=True,
            timeout=300,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise OCIReleaseError(f"failed to compile {service} for linux/{architecture}") from error


def _source_manifest(
    project_root: Path,
    services: tuple[str, ...],
    ca_bundle: bytes,
    go_binary: Path,
    go_version: str,
) -> dict[str, object]:
    inputs: list[dict[str, object]] = []
    for path in _source_input_paths(project_root, services):
        data = _read_regular(path, MAX_BLOB_BYTES, "source input")
        inputs.append(
            {
                "name": "project:" + path.relative_to(project_root).as_posix(),
                "sha256": _sha256(data),
                "size": len(data),
            }
        )
    go_data = _read_regular(go_binary, MAX_BLOB_BYTES, "Go executable")
    inputs.extend(
        [
            {"name": "runtime:ca-bundle", "sha256": _sha256(ca_bundle), "size": len(ca_bundle)},
            {
                "name": "toolchain:go-executable",
                "sha256": _sha256(go_data),
                "size": len(go_data),
                "version": go_version,
            },
        ]
    )
    inputs.sort(key=lambda item: str(item["name"]))
    return {"schema": 1, "algorithm": "sha256", "inputs": inputs}


def _spdx_document(
    service: str,
    version: str,
    image_digest: str,
    source_inputs_sha256: str,
    ca_sha256: str,
    go_version: str,
    created: str,
) -> dict[str, object]:
    image_hex = DIGEST.fullmatch(image_digest).group(1)  # type: ignore[union-attr]
    namespace_seed = _sha256(
        (service + "\x00" + version + "\x00" + image_digest + "\x00" + source_inputs_sha256).encode()
    )
    return {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": created,
            "creators": ["Tool: xiaozhi-agent-daemonless-oci-builder/2"],
        },
        "dataLicense": "CC0-1.0",
        "documentDescribes": ["SPDXRef-Package-Service"],
        "documentNamespace": "https://xiaozhi-agent.local/spdx/" + namespace_seed,
        "name": f"xiaozhi-agent-{service}-{version}",
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-Service",
                "checksums": [{"algorithm": "SHA256", "checksumValue": image_hex}],
                "copyrightText": "NOASSERTION",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "name": "xiaozhi-agent-" + service,
                "supplier": "Organization: XiaoZhi Agent Platform",
                "versionInfo": version,
            },
            {
                "SPDXID": "SPDXRef-Package-Websocket",
                "copyrightText": "Copyright (c) 2025 Coder",
                "downloadLocation": "https://github.com/coder/websocket",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceLocator": "pkg:golang/github.com/coder/websocket@v1.8.15",
                        "referenceType": "purl",
                    }
                ],
                "filesAnalyzed": False,
                "licenseConcluded": "ISC",
                "licenseDeclared": "ISC",
                "name": "github.com/coder/websocket",
                "supplier": "Organization: Coder Technologies Inc.",
                "versionInfo": "v1.8.15",
            },
            {
                "SPDXID": "SPDXRef-Package-Go",
                "copyrightText": "Copyright The Go Authors",
                "downloadLocation": "https://go.dev/dl/",
                "filesAnalyzed": False,
                "licenseConcluded": "BSD-3-Clause",
                "licenseDeclared": "BSD-3-Clause",
                "name": "Go standard library",
                "supplier": "Organization: The Go Authors",
                "versionInfo": go_version,
            },
            {
                "SPDXID": "SPDXRef-Package-CABundle",
                "checksums": [{"algorithm": "SHA256", "checksumValue": ca_sha256}],
                "copyrightText": "NOASSERTION",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "name": "operator-supplied CA certificate bundle",
                "supplier": "NOASSERTION",
            },
        ],
        "relationships": [
            {
                "relatedSpdxElement": "SPDXRef-Package-Service",
                "relationshipType": "DESCRIBES",
                "spdxElementId": "SPDXRef-DOCUMENT",
            },
            *[
                {
                    "relatedSpdxElement": dependency,
                    "relationshipType": "DEPENDS_ON",
                    "spdxElementId": "SPDXRef-Package-Service",
                }
                for dependency in (
                    "SPDXRef-Package-Websocket",
                    "SPDXRef-Package-Go",
                    "SPDXRef-Package-CABundle",
                )
            ],
        ],
        "spdxVersion": SPDX_VERSION,
    }


def _provenance_statement(
    service: str,
    version: str,
    image_digest: str,
    source_inputs_sha256: str,
    ca_sha256: str,
    go_version: str,
    go_sha256: str,
    sbom_sha256: str,
    source_date_epoch: int,
) -> dict[str, object]:
    created = _timestamp(source_date_epoch)
    invocation = _sha256(
        (service + "\x00" + version + "\x00" + image_digest + "\x00" + source_inputs_sha256).encode()
    )
    return {
        "_type": INTOTO_STATEMENT_TYPE,
        "predicateType": SLSA_PROVENANCE_TYPE,
        "subject": [
            {
                "name": "xiaozhi-agent/" + service,
                "digest": {"sha256": image_digest.split(":", 1)[1]},
            }
        ],
        "predicate": {
            "buildDefinition": {
                "buildType": BUILD_TYPE,
                "externalParameters": {
                    "architectures": list(ARCHITECTURES),
                    "service": service,
                    "sourceDateEpoch": source_date_epoch,
                    "version": version,
                },
                "resolvedDependencies": [
                    {
                        "uri": "file:source-inputs.json",
                        "digest": {"sha256": source_inputs_sha256},
                    },
                    {
                        "uri": "file:go-executable",
                        "digest": {"sha256": go_sha256},
                    },
                    {
                        "uri": "file:ca-certificates.crt",
                        "digest": {"sha256": ca_sha256},
                    },
                    {"uri": "pkg:golang/github.com/coder/websocket@v1.8.15"},
                ],
            },
            "runDetails": {
                "builder": {"id": BUILDER_ID, "version": {"oci-release": "2"}},
                "metadata": {
                    "buildFinishedOn": created,
                    "buildInvocationId": "urn:sha256:" + invocation,
                    "buildStartedOn": created,
                    "reproducible": True,
                },
                "byproducts": [
                    {"uri": "spdx:" + service, "digest": {"sha256": sbom_sha256}}
                ],
            },
        },
    }


def _artifact_manifest(
    subject: dict[str, object], artifact_type: str, payload: bytes, title: str
) -> dict[str, object]:
    empty = b"{}"
    return {
        "artifactType": artifact_type,
        "config": _descriptor(OCI_EMPTY_CONFIG, empty),
        "layers": [_descriptor(artifact_type, payload, annotations={"org.opencontainers.image.title": title})],
        "mediaType": OCI_IMAGE_MANIFEST,
        "schemaVersion": 2,
        "subject": subject,
    }


def _build_service_layout(
    layout: Path,
    service: str,
    version: str,
    binaries: dict[str, bytes],
    ca_bundle: bytes,
    websocket_license: bytes,
    notices: bytes,
    source_inputs_sha256: str,
    go_version: str,
    go_sha256: str,
    source_date_epoch: int,
) -> dict[str, object]:
    (layout / "blobs/sha256").mkdir(parents=True, mode=0o700)
    _write_new(layout / "oci-layout", _json_bytes({"imageLayoutVersion": OCI_LAYOUT_VERSION}))
    empty = b"{}"
    _add_blob(layout, empty)
    created = _timestamp(source_date_epoch)
    platform_records: list[dict[str, object]] = []
    platform_descriptors: list[dict[str, object]] = []
    for architecture in ARCHITECTURES:
        binary = binaries[architecture]
        layer, uncompressed = _make_layer(
            binary, architecture, ca_bundle, websocket_license, notices, source_date_epoch
        )
        _add_blob(layout, layer)
        config = {
            "architecture": architecture,
            "config": {
                "Entrypoint": ["/service"],
                "Env": ["SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"],
                "StopSignal": "SIGTERM",
                "User": "65532:65532",
                "WorkingDir": "/",
            },
            "created": created,
            "history": [
                {
                    "comment": "reproducible daemonless OCI builder",
                    "created": created,
                    "created_by": "xiaozhi-agent-daemonless-oci-builder/2",
                }
            ],
            "os": "linux",
            "rootfs": {"diff_ids": [_digest(uncompressed)], "type": "layers"},
        }
        config_bytes = _compact_bytes(config)
        _add_blob(layout, config_bytes)
        manifest = {
            "config": _descriptor(OCI_IMAGE_CONFIG, config_bytes),
            "layers": [
                _descriptor(
                    OCI_LAYER_GZIP,
                    layer,
                    annotations={"org.opencontainers.image.title": f"{service}-{architecture}.tar.gz"},
                )
            ],
            "mediaType": OCI_IMAGE_MANIFEST,
            "schemaVersion": 2,
        }
        manifest_bytes = _compact_bytes(manifest)
        _add_blob(layout, manifest_bytes)
        descriptor = _descriptor(
            OCI_IMAGE_MANIFEST,
            manifest_bytes,
            platform={"architecture": architecture, "os": "linux"},
        )
        platform_descriptors.append(descriptor)
        platform_records.append(
            {
                "architecture": architecture,
                "binary_sha256": _sha256(binary),
                "binary_size": len(binary),
                "image_manifest_digest": descriptor["digest"],
                "image_manifest_size": descriptor["size"],
            }
        )
    image_index = {
        "annotations": {
            "org.opencontainers.image.created": created,
            "org.opencontainers.image.title": "xiaozhi-agent-" + service,
            "org.opencontainers.image.version": version,
        },
        "manifests": platform_descriptors,
        "mediaType": OCI_IMAGE_INDEX,
        "schemaVersion": 2,
    }
    image_index_bytes = _compact_bytes(image_index)
    _add_blob(layout, image_index_bytes)
    image_descriptor = _descriptor(
        OCI_IMAGE_INDEX,
        image_index_bytes,
        annotations={
            "org.opencontainers.image.ref.name": version,
            "org.opencontainers.image.title": "xiaozhi-agent-" + service,
        },
    )
    spdx = _spdx_document(
        service,
        version,
        str(image_descriptor["digest"]),
        source_inputs_sha256,
        _sha256(ca_bundle),
        go_version,
        created,
    )
    spdx_bytes = _compact_bytes(spdx)
    _add_blob(layout, spdx_bytes)
    sbom_manifest = _artifact_manifest(
        image_descriptor, SPDX_MEDIA_TYPE, spdx_bytes, f"{service}.spdx.json"
    )
    sbom_manifest_bytes = _compact_bytes(sbom_manifest)
    _add_blob(layout, sbom_manifest_bytes)
    sbom_descriptor = _descriptor(
        OCI_IMAGE_MANIFEST,
        sbom_manifest_bytes,
        artifactType=SPDX_MEDIA_TYPE,
        annotations={"org.opencontainers.image.ref.name": version + ".sbom"},
    )
    provenance = _provenance_statement(
        service,
        version,
        str(image_descriptor["digest"]),
        source_inputs_sha256,
        _sha256(ca_bundle),
        go_version,
        go_sha256,
        _sha256(spdx_bytes),
        source_date_epoch,
    )
    provenance_bytes = _compact_bytes(provenance)
    _add_blob(layout, provenance_bytes)
    provenance_manifest = _artifact_manifest(
        image_descriptor,
        INTOTO_MEDIA_TYPE,
        provenance_bytes,
        f"{service}.intoto.json",
    )
    provenance_manifest_bytes = _compact_bytes(provenance_manifest)
    _add_blob(layout, provenance_manifest_bytes)
    provenance_descriptor = _descriptor(
        OCI_IMAGE_MANIFEST,
        provenance_manifest_bytes,
        artifactType=INTOTO_MEDIA_TYPE,
        annotations={"org.opencontainers.image.ref.name": version + ".provenance"},
    )
    root_index = {
        "annotations": {
            "org.opencontainers.image.title": "xiaozhi-agent-" + service,
            "org.opencontainers.image.version": version,
        },
        "manifests": [image_descriptor, sbom_descriptor, provenance_descriptor],
        "mediaType": OCI_IMAGE_INDEX,
        "schemaVersion": 2,
    }
    root_index_bytes = _json_bytes(root_index)
    _write_new(layout / "index.json", root_index_bytes)
    return {
        "name": service,
        "oci_index_sha256": _sha256(root_index_bytes),
        "oci_index_size": len(root_index_bytes),
        "image_index_digest": image_descriptor["digest"],
        "image_index_size": image_descriptor["size"],
        "sbom_manifest_digest": sbom_descriptor["digest"],
        "sbom_manifest_size": sbom_descriptor["size"],
        "provenance_manifest_digest": provenance_descriptor["digest"],
        "provenance_manifest_size": provenance_descriptor["size"],
        "platforms": platform_records,
    }


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    data = _read_regular(path, MAX_KEY_BYTES, "release signing private key")
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (TypeError, ValueError) as error:
        raise OCIReleaseError("release signing private key PEM is invalid") from error
    if not isinstance(key, Ed25519PrivateKey):
        raise OCIReleaseError("release signing private key must be Ed25519")
    return key


def _load_public_key(path: Path) -> Ed25519PublicKey:
    data = _read_regular(path, MAX_KEY_BYTES, "trusted release public key")
    try:
        key = serialization.load_pem_public_key(data)
    except (TypeError, ValueError) as error:
        raise OCIReleaseError("trusted release public key PEM is invalid") from error
    if not isinstance(key, Ed25519PublicKey):
        raise OCIReleaseError("trusted release public key must be Ed25519")
    return key


def _signature_payload(receipt: dict[str, object]) -> bytes:
    unsigned = dict(receipt)
    unsigned.pop("signature_b64url", None)
    return SIGNATURE_DOMAIN + _compact_bytes(unsigned)


def build_release_bundle(
    *,
    project_root: Path,
    go_binary: Path,
    ca_bundle_path: Path,
    signing_private_key_path: Path,
    signing_key_id: str,
    release_id: str,
    version: str,
    source_date_epoch: int,
    output_path: Path,
    services: tuple[str, ...] = SERVICES,
    compile_callback: Callable[[Path, Path, str, str, Path], None] = _compile_service,
) -> dict[str, object]:
    release_id = _require_identifier(release_id, "release ID")
    signing_key_id = _require_identifier(signing_key_id, "signing key ID")
    version = _require_version(version)
    _timestamp(source_date_epoch)
    if services != SERVICES:
        raise OCIReleaseError("release must contain the exact ordered seven-service set")
    if output_path.exists() or output_path.is_symlink():
        raise OCIReleaseError("output bundle already exists")
    if not output_path.parent.is_dir():
        raise OCIReleaseError("output bundle parent does not exist")
    ca_bundle = _read_regular(ca_bundle_path, 16 * 1024 * 1024, "CA bundle")
    if b"-----BEGIN CERTIFICATE-----" not in ca_bundle:
        raise OCIReleaseError("CA bundle does not contain PEM certificates")
    key = _load_private_key(signing_private_key_path)
    go_version = _go_version(go_binary)
    if go_version != "go1.26.5":
        raise OCIReleaseError("Go toolchain must be exactly go1.26.5")
    source_manifest = _source_manifest(project_root, services, ca_bundle, go_binary, go_version)
    source_manifest_bytes = _json_bytes(source_manifest)
    source_inputs_sha256 = _sha256(source_manifest_bytes)
    go_entry = next(
        item
        for item in source_manifest["inputs"]
        if item["name"] == "toolchain:go-executable"
    )
    websocket_license = _read_regular(
        project_root / "gateway/third_party/coder-websocket-LICENSE.txt",
        1024 * 1024,
        "websocket license",
    )
    notices = _read_regular(project_root / "THIRD_PARTY_NOTICES.md", 1024 * 1024, "notices")

    created = False
    work_directory: Path | None = None
    try:
        output_path.mkdir(mode=0o700)
        created = True
        _write_new(output_path / "source-inputs.json", source_manifest_bytes)
        services_directory = output_path / "services"
        services_directory.mkdir(mode=0o700)
        work_directory = Path(tempfile.mkdtemp(prefix="oci-release-build-"))
        service_records: list[dict[str, object]] = []
        for service in services:
            binaries: dict[str, bytes] = {}
            for architecture in ARCHITECTURES:
                binary_path = work_directory / f"{service}-{architecture}"
                compile_callback(project_root, go_binary, service, architecture, binary_path)
                binaries[architecture] = _read_regular(
                    binary_path, 64 * 1024 * 1024, f"{service} {architecture} binary"
                )
            layout = services_directory / service
            layout.mkdir(mode=0o700)
            service_records.append(
                _build_service_layout(
                    layout,
                    service,
                    version,
                    binaries,
                    ca_bundle,
                    websocket_license,
                    notices,
                    source_inputs_sha256,
                    go_version,
                    str(go_entry["sha256"]),
                    source_date_epoch,
                )
            )
        receipt: dict[str, object] = {
            "schema": SCHEMA_VERSION,
            "release_id": release_id,
            "version": version,
            "source_date_epoch": source_date_epoch,
            "source_inputs_sha256": source_inputs_sha256,
            "ca_bundle_sha256": _sha256(ca_bundle),
            "go_executable_sha256": go_entry["sha256"],
            "go_version": go_version,
            "signing_key_id": signing_key_id,
            "signature_algorithm": "Ed25519",
            "services": service_records,
        }
        receipt["signature_b64url"] = _b64url(key.sign(_signature_payload(receipt)))
        receipt_bytes = _json_bytes(receipt)
        _write_new(output_path / "release-receipt.json", receipt_bytes)
        _write_new(output_path / "READY", (_sha256(receipt_bytes) + "\n").encode("ascii"))
        for directory in sorted(
            (path for path in output_path.rglob("*") if path.is_dir()),
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            _fsync_directory(directory)
        _fsync_directory(output_path)
        _lock_tree(output_path)
    except BaseException:
        if created:
            _unlock_tree(output_path)
            shutil.rmtree(output_path)
        raise
    finally:
        if work_directory is not None:
            shutil.rmtree(work_directory, ignore_errors=True)
    return receipt


def _object(value: object, fields: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise OCIReleaseError(f"{label} fields do not match schema")
    return value


def _integer(value: object, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise OCIReleaseError(f"{label} is outside range")
    return value


def _blob(layout: Path, descriptor: object, media_type: str, label: str) -> tuple[bytes, dict[str, object]]:
    item = _object(descriptor, set(descriptor) if isinstance(descriptor, dict) else set(), label)
    if item.get("mediaType") != media_type:
        raise OCIReleaseError(f"{label} has wrong media type")
    digest = _require_digest(item.get("digest"), label + " digest")
    size = _integer(item.get("size"), 0, MAX_BLOB_BYTES, label + " size")
    data = _read_regular(
        layout / "blobs/sha256" / digest.split(":", 1)[1], MAX_BLOB_BYTES, label, allow_empty=True
    )
    if len(data) != size or _digest(data) != digest:
        raise OCIReleaseError(f"{label} descriptor does not match blob")
    return data, item


def _canonical_blob_json(data: bytes, label: str) -> dict[str, object]:
    value = _strict_json(data, label)
    if not isinstance(value, dict) or _compact_bytes(value) != data:
        raise OCIReleaseError(f"{label} is not canonical compact JSON")
    return value


def _validate_layer(
    compressed: bytes,
    architecture: str,
    source_date_epoch: int,
    binary_sha256: str,
    binary_size: int,
    ca_sha256: str,
) -> bytes:
    if (
        len(compressed) < 10
        or compressed[:4] != b"\x1f\x8b\x08\x00"
        or compressed[8:10] != b"\x02\xff"
    ):
        raise OCIReleaseError("OCI layer does not have the deterministic gzip header")
    gzip_mtime = struct.unpack_from("<I", compressed, 4)[0]
    if gzip_mtime != source_date_epoch:
        raise OCIReleaseError("OCI layer gzip timestamp is not reproducible")
    try:
        uncompressed = gzip.decompress(compressed)
    except (OSError, EOFError) as error:
        raise OCIReleaseError("OCI layer gzip is invalid") from error
    expected = {
        "etc": (tarfile.DIRTYPE, 0o555, 0, 0),
        "etc/ssl": (tarfile.DIRTYPE, 0o555, 0, 0),
        "etc/ssl/certs": (tarfile.DIRTYPE, 0o555, 0, 0),
        "licenses": (tarfile.DIRTYPE, 0o555, 0, 0),
        "service": (tarfile.REGTYPE, 0o555, 65532, 65532),
        "etc/ssl/certs/ca-certificates.crt": (tarfile.REGTYPE, 0o444, 0, 0),
        "licenses/coder-websocket-LICENSE.txt": (tarfile.REGTYPE, 0o444, 0, 0),
        "licenses/THIRD_PARTY_NOTICES.md": (tarfile.REGTYPE, 0o444, 0, 0),
    }
    seen: set[str] = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(uncompressed), mode="r:") as archive:
            for member in archive:
                path = PurePosixPath(member.name)
                if (
                    member.name in seen
                    or path.is_absolute()
                    or ".." in path.parts
                    or path.as_posix() != member.name
                    or member.name not in expected
                ):
                    raise OCIReleaseError("OCI layer contains an unsafe or duplicate path")
                seen.add(member.name)
                entry_type, mode, uid, gid = expected[member.name]
                if (
                    member.type != entry_type
                    or member.mode != mode
                    or member.uid != uid
                    or member.gid != gid
                    or member.mtime != source_date_epoch
                    or member.uname
                    or member.gname
                    or member.pax_headers
                ):
                    raise OCIReleaseError("OCI layer metadata violates static image policy")
                if member.isfile():
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise OCIReleaseError("OCI layer regular file is unreadable")
                    payload = stream.read(MAX_BLOB_BYTES + 1)
                    if len(payload) != member.size or len(payload) > MAX_BLOB_BYTES:
                        raise OCIReleaseError("OCI layer file size is invalid")
                    if member.name == "service":
                        if (
                            len(payload) != binary_size
                            or _sha256(payload) != binary_sha256
                            or not _static_elf(payload, architecture)
                        ):
                            raise OCIReleaseError("OCI service binary violates static ELF policy")
                    elif member.name.endswith("ca-certificates.crt"):
                        if _sha256(payload) != ca_sha256 or b"-----BEGIN CERTIFICATE-----" not in payload:
                            raise OCIReleaseError("OCI CA bundle does not match receipt")
            if seen != set(expected):
                raise OCIReleaseError("OCI layer file layout is incomplete")
    except tarfile.TarError as error:
        raise OCIReleaseError("OCI layer tar is invalid") from error
    return uncompressed


def _validate_artifact(
    layout: Path,
    descriptor: dict[str, object],
    artifact_type: str,
    image_descriptor: dict[str, object],
    label: str,
) -> tuple[dict[str, object], set[str]]:
    manifest_data, _ = _blob(layout, descriptor, OCI_IMAGE_MANIFEST, label + " manifest")
    manifest = _canonical_blob_json(manifest_data, label + " manifest")
    _object(
        manifest,
        {"artifactType", "config", "layers", "mediaType", "schemaVersion", "subject"},
        label + " manifest",
    )
    if (
        manifest["schemaVersion"] != 2
        or manifest["mediaType"] != OCI_IMAGE_MANIFEST
        or manifest["artifactType"] != artifact_type
        or manifest["subject"] != image_descriptor
    ):
        raise OCIReleaseError(f"{label} manifest is not attached to the image index")
    empty_data, empty_descriptor = _blob(
        layout, manifest["config"], OCI_EMPTY_CONFIG, label + " empty config"
    )
    if empty_data != b"{}" or set(empty_descriptor) != {"mediaType", "digest", "size"}:
        raise OCIReleaseError(f"{label} empty config is invalid")
    layers = manifest["layers"]
    if not isinstance(layers, list) or len(layers) != 1:
        raise OCIReleaseError(f"{label} must have exactly one layer")
    payload, payload_descriptor = _blob(layout, layers[0], artifact_type, label + " payload")
    if set(payload_descriptor) != {"mediaType", "digest", "size", "annotations"}:
        raise OCIReleaseError(f"{label} payload descriptor fields are invalid")
    document = _canonical_blob_json(payload, label + " payload")
    return document, {
        str(descriptor["digest"]).split(":", 1)[1],
        str(empty_descriptor["digest"]).split(":", 1)[1],
        str(payload_descriptor["digest"]).split(":", 1)[1],
    }


def _validate_service_layout(
    root: Path,
    record: dict[str, object],
    receipt: dict[str, object],
) -> set[Path]:
    fields = {
        "name",
        "oci_index_sha256",
        "oci_index_size",
        "image_index_digest",
        "image_index_size",
        "sbom_manifest_digest",
        "sbom_manifest_size",
        "provenance_manifest_digest",
        "provenance_manifest_size",
        "platforms",
    }
    _object(record, fields, "service receipt")
    service = _require_identifier(record["name"], "service name")
    if service not in SERVICES:
        raise OCIReleaseError("receipt contains an unsupported service")
    layout = root / "services" / service
    layout_info = layout.lstat()
    if stat.S_ISLNK(layout_info.st_mode) or not stat.S_ISDIR(layout_info.st_mode):
        raise OCIReleaseError("OCI layout must be a non-symlink directory")
    oci_layout_data = _read_regular(layout / "oci-layout", 1024, "oci-layout")
    if oci_layout_data != _json_bytes({"imageLayoutVersion": OCI_LAYOUT_VERSION}):
        raise OCIReleaseError("oci-layout is invalid")
    index_data = _read_regular(layout / "index.json", MAX_JSON_BYTES, "OCI root index")
    if (
        len(index_data) != _integer(record["oci_index_size"], 1, MAX_JSON_BYTES, "OCI index size")
        or _sha256(index_data) != _require_sha(record["oci_index_sha256"], "OCI index hash")
    ):
        raise OCIReleaseError("OCI root index does not match receipt")
    root_index = _strict_json(index_data, "OCI root index")
    if not isinstance(root_index, dict) or _json_bytes(root_index) != index_data:
        raise OCIReleaseError("OCI root index is not canonical JSON")
    _object(root_index, {"annotations", "manifests", "mediaType", "schemaVersion"}, "OCI root index")
    manifests = root_index["manifests"]
    if (
        root_index["schemaVersion"] != 2
        or root_index["mediaType"] != OCI_IMAGE_INDEX
        or not isinstance(manifests, list)
        or len(manifests) != 3
    ):
        raise OCIReleaseError("OCI root index structure is invalid")
    image_descriptor = manifests[0]
    if not isinstance(image_descriptor, dict) or set(image_descriptor) != {
        "annotations", "digest", "mediaType", "size"
    }:
        raise OCIReleaseError("OCI image index descriptor fields are invalid")
    if (
        image_descriptor.get("digest") != record["image_index_digest"]
        or image_descriptor.get("size") != record["image_index_size"]
    ):
        raise OCIReleaseError("OCI image index descriptor does not match receipt")
    image_data, _ = _blob(layout, image_descriptor, OCI_IMAGE_INDEX, "OCI image index")
    image_index = _canonical_blob_json(image_data, "OCI image index")
    _object(image_index, {"annotations", "manifests", "mediaType", "schemaVersion"}, "OCI image index")
    platform_descriptors = image_index["manifests"]
    platform_records = record["platforms"]
    if not isinstance(platform_descriptors, list) or not isinstance(platform_records, list):
        raise OCIReleaseError("OCI platform lists are invalid")
    if len(platform_descriptors) != 2 or len(platform_records) != 2:
        raise OCIReleaseError("OCI image must contain exactly amd64 and arm64")
    referenced = {str(image_descriptor["digest"]).split(":", 1)[1]}
    seen_architectures: list[str] = []
    for descriptor, platform_record in zip(platform_descriptors, platform_records):
        if not isinstance(descriptor, dict) or set(descriptor) != {
            "digest", "mediaType", "platform", "size"
        }:
            raise OCIReleaseError("OCI platform descriptor fields are invalid")
        platform_record = _object(
            platform_record,
            {
                "architecture",
                "binary_sha256",
                "binary_size",
                "image_manifest_digest",
                "image_manifest_size",
            },
            "platform receipt",
        )
        architecture = platform_record["architecture"]
        if architecture not in ARCHITECTURES or descriptor.get("platform") != {
            "architecture": architecture,
            "os": "linux",
        }:
            raise OCIReleaseError("OCI platform descriptor is invalid")
        if (
            descriptor.get("digest") != platform_record["image_manifest_digest"]
            or descriptor.get("size") != platform_record["image_manifest_size"]
        ):
            raise OCIReleaseError("OCI platform manifest does not match receipt")
        seen_architectures.append(str(architecture))
        manifest_data, _ = _blob(layout, descriptor, OCI_IMAGE_MANIFEST, "platform manifest")
        referenced.add(str(descriptor["digest"]).split(":", 1)[1])
        manifest = _canonical_blob_json(manifest_data, "platform manifest")
        _object(manifest, {"config", "layers", "mediaType", "schemaVersion"}, "platform manifest")
        if manifest["schemaVersion"] != 2 or manifest["mediaType"] != OCI_IMAGE_MANIFEST:
            raise OCIReleaseError("platform manifest structure is invalid")
        config_data, config_descriptor = _blob(
            layout, manifest["config"], OCI_IMAGE_CONFIG, "platform config"
        )
        referenced.add(str(config_descriptor["digest"]).split(":", 1)[1])
        config = _canonical_blob_json(config_data, "platform config")
        expected_config_fields = {"architecture", "config", "created", "history", "os", "rootfs"}
        _object(config, expected_config_fields, "platform config")
        expected_created = _timestamp(int(receipt["source_date_epoch"]))
        if (
            config["architecture"] != architecture
            or config["os"] != "linux"
            or config["created"] != expected_created
            or config["config"]
            != {
                "Entrypoint": ["/service"],
                "Env": ["SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"],
                "StopSignal": "SIGTERM",
                "User": "65532:65532",
                "WorkingDir": "/",
            }
            or config["history"]
            != [
                {
                    "comment": "reproducible daemonless OCI builder",
                    "created": expected_created,
                    "created_by": "xiaozhi-agent-daemonless-oci-builder/2",
                }
            ]
        ):
            raise OCIReleaseError("platform config violates static image policy")
        layers = manifest["layers"]
        if not isinstance(layers, list) or len(layers) != 1:
            raise OCIReleaseError("platform manifest must contain exactly one layer")
        layer_data, layer_descriptor = _blob(layout, layers[0], OCI_LAYER_GZIP, "platform layer")
        referenced.add(str(layer_descriptor["digest"]).split(":", 1)[1])
        uncompressed = _validate_layer(
            layer_data,
            str(architecture),
            int(receipt["source_date_epoch"]),
            _require_sha(platform_record["binary_sha256"], "binary hash"),
            _integer(platform_record["binary_size"], 1, 64 * 1024 * 1024, "binary size"),
            _require_sha(receipt["ca_bundle_sha256"], "CA bundle hash"),
        )
        rootfs = config["rootfs"]
        if rootfs != {"diff_ids": [_digest(uncompressed)], "type": "layers"}:
            raise OCIReleaseError("platform rootfs diff ID is invalid")
    if tuple(seen_architectures) != ARCHITECTURES:
        raise OCIReleaseError("OCI platform ordering is not canonical")

    sbom_descriptor, provenance_descriptor = manifests[1], manifests[2]
    if not isinstance(sbom_descriptor, dict) or not isinstance(provenance_descriptor, dict):
        raise OCIReleaseError("OCI artifact descriptors are invalid")
    if (
        set(sbom_descriptor)
        != {"annotations", "artifactType", "digest", "mediaType", "size"}
        or set(provenance_descriptor)
        != {"annotations", "artifactType", "digest", "mediaType", "size"}
        or
        sbom_descriptor.get("digest") != record["sbom_manifest_digest"]
        or sbom_descriptor.get("size") != record["sbom_manifest_size"]
        or sbom_descriptor.get("artifactType") != SPDX_MEDIA_TYPE
        or provenance_descriptor.get("digest") != record["provenance_manifest_digest"]
        or provenance_descriptor.get("size") != record["provenance_manifest_size"]
        or provenance_descriptor.get("artifactType") != INTOTO_MEDIA_TYPE
    ):
        raise OCIReleaseError("OCI artifact descriptors do not match receipt")
    spdx, sbom_refs = _validate_artifact(
        layout, sbom_descriptor, SPDX_MEDIA_TYPE, image_descriptor, "SPDX SBOM"
    )
    provenance, provenance_refs = _validate_artifact(
        layout, provenance_descriptor, INTOTO_MEDIA_TYPE, image_descriptor, "provenance"
    )
    referenced.update(sbom_refs)
    referenced.update(provenance_refs)
    if (
        spdx.get("spdxVersion") != SPDX_VERSION
        or spdx.get("SPDXID") != "SPDXRef-DOCUMENT"
        or spdx.get("dataLicense") != "CC0-1.0"
        or spdx.get("documentDescribes") != ["SPDXRef-Package-Service"]
        or spdx.get("creationInfo")
        != {
            "created": _timestamp(int(receipt["source_date_epoch"])),
            "creators": ["Tool: xiaozhi-agent-daemonless-oci-builder/2"],
        }
    ):
        raise OCIReleaseError("SPDX document identity is invalid")
    packages = spdx.get("packages")
    if not isinstance(packages, list) or len(packages) != 4 or any(
        not isinstance(package, dict) or package.get("filesAnalyzed") is not False
        for package in packages
    ):
        raise OCIReleaseError("SPDX package inventory is incomplete or overclaims analysis")
    image_hex = str(image_descriptor["digest"]).split(":", 1)[1]
    service_package = packages[0]
    if service_package.get("checksums") != [{"algorithm": "SHA256", "checksumValue": image_hex}]:
        raise OCIReleaseError("SPDX service package is not bound to image index")
    if (
        provenance.get("_type") != INTOTO_STATEMENT_TYPE
        or provenance.get("predicateType") != SLSA_PROVENANCE_TYPE
        or provenance.get("subject")
        != [{"digest": {"sha256": image_hex}, "name": "xiaozhi-agent/" + service}]
    ):
        raise OCIReleaseError("provenance subject is not bound to image index")
    predicate = provenance.get("predicate")
    if not isinstance(predicate, dict):
        raise OCIReleaseError("provenance predicate is invalid")
    build_definition = predicate.get("buildDefinition")
    run_details = predicate.get("runDetails")
    builder = run_details.get("builder") if isinstance(run_details, dict) else None
    if (
        not isinstance(build_definition, dict)
        or build_definition.get("buildType") != BUILD_TYPE
        or not isinstance(run_details, dict)
        or not isinstance(builder, dict)
        or builder.get("id") != BUILDER_ID
        or builder.get("version") != {"oci-release": "2"}
    ):
        raise OCIReleaseError("provenance builder identity is invalid")
    dependencies = build_definition.get("resolvedDependencies")
    resolved: set[tuple[object, object]] = set()
    if isinstance(dependencies, list):
        for item in dependencies:
            if not isinstance(item, dict):
                continue
            digest = item.get("digest")
            resolved.add(
                (item.get("uri"), digest.get("sha256") if isinstance(digest, dict) else None)
            )
    if not isinstance(dependencies, list) or resolved < {
        ("file:source-inputs.json", receipt["source_inputs_sha256"]),
        ("file:ca-certificates.crt", receipt["ca_bundle_sha256"]),
        ("file:go-executable", receipt["go_executable_sha256"]),
    }:
        raise OCIReleaseError("provenance dependencies do not match release receipt")

    expected = {
        Path("services") / service / "oci-layout",
        Path("services") / service / "index.json",
    }
    expected.update(Path("services") / service / "blobs/sha256" / digest for digest in referenced)
    actual_blobs = {
        path.name
        for path in (layout / "blobs/sha256").iterdir()
        if path.is_file() and not path.is_symlink()
    }
    if actual_blobs != referenced:
        raise OCIReleaseError("OCI layout contains missing or orphaned blobs")
    return expected


def validate_release_bundle(
    root: Path,
    *,
    trusted_public_key_path: Path,
    expected_signing_key_id: str,
    expected_release_id: str | None = None,
    require_read_only: bool = True,
) -> dict[str, object]:
    try:
        root_info = root.lstat()
    except OSError as error:
        raise OCIReleaseError("release bundle does not exist") from error
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise OCIReleaseError("release bundle must be a non-symlink directory")
    receipt_data = _read_regular(root / "release-receipt.json", MAX_JSON_BYTES, "release receipt")
    receipt = _strict_json(receipt_data, "release receipt")
    receipt_fields = {
        "schema",
        "release_id",
        "version",
        "source_date_epoch",
        "source_inputs_sha256",
        "ca_bundle_sha256",
        "go_executable_sha256",
        "go_version",
        "signing_key_id",
        "signature_algorithm",
        "signature_b64url",
        "services",
    }
    receipt = _object(receipt, receipt_fields, "release receipt")
    if _json_bytes(receipt) != receipt_data:
        raise OCIReleaseError("release receipt is not canonical JSON")
    if receipt["schema"] != SCHEMA_VERSION:
        raise OCIReleaseError("release receipt schema is unsupported")
    release_id = _require_identifier(receipt["release_id"], "release ID")
    _require_version(receipt["version"])
    _timestamp(_integer(receipt["source_date_epoch"], MIN_SOURCE_DATE_EPOCH, MAX_SOURCE_DATE_EPOCH, "source date epoch"))
    _require_sha(receipt["source_inputs_sha256"], "source inputs hash")
    _require_sha(receipt["ca_bundle_sha256"], "CA bundle hash")
    _require_sha(receipt["go_executable_sha256"], "Go executable hash")
    signing_key_id = _require_identifier(receipt["signing_key_id"], "signing key ID")
    if signing_key_id != _require_identifier(expected_signing_key_id, "expected signing key ID"):
        raise OCIReleaseError("release signing key ID does not match trust policy")
    if expected_release_id is not None and release_id != expected_release_id:
        raise OCIReleaseError("release ID does not match expectation")
    if receipt["go_version"] != "go1.26.5" or receipt["signature_algorithm"] != "Ed25519":
        raise OCIReleaseError("release toolchain or signature algorithm is unsupported")
    signature = _decode_b64url(receipt["signature_b64url"], 64, "release signature")
    public_key = _load_public_key(trusted_public_key_path)
    try:
        public_key.verify(signature, _signature_payload(receipt))
    except InvalidSignature as error:
        raise OCIReleaseError("release receipt signature is invalid") from error
    ready = _read_regular(root / "READY", 128, "READY marker")
    if ready != (_sha256(receipt_data) + "\n").encode("ascii"):
        raise OCIReleaseError("release READY marker is invalid")
    source_data = _read_regular(root / "source-inputs.json", MAX_JSON_BYTES, "source inputs")
    if _sha256(source_data) != receipt["source_inputs_sha256"]:
        raise OCIReleaseError("source inputs do not match release receipt")
    source = _strict_json(source_data, "source inputs")
    if not isinstance(source, dict) or _json_bytes(source) != source_data:
        raise OCIReleaseError("source inputs are not canonical JSON")
    _object(source, {"algorithm", "inputs", "schema"}, "source inputs")
    inputs = source["inputs"]
    if (
        source["schema"] != 1
        or source["algorithm"] != "sha256"
        or not isinstance(inputs, list)
        or not 1 <= len(inputs) <= MAX_SOURCE_INPUTS
    ):
        raise OCIReleaseError("source input manifest is invalid")
    names: list[str] = []
    go_input: dict[str, object] | None = None
    for item in inputs:
        if not isinstance(item, dict) or set(item) not in (
            {"name", "sha256", "size"},
            {"name", "sha256", "size", "version"},
        ):
            raise OCIReleaseError("source input entry fields are invalid")
        name = item.get("name")
        if not isinstance(name, str) or not name or len(name) > 512:
            raise OCIReleaseError("source input name is invalid")
        names.append(name)
        if name == "toolchain:go-executable":
            go_input = item
        _require_sha(item.get("sha256"), "source input hash")
        _integer(item.get("size"), 1, MAX_BLOB_BYTES, "source input size")
    if names != sorted(set(names)):
        raise OCIReleaseError("source inputs are not uniquely sorted")
    if (
        go_input is None
        or go_input.get("sha256") != receipt["go_executable_sha256"]
        or go_input.get("version") != receipt["go_version"]
    ):
        raise OCIReleaseError("Go executable source input does not match release receipt")
    services = receipt["services"]
    if (
        not isinstance(services, list)
        or len(services) != len(SERVICES)
        or any(not isinstance(record, dict) for record in services)
        or tuple(record.get("name") for record in services) != SERVICES
    ):
        raise OCIReleaseError("release must contain the exact ordered seven-service set")
    expected_files = {Path("READY"), Path("release-receipt.json"), Path("source-inputs.json")}
    service_names: list[str] = []
    for record in services:
        if not isinstance(record, dict):
            raise OCIReleaseError("release service record is invalid")
        service_names.append(str(record.get("name")))
        expected_files.update(_validate_service_layout(root, record, receipt))
    if tuple(service_names) != SERVICES:
        raise OCIReleaseError("release service ordering is not canonical")
    actual_files: set[Path] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise OCIReleaseError("release bundle contains a symlink")
        mode = path.lstat().st_mode
        if require_read_only and mode & 0o222:
            raise OCIReleaseError("release bundle tree must be read-only")
        if path.is_file():
            actual_files.add(path.relative_to(root))
        elif not path.is_dir():
            raise OCIReleaseError("release bundle contains a non-regular object")
    if require_read_only and root_info.st_mode & 0o222:
        raise OCIReleaseError("release bundle root must be read-only")
    if actual_files != expected_files:
        raise OCIReleaseError("release bundle file layout is not exact")
    return receipt
