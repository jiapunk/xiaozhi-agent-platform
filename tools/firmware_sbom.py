#!/usr/bin/env python3
"""Shared fail-closed helpers for the M26 firmware SBOM release gate."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Set, Tuple


MAX_JSON = 4 * 1024 * 1024
MAX_SPDX = 8 * 1024 * 1024
MAX_MAP = 64 * 1024 * 1024
MAX_LICENSE = 2 * 1024 * 1024
MAX_SOURCE_PATCH = 2 * 1024 * 1024
MAX_ARCHIVE = 128 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ARCHIVE_RE = re.compile(r"(?:^|\s)([^\s()]+\.a)\(")


class FirmwareSBOMError(RuntimeError):
    pass


def _reject_duplicate_pairs(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FirmwareSBOMError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def require_regular(path: Path, maximum: int, label: str) -> bytes:
    try:
        info = path.lstat()
    except OSError as exc:
        raise FirmwareSBOMError(f"{label} is unavailable: {path}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise FirmwareSBOMError(f"{label} must be a regular non-symlink file: {path}")
    if info.st_size < 1 or info.st_size > maximum:
        raise FirmwareSBOMError(
            f"{label} size is outside 1..{maximum} bytes: {info.st_size}"
        )
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise FirmwareSBOMError(f"cannot read {label}: {path}: {exc}") from exc
    if len(data) != info.st_size:
        raise FirmwareSBOMError(f"{label} changed while it was read: {path}")
    return data


def load_json(path: Path, maximum: int = MAX_JSON, label: str = "JSON") -> Dict[str, Any]:
    raw = require_regular(path, maximum, label)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FirmwareSBOMError(f"invalid {label}: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise FirmwareSBOMError(f"{label} must contain one JSON object: {path}")
    return value


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def exact_keys(value: Mapping[str, Any], expected: Iterable[str], label: str) -> None:
    wanted = set(expected)
    actual = set(value)
    if actual != wanted:
        raise FirmwareSBOMError(
            f"{label} keys mismatch; missing={sorted(wanted - actual)}, "
            f"unexpected={sorted(actual - wanted)}"
        )


def safe_relative(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise FirmwareSBOMError(f"{label} must be a nonempty POSIX relative path")
    raw_parts = value.split("/")
    if any(part in ("", ".", "..") for part in raw_parts):
        raise FirmwareSBOMError(f"{label} is not a safe relative path: {value}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise FirmwareSBOMError(f"{label} is not a safe relative path: {value}")
    return path


def resolve_inside(root: Path, relative: Any, label: str) -> Path:
    rel = safe_relative(relative, label)
    candidate = root.joinpath(*rel.parts)
    try:
        resolved_root = root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise FirmwareSBOMError(f"cannot resolve {label}: {candidate}: {exc}") from exc
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise FirmwareSBOMError(f"{label} escapes its root: {relative}") from exc
    return resolved


def _rooted(path: Path, root: Path) -> str | None:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return None


def _git_head(root: Path, label: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise FirmwareSBOMError(f"cannot resolve {label} git revision: {exc}") from exc
    revision = result.stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise FirmwareSBOMError(f"invalid {label} git revision: {revision!r}")
    return revision


def load_policy(path: Path) -> Tuple[Dict[str, Any], bytes]:
    raw = require_regular(path, MAX_JSON, "firmware SBOM policy")
    try:
        policy = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FirmwareSBOMError(f"invalid firmware SBOM policy: {exc}") from exc
    if not isinstance(policy, dict):
        raise FirmwareSBOMError("firmware SBOM policy must be one JSON object")
    exact_keys(
        policy,
        {
            "schema_version",
            "profile",
            "source_date_epoch",
            "project",
            "sbom_tool",
            "artifacts",
            "managed_components",
            "required_spdx_ids",
            "supplemental_prebuilt_packages",
            "source_patches",
            "license_files",
            "unresolved_release_gates",
        },
        "firmware SBOM policy",
    )
    if policy["schema_version"] != 2 or policy["profile"] != "box3-production-security":
        raise FirmwareSBOMError("unsupported firmware SBOM policy version/profile")
    epoch = policy["source_date_epoch"]
    if not isinstance(epoch, int) or epoch < 1:
        raise FirmwareSBOMError("source_date_epoch must be a positive integer")
    for digest in re.findall(r'"sha256"\s*:\s*"([^"]+)"', raw.decode("utf-8")):
        if not SHA256_RE.fullmatch(digest):
            raise FirmwareSBOMError(f"invalid SHA-256 in firmware SBOM policy: {digest}")
    return policy, raw


def load_build_context(project_description: Path, policy: Mapping[str, Any]) -> Dict[str, Path]:
    description = load_json(project_description, MAX_JSON, "project description")
    required = {
        "project_name",
        "project_version",
        "target",
        "project_path",
        "build_dir",
        "idf_path",
        "c_compiler",
        "app_bin",
        "build_component_info",
    }
    missing = required - set(description)
    if missing:
        raise FirmwareSBOMError(f"project description is missing fields: {sorted(missing)}")
    fixed = policy["project"]
    for field, expected in (
        ("project_name", fixed["name"]),
        ("project_version", fixed["version"]),
        ("target", fixed["target"]),
    ):
        if description[field] != expected:
            raise FirmwareSBOMError(
                f"project description {field} mismatch: {description[field]!r} != {expected!r}"
            )

    project_root = Path(description["project_path"]).resolve(strict=True)
    build_root = Path(description["build_dir"]).resolve(strict=True)
    idf_root = Path(description["idf_path"]).resolve(strict=True)
    compiler = Path(description["c_compiler"]).resolve(strict=True)
    toolchain_root = compiler.parent.parent
    managed_root = project_root / "managed_components"
    if project_description.resolve(strict=True) != build_root / "project_description.json":
        raise FirmwareSBOMError("project description is not the configured build-root descriptor")
    if build_root.parent != project_root:
        raise FirmwareSBOMError("build directory must be an immediate child of the project root")
    if toolchain_root.parent.name != fixed["toolchain_version"]:
        raise FirmwareSBOMError("toolchain version directory does not match the frozen policy")

    component_info = description["build_component_info"]
    if not isinstance(component_info, dict) or "claw_core" not in component_info:
        raise FirmwareSBOMError("project description does not contain the ESP-Claw core")
    claw_dir = Path(component_info["claw_core"]["dir"]).resolve(strict=True)
    esp_claw_root = claw_dir.parents[2]
    if _git_head(idf_root, "ESP-IDF") != fixed["esp_idf_commit"]:
        raise FirmwareSBOMError("ESP-IDF git revision does not match the frozen policy")
    if _git_head(esp_claw_root, "ESP-Claw") != fixed["esp_claw_commit"]:
        raise FirmwareSBOMError("ESP-Claw git revision does not match the frozen policy")

    roots = {
        "project": project_root,
        "build": build_root,
        "idf": idf_root,
        "toolchain": toolchain_root,
        "managed": managed_root.resolve(strict=True),
        "esp_claw": esp_claw_root,
    }
    return {**roots, "project_description": project_description.resolve(strict=True)}


def _verify_artifacts(policy: Mapping[str, Any], roots: Mapping[str, Path]) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    artifacts = policy["artifacts"]
    if not isinstance(artifacts, list) or not artifacts:
        raise FirmwareSBOMError("artifact policy must be a nonempty list")
    seen: Set[Tuple[str, str]] = set()
    for index, entry in enumerate(artifacts):
        if not isinstance(entry, dict):
            raise FirmwareSBOMError(f"artifact {index} must be an object")
        exact_keys(entry, {"root", "path", "size", "sha256"}, f"artifact {index}")
        root_name = entry["root"]
        if root_name not in ("project", "build"):
            raise FirmwareSBOMError(f"artifact {index} has unsupported root: {root_name}")
        rel = safe_relative(entry["path"], f"artifact {index} path").as_posix()
        key = (root_name, rel)
        if key in seen:
            raise FirmwareSBOMError(f"duplicate artifact policy entry: {key}")
        seen.add(key)
        path = resolve_inside(roots[root_name], rel, f"artifact {index}")
        maximum = MAX_MAP if rel.endswith(".map") else MAX_JSON if rel.endswith(".json") else 4 * 1024 * 1024
        data = require_regular(path, maximum, f"artifact {rel}")
        actual = {"root": root_name, "path": rel, "size": len(data), "sha256": sha256_bytes(data)}
        if actual["size"] != entry["size"] or actual["sha256"] != entry["sha256"]:
            raise FirmwareSBOMError(f"artifact does not match frozen policy: {root_name}:{rel}")
        records.append(actual)
    return records


def _parse_dependency_lock(path: Path) -> Dict[str, Dict[str, str]]:
    text = require_regular(path, MAX_JSON, "dependencies.lock").decode("utf-8")
    entries: Dict[str, Dict[str, str]] = {}
    matches = list(re.finditer(r"(?m)^  ([A-Za-z0-9_.\-/]+):\n", text))
    for index, match in enumerate(matches):
        name = match.group(1)
        block = text[match.end() : matches[index + 1].start() if index + 1 < len(matches) else len(text)]
        version_match = re.search(r"(?m)^    version: ['\"]?([^'\"\n]+)['\"]?\s*$", block)
        hash_match = re.search(r"(?m)^    component_hash: ([0-9a-f]{64})\s*$", block)
        entries[name] = {
            "version": version_match.group(1) if version_match else "",
            "component_hash": hash_match.group(1) if hash_match else "",
        }
    return entries


def verify_source_locks(policy: Mapping[str, Any], roots: Mapping[str, Path]) -> None:
    dependencies = _parse_dependency_lock(roots["project"] / "dependencies.lock")
    for name, expected in policy["managed_components"].items():
        actual = dependencies.get(name)
        if not actual:
            raise FirmwareSBOMError(f"managed component is absent from dependencies.lock: {name}")
        if actual["version"] != expected["version"] or actual["component_hash"] != expected["component_hash"]:
            raise FirmwareSBOMError(f"managed component lock mismatch: {name}")

    upstream = load_json(roots["project"] / "upstream.lock.json", MAX_JSON, "upstream lock")
    try:
        xiaozhi = upstream["upstreams"]["xiaozhi-esp32"]["commit"]
        claw_entry = upstream["upstreams"]["esp-claw"]
        claw = claw_entry["commit"]
        claw_patches = claw_entry["patches"]
    except (KeyError, TypeError) as exc:
        raise FirmwareSBOMError("upstream lock is missing required commits or patches") from exc
    if xiaozhi != policy["project"]["xiaozhi_commit"] or claw != policy["project"]["esp_claw_commit"]:
        raise FirmwareSBOMError("upstream lock commits do not match the frozen policy")
    if not isinstance(claw_patches, list):
        raise FirmwareSBOMError("upstream lock ESP-Claw patches must be a list")
    locked_patches: List[Tuple[str, str]] = []
    for index, entry in enumerate(claw_patches):
        if not isinstance(entry, dict):
            raise FirmwareSBOMError(f"upstream lock patch {index} must be an object")
        exact_keys(entry, {"path", "sha256"}, f"upstream lock patch {index}")
        locked_patches.append(
            (
                safe_relative(entry["path"], f"upstream lock patch {index} path").as_posix(),
                entry["sha256"],
            )
        )
    if not isinstance(policy["source_patches"], list):
        raise FirmwareSBOMError("source patch policy must be a list")
    policy_patches: List[Tuple[str, str]] = []
    for index, entry in enumerate(policy["source_patches"]):
        if not isinstance(entry, dict):
            raise FirmwareSBOMError(f"source patch {index} must be an object")
        exact_keys(entry, {"root", "source", "bundle", "sha256"}, f"source patch {index}")
        if entry["root"] == "project":
            policy_patches.append(
                (
                    safe_relative(entry["source"], f"source patch {index} source").as_posix(),
                    entry["sha256"],
                )
            )
    if locked_patches != policy_patches:
        raise FirmwareSBOMError("upstream lock patches do not match the frozen policy")


def verify_sbom_tool(sbom_tool: Path, policy: Mapping[str, Any]) -> Dict[str, str]:
    try:
        tool = sbom_tool.resolve(strict=True)
    except OSError as exc:
        raise FirmwareSBOMError(f"SBOM tool is unavailable: {sbom_tool}: {exc}") from exc
    if not tool.is_file() or sbom_tool.is_symlink():
        raise FirmwareSBOMError("SBOM tool must be a regular non-symlink executable")
    try:
        result = subprocess.run(
            [str(tool), "--version"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise FirmwareSBOMError(f"cannot execute the SBOM tool: {exc}") from exc
    expected_line = f"{policy['sbom_tool']['name']} {policy['sbom_tool']['version']}"
    if result.stdout.strip() != expected_line or result.stderr.strip():
        raise FirmwareSBOMError("SBOM tool version output does not match the frozen policy")

    python = tool.parent / "python"
    try:
        freeze = subprocess.run(
            [str(python), "-m", "pip", "freeze"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise FirmwareSBOMError(f"cannot inventory the SBOM Python environment: {exc}") from exc
    packages: Dict[str, str] = {}
    for line in freeze.stdout.splitlines():
        if not line or line.startswith("#") or "==" not in line:
            raise FirmwareSBOMError(f"unsupported pip freeze entry in SBOM environment: {line!r}")
        name, version = line.split("==", 1)
        if name in packages:
            raise FirmwareSBOMError(f"duplicate SBOM Python package: {name}")
        packages[name] = version
    if packages != policy["sbom_tool"]["python_packages"]:
        raise FirmwareSBOMError("SBOM Python environment does not match the frozen package set")
    return packages


def source_timestamp(epoch: int) -> str:
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def canonicalize_spdx(raw: bytes, role: str, artifact_sha256: str, epoch: int) -> bytes:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FirmwareSBOMError(f"{role} SPDX is not UTF-8") from exc
    if "\r" in text or "\x00" in text:
        raise FirmwareSBOMError(f"{role} SPDX contains unsupported characters")
    lines = text.splitlines()
    if not lines or not lines[0].startswith("# Generated by esp-idf-sbom "):
        raise FirmwareSBOMError(f"{role} SPDX lacks the official generator marker")
    lines[0] = "# Generated by esp-idf-sbom 1.2.0; canonicalized by xiaozhi-agent-platform M26"
    namespace = f"https://xiaozhi-agent.local/spdx/firmware/{role}/sha256-{artifact_sha256}"
    created = source_timestamp(epoch)
    namespace_hits = created_hits = 0
    for index, line in enumerate(lines):
        if line.startswith("DocumentNamespace: "):
            lines[index] = f"DocumentNamespace: {namespace}"
            namespace_hits += 1
        elif line.startswith("Created: "):
            lines[index] = f"Created: {created}"
            created_hits += 1
    if namespace_hits != 1 or created_hits != 1:
        raise FirmwareSBOMError(f"{role} SPDX document metadata is ambiguous")
    canonical = ("\n".join(lines) + "\n").encode("utf-8")
    if len(canonical) > MAX_SPDX:
        raise FirmwareSBOMError(f"{role} canonical SPDX is too large")
    return canonical


def _single_line(text: str, prefix: str, label: str) -> str:
    matches = [line[len(prefix) :] for line in text.splitlines() if line.startswith(prefix)]
    if len(matches) != 1:
        raise FirmwareSBOMError(f"{label} must occur exactly once")
    return matches[0]


def _package_blocks(text: str) -> List[Dict[str, List[str]]]:
    packages: List[Dict[str, List[str]]] = []
    for paragraph in text.split("\n\n"):
        if not any(line.startswith("PackageName: ") for line in paragraph.splitlines()):
            continue
        block: Dict[str, List[str]] = {}
        for line in paragraph.splitlines():
            if ": " not in line or line.startswith("#"):
                continue
            key, value = line.split(": ", 1)
            block.setdefault(key, []).append(value)
        if len(block.get("PackageName", [])) != 1 or len(block.get("SPDXID", [])) != 1:
            raise FirmwareSBOMError("SPDX package block has ambiguous identity")
        packages.append(block)
    return packages


def inspect_spdx(
    path: Path,
    role: str,
    artifact_name: str,
    artifact_sha256: str,
    policy: Mapping[str, Any],
) -> Dict[str, Any]:
    raw = require_regular(path, MAX_SPDX, f"{role} SPDX")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FirmwareSBOMError(f"{role} SPDX is not UTF-8") from exc
    expected_doc = "xiaozhi_agent_platform" if role == "app" else "bootloader"
    expected_project = (
        "SPDXRef-PROJECT-xiaozhi-agent-platform" if role == "app" else "SPDXRef-PROJECT-bootloader"
    )
    if _single_line(text, "SPDXVersion: ", f"{role} SPDX version") != policy["sbom_tool"]["spdx_version"]:
        raise FirmwareSBOMError(f"{role} SPDX version mismatch")
    if _single_line(text, "DocumentName: ", f"{role} document name") != expected_doc:
        raise FirmwareSBOMError(f"{role} SPDX document name mismatch")
    expected_namespace = f"https://xiaozhi-agent.local/spdx/firmware/{role}/sha256-{artifact_sha256}"
    if _single_line(text, "DocumentNamespace: ", f"{role} namespace") != expected_namespace:
        raise FirmwareSBOMError(f"{role} SPDX namespace mismatch")
    if _single_line(text, "Created: ", f"{role} created time") != source_timestamp(policy["source_date_epoch"]):
        raise FirmwareSBOMError(f"{role} SPDX timestamp mismatch")
    if f"Relationship: SPDXRef-DOCUMENT DESCRIBES {expected_project}" not in text:
        raise FirmwareSBOMError(f"{role} SPDX does not describe the expected project")

    packages = _package_blocks(text)
    package_by_id = {block["SPDXID"][0]: block for block in packages}
    if len(package_by_id) != len(packages):
        raise FirmwareSBOMError(f"{role} SPDX contains duplicate package IDs")
    missing = set(policy["required_spdx_ids"][role]) - ({"SPDXRef-DOCUMENT"} | set(package_by_id))
    if missing:
        raise FirmwareSBOMError(f"{role} SPDX is missing required packages: {sorted(missing)}")
    framework = package_by_id["SPDXRef-FRAMEWORK-esp-idf"]
    toolchain = package_by_id["SPDXRef-TOOLCHAIN-xtensa-esp-elf"]
    if framework.get("PackageVersion") != [policy["project"]["esp_idf_version"]]:
        raise FirmwareSBOMError(f"{role} SPDX ESP-IDF version mismatch")
    if toolchain.get("PackageVersion") != [policy["project"]["toolchain_version"]]:
        raise FirmwareSBOMError(f"{role} SPDX toolchain version mismatch")

    file_pattern = re.compile(
        rf"(?ms)^FileName: \./{re.escape(artifact_name)}\n.*?^FileChecksum: SHA256: ([0-9a-f]{{64}})$"
    )
    file_matches = file_pattern.findall(text)
    if file_matches != [artifact_sha256]:
        raise FirmwareSBOMError(f"{role} SPDX artifact checksum mismatch")
    dependency_edges: Dict[str, Set[str]] = {}
    for parent, child in re.findall(
        r"(?m)^Relationship: (SPDXRef-[^\s]+) DEPENDS_ON (SPDXRef-[^\s]+)$",
        text,
    ):
        if parent not in package_by_id or child not in package_by_id:
            raise FirmwareSBOMError(f"{role} SPDX dependency references a non-package ID")
        dependency_edges.setdefault(parent, set()).add(child)
    reachable = {expected_project}
    pending = [expected_project]
    while pending:
        parent = pending.pop()
        for child in dependency_edges.get(parent, set()):
            if child not in reachable:
                reachable.add(child)
                pending.append(child)
    unreachable = set(package_by_id) - reachable
    if unreachable:
        raise FirmwareSBOMError(
            f"{role} SPDX contains packages outside the project dependency graph: "
            f"{sorted(unreachable)}"
        )
    file_count = sum(1 for line in text.splitlines() if line.startswith("FileName: "))
    return {
        "file": path.name,
        "size": len(raw),
        "sha256": sha256_bytes(raw),
        "package_count": len(packages),
        "reachable_package_count": len(reachable),
        "file_count": file_count,
        "document_namespace": expected_namespace,
        "package_ids": sorted(package_by_id),
    }


def _component_id(component: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9.-]", "-", component)
    return f"SPDXRef-COMPONENT-{normalized}"


def _archive_paths(map_path: Path) -> Set[str]:
    raw = require_regular(map_path, MAX_MAP, f"linker map {map_path.name}")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise FirmwareSBOMError(f"linker map is not UTF-8: {map_path}") from exc
    archives = set(ARCHIVE_RE.findall(text))
    if not archives:
        raise FirmwareSBOMError(f"linker map has no archive members: {map_path}")
    return archives


def inspect_map(
    map_path: Path,
    roots: Mapping[str, Path],
    spdx_package_ids: Sequence[str],
    policy: Mapping[str, Any],
    role: str,
) -> Dict[str, Any]:
    ids = set(spdx_package_ids)
    component_ids: Set[str] = set()
    external: List[Dict[str, Any]] = []
    managed_found: Set[Tuple[str, str]] = set()
    supplement_by_path: Dict[Tuple[str, str], Mapping[str, Any]] = {}
    for entry in policy["supplemental_prebuilt_packages"]:
        key = (entry["root"], safe_relative(entry["archive"], "supplement archive").as_posix())
        if key in supplement_by_path:
            raise FirmwareSBOMError(f"duplicate supplemental archive policy: {key}")
        supplement_by_path[key] = entry

    for archive in sorted(_archive_paths(map_path)):
        if not archive.startswith("/"):
            path = PurePosixPath(archive)
            if len(path.parts) < 3 or path.parts[0] != "esp-idf":
                raise FirmwareSBOMError(f"unexpected relative archive in {role} map: {archive}")
            component_ids.add(_component_id(path.parts[1]))
            continue

        try:
            resolved = Path(archive).resolve(strict=True)
        except OSError as exc:
            raise FirmwareSBOMError(f"cannot resolve linked archive {archive}: {exc}") from exc
        source_root = ""
        rel = _rooted(resolved, roots["idf"])
        component = None
        if rel is not None and rel.startswith("components/"):
            source_root = "idf"
            parts = PurePosixPath(rel).parts
            if len(parts) < 3:
                raise FirmwareSBOMError(f"invalid ESP-IDF prebuilt archive path: {rel}")
            component = parts[1]
            component_ids.add(_component_id(component))
        else:
            rel = _rooted(resolved, roots["project"])
            if rel is not None and rel.startswith("managed_components/"):
                source_root = "project"
                key = (source_root, rel)
                if key not in supplement_by_path:
                    raise FirmwareSBOMError(
                        f"linked managed prebuilt archive lacks a supplemental package: {rel}"
                    )
                managed_found.add(key)
            else:
                rel = _rooted(resolved, roots["toolchain"])
                if rel is not None:
                    source_root = "toolchain"
                    if resolved.name not in {"libgcc.a", "libc.a", "libstdc++.a"}:
                        raise FirmwareSBOMError(f"unexpected linked toolchain archive: {rel}")
                    if "SPDXRef-TOOLCHAIN-xtensa-esp-elf" not in ids:
                        raise FirmwareSBOMError("toolchain runtime is linked but absent from SPDX")
                else:
                    raise FirmwareSBOMError(f"linked archive is outside every approved root: {resolved}")
        data = require_regular(resolved, MAX_ARCHIVE, f"linked archive {resolved.name}")
        record: Dict[str, Any] = {
            "root": source_root,
            "path": rel,
            "size": len(data),
            "sha256": sha256_bytes(data),
        }
        if component is not None:
            record["component_spdx_id"] = _component_id(component)
        external.append(record)

    missing_ids = component_ids - ids
    if missing_ids:
        raise FirmwareSBOMError(
            f"{role} linker map components are absent from SPDX: {sorted(missing_ids)}"
        )
    expected_managed = set(supplement_by_path) if role == "app" else set()
    if managed_found != expected_managed:
        raise FirmwareSBOMError(
            f"{role} supplemental archive coverage mismatch; "
            f"missing={sorted(expected_managed - managed_found)}, "
            f"unexpected={sorted(managed_found - expected_managed)}"
        )
    return {
        "component_spdx_ids": sorted(component_ids),
        "external_archives": sorted(external, key=lambda item: (item["root"], item["path"])),
    }


def verify_and_copy_licenses(
    policy: Mapping[str, Any],
    roots: Mapping[str, Path],
    bundle_root: Path | None,
) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    seen_bundle: Set[str] = set()
    for index, entry in enumerate(policy["license_files"]):
        exact_keys(entry, {"root", "source", "bundle", "sha256"}, f"license file {index}")
        root_name = entry["root"]
        if root_name not in roots:
            raise FirmwareSBOMError(f"license file {index} has unsupported root: {root_name}")
        source_rel = safe_relative(entry["source"], f"license file {index} source").as_posix()
        bundle_rel = safe_relative(entry["bundle"], f"license file {index} bundle").as_posix()
        if not bundle_rel.startswith("licenses/") or bundle_rel in seen_bundle:
            raise FirmwareSBOMError(f"invalid or duplicate license bundle path: {bundle_rel}")
        seen_bundle.add(bundle_rel)
        source = resolve_inside(roots[root_name], source_rel, f"license source {index}")
        data = require_regular(source, MAX_LICENSE, f"license source {source_rel}")
        digest = sha256_bytes(data)
        if digest != entry["sha256"]:
            raise FirmwareSBOMError(f"license source hash mismatch: {root_name}:{source_rel}")
        if bundle_root is not None:
            destination = resolve_inside(bundle_root, bundle_rel, f"bundled license {index}")
            bundled = require_regular(destination, MAX_LICENSE, f"bundled license {bundle_rel}")
            if bundled != data:
                raise FirmwareSBOMError(f"bundled license differs from its frozen source: {bundle_rel}")
        result.append(
            {
                "source_root": root_name,
                "source_path": source_rel,
                "bundle_path": bundle_rel,
                "size": len(data),
                "sha256": digest,
            }
        )
    return result


def verify_and_copy_source_patches(
    policy: Mapping[str, Any],
    roots: Mapping[str, Path],
    bundle_root: Path | None,
) -> List[Dict[str, Any]]:
    patches = policy["source_patches"]
    if not isinstance(patches, list) or not patches:
        raise FirmwareSBOMError("source patch policy must be a nonempty list")
    result: List[Dict[str, Any]] = []
    seen_bundle: Set[str] = set()
    for index, entry in enumerate(patches):
        if not isinstance(entry, dict):
            raise FirmwareSBOMError(f"source patch {index} must be an object")
        exact_keys(entry, {"root", "source", "bundle", "sha256"}, f"source patch {index}")
        root_name = entry["root"]
        if root_name not in roots:
            raise FirmwareSBOMError(f"source patch {index} has unsupported root: {root_name}")
        source_rel = safe_relative(entry["source"], f"source patch {index} source").as_posix()
        bundle_rel = safe_relative(entry["bundle"], f"source patch {index} bundle").as_posix()
        if not bundle_rel.startswith("sources/") or bundle_rel in seen_bundle:
            raise FirmwareSBOMError(f"invalid or duplicate source patch bundle path: {bundle_rel}")
        seen_bundle.add(bundle_rel)
        source = resolve_inside(roots[root_name], source_rel, f"source patch {index}")
        data = require_regular(source, MAX_SOURCE_PATCH, f"source patch {source_rel}")
        digest = sha256_bytes(data)
        if digest != entry["sha256"]:
            raise FirmwareSBOMError(f"source patch hash mismatch: {root_name}:{source_rel}")
        if bundle_root is not None:
            destination = resolve_inside(bundle_root, bundle_rel, f"bundled source patch {index}")
            bundled = require_regular(
                destination, MAX_SOURCE_PATCH, f"bundled source patch {bundle_rel}"
            )
            if bundled != data:
                raise FirmwareSBOMError(
                    f"bundled source patch differs from its frozen source: {bundle_rel}"
                )
        result.append(
            {
                "source_root": root_name,
                "source_path": source_rel,
                "bundle_path": bundle_rel,
                "size": len(data),
                "sha256": digest,
            }
        )
    return result


def supplemental_records(
    policy: Mapping[str, Any], roots: Mapping[str, Path], app_map: Mapping[str, Any]
) -> List[Dict[str, Any]]:
    external_by_key = {
        (entry["root"], entry["path"]): entry for entry in app_map["external_archives"]
    }
    records: List[Dict[str, Any]] = []
    for index, entry in enumerate(policy["supplemental_prebuilt_packages"]):
        exact_keys(
            entry,
            {"root", "archive", "name", "version", "component_hash", "license", "reason"},
            f"supplemental package {index}",
        )
        root_name = entry["root"]
        rel = safe_relative(entry["archive"], f"supplemental package {index} archive").as_posix()
        linked = external_by_key.get((root_name, rel))
        if linked is None:
            raise FirmwareSBOMError(f"supplemental archive is not linked: {root_name}:{rel}")
        managed = policy["managed_components"].get(entry["name"])
        if managed is None or any(
            entry[key] != managed[key] for key in ("version", "component_hash", "license")
        ):
            raise FirmwareSBOMError(f"supplemental package does not match managed lock policy: {entry['name']}")
        records.append(
            {
                "root": root_name,
                "archive": rel,
                "archive_size": linked["size"],
                "archive_sha256": linked["sha256"],
                "name": entry["name"],
                "version": entry["version"],
                "component_hash": entry["component_hash"],
                "license": entry["license"],
                "reason": entry["reason"],
            }
        )
    return records


def build_expected_receipt(
    bundle_root: Path,
    project_description: Path,
    policy_path: Path,
    tool_packages: Mapping[str, str] | None = None,
) -> Dict[str, Any]:
    policy, policy_raw = load_policy(policy_path)
    roots = load_build_context(project_description, policy)
    artifacts = _verify_artifacts(policy, roots)
    verify_source_locks(policy, roots)
    artifact_index = {(item["root"], item["path"]): item for item in artifacts}
    app_artifact = artifact_index[("build", "xiaozhi_agent_platform.bin")]
    boot_artifact = artifact_index[("build", "bootloader/bootloader.bin")]
    app_spdx = inspect_spdx(
        bundle_root / "app.spdx",
        "app",
        "xiaozhi_agent_platform.bin",
        app_artifact["sha256"],
        policy,
    )
    boot_spdx = inspect_spdx(
        bundle_root / "bootloader.spdx",
        "bootloader",
        "bootloader.bin",
        boot_artifact["sha256"],
        policy,
    )
    app_map = inspect_map(
        roots["build"] / "xiaozhi_agent_platform.map",
        roots,
        app_spdx.pop("package_ids"),
        policy,
        "app",
    )
    boot_map = inspect_map(
        roots["build"] / "bootloader/bootloader.map",
        roots,
        boot_spdx.pop("package_ids"),
        policy,
        "bootloader",
    )
    licenses = verify_and_copy_licenses(policy, roots, bundle_root)
    source_patches = verify_and_copy_source_patches(policy, roots, bundle_root)
    packages = (
        dict(tool_packages)
        if tool_packages is not None
        else dict(policy["sbom_tool"]["python_packages"])
    )
    if packages != policy["sbom_tool"]["python_packages"]:
        raise FirmwareSBOMError("receipt tool packages do not match policy")
    return {
        "schema_version": 2,
        "profile": policy["profile"],
        "created": source_timestamp(policy["source_date_epoch"]),
        "source_date_epoch": policy["source_date_epoch"],
        "policy_sha256": sha256_bytes(policy_raw),
        "project": dict(policy["project"]),
        "sbom_tool": {
            "name": policy["sbom_tool"]["name"],
            "version": policy["sbom_tool"]["version"],
            "arguments": list(policy["sbom_tool"]["arguments"]),
            "python_packages": packages,
        },
        "artifacts": artifacts,
        "sboms": {"app": app_spdx, "bootloader": boot_spdx},
        "map_coverage": {"app": app_map, "bootloader": boot_map},
        "supplemental_prebuilt_packages": supplemental_records(policy, roots, app_map),
        "source_patches": source_patches,
        "license_files": licenses,
        "unresolved_release_gates": list(policy["unresolved_release_gates"]),
    }


def write_exclusive(path: Path, data: bytes, mode: int = 0o644) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(path, flags, mode)
    except OSError as exc:
        raise FirmwareSBOMError(f"cannot create output without overwrite: {path}: {exc}") from exc
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written < 1:
                raise FirmwareSBOMError(f"short write while creating {path}")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def fsync_directory(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError as exc:
        raise FirmwareSBOMError(f"cannot open output directory for fsync: {path}: {exc}") from exc
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def verify_ready(bundle_root: Path, receipt_raw: bytes) -> None:
    ready = require_regular(bundle_root / "READY", 256, "firmware SBOM READY marker")
    expected = f"sha256:{sha256_bytes(receipt_raw)}\n".encode("ascii")
    if ready != expected:
        raise FirmwareSBOMError("READY marker does not bind the canonical receipt")
