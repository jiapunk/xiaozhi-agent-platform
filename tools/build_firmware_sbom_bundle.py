#!/usr/bin/env python3
"""Build a non-overwriting M26 app/bootloader firmware SBOM bundle."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from firmware_sbom import (
    FirmwareSBOMError,
    build_expected_receipt,
    canonical_json,
    canonicalize_spdx,
    fsync_directory,
    load_build_context,
    load_policy,
    require_regular,
    resolve_inside,
    safe_relative,
    sha256_bytes,
    verify_and_copy_licenses,
    verify_and_copy_source_patches,
    verify_sbom_tool,
    verify_source_locks,
    write_exclusive,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-description", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--sbom-tool", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser.parse_args()


def run_generator(tool: Path, arguments: list[str], description: Path, output: Path) -> None:
    command = [str(tool), *arguments, "-o", str(output), str(description)]
    environment = dict(os.environ)
    environment.update({"LC_ALL": "C", "LANG": "C", "TZ": "UTC"})
    try:
        subprocess.run(command, check=True, env=environment, timeout=180)
    except (OSError, subprocess.SubprocessError) as exc:
        raise FirmwareSBOMError(f"official ESP-IDF SBOM generation failed: {exc}") from exc


def main() -> int:
    args = parse_args()
    try:
        policy, _ = load_policy(args.policy)
        roots = load_build_context(args.project_description, policy)
        verify_source_locks(policy, roots)
        tool_packages = verify_sbom_tool(args.sbom_tool, policy)

        output = args.output_dir.absolute()
        if output.exists() or output.is_symlink():
            raise FirmwareSBOMError(f"output directory already exists: {output}")
        output.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        os.mkdir(output, 0o755)
        os.mkdir(output / "licenses", 0o755)
        os.mkdir(output / "sources", 0o755)

        app_raw = output / ".app.raw.spdx"
        boot_raw = output / ".bootloader.raw.spdx"
        boot_description = roots["build"] / "bootloader/project_description.json"
        run_generator(args.sbom_tool, policy["sbom_tool"]["arguments"], args.project_description, app_raw)
        run_generator(args.sbom_tool, policy["sbom_tool"]["arguments"], boot_description, boot_raw)

        artifact_by_path = {entry["path"]: entry for entry in policy["artifacts"] if entry["root"] == "build"}
        app_canonical = canonicalize_spdx(
            require_regular(app_raw, 8 * 1024 * 1024, "raw app SPDX"),
            "app",
            artifact_by_path["xiaozhi_agent_platform.bin"]["sha256"],
            policy["source_date_epoch"],
        )
        boot_canonical = canonicalize_spdx(
            require_regular(boot_raw, 8 * 1024 * 1024, "raw bootloader SPDX"),
            "bootloader",
            artifact_by_path["bootloader/bootloader.bin"]["sha256"],
            policy["source_date_epoch"],
        )
        write_exclusive(output / "app.spdx", app_canonical)
        write_exclusive(output / "bootloader.spdx", boot_canonical)
        app_raw.unlink()
        boot_raw.unlink()

        for index, entry in enumerate(policy["license_files"]):
            source = resolve_inside(roots[entry["root"]], entry["source"], f"license source {index}")
            data = require_regular(source, 2 * 1024 * 1024, f"license source {entry['source']}")
            if sha256_bytes(data) != entry["sha256"]:
                raise FirmwareSBOMError(f"license source hash mismatch: {entry['source']}")
            relative = safe_relative(entry["bundle"], f"license bundle {index}")
            destination = output.joinpath(*relative.parts)
            destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            write_exclusive(destination, data)

        for index, entry in enumerate(policy["source_patches"]):
            source = resolve_inside(roots[entry["root"]], entry["source"], f"source patch {index}")
            data = require_regular(source, 2 * 1024 * 1024, f"source patch {entry['source']}")
            if sha256_bytes(data) != entry["sha256"]:
                raise FirmwareSBOMError(f"source patch hash mismatch: {entry['source']}")
            relative = safe_relative(entry["bundle"], f"source patch bundle {index}")
            destination = output.joinpath(*relative.parts)
            destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            write_exclusive(destination, data)

        # Re-read every emitted file through the same strict release policy before
        # committing the canonical receipt and READY marker.
        verify_and_copy_licenses(policy, roots, output)
        verify_and_copy_source_patches(policy, roots, output)
        receipt = build_expected_receipt(
            output, args.project_description, args.policy, tool_packages=tool_packages
        )
        receipt_raw = canonical_json(receipt)
        write_exclusive(output / "firmware-sbom-receipt.json", receipt_raw)
        fsync_directory(output / "licenses")
        for entry in policy["source_patches"]:
            fsync_directory(output.joinpath(*safe_relative(entry["bundle"], "source patch").parts).parent)
        fsync_directory(output / "sources")
        write_exclusive(output / "READY", f"sha256:{sha256_bytes(receipt_raw)}\n".encode("ascii"))
        fsync_directory(output)
        fsync_directory(output.parent)
        print(
            "firmware SBOM bundle PASS: "
            f"{receipt['sboms']['app']['package_count']} app packages, "
            f"{receipt['sboms']['bootloader']['package_count']} bootloader packages, "
            f"{len(receipt['supplemental_prebuilt_packages'])} supplemental prebuilt packages, "
            f"{len(receipt['source_patches'])} source patches"
        )
        return 0
    except FirmwareSBOMError as exc:
        print(f"firmware SBOM bundle ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
