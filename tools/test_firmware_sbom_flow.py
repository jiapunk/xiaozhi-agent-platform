#!/usr/bin/env python3
"""Exercise reproducibility and negative verification for the M26 SBOM gate."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]


def run(command: list[str], should_pass: bool = True) -> None:
    result = subprocess.run(
        command,
        cwd=PROJECT,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=240,
    )
    if (result.returncode == 0) != should_pass:
        raise RuntimeError(
            f"unexpected command result {result.returncode}: {' '.join(command)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


def snapshot(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sbom-tool", required=True, type=Path)
    args = parser.parse_args()
    builder = PROJECT / "tools" / "build_firmware_sbom_bundle.py"
    verifier = PROJECT / "tools" / "verify_firmware_sbom_bundle.py"
    description = PROJECT / "build-box3-production-security" / "project_description.json"
    policy = PROJECT / "firmware" / "sbom-release-policy.json"

    with tempfile.TemporaryDirectory(prefix="xz-firmware-sbom-") as directory:
        root = Path(directory)
        first = root / "first"
        second = root / "second"

        def build(target: Path, should_pass: bool = True) -> None:
            run(
                [
                    sys.executable,
                    str(builder),
                    "--project-description",
                    str(description),
                    "--policy",
                    str(policy),
                    "--sbom-tool",
                    str(args.sbom_tool),
                    "--output-dir",
                    str(target),
                ],
                should_pass,
            )

        def verify(target: Path, should_pass: bool = True) -> None:
            run(
                [
                    sys.executable,
                    str(verifier),
                    "--bundle",
                    str(target),
                    "--project-description",
                    str(description),
                    "--policy",
                    str(policy),
                ],
                should_pass,
            )

        build(first)
        build(second)
        verify(first)
        verify(second)
        if snapshot(first) != snapshot(second):
            raise RuntimeError("two M26 firmware SBOM bundles are not byte-identical")
        build(first, should_pass=False)

        tampered_spdx = root / "tampered-spdx"
        shutil.copytree(first, tampered_spdx)
        spdx = tampered_spdx / "app.spdx"
        spdx.write_bytes(spdx.read_bytes().replace(b"SPDX-2.2", b"SPDX-2.1", 1))
        verify(tampered_spdx, should_pass=False)

        tampered_license = root / "tampered-license"
        shutil.copytree(first, tampered_license)
        license_path = tampered_license / "licenses" / "xiaozhi-esp32-MIT.txt"
        license_path.write_bytes(license_path.read_bytes() + b"tampered\n")
        verify(tampered_license, should_pass=False)

        tampered_patch = root / "tampered-patch"
        shutil.copytree(first, tampered_patch)
        patch_path = (
            tampered_patch
            / "sources"
            / "esp-claw"
            / "0001-redact-agent-content-logs.patch"
        )
        patch_path.write_bytes(patch_path.read_bytes() + b"tampered\n")
        verify(tampered_patch, should_pass=False)

        extra_file = root / "extra-file"
        shutil.copytree(first, extra_file)
        (extra_file / "unexpected.txt").write_text("unexpected\n")
        verify(extra_file, should_pass=False)

    print(
        "firmware SBOM flow PASS: reproducible plus "
        "overwrite/SPDX/license/source-patch/file-set rejection"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
