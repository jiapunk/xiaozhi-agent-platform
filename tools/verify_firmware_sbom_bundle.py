#!/usr/bin/env python3
"""Verify an M26 firmware SBOM bundle against build bytes and linker maps."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from firmware_sbom import (
    FirmwareSBOMError,
    build_expected_receipt,
    canonical_json,
    load_json,
    require_regular,
    verify_ready,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--project-description", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        bundle = args.bundle.absolute()
        if bundle.is_symlink() or not bundle.is_dir():
            raise FirmwareSBOMError("bundle must be a non-symlink directory")
        receipt_path = bundle / "firmware-sbom-receipt.json"
        receipt_raw = require_regular(receipt_path, 4 * 1024 * 1024, "firmware SBOM receipt")
        receipt = load_json(receipt_path, 4 * 1024 * 1024, "firmware SBOM receipt")
        if receipt_raw != canonical_json(receipt):
            raise FirmwareSBOMError("firmware SBOM receipt is not canonical JSON")
        expected = build_expected_receipt(bundle, args.project_description, args.policy)
        if receipt != expected:
            raise FirmwareSBOMError("firmware SBOM receipt does not match build/policy evidence")
        verify_ready(bundle, receipt_raw)

        expected_files = {
            "READY",
            "app.spdx",
            "bootloader.spdx",
            "firmware-sbom-receipt.json",
            *[item["bundle_path"] for item in receipt["source_patches"]],
            *[item["bundle_path"] for item in receipt["license_files"]],
        }
        actual_files = {
            path.relative_to(bundle).as_posix()
            for path in bundle.rglob("*")
            if path.is_file() or path.is_symlink()
        }
        if actual_files != expected_files:
            raise FirmwareSBOMError(
                f"bundle file set mismatch; missing={sorted(expected_files - actual_files)}, "
                f"unexpected={sorted(actual_files - expected_files)}"
            )
        print(
            "firmware SBOM verification PASS: "
            f"{receipt['sboms']['app']['package_count']} app packages, "
            f"{receipt['sboms']['bootloader']['package_count']} bootloader packages, "
            f"{len(receipt['license_files'])} license/notice files, "
            f"{len(receipt['source_patches'])} source patches"
        )
        return 0
    except FirmwareSBOMError as exc:
        print(f"firmware SBOM verification ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
