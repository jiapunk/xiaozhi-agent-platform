#!/usr/bin/env python3
"""Verify a signed OTA manifest against its exact release artifacts."""

from __future__ import annotations

import argparse
from pathlib import Path

from sign_release_manifest import (
    ManifestError,
    load_manifest_json,
    verify_release_artifacts,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify a XiaoZhi Agent OTA release bundle"
    )
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--sdkconfig", required=True, type=Path)
    parser.add_argument("--reset-qualification-receipt", required=True, type=Path)
    parser.add_argument("--reset-qualification-public-key", required=True, type=Path)
    parser.add_argument("--reset-qualification-signing-key-id", required=True)
    parser.add_argument("--expected-authority", required=True)
    arguments = parser.parse_args()
    try:
        manifest = load_manifest_json(arguments.manifest.read_bytes())
        verify_release_artifacts(
            manifest,
            arguments.public_key.read_bytes(),
            arguments.image.read_bytes(),
            arguments.sdkconfig.read_text(encoding="utf-8"),
            expected_authority=arguments.expected_authority,
            reset_qualification_receipt=(
                arguments.reset_qualification_receipt.read_bytes()
            ),
            reset_qualification_public_key_pem=(
                arguments.reset_qualification_public_key.read_bytes()
            ),
            reset_qualification_signing_key_id=(
                arguments.reset_qualification_signing_key_id
            ),
        )
    except (OSError, ManifestError) as error:
        parser.error(str(error))
    print(
        f"verified OTA release {manifest['release_id']} for "
        f"{manifest['board']} sequence={manifest['release_sequence']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
