#!/usr/bin/env python3
"""Validate a complete OTA deployment bundle before service staging."""

from __future__ import annotations

import argparse
from pathlib import Path

from build_ota_deployment_bundle import (
    DeploymentBundleError,
    validate_deployment_bundle,
)
from sign_release_manifest import ManifestError


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate an immutable XiaoZhi Agent OTA deployment bundle"
    )
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--expected-authority", required=True)
    arguments = parser.parse_args()
    try:
        receipt = validate_deployment_bundle(
            arguments.bundle,
            expected_authority=arguments.expected_authority,
            require_read_only=True,
        )
    except (OSError, ManifestError, DeploymentBundleError) as error:
        parser.error(str(error))
    print(
        f"OTA deployment bundle verified for {receipt['release_id']} "
        f"sequence={receipt['release_sequence']} rollout=disabled"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
