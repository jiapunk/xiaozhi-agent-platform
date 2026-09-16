#!/usr/bin/env python3
"""Validate an approved immutable OTA rollout generation and parent link."""

from __future__ import annotations

import argparse
from pathlib import Path

from build_ota_deployment_bundle import DeploymentBundleError
from ota_rollout import RolloutError, validate_rollout_chain
from sign_release_manifest import ManifestError


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate an approved OTA rollout generation"
    )
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument(
        "--parent-bundle", required=True, action="append", type=Path,
        help="repeat in immediate-parent through original-staging order",
    )
    parser.add_argument(
        "--approver-keyring", required=True, action="append", type=Path,
        help="repeat for every trusted historical keyring snapshot",
    )
    parser.add_argument("--expected-authority", required=True)
    arguments = parser.parse_args()
    try:
        receipt = validate_rollout_chain(
            arguments.bundle,
            expected_authority=arguments.expected_authority,
            approver_keyring_paths=arguments.approver_keyring,
            parent_roots=arguments.parent_bundle,
        )
    except (OSError, ManifestError, DeploymentBundleError, RolloutError) as error:
        parser.error(str(error))
    print(
        f"OTA rollout generation verified: generation={receipt['generation_id']} "
        f"action={receipt['promotion_action']} "
        f"basis_points={receipt['rollout_basis_points']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
