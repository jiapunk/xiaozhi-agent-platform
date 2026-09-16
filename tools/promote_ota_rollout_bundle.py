#!/usr/bin/env python3
"""Promote an immutable OTA bundle after two trusted approvals."""

from __future__ import annotations

import argparse
import time
from pathlib import Path

from build_ota_deployment_bundle import DeploymentBundleError
from ota_rollout import RolloutError, promote_rollout_bundle
from sign_release_manifest import ManifestError


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a no-overwrite approved OTA rollout generation"
    )
    parser.add_argument("--parent-bundle", required=True, type=Path)
    parser.add_argument(
        "--parent-lineage-bundle", action="append", type=Path,
        help="for a promoted parent, repeat from its immediate parent to staging",
    )
    parser.add_argument(
        "--parent-approver-keyring", action="append", type=Path,
        help="trusted keyring snapshots needed to validate the parent lineage",
    )
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--approval", required=True, action="append", type=Path)
    parser.add_argument("--approver-keyring", required=True, type=Path)
    parser.add_argument("--expected-authority", required=True)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    if len(arguments.approval) != 2:
        parser.error("exactly two --approval files are required")
    try:
        receipt = promote_rollout_bundle(
            parent_bundle=arguments.parent_bundle,
            parent_lineage=arguments.parent_lineage_bundle,
            parent_approver_keyring_paths=arguments.parent_approver_keyring,
            request_path=arguments.request,
            approval_paths=arguments.approval,
            approver_keyring_path=arguments.approver_keyring,
            expected_authority=arguments.expected_authority,
            verification_time=int(time.time()),
            output_path=arguments.output,
        )
    except (OSError, ManifestError, DeploymentBundleError, RolloutError) as error:
        parser.error(str(error))
    print(
        f"OTA rollout generation ready: generation={receipt['generation_id']} "
        f"action={receipt['promotion_action']} "
        f"basis_points={receipt['rollout_basis_points']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
