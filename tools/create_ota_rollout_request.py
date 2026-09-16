#!/usr/bin/env python3
"""Create a canonical OTA rollout request bound to an immutable parent bundle."""

from __future__ import annotations

import argparse
import time
from pathlib import Path

from build_ota_deployment_bundle import DeploymentBundleError, _json_bytes
from ota_rollout import RolloutError, create_rollout_request
from sign_release_manifest import ManifestError, _publish_new


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create an immutable two-person OTA rollout request"
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
    parser.add_argument("--approver-keyring", required=True, type=Path)
    parser.add_argument("--expected-authority", required=True)
    parser.add_argument("--generation-id", required=True)
    parser.add_argument(
        "--action", required=True, choices=("EXPAND", "EMERGENCY_STOP", "RESUME")
    )
    parser.add_argument("--rollout-basis-points", required=True, type=int)
    parser.add_argument("--valid-for-seconds", type=int, default=3600)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        created_at = int(time.time())
        request = create_rollout_request(
            parent_bundle=arguments.parent_bundle,
            parent_lineage=arguments.parent_lineage_bundle,
            parent_approver_keyring_paths=arguments.parent_approver_keyring,
            approver_keyring_path=arguments.approver_keyring,
            expected_authority=arguments.expected_authority,
            generation_id=arguments.generation_id,
            action=arguments.action,
            rollout_basis_points=arguments.rollout_basis_points,
            created_at=created_at,
            expires_at=created_at + arguments.valid_for_seconds,
        )
        _publish_new(arguments.output, _json_bytes(request))
    except (OSError, ManifestError, DeploymentBundleError, RolloutError) as error:
        parser.error(str(error))
    print(
        f"OTA rollout request created: generation={request['generation_id']} "
        f"action={request['promotion_action']} basis_points={request['rollout_basis_points']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
