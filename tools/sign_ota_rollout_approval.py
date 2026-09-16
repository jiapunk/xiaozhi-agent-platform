#!/usr/bin/env python3
"""Sign one approver's decision for an exact OTA rollout request."""

from __future__ import annotations

import argparse
import stat
import time
from pathlib import Path

from build_ota_deployment_bundle import DeploymentBundleError, _json_bytes, _read_regular
from ota_rollout import MAX_JSON_BYTES, MAX_KEY_BYTES, RolloutError, sign_rollout_approval
from sign_release_manifest import ManifestError, _publish_new


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sign one Ed25519 approval for an OTA rollout request"
    )
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--approver-id", required=True)
    parser.add_argument("--approval-key-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        key_mode = stat.S_IMODE(arguments.private_key.stat().st_mode)
        if key_mode & 0o077:
            raise RolloutError("approval private key file must be mode 0600 or stricter")
        approval = sign_rollout_approval(
            _read_regular(arguments.request, MAX_JSON_BYTES, "rollout request"),
            _read_regular(arguments.private_key, MAX_KEY_BYTES, "approval private key"),
            approver_id=arguments.approver_id,
            approval_key_id=arguments.approval_key_id,
            signed_at=int(time.time()),
        )
        _publish_new(arguments.output, _json_bytes(approval))
    except (OSError, ManifestError, DeploymentBundleError, RolloutError) as error:
        parser.error(str(error))
    print(
        f"OTA rollout approval signed: approver={approval['approver_id']} "
        f"request_sha256={approval['request_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
