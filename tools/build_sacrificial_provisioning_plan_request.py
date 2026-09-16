#!/usr/bin/env python3
"""Build one canonical M58 sacrificial-board authorization request."""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from factory_flash_manifest import read_regular, write_new  # noqa: E402
from sacrificial_provisioning_plan import (  # noqa: E402
    SacrificialPlanError,
    build_request,
    canonical_json,
    load_release_evidence,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-id", required=True)
    parser.add_argument("--transaction-id", required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--serial-number", required=True)
    parser.add_argument("--base-mac", required=True)
    parser.add_argument("--chip-revision", required=True, type=int)
    parser.add_argument("--signing-request", required=True, type=Path)
    parser.add_argument("--signed-artifact-verification", required=True, type=Path)
    parser.add_argument("--station-id", required=True)
    parser.add_argument("--operator", required=True, action="append")
    parser.add_argument("--fixture-id", required=True)
    parser.add_argument("--fixture-version", required=True)
    parser.add_argument("--fixture-calibration", required=True, type=Path)
    parser.add_argument("--authorization-key-id", required=True)
    parser.add_argument("--port-fingerprint", required=True, type=Path)
    parser.add_argument("--chip-probe", required=True, type=Path)
    parser.add_argument("--flash-probe", required=True, type=Path)
    parser.add_argument("--tool-versions", required=True, type=Path)
    parser.add_argument("--efuse-summary-before", required=True, type=Path)
    parser.add_argument("--efuse-summary-after", required=True, type=Path)
    parser.add_argument("--efuse-check-error", required=True, type=Path)
    parser.add_argument("--capture-started-at", required=True)
    parser.add_argument("--capture-finished-at", required=True)
    parser.add_argument("--issued-at", required=True)
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        signing_request = read_regular(
            args.signing_request, 512 * 1024, "signing request"
        )
        signed_artifact = read_regular(
            args.signed_artifact_verification,
            512 * 1024,
            "signed-artifact verification",
        )
        request = build_request(
            plan_id=args.plan_id,
            transaction_id=args.transaction_id,
            attempt_id=args.attempt_id,
            device_id=args.device_id,
            serial_number=args.serial_number,
            base_mac=args.base_mac,
            chip_revision=args.chip_revision,
            release=load_release_evidence(signing_request, signed_artifact),
            station_id=args.station_id,
            operators=args.operator,
            fixture_id=args.fixture_id,
            fixture_version=args.fixture_version,
            fixture_calibration_sha256=hashlib.sha256(
                read_regular(args.fixture_calibration, 2 * 1024 * 1024, "fixture calibration")
            ).hexdigest(),
            authorization_key_id=args.authorization_key_id,
            port_fingerprint_sha256=hashlib.sha256(
                read_regular(args.port_fingerprint, 2 * 1024 * 1024, "port fingerprint")
            ).hexdigest(),
            chip_probe=read_regular(args.chip_probe, 2 * 1024 * 1024, "chip probe"),
            flash_probe=read_regular(args.flash_probe, 2 * 1024 * 1024, "flash probe"),
            tool_versions=read_regular(args.tool_versions, 1024, "tool versions"),
            efuse_summary_before=read_regular(
                args.efuse_summary_before, 2 * 1024 * 1024, "eFuse summary before"
            ),
            efuse_summary_after=read_regular(
                args.efuse_summary_after, 2 * 1024 * 1024, "eFuse summary after"
            ),
            efuse_check_error=read_regular(
                args.efuse_check_error, 2 * 1024 * 1024, "eFuse check-error"
            ),
            capture_started_at=args.capture_started_at,
            capture_finished_at=args.capture_finished_at,
            issued_at=args.issued_at,
            expires_at=args.expires_at,
        )
        payload = canonical_json(request)
        write_new(Path(os.path.abspath(args.output)), payload)
    except (OSError, ValueError, SacrificialPlanError) as error:
        print(f"sacrificial provisioning plan request rejected: {error}", file=sys.stderr)
        return 1
    print(
        "sacrificial provisioning plan request READY: "
        f"id={request['plan_id']} sha256={hashlib.sha256(payload).hexdigest()}"
    )
    print("NON-EXECUTING request: no eFuse or flash write capability is included")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

