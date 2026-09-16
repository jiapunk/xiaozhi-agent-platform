#!/usr/bin/env python3
"""Strictly verify a signed, active M58 sacrificial-board plan."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from factory_flash_manifest import read_regular  # noqa: E402
from sacrificial_provisioning_plan import (  # noqa: E402
    SacrificialPlanError,
    bind_release,
    parse_canonical,
    require_active,
    verify_receipt,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--signing-request", required=True, type=Path)
    parser.add_argument("--signed-artifact-verification", required=True, type=Path)
    parser.add_argument("--verification-time", required=True)
    args = parser.parse_args()
    try:
        raw = read_regular(args.receipt, 512 * 1024, "sacrificial plan receipt")
        receipt = parse_canonical(raw, signed=True)
        verify_receipt(
            receipt,
            read_regular(args.public_key, 16 * 1024, "authorization public key"),
        )
        bind_release(
            receipt,
            read_regular(args.signing_request, 512 * 1024, "signing request"),
            read_regular(
                args.signed_artifact_verification,
                512 * 1024,
                "signed-artifact verification",
            ),
        )
        require_active(receipt, args.verification_time)
    except (OSError, ValueError, SacrificialPlanError) as error:
        print(f"sacrificial provisioning plan FAILED: {error}", file=sys.stderr)
        return 1
    print(
        "sacrificial provisioning plan PASS: "
        f"id={receipt['plan_id']} sha256={hashlib.sha256(raw).hexdigest()}"
    )
    print("SACRIFICIAL ONLY; never production inventory evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

