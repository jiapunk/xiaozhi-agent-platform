#!/usr/bin/env python3
"""Attach and verify an external Ed25519 signature on an M58 plan."""

from __future__ import annotations

import argparse
import base64
import os
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from factory_flash_manifest import read_regular, write_new  # noqa: E402
from sacrificial_provisioning_plan import (  # noqa: E402
    SacrificialPlanError,
    canonical_json,
    parse_canonical,
    require_active,
    verify_receipt,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--verification-time", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        request = parse_canonical(
            read_regular(args.request, 512 * 1024, "sacrificial plan request"),
            signed=False,
        )
        signature = read_regular(args.signature, 64, "sacrificial plan signature")
        if len(signature) != 64:
            raise SacrificialPlanError("sacrificial plan signature must be 64 bytes")
        receipt = dict(request)
        receipt["signature_b64url"] = base64.urlsafe_b64encode(signature).rstrip(
            b"="
        ).decode("ascii")
        verify_receipt(
            receipt,
            read_regular(args.public_key, 16 * 1024, "authorization public key"),
        )
        require_active(receipt, args.verification_time)
        write_new(Path(os.path.abspath(args.output)), canonical_json(receipt))
    except (OSError, ValueError, SacrificialPlanError) as error:
        print(f"sacrificial provisioning plan finalization rejected: {error}", file=sys.stderr)
        return 1
    print(
        "sacrificial provisioning plan VERIFIED: "
        f"id={receipt['plan_id']} attempt={receipt['transaction']['attempt_id']}"
    )
    print("NON-EXECUTING authorization: executor_included=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

