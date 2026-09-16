#!/usr/bin/env python3
"""TEST ONLY: consume an M59/M60 attempt from a prebuilt trusted-time receipt."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from factory_flash_manifest import read_regular  # noqa: E402
from sacrificial_attempt_ledger import (  # noqa: E402
    AttemptLedgerError,
    _consume_attempt_with_receipt_for_test,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--authorization-public-key", required=True, type=Path)
    parser.add_argument("--signing-request", required=True, type=Path)
    parser.add_argument("--signed-artifact-verification", required=True, type=Path)
    parser.add_argument("--trusted-time-receipt", required=True, type=Path)
    parser.add_argument("--trusted-time-public-key", required=True, type=Path)
    args = parser.parse_args()
    try:
        record, _ = _consume_attempt_with_receipt_for_test(
            root=args.root,
            plan_data=read_regular(args.plan, 512 * 1024, "sacrificial plan"),
            authorization_public_key=read_regular(
                args.authorization_public_key, 16 * 1024, "authorization public key"
            ),
            signing_request_data=read_regular(
                args.signing_request, 512 * 1024, "signing request"
            ),
            signed_artifact_data=read_regular(
                args.signed_artifact_verification,
                512 * 1024,
                "signed-artifact verification",
            ),
            trusted_time_receipt_data=read_regular(
                args.trusted_time_receipt, 64 * 1024, "trusted-time receipt"
            ),
            trusted_time_public_key=read_regular(
                args.trusted_time_public_key, 16 * 1024, "trusted-time public key"
            ),
            https_round_trip_ms=1,
        )
    except (OSError, ValueError, AttemptLedgerError) as error:
        print(f"TEST ONLY consumption rejected: {error}", file=sys.stderr)
        return 1
    print(f"TEST ONLY attempt consumed: {record['transaction']['attempt_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
