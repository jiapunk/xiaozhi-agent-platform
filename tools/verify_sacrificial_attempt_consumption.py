#!/usr/bin/env python3
"""Independently verify an immutable M59 attempt-consumption record."""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from factory_flash_manifest import read_regular  # noqa: E402
from sacrificial_attempt_ledger import (  # noqa: E402
    AttemptLedgerError,
    canonical_json,
    verify_consumption,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--authorization-public-key", required=True, type=Path)
    parser.add_argument("--signing-request", required=True, type=Path)
    parser.add_argument("--signed-artifact-verification", required=True, type=Path)
    parser.add_argument("--trusted-time-public-key", required=True, type=Path)
    args = parser.parse_args()
    try:
        record, path = verify_consumption(
            root=Path(os.path.abspath(args.root)),
            plan_data=read_regular(args.plan, 512 * 1024, "sacrificial plan"),
            authorization_public_key=read_regular(
                args.authorization_public_key,
                16 * 1024,
                "authorization public key",
            ),
            signing_request_data=read_regular(
                args.signing_request, 512 * 1024, "signing request"
            ),
            signed_artifact_data=read_regular(
                args.signed_artifact_verification,
                512 * 1024,
                "signed-artifact verification",
            ),
            trusted_time_public_key=read_regular(
                args.trusted_time_public_key,
                16 * 1024,
                "trusted-time public key",
            ),
        )
        payload = canonical_json(record)
    except (OSError, ValueError, AttemptLedgerError) as error:
        print(f"sacrificial attempt consumption FAILED: {error}", file=sys.stderr)
        return 1
    print(
        "sacrificial attempt consumption PASS: "
        f"attempt={record['transaction']['attempt_id']} "
        f"sha256={hashlib.sha256(payload).hexdigest()}"
    )
    print("ONE-TIME LOCAL HANDOFF ONLY; not physical or inventory evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
