#!/usr/bin/env python3
"""Verify an external Ed25519 policy signature and activate an M59 ledger."""

from __future__ import annotations

import argparse
import base64
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
    parse_policy,
    publish_policy,
    require_policy_active,
    verify_policy,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--policy-request", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--verification-time", required=True)
    args = parser.parse_args()
    try:
        request = parse_policy(
            read_regular(args.policy_request, 128 * 1024, "ledger policy request"),
            signed=False,
        )
        signature = read_regular(args.signature, 64, "ledger policy signature")
        if len(signature) != 64:
            raise AttemptLedgerError("ledger policy signature must be 64 bytes")
        receipt = dict(request)
        receipt["signature_b64url"] = base64.urlsafe_b64encode(signature).rstrip(
            b"="
        ).decode("ascii")
        public_key = read_regular(args.public_key, 16 * 1024, "authorization public key")
        verify_policy(receipt, public_key)
        require_policy_active(receipt, args.verification_time)
        payload = canonical_json(receipt)
        publish_policy(Path(os.path.abspath(args.root)), payload, public_key)
    except (OSError, ValueError, AttemptLedgerError) as error:
        print(f"sacrificial attempt ledger finalization rejected: {error}", file=sys.stderr)
        return 1
    print(
        "sacrificial attempt ledger ACTIVE: "
        f"ledger={receipt['ledger_id']} sha256={hashlib.sha256(payload).hexdigest()}"
    )
    print("LOCAL SINGLE-STATION ONLY; no executor or deletion API is included")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

