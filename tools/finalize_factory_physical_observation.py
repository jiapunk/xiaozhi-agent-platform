#!/usr/bin/env python3
"""Attach and verify an external Ed25519 signature on a physical observation."""

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
from factory_physical_observation import (  # noqa: E402
    PhysicalObservationError,
    canonical_json,
    parse_canonical,
    verify_receipt,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--signature", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        request = parse_canonical(
            read_regular(args.request, 128 * 1024, "physical observation request"),
            signed=False,
        )
        signature = read_regular(args.signature, 64, "physical observation signature")
        if len(signature) != 64:
            raise PhysicalObservationError("physical observation signature must be 64 bytes")
        receipt = dict(request)
        receipt["signature_b64url"] = base64.urlsafe_b64encode(signature).rstrip(
            b"="
        ).decode("ascii")
        public_key = read_regular(args.public_key, 16 * 1024, "observation public key")
        verify_receipt(receipt, public_key)
        write_new(Path(os.path.abspath(args.output)), canonical_json(receipt))
    except (OSError, ValueError, PhysicalObservationError) as error:
        print(f"physical observation finalization rejected: {error}", file=sys.stderr)
        return 1
    print(
        "physical factory flash observation VERIFIED: "
        f"id={receipt['observation_id']} station={receipt['station']['id']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

