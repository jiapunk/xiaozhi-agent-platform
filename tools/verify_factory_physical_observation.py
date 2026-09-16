#!/usr/bin/env python3
"""Strictly verify a signed physical factory flash observation."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from factory_flash_manifest import read_regular  # noqa: E402
from factory_physical_observation import (  # noqa: E402
    PhysicalObservationError,
    parse_canonical,
    verify_receipt,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    args = parser.parse_args()
    try:
        raw = read_regular(args.receipt, 128 * 1024, "physical observation receipt")
        receipt = parse_canonical(raw, signed=True)
        verify_receipt(
            receipt,
            read_regular(args.public_key, 16 * 1024, "observation public key"),
        )
    except (OSError, ValueError, PhysicalObservationError) as error:
        print(f"physical factory flash observation FAILED: {error}", file=sys.stderr)
        return 1
    print(
        "physical factory flash observation PASS: "
        f"id={receipt['observation_id']} sha256={hashlib.sha256(raw).hexdigest()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

