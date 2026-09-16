#!/usr/bin/env python3
"""Independently verify M57 virtual-eFuse evidence."""

from __future__ import annotations

import argparse
from pathlib import Path

from virtual_efuse_rehearsal import (
    RehearsalError,
    load_evidence,
    validate_signing_request_binding,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--signing-request", required=True, type=Path)
    args = parser.parse_args()
    try:
        value = load_evidence(args.evidence)
        validate_signing_request_binding(value, args.signing_request)
    except (OSError, RehearsalError) as exc:
        parser.error(str(exc))
    print(
        "verified virtual-eFuse rehearsal: "
        f"{value['subject']['profile']} / {value['tool']['version']} / {value['result']}"
    )
    print("VIRTUAL_TEST_ONLY: not physical factory evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
