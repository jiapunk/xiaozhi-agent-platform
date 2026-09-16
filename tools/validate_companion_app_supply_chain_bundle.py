#!/usr/bin/env python3
"""Independently validate a signed Companion App source supply-chain bundle."""

from __future__ import annotations

import argparse
from pathlib import Path

from companion_app_supply_chain import CompanionSupplyChainError, validate_bundle


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--trusted-policy", required=True, type=Path)
    parser.add_argument("--trusted-public-key", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        receipt = validate_bundle(
            arguments.bundle,
            project_root=arguments.project_root,
            trusted_policy_path=arguments.trusted_policy,
            trusted_public_key_path=arguments.trusted_public_key,
        )
    except (OSError, CompanionSupplyChainError) as error:
        parser.error(str(error))
    print(
        f"Companion App source supply-chain valid release={receipt['release_id']} "
        f"result={receipt['result']} production_ready={str(receipt['production_ready']).lower()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
