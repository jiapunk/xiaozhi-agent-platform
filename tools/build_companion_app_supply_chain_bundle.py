#!/usr/bin/env python3
"""Build a signed Companion App source supply-chain bundle."""

from __future__ import annotations

import argparse
from pathlib import Path

from companion_app_supply_chain import CompanionSupplyChainError, build_bundle


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--attest-companion-source-release",
        action="store_true",
        help="acknowledge that the signing key attests this exact source release",
    )
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--signing-private-key", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    if not arguments.attest_companion_source_release:
        parser.error("--attest-companion-source-release is required")
    try:
        receipt = build_bundle(
            project_root=arguments.project_root,
            policy_path=arguments.policy,
            signing_private_key_path=arguments.signing_private_key,
            output_path=arguments.output,
        )
    except (OSError, CompanionSupplyChainError) as error:
        parser.error(str(error))
    print(
        f"Companion App source supply-chain PASS release={receipt['release_id']} "
        f"sources={receipt['source_file_count']} dependencies={len(receipt['dependencies'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
