#!/usr/bin/env python3
"""Build a signed M79 market-release record from all evidence and SLO proof."""

from __future__ import annotations

import argparse
from pathlib import Path

from product_release import (
    ProductReleaseError,
    build_bundle,
    parse_key_assignments,
    parse_object_assignments,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--authorize-market-release",
        action="store_true",
        help="acknowledge that MARKET_RELEASE_PASS authorizes a market release",
    )
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--attestation", action="append", required=True, type=Path)
    parser.add_argument(
        "--evidence-key",
        action="append",
        required=True,
        metavar="TYPE=PATH",
    )
    parser.add_argument(
        "--evidence-object",
        action="append",
        required=True,
        metavar="TYPE=PATH",
        help="local snapshot of the detailed immutable evidence object",
    )
    parser.add_argument("--release-signing-private-key", required=True, type=Path)
    parser.add_argument("--backend-slo-observation", required=True, type=Path)
    parser.add_argument("--backend-slo-policy", required=True, type=Path)
    parser.add_argument("--backend-slo-trusted-public-key", required=True, type=Path)
    parser.add_argument("--previous-record", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    if not arguments.authorize_market_release:
        parser.error("--authorize-market-release is required")
    try:
        record = build_bundle(
            policy_path=arguments.policy,
            attestation_paths=arguments.attestation,
            evidence_public_keys=parse_key_assignments(arguments.evidence_key),
            evidence_objects=parse_object_assignments(arguments.evidence_object),
            backend_slo_observation_path=arguments.backend_slo_observation,
            backend_slo_policy_path=arguments.backend_slo_policy,
            backend_slo_public_key_path=arguments.backend_slo_trusted_public_key,
            release_private_key_path=arguments.release_signing_private_key,
            output_path=arguments.output,
            previous_record_path=arguments.previous_record,
        )
    except (OSError, ProductReleaseError) as error:
        parser.error(str(error))
    print(
        f"product market-release bundle PASS id={record['record_id']} "
        f"sequence={record['release_sequence']} evidence={len(record['evidence'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
