#!/usr/bin/env python3
"""Independently validate an M79 signed market-release bundle and SLO proof."""

from __future__ import annotations

import argparse
from pathlib import Path

from product_release import (
    ProductReleaseError,
    parse_key_assignments,
    parse_object_assignments,
    validate_bundle,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--trusted-policy", required=True, type=Path)
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
        help="independently retrieved detailed immutable evidence object",
    )
    parser.add_argument("--release-trusted-public-key", required=True, type=Path)
    parser.add_argument("--backend-slo-observation", required=True, type=Path)
    parser.add_argument("--backend-slo-policy", required=True, type=Path)
    parser.add_argument("--backend-slo-trusted-public-key", required=True, type=Path)
    parser.add_argument(
        "--evaluation-time",
        required=True,
        help="trusted UTC time in YYYY-MM-DDTHH:MM:SSZ form",
    )
    parser.add_argument("--previous-record", type=Path)
    arguments = parser.parse_args()
    try:
        record = validate_bundle(
            arguments.bundle,
            trusted_policy_path=arguments.trusted_policy,
            evidence_public_keys=parse_key_assignments(arguments.evidence_key),
            evidence_objects=parse_object_assignments(arguments.evidence_object),
            backend_slo_observation_path=arguments.backend_slo_observation,
            backend_slo_policy_path=arguments.backend_slo_policy,
            backend_slo_public_key_path=arguments.backend_slo_trusted_public_key,
            release_public_key_path=arguments.release_trusted_public_key,
            evaluation_time=arguments.evaluation_time,
            previous_record_path=arguments.previous_record,
        )
    except (OSError, ProductReleaseError) as error:
        parser.error(str(error))
    print(
        f"product market-release valid id={record['record_id']} "
        f"sequence={record['release_sequence']} result={record['result']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
