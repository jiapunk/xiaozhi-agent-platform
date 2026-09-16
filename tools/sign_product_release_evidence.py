#!/usr/bin/env python3
"""Sign one reviewed production evidence attestation for the M52 release gate."""

from __future__ import annotations

import argparse
from pathlib import Path

import product_release as release


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--attest-production-evidence",
        action="store_true",
        help="acknowledge that the referenced immutable evidence was independently reviewed",
    )
    parser.add_argument("--unsigned-attestation", required=True, type=Path)
    parser.add_argument("--signing-private-key", required=True, type=Path)
    parser.add_argument("--signing-key-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    if not arguments.attest_production_evidence:
        parser.error("--attest-production-evidence is required")
    try:
        raw = release._read_regular(
            arguments.unsigned_attestation,
            release.MAX_JSON_BYTES,
            "unsigned product release evidence",
        )
        value = release._strict_json(raw, "unsigned product release evidence")
        if not isinstance(value, dict) or raw != release._canonical(value):
            raise release.ProductReleaseError(
                "unsigned product release evidence must be one canonical JSON object"
            )
        signed = release.sign_attestation(
            value,
            private_key_path=arguments.signing_private_key,
            expected_key_id=arguments.signing_key_id,
        )
        release._write_new(arguments.output, release._canonical(signed))
    except (OSError, release.ProductReleaseError) as error:
        parser.error(str(error))
    print(
        f"product release evidence signed type={signed['evidence_type']} "
        f"id={signed['evidence_id']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
