#!/usr/bin/env python3
"""Validate a signed deterministic OCI release bundle before publication."""

from __future__ import annotations

import argparse
from pathlib import Path

from oci_release import OCIReleaseError, validate_release_bundle


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate an immutable OCI release bundle")
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--trusted-public-key", required=True, type=Path)
    parser.add_argument("--expected-signing-key-id", required=True)
    parser.add_argument("--expected-release-id")
    arguments = parser.parse_args()
    try:
        receipt = validate_release_bundle(
            arguments.bundle,
            trusted_public_key_path=arguments.trusted_public_key,
            expected_signing_key_id=arguments.expected_signing_key_id,
            expected_release_id=arguments.expected_release_id,
        )
    except (OSError, OCIReleaseError) as error:
        parser.error(str(error))
    print(
        f"OCI release bundle verified release={receipt['release_id']} "
        f"services={len(receipt['services'])} signature=Ed25519"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
