#!/usr/bin/env python3
"""Build a signed deterministic Kubernetes deployment bundle."""

from __future__ import annotations

import argparse
from pathlib import Path

from kubernetes_deployment import DeploymentError, build_bundle
from oci_release import OCIReleaseError


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the hardened seven-service Kubernetes deployment bundle")
    parser.add_argument("--oci-bundle", required=True, type=Path)
    parser.add_argument("--oci-trusted-public-key", required=True, type=Path)
    parser.add_argument("--oci-signing-key-id", required=True)
    parser.add_argument("--oci-release-id", required=True)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--signing-private-key", required=True, type=Path)
    parser.add_argument("--signing-key-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        receipt = build_bundle(
            oci_bundle=arguments.oci_bundle,
            oci_trusted_public_key=arguments.oci_trusted_public_key,
            oci_signing_key_id=arguments.oci_signing_key_id,
            expected_oci_release_id=arguments.oci_release_id,
            profile_path=arguments.profile,
            signing_private_key_path=arguments.signing_private_key,
            signing_key_id=arguments.signing_key_id,
            output_path=arguments.output,
        )
    except (OSError, OCIReleaseError, DeploymentError) as error:
        parser.error(str(error))
    print(f"Kubernetes deployment bundle ready deployment={receipt['deployment_id']} services=7 digest_only=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
