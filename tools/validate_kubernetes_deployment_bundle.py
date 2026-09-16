#!/usr/bin/env python3
"""Validate a signed deterministic Kubernetes deployment bundle."""

from __future__ import annotations

import argparse
from pathlib import Path

from kubernetes_deployment import DeploymentError, validate_bundle
from oci_release import OCIReleaseError


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate the hardened seven-service Kubernetes deployment bundle")
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--oci-bundle", required=True, type=Path)
    parser.add_argument("--oci-trusted-public-key", required=True, type=Path)
    parser.add_argument("--oci-signing-key-id", required=True)
    parser.add_argument("--oci-release-id", required=True)
    parser.add_argument("--trusted-public-key", required=True, type=Path)
    parser.add_argument("--signing-key-id", required=True)
    parser.add_argument("--deployment-id", required=True)
    arguments = parser.parse_args()
    try:
        receipt = validate_bundle(
            arguments.bundle,
            oci_bundle=arguments.oci_bundle,
            oci_trusted_public_key=arguments.oci_trusted_public_key,
            expected_oci_signing_key_id=arguments.oci_signing_key_id,
            expected_oci_release_id=arguments.oci_release_id,
            trusted_public_key=arguments.trusted_public_key,
            expected_signing_key_id=arguments.signing_key_id,
            expected_deployment_id=arguments.deployment_id,
        )
    except (OSError, OCIReleaseError, DeploymentError) as error:
        parser.error(str(error))
    print(f"Kubernetes deployment bundle valid deployment={receipt['deployment_id']} services=7 digest_only=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
