#!/usr/bin/env python3
"""Validate a signed M51 live kube-apiserver qualification bundle."""

from __future__ import annotations

import argparse
from pathlib import Path

from kubernetes_admission import AdmissionError
from kubernetes_admission_qualification import QualificationError, validate_bundle
from kubernetes_deployment import DeploymentError
from oci_release import OCIReleaseError


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate signed live Kubernetes admission qualification evidence")
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--admission-bundle", required=True, type=Path)
    parser.add_argument("--deployment-bundle", required=True, type=Path)
    parser.add_argument("--oci-bundle", required=True, type=Path)
    parser.add_argument("--oci-trusted-public-key", required=True, type=Path)
    parser.add_argument("--oci-signing-key-id", required=True)
    parser.add_argument("--oci-release-id", required=True)
    parser.add_argument("--deployment-trusted-public-key", required=True, type=Path)
    parser.add_argument("--deployment-signing-key-id", required=True)
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--admission-trusted-public-key", required=True, type=Path)
    parser.add_argument("--admission-signing-key-id", required=True)
    parser.add_argument("--trusted-public-key", required=True, type=Path)
    parser.add_argument("--signing-key-id", required=True)
    parser.add_argument("--qualification-id", required=True)
    parser.add_argument("--expected-cluster-server", required=True)
    parser.add_argument("--expected-kube-system-uid", required=True)
    parser.add_argument("--expected-kubectl-sha256", required=True)
    parser.add_argument("--expected-tool-sha256", required=True)
    arguments = parser.parse_args()
    try:
        receipt = validate_bundle(
            arguments.bundle, admission_bundle=arguments.admission_bundle,
            deployment_bundle=arguments.deployment_bundle,
            oci_bundle=arguments.oci_bundle,
            oci_trusted_public_key=arguments.oci_trusted_public_key,
            expected_oci_signing_key_id=arguments.oci_signing_key_id,
            expected_oci_release_id=arguments.oci_release_id,
            deployment_trusted_public_key=arguments.deployment_trusted_public_key,
            expected_deployment_signing_key_id=arguments.deployment_signing_key_id,
            expected_deployment_id=arguments.deployment_id,
            admission_trusted_public_key=arguments.admission_trusted_public_key,
            expected_admission_signing_key_id=arguments.admission_signing_key_id,
            trusted_public_key=arguments.trusted_public_key,
            expected_signing_key_id=arguments.signing_key_id,
            expected_qualification_id=arguments.qualification_id,
            expected_cluster_server=arguments.expected_cluster_server,
            expected_kube_system_uid=arguments.expected_kube_system_uid,
            expected_kubectl_sha256=arguments.expected_kubectl_sha256,
            expected_tool_sha256=arguments.expected_tool_sha256,
        )
    except (OSError, OCIReleaseError, DeploymentError, AdmissionError, QualificationError) as error:
        parser.error(str(error))
    print(
        f"live Kubernetes admission qualification valid id={receipt['qualification_id']} "
        f"deployment={receipt['deployment_id']} result={receipt['result']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
