#!/usr/bin/env python3
"""Recover cleanup for an interrupted M51 live qualification."""

from __future__ import annotations

import argparse
from pathlib import Path

from kubernetes_admission import AdmissionError
from kubernetes_admission_qualification import KubectlClient, QualificationError, recover_cleanup
from kubernetes_deployment import DeploymentError
from oci_release import OCIReleaseError


def main() -> int:
    parser = argparse.ArgumentParser(description="Delete only M51 objects owned by one exact qualification ID")
    parser.add_argument("--execute-owned-cleanup", action="store_true")
    parser.add_argument("--kubectl", required=True, type=Path)
    parser.add_argument("--kubeconfig", required=True, type=Path)
    parser.add_argument("--context", required=True)
    parser.add_argument("--expected-cluster-server", required=True)
    parser.add_argument("--expected-kube-system-uid", required=True)
    parser.add_argument("--expected-kubectl-sha256", required=True)
    parser.add_argument("--expected-tool-sha256", required=True)
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
    parser.add_argument("--qualification-id", required=True)
    parser.add_argument("--request-timeout-seconds", type=int, default=30)
    arguments = parser.parse_args()
    if not arguments.execute_owned_cleanup:
        parser.error("--execute-owned-cleanup is required; unowned objects are always refused")
    try:
        client = KubectlClient(
            kubectl=arguments.kubectl, kubeconfig=arguments.kubeconfig,
            context=arguments.context,
            request_timeout_seconds=arguments.request_timeout_seconds,
        )
        result = recover_cleanup(
            client=client, admission_bundle=arguments.admission_bundle,
            deployment_bundle=arguments.deployment_bundle,
            oci_bundle=arguments.oci_bundle,
            oci_trusted_public_key=arguments.oci_trusted_public_key,
            oci_signing_key_id=arguments.oci_signing_key_id,
            expected_oci_release_id=arguments.oci_release_id,
            deployment_trusted_public_key=arguments.deployment_trusted_public_key,
            deployment_signing_key_id=arguments.deployment_signing_key_id,
            expected_deployment_id=arguments.deployment_id,
            admission_trusted_public_key=arguments.admission_trusted_public_key,
            admission_signing_key_id=arguments.admission_signing_key_id,
            qualification_id=arguments.qualification_id,
            expected_cluster_server=arguments.expected_cluster_server,
            expected_kube_system_uid=arguments.expected_kube_system_uid,
            expected_kubectl_sha256=arguments.expected_kubectl_sha256,
            expected_tool_sha256=arguments.expected_tool_sha256,
        )
    except (OSError, OCIReleaseError, DeploymentError, AdmissionError, QualificationError) as error:
        parser.error(str(error))
    print(
        f"Kubernetes admission qualification cleanup verified id={result['qualification_id']} "
        f"namespace={result['namespace']} result={result['result']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
