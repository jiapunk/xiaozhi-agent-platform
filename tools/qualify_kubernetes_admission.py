#!/usr/bin/env python3
"""Run the destructive-but-cleaned live M51 kube-apiserver qualification."""

from __future__ import annotations

import argparse
from pathlib import Path

from kubernetes_admission import AdmissionError
from kubernetes_admission_qualification import KubectlClient, QualificationError, qualify
from kubernetes_deployment import DeploymentError
from oci_release import OCIReleaseError


def main() -> int:
    parser = argparse.ArgumentParser(description="Qualify signed admission policy against one exact empty Kubernetes scope")
    parser.add_argument("--execute-live-qualification", action="store_true", help="acknowledge temporary policy/namespace/PVC creation and verified cleanup")
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
    parser.add_argument("--signing-private-key", required=True, type=Path)
    parser.add_argument("--signing-key-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--request-timeout-seconds", type=int, default=30)
    parser.add_argument("--typecheck-timeout-seconds", type=int, default=60)
    arguments = parser.parse_args()
    if not arguments.execute_live_qualification:
        parser.error("--execute-live-qualification is required because this command temporarily creates cluster resources")
    try:
        client = KubectlClient(
            kubectl=arguments.kubectl, kubeconfig=arguments.kubeconfig,
            context=arguments.context,
            request_timeout_seconds=arguments.request_timeout_seconds,
        )
        receipt = qualify(
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
            signing_private_key_path=arguments.signing_private_key,
            signing_key_id=arguments.signing_key_id,
            output_path=arguments.output,
            typecheck_timeout_seconds=arguments.typecheck_timeout_seconds,
        )
    except (OSError, OCIReleaseError, DeploymentError, AdmissionError, QualificationError) as error:
        parser.error(str(error))
    print(
        f"live Kubernetes admission qualification PASS id={receipt['qualification_id']} "
        f"deployment={receipt['deployment_id']} cleanup=verified"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
