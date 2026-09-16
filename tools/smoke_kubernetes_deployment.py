#!/usr/bin/env python3
"""Run a real seven-service OCI-to-Kubernetes deployment smoke."""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import kubernetes_deployment as deployment
import oci_release as oci


SOURCE_DATE_EPOCH = 1786276800


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for file in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(file.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(file.read_bytes())
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the real OCI-to-Kubernetes deployment smoke")
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--go", required=True, type=Path)
    parser.add_argument("--ca-bundle", required=True, type=Path)
    parser.add_argument("--kubectl", required=True, type=Path)
    arguments = parser.parse_args()
    project = arguments.project_root.resolve()
    with tempfile.TemporaryDirectory(prefix="xiaozhi-kubernetes-smoke-") as temporary_text:
        temporary = Path(temporary_text)
        oci_private = Ed25519PrivateKey.generate()
        deployment_private = Ed25519PrivateKey.generate()

        def write_keypair(prefix: str, key: Ed25519PrivateKey) -> tuple[Path, Path]:
            private = temporary / f"{prefix}-private.pem"
            public = temporary / f"{prefix}-public.pem"
            private.write_bytes(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
            public.write_bytes(key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
            return private, public

        oci_private_path, oci_public_path = write_keypair("oci", oci_private)
        deploy_private_path, deploy_public_path = write_keypair("deployment", deployment_private)
        oci_bundle = temporary / "oci"
        outputs = [temporary / "deployment-a", temporary / "deployment-b"]
        try:
            oci.build_release_bundle(
                project_root=project,
                go_binary=arguments.go.resolve(),
                ca_bundle_path=arguments.ca_bundle,
                signing_private_key_path=oci_private_path,
                signing_key_id="m49-smoke-oci-key",
                release_id="m49-real-deployment-smoke",
                version="0.49.0-smoke",
                source_date_epoch=SOURCE_DATE_EPOCH,
                output_path=oci_bundle,
            )
            receipts = []
            for output in outputs:
                receipts.append(deployment.build_bundle(
                    oci_bundle=oci_bundle,
                    oci_trusted_public_key=oci_public_path,
                    oci_signing_key_id="m49-smoke-oci-key",
                    expected_oci_release_id="m49-real-deployment-smoke",
                    profile_path=project / "deployment/kubernetes-deployment-profile.example.json",
                    signing_private_key_path=deploy_private_path,
                    signing_key_id="m49-smoke-deployment-key",
                    output_path=output,
                ))
                deployment.validate_bundle(
                    output,
                    oci_bundle=oci_bundle,
                    oci_trusted_public_key=oci_public_path,
                    expected_oci_signing_key_id="m49-smoke-oci-key",
                    expected_oci_release_id="m49-real-deployment-smoke",
                    trusted_public_key=deploy_public_path,
                    expected_signing_key_id="m49-smoke-deployment-key",
                    expected_deployment_id="m49-pilot",
                )
            digests = [tree_digest(output) for output in outputs]
            if digests[0] != digests[1] or receipts[0] != receipts[1]:
                raise deployment.DeploymentError("deployment bundles are not byte-for-byte reproducible")
            render_directory = temporary / "kubectl-render"
            render_directory.mkdir()
            (render_directory / "kubernetes.json").write_bytes(
                (outputs[0] / "kubernetes.json").read_bytes())
            (render_directory / "kustomization.yaml").write_text(
                "apiVersion: kustomize.config.k8s.io/v1beta1\n"
                "kind: Kustomization\n"
                "resources:\n- kubernetes.json\n")
            completed = subprocess.run(
                [str(arguments.kubectl.resolve()), "kustomize", str(render_directory)],
                check=False, capture_output=True, text=True, timeout=60,
                env={**os.environ, "KUBECONFIG": str(temporary / "no-cluster-config")},
            )
            if completed.returncode != 0:
                raise deployment.DeploymentError(
                    "kubectl Kustomize parse failed: " + completed.stderr.strip())
            resource_count = sum(
                line.startswith("kind: ") for line in completed.stdout.splitlines())
            current_oci_receipt = oci.validate_release_bundle(
                oci_bundle, trusted_public_key_path=oci_public_path,
                expected_signing_key_id="m49-smoke-oci-key",
                expected_release_id="m49-real-deployment-smoke")
            expected_resources = len(deployment.build_kubernetes_list(
                deployment.load_profile(project / "deployment/kubernetes-deployment-profile.example.json")[0],
                current_oci_receipt,
            )["items"])
            if resource_count != expected_resources:
                raise deployment.DeploymentError(
                    f"kubectl parsed {resource_count} resources, expected {expected_resources}")
            total = sum(file.stat().st_size for file in outputs[0].rglob("*") if file.is_file())
            print(
                f"real Kubernetes smoke passed tree_sha256={digests[0]} bytes={total} "
                f"services=7 resources={resource_count} validators=python,kubectl-kustomize"
            )
            print(f"kubectl={completed.args[0]} offline_parse=true openapi=false server_admission=false")
            for service in current_oci_receipt["services"]:
                platforms = ",".join(
                    f"{item['architecture']}:{item['binary_size']}"
                    for item in service["platforms"])
                print(
                    f"{service['name']} image={service['image_index_digest']} "
                    f"binaries={platforms}")
        finally:
            for output in outputs:
                deployment.oci._unlock_tree(output)
            oci._unlock_tree(oci_bundle)
            for key_file in (oci_private_path, oci_public_path, deploy_private_path, deploy_public_path):
                if key_file.exists():
                    os.chmod(key_file, 0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
