#!/usr/bin/env python3
"""Run a real OCI-to-deployment-to-admission bundle smoke."""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import kubernetes_admission as admission
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
    parser = argparse.ArgumentParser(description="Run the real Kubernetes admission bundle smoke")
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--go", required=True, type=Path)
    parser.add_argument("--ca-bundle", required=True, type=Path)
    parser.add_argument("--kubectl", required=True, type=Path)
    arguments = parser.parse_args()
    project = arguments.project_root.resolve()
    with tempfile.TemporaryDirectory(prefix="xiaozhi-admission-smoke-") as temporary_text:
        temporary = Path(temporary_text)
        oci_key = Ed25519PrivateKey.generate()
        deployment_key = Ed25519PrivateKey.generate()
        admission_key = Ed25519PrivateKey.generate()

        def write_keypair(prefix: str, key: Ed25519PrivateKey) -> tuple[Path, Path]:
            private = temporary / f"{prefix}-private.pem"
            public = temporary / f"{prefix}-public.pem"
            private.write_bytes(key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
            public.write_bytes(key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo))
            return private, public

        oci_private, oci_public = write_keypair("oci", oci_key)
        deployment_private, deployment_public = write_keypair("deployment", deployment_key)
        admission_private, admission_public = write_keypair("admission", admission_key)
        oci_bundle = temporary / "oci"
        deployment_bundle = temporary / "deployment"
        outputs = [temporary / "admission-a", temporary / "admission-b"]
        try:
            oci.build_release_bundle(
                project_root=project, go_binary=arguments.go.resolve(),
                ca_bundle_path=arguments.ca_bundle,
                signing_private_key_path=oci_private,
                signing_key_id="m50-smoke-oci-key",
                release_id="m50-real-admission-smoke",
                version="0.50.0-smoke", source_date_epoch=SOURCE_DATE_EPOCH,
                output_path=oci_bundle,
            )
            deployment.build_bundle(
                oci_bundle=oci_bundle, oci_trusted_public_key=oci_public,
                oci_signing_key_id="m50-smoke-oci-key",
                expected_oci_release_id="m50-real-admission-smoke",
                profile_path=project / "deployment/kubernetes-deployment-profile.example.json",
                signing_private_key_path=deployment_private,
                signing_key_id="m50-smoke-deployment-key",
                output_path=deployment_bundle,
            )
            receipts = []
            for output in outputs:
                receipts.append(admission.build_bundle(
                    deployment_bundle=deployment_bundle, oci_bundle=oci_bundle,
                    oci_trusted_public_key=oci_public,
                    oci_signing_key_id="m50-smoke-oci-key",
                    expected_oci_release_id="m50-real-admission-smoke",
                    deployment_trusted_public_key=deployment_public,
                    deployment_signing_key_id="m50-smoke-deployment-key",
                    expected_deployment_id="m49-pilot",
                    signing_private_key_path=admission_private,
                    signing_key_id="m50-smoke-admission-key",
                    output_path=output,
                ))
                admission.validate_bundle(
                    output, deployment_bundle=deployment_bundle,
                    oci_bundle=oci_bundle, oci_trusted_public_key=oci_public,
                    expected_oci_signing_key_id="m50-smoke-oci-key",
                    expected_oci_release_id="m50-real-admission-smoke",
                    deployment_trusted_public_key=deployment_public,
                    expected_deployment_signing_key_id="m50-smoke-deployment-key",
                    expected_deployment_id="m49-pilot",
                    trusted_public_key=admission_public,
                    expected_signing_key_id="m50-smoke-admission-key",
                )
            digests = [tree_digest(output) for output in outputs]
            if digests[0] != digests[1] or receipts[0] != receipts[1]:
                raise admission.AdmissionError("admission bundles are not byte-for-byte reproducible")
            render_directory = temporary / "kubectl-render"
            render_directory.mkdir()
            (render_directory / "admission.json").write_bytes((outputs[0] / "admission.json").read_bytes())
            (render_directory / "kustomization.yaml").write_text(
                "apiVersion: kustomize.config.k8s.io/v1beta1\n"
                "kind: Kustomization\n"
                "resources:\n- admission.json\n")
            completed = subprocess.run(
                [str(arguments.kubectl.resolve()), "kustomize", str(render_directory)],
                check=False, capture_output=True, text=True, timeout=60,
                env={**os.environ, "KUBECONFIG": str(temporary / "no-cluster-config")},
            )
            if completed.returncode != 0:
                raise admission.AdmissionError(
                    "kubectl Kustomize parse failed: " + completed.stderr.strip())
            resource_count = sum(line.startswith("kind: ") for line in completed.stdout.splitlines())
            if resource_count != 20:
                raise admission.AdmissionError(
                    f"kubectl parsed {resource_count} resources, expected 20")
            total = sum(file.stat().st_size for file in outputs[0].rglob("*") if file.is_file())
            print(
                f"real Kubernetes admission smoke passed tree_sha256={digests[0]} bytes={total} "
                "policies=10 bindings=10 resources=20 validators=python,kubectl-kustomize"
            )
            print(
                f"kubectl={completed.args[0]} offline_parse=true openapi=false "
                "cel_typecheck=false server_admission=false"
            )
            print(
                f"deployment_receipt_sha256={receipts[0]['deployment_receipt_sha256']} "
                f"admission_sha256={receipts[0]['admission_sha256']}"
            )
        finally:
            for output in outputs:
                oci._unlock_tree(output)
            oci._unlock_tree(deployment_bundle)
            oci._unlock_tree(oci_bundle)
            for key_file in (
                oci_private, oci_public, deployment_private, deployment_public,
                admission_private, admission_public,
            ):
                if key_file.exists():
                    os.chmod(key_file, 0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
