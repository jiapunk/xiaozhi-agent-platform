#!/usr/bin/env python3
"""Build and cross-validate two real reproducible OCI release bundles."""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import oci_release as oci


SOURCE_DATE_EPOCH = 1786276800


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the real multi-service, multi-architecture OCI release smoke"
    )
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--go", required=True, type=Path)
    parser.add_argument("--ca-bundle", required=True, type=Path)
    arguments = parser.parse_args()
    project = arguments.project_root.resolve()
    with tempfile.TemporaryDirectory(prefix="xiaozhi-oci-smoke-") as temporary_text:
        temporary = Path(temporary_text)
        private = Ed25519PrivateKey.generate()
        private_path = temporary / "private.pem"
        public_path = temporary / "public.pem"
        private_path.write_bytes(
            private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        public_path.write_bytes(
            private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        outputs = [temporary / "release-a", temporary / "release-b"]
        receipts: list[dict[str, object]] = []
        try:
            for output in outputs:
                receipts.append(
                    oci.build_release_bundle(
                        project_root=project,
                        go_binary=arguments.go.resolve(),
                        ca_bundle_path=arguments.ca_bundle,
                        signing_private_key_path=private_path,
                        signing_key_id="m48-smoke-key",
                        release_id="m48-real-smoke",
                        version="0.48.0-smoke",
                        source_date_epoch=SOURCE_DATE_EPOCH,
                        output_path=output,
                    )
                )
                oci.validate_release_bundle(
                    output,
                    trusted_public_key_path=public_path,
                    expected_signing_key_id="m48-smoke-key",
                    expected_release_id="m48-real-smoke",
                )
            first_digest, second_digest = (tree_digest(output) for output in outputs)
            if first_digest != second_digest or receipts[0] != receipts[1]:
                raise oci.OCIReleaseError("real builds are not byte-for-byte reproducible")
            completed = subprocess.run(
                [
                    str(arguments.go.resolve()),
                    "run",
                    "./cmd/validateocirelease",
                    "-bundle",
                    str(outputs[0]),
                    "-public-key",
                    str(public_path),
                    "-key-id",
                    "m48-smoke-key",
                    "-release-id",
                    "m48-real-smoke",
                ],
                cwd=project / "gateway",
                check=False,
                capture_output=True,
                text=True,
                timeout=120,
            )
            if completed.returncode != 0:
                raise oci.OCIReleaseError(
                    "independent Go validation failed: " + completed.stderr.strip()
                )
            total_bytes = sum(
                path.stat().st_size for path in outputs[0].rglob("*") if path.is_file()
            )
            print(
                f"real OCI smoke passed tree_sha256={first_digest} bytes={total_bytes} "
                f"services={len(receipts[0]['services'])} platforms=2 validators=python,go"
            )
            for service in receipts[0]["services"]:
                platforms = ",".join(
                    f"{item['architecture']}:{item['binary_size']}"
                    for item in service["platforms"]
                )
                print(
                    f"{service['name']} image={service['image_index_digest']} binaries={platforms}"
                )
        finally:
            for output in outputs:
                oci._unlock_tree(output)
            for key_path in (private_path, public_path):
                if key_path.exists():
                    os.chmod(key_path, 0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
