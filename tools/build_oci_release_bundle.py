#!/usr/bin/env python3
"""Build a signed deterministic multi-architecture OCI release bundle."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

from oci_release import OCIReleaseError, build_release_bundle


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a daemonless OCI 1.1 release bundle for gateway services"
    )
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--go", type=Path, default=Path(shutil.which("go") or "go"))
    parser.add_argument("--ca-bundle", required=True, type=Path)
    parser.add_argument("--signing-private-key", required=True, type=Path)
    parser.add_argument("--signing-key-id", required=True)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        receipt = build_release_bundle(
            project_root=arguments.project_root.resolve(),
            go_binary=arguments.go.resolve(),
            ca_bundle_path=arguments.ca_bundle,
            signing_private_key_path=arguments.signing_private_key,
            signing_key_id=arguments.signing_key_id,
            release_id=arguments.release_id,
            version=arguments.version,
            source_date_epoch=arguments.source_date_epoch,
            output_path=arguments.output,
        )
    except (OSError, OCIReleaseError) as error:
        parser.error(str(error))
    print(
        f"OCI release bundle ready release={receipt['release_id']} "
        f"services={len(receipt['services'])} platforms=linux/amd64,linux/arm64"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
