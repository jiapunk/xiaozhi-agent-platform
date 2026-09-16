#!/usr/bin/env python3
"""Generate one non-overwriting, per-device factory SKU manifest."""

from __future__ import annotations

import argparse
import json
import os
import stat
import tempfile
from pathlib import Path

from factory_sku_manifest import FactorySKUManifestError, build_manifest


def write_exclusive(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=path.name + ".", dir=path.parent
    )
    temporary = Path(temporary_name)
    linked = False
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        os.link(temporary, path)
        linked = True
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except FileExistsError as error:
        raise FactorySKUManifestError(f"output already exists: {path}") from error
    except Exception:
        if linked:
            path.unlink(missing_ok=True)
        raise
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device-hmac-key", required=True, type=Path)
    parser.add_argument("--base-mac", required=True)
    parser.add_argument("--sku", required=True)
    parser.add_argument("--board", required=True)
    parser.add_argument("--hardware-revision", required=True, type=int)
    parser.add_argument("--chip-revision", required=True, type=int)
    parser.add_argument("--factory-record-version", required=True, type=int)
    parser.add_argument("--manifest-id", required=True)
    parser.add_argument("--manifest-output", required=True, type=Path)
    parser.add_argument("--evidence-output", required=True, type=Path)
    arguments = parser.parse_args()
    key = b""
    try:
        key_stat = arguments.device_hmac_key.stat()
        if not stat.S_ISREG(key_stat.st_mode) or arguments.device_hmac_key.is_symlink():
            raise FactorySKUManifestError("device HMAC key must be a regular non-symlink file")
        if stat.S_IMODE(key_stat.st_mode) & 0o077:
            raise FactorySKUManifestError("device HMAC key file must have mode 0600 or stricter")
        key = arguments.device_hmac_key.read_bytes()
        blob, evidence = build_manifest(
            key,
            base_mac=arguments.base_mac,
            sku=arguments.sku,
            board=arguments.board,
            hardware_revision=arguments.hardware_revision,
            chip_revision=arguments.chip_revision,
            factory_record_version=arguments.factory_record_version,
            manifest_id=arguments.manifest_id,
        )
        write_exclusive(arguments.manifest_output, blob, 0o600)
        write_exclusive(
            arguments.evidence_output,
            (json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n").encode(),
            0o600,
        )
    except (OSError, FactorySKUManifestError) as error:
        parser.error(str(error))
    finally:
        key = b""
    print("factory SKU manifest generated; raw identity key was not emitted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
