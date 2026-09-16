#!/usr/bin/env python3
"""Build or reproduce one complete per-device encrypted-flash manifest."""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from factory_flash_manifest import (  # noqa: E402
    ESPSECURE_VERSION,
    FactoryFlashManifestError,
    build_manifest,
    canonical_json,
    load_canonical_json,
    read_regular,
    tool_bundle_sha256,
    write_new,
)
from factory_physical_observation import (  # noqa: E402
    PhysicalObservationError,
    parse_canonical as parse_physical_observation,
)
from verify_production_signed_artifacts import (  # noqa: E402
    VerificationError as SignedArtifactError,
    load_request,
)


def require_secret_key(path: Path) -> None:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise FactoryFlashManifestError(
            "Flash Encryption key must be a regular non-symlink file"
        )
    if metadata.st_size != 32 or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise FactoryFlashManifestError(
            "Flash Encryption key must be 32 bytes with mode 0600 or stricter"
        )


def run(command: list[str], label: str) -> str:
    result = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=120,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    if result.returncode:
        detail = " ".join(result.stdout.strip().split())[:500]
        raise FactoryFlashManifestError(f"{label} failed: {detail}")
    return result.stdout


def espsecure_version(python: Path) -> str:
    output = run(
        [
            str(python),
            "-c",
            "import importlib.metadata; print(importlib.metadata.version('esptool'))",
        ],
        "espsecure package version",
    )
    line = " ".join(output.split())
    if line != ESPSECURE_VERSION:
        raise FactoryFlashManifestError(
            f"espsecure version must be exactly {ESPSECURE_VERSION}"
        )
    return ESPSECURE_VERSION


def encrypt_reference(
    python: Path, key: Path, source: Path, address: int, output: Path
) -> bytes:
    run(
        [
            str(python),
            "-m",
            "espsecure",
            "encrypt-flash-data",
            "--aes-xts",
            "--keyfile",
            str(key),
            "--address",
            hex(address),
            "--output",
            str(output),
            str(source),
        ],
        f"espsecure encryption at {address:#x}",
    )
    return read_regular(output, 0x581000, "reference ciphertext")


def parse_nvs(python: Path, tool: Path, image: Path) -> list[dict[str, object]]:
    output = run(
        [
            str(python),
            str(tool),
            str(image),
            "--dump",
            "minimal",
            "--format",
            "json",
            "--color",
            "never",
        ],
        "NVS parse",
    )
    try:
        entries = json.loads(output)
    except json.JSONDecodeError as error:
        raise FactoryFlashManifestError("NVS tool did not emit JSON") from error
    integrity_output = run(
        [
            str(python),
            str(tool),
            str(image),
            "--dump",
            "none",
            "--integrity-check",
            "--color",
            "never",
        ],
        "NVS integrity check",
    )
    integrity_lines = [
        " ".join(line.split())
        for line in integrity_output.splitlines()
        if line.strip()
    ]
    if integrity_lines != ["Page no. 0 CRC32: OK"] + ["Page Empty"] * 5:
        raise FactoryFlashManifestError(
            "NVS integrity output differs from one active plus five empty pages"
        )
    if not isinstance(entries, list):
        raise FactoryFlashManifestError("NVS tool output root must be a list")
    return entries


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--transaction-id", required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--serial-number", required=True)
    parser.add_argument("--base-mac", required=True)
    parser.add_argument("--chip-revision", required=True, type=int)
    parser.add_argument("--signing-request", required=True, type=Path)
    parser.add_argument("--signed-artifact-verification", required=True, type=Path)
    parser.add_argument("--signed-bootloader", required=True, type=Path)
    parser.add_argument("--signed-application", required=True, type=Path)
    parser.add_argument("--partition-table", required=True, type=Path)
    parser.add_argument("--ota-data-initial", required=True, type=Path)
    parser.add_argument("--factory-sku-manifest", required=True, type=Path)
    parser.add_argument("--factory-sku-evidence", required=True, type=Path)
    parser.add_argument("--onboarding-material", required=True, type=Path)
    parser.add_argument("--nvs-csv", required=True, type=Path)
    parser.add_argument("--nvs-factory-image", required=True, type=Path)
    parser.add_argument("--encrypted-bootloader", required=True, type=Path)
    parser.add_argument("--encrypted-partition-table", required=True, type=Path)
    parser.add_argument("--encrypted-ota-data-initial", required=True, type=Path)
    parser.add_argument("--encrypted-application", required=True, type=Path)
    parser.add_argument("--readback-bootloader", required=True, type=Path)
    parser.add_argument("--readback-partition-table", required=True, type=Path)
    parser.add_argument("--readback-nvs-factory", required=True, type=Path)
    parser.add_argument("--readback-ota-data-initial", required=True, type=Path)
    parser.add_argument("--readback-application", required=True, type=Path)
    parser.add_argument("--physical-observation", required=True, type=Path)
    parser.add_argument("--physical-observation-public-key", required=True, type=Path)
    parser.add_argument("--flash-encryption-key", required=True, type=Path)
    parser.add_argument("--espsecure-python", required=True, type=Path)
    parser.add_argument("--nvs-tool", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        require_secret_key(arguments.flash_encryption_key)
        read_regular(arguments.signing_request, 64 * 1024, "signing request")
        request, request_sha256 = load_request(arguments.signing_request)
        signed_receipt, signed_receipt_raw = load_canonical_json(
            arguments.signed_artifact_verification,
            "signed-artifact verification receipt",
        )
        sku_evidence, _ = load_canonical_json(
            arguments.factory_sku_evidence, "factory SKU evidence"
        )
        physical_observation_raw = read_regular(
            arguments.physical_observation,
            128 * 1024,
            "physical flash observation",
        )
        physical_observation = parse_physical_observation(
            physical_observation_raw, signed=True
        )
        physical_observation_public_key = read_regular(
            arguments.physical_observation_public_key,
            16 * 1024,
            "physical observation public key",
        )
        sources = {
            "bootloader": arguments.signed_bootloader,
            "partition_table": arguments.partition_table,
            "ota_data_initial": arguments.ota_data_initial,
            "application": arguments.signed_application,
        }
        source_limits = {
            "bootloader": 0x10000,
            "partition_table": 0xC00,
            "ota_data_initial": 0x2000,
            "application": 0x581000,
        }
        source_bytes = {
            item: read_regular(source, source_limits[item], f"source {item}")
            for item, source in sources.items()
        }
        encrypted_paths = {
            "bootloader": arguments.encrypted_bootloader,
            "partition_table": arguments.encrypted_partition_table,
            "ota_data_initial": arguments.encrypted_ota_data_initial,
            "application": arguments.encrypted_application,
        }
        readback_paths = {
            "bootloader": arguments.readback_bootloader,
            "partition_table": arguments.readback_partition_table,
            "nvs_factory": arguments.readback_nvs_factory,
            "ota_data_initial": arguments.readback_ota_data_initial,
            "application": arguments.readback_application,
        }
        offsets = {
            "bootloader": 0x00000,
            "partition_table": 0x10000,
            "ota_data_initial": 0x21000,
            "application": 0x40000,
        }
        # Preserve an ESP-IDF virtual-environment launcher. Resolving its
        # symlink can bypass pyvenv.cfg and silently drop espsecure.
        python = Path(os.path.abspath(arguments.espsecure_python))
        key = arguments.flash_encryption_key.resolve()
        with tempfile.TemporaryDirectory(prefix="xz-factory-flash-reference-") as name:
            temporary = Path(name)
            references = {}
            for item, data in source_bytes.items():
                frozen_source = temporary / f"{item}-source.bin"
                write_new(frozen_source, data)
                references[item] = encrypt_reference(
                    python,
                    key,
                    frozen_source,
                    offsets[item],
                    temporary / f"{item}.bin",
                )
        read_regular(arguments.nvs_tool, 2 * 1024 * 1024, "NVS tool")
        nvs_tool = arguments.nvs_tool.resolve()
        nvs_entries = parse_nvs(
            python, nvs_tool, arguments.nvs_factory_image.resolve()
        )
        nvs_tool_files = [
            nvs_tool.parent / name
            for name in ("nvs_tool.py", "nvs_parser.py", "nvs_check.py", "nvs_logger.py")
        ]
        manifest = build_manifest(
            transaction_id=arguments.transaction_id,
            attempt_id=arguments.attempt_id,
            device_id=arguments.device_id,
            serial_number=arguments.serial_number,
            base_mac=arguments.base_mac,
            chip_revision=arguments.chip_revision,
            request=request,
            request_sha256=request_sha256,
            signed_artifact_receipt=signed_receipt,
            signed_artifact_receipt_raw=signed_receipt_raw,
            factory_sku_evidence=sku_evidence,
            signed_bootloader=source_bytes["bootloader"],
            signed_application=source_bytes["application"],
            partition_table=source_bytes["partition_table"],
            ota_data_initial=source_bytes["ota_data_initial"],
            factory_sku_manifest=read_regular(
                arguments.factory_sku_manifest, 70, "factory SKU manifest"
            ),
            onboarding_material=read_regular(
                arguments.onboarding_material, 460, "onboarding material"
            ),
            nvs_csv=read_regular(arguments.nvs_csv, 64 * 1024, "factory NVS CSV"),
            nvs_factory_image=read_regular(
                arguments.nvs_factory_image, 0x6000, "nvs_factory image"
            ),
            nvs_entries=nvs_entries,
            encrypted={
                item: read_regular(path, 0x581000, f"encrypted {item}")
                for item, path in encrypted_paths.items()
            },
            encryption_reference=references,
            readback={
                item: read_regular(path, 0x581000, f"readback {item}")
                for item, path in readback_paths.items()
            },
            physical_observation_receipt=physical_observation,
            physical_observation_receipt_raw=physical_observation_raw,
            physical_observation_public_key_pem=physical_observation_public_key,
            espsecure_version=espsecure_version(python),
            nvs_tool_bundle_sha256=tool_bundle_sha256(nvs_tool_files),
            builder_tool_bundle_sha256=tool_bundle_sha256(
                [
                    Path(__file__).resolve(),
                    TOOLS / "factory_flash_manifest.py",
                    TOOLS / "factory_physical_observation.py",
                ]
            ),
        )
        payload = canonical_json(manifest)
        write_new(Path(os.path.abspath(arguments.output)), payload)
    except (
        OSError,
        KeyError,
        TypeError,
        ValueError,
        subprocess.SubprocessError,
        SignedArtifactError,
        FactoryFlashManifestError,
        PhysicalObservationError,
    ) as error:
        print(f"factory encrypted-flash manifest rejected: {error}", file=sys.stderr)
        return 1
    print(
        "factory encrypted-flash manifest COMPLETE: "
        f"transaction={manifest['transaction']['transaction_id']} "
        f"device={manifest['transaction']['device_id']} "
        f"sha256={__import__('hashlib').sha256(payload).hexdigest()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
