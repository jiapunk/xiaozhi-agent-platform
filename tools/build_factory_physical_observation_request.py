#!/usr/bin/env python3
"""Build a canonical physical factory flash observation signing request."""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from factory_flash_manifest import read_regular, write_new  # noqa: E402
from factory_physical_observation import (  # noqa: E402
    PhysicalObservationError,
    build_request,
    canonical_json,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observation-id", required=True)
    parser.add_argument("--transaction-id", required=True)
    parser.add_argument("--attempt-id", required=True)
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--serial-number", required=True)
    parser.add_argument("--base-mac", required=True)
    parser.add_argument("--chip-revision", required=True, type=int)
    parser.add_argument("--signing-request-sha256", required=True)
    parser.add_argument("--signed-artifact-verification-sha256", required=True)
    parser.add_argument("--anti-rollback-secure-version", required=True, type=int)
    parser.add_argument("--station-id", required=True)
    parser.add_argument("--operator", required=True, action="append")
    parser.add_argument("--fixture-id", required=True)
    parser.add_argument("--fixture-version", required=True)
    parser.add_argument("--fixture-calibration", required=True, type=Path)
    parser.add_argument("--signing-key-id", required=True)
    parser.add_argument("--port-fingerprint", required=True, type=Path)
    parser.add_argument("--chip-probe-log", required=True, type=Path)
    parser.add_argument("--efuse-summary-before", required=True, type=Path)
    parser.add_argument("--efuse-summary-after", required=True, type=Path)
    parser.add_argument("--readback-bootloader", required=True, type=Path)
    parser.add_argument("--readback-partition-table", required=True, type=Path)
    parser.add_argument("--readback-nvs-factory", required=True, type=Path)
    parser.add_argument("--readback-ota-data-initial", required=True, type=Path)
    parser.add_argument("--readback-application", required=True, type=Path)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--finished-at", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        def digest(path: Path, label: str) -> str:
            return hashlib.sha256(read_regular(path, 2 * 1024 * 1024, label)).hexdigest()

        request = build_request(
            observation_id=args.observation_id,
            transaction_id=args.transaction_id,
            attempt_id=args.attempt_id,
            device_id=args.device_id,
            serial_number=args.serial_number,
            base_mac=args.base_mac,
            chip_revision=args.chip_revision,
            signing_request_sha256=args.signing_request_sha256,
            signed_artifact_verification_sha256=args.signed_artifact_verification_sha256,
            anti_rollback_secure_version=args.anti_rollback_secure_version,
            station_id=args.station_id,
            operators=args.operator,
            fixture_id=args.fixture_id,
            fixture_version=args.fixture_version,
            fixture_calibration_sha256=digest(
                args.fixture_calibration, "fixture calibration"
            ),
            signing_key_id=args.signing_key_id,
            port_fingerprint_sha256=digest(args.port_fingerprint, "port fingerprint"),
            chip_probe_log_sha256=digest(args.chip_probe_log, "chip probe log"),
            efuse_summary_before=read_regular(
                args.efuse_summary_before, 2 * 1024 * 1024, "eFuse summary before"
            ),
            efuse_summary_after=read_regular(
                args.efuse_summary_after, 2 * 1024 * 1024, "eFuse summary after"
            ),
            readbacks={
                "bootloader": read_regular(
                    args.readback_bootloader, 0x581000, "bootloader readback"
                ),
                "partition_table": read_regular(
                    args.readback_partition_table, 0x581000, "partition-table readback"
                ),
                "nvs_factory": read_regular(
                    args.readback_nvs_factory, 0x581000, "nvs_factory readback"
                ),
                "ota_data_initial": read_regular(
                    args.readback_ota_data_initial, 0x581000, "OTA-data readback"
                ),
                "application": read_regular(
                    args.readback_application, 0x581000, "application readback"
                ),
            },
            started_at=args.started_at,
            finished_at=args.finished_at,
        )
        payload = canonical_json(request)
        write_new(Path(os.path.abspath(args.output)), payload)
    except (OSError, ValueError, PhysicalObservationError) as error:
        print(f"physical observation request rejected: {error}", file=sys.stderr)
        return 1
    print(
        "physical observation signing request READY: "
        f"id={request['observation_id']} sha256={hashlib.sha256(payload).hexdigest()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
