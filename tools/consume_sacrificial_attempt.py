#!/usr/bin/env python3
"""Atomically consume one active M58 attempt without invoking hardware."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from factory_flash_manifest import read_regular  # noqa: E402
from sacrificial_attempt_ledger import (  # noqa: E402
    AttemptLedgerError,
    canonical_json,
    consume_attempt_online,
)


def private_key_path(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    info = os.lstat(absolute)
    if (
        stat.S_ISLNK(info.st_mode)
        or not stat.S_ISREG(info.st_mode)
        or info.st_size < 1
        or info.st_size > 64 * 1024
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise AttemptLedgerError("trusted-time client private key path is unsafe")
    return absolute


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--authorization-public-key", required=True, type=Path)
    parser.add_argument("--signing-request", required=True, type=Path)
    parser.add_argument("--signed-artifact-verification", required=True, type=Path)
    parser.add_argument("--trusted-time-public-key", required=True, type=Path)
    parser.add_argument("--trusted-time-ca-certificate", required=True, type=Path)
    parser.add_argument("--trusted-time-client-certificate", required=True, type=Path)
    parser.add_argument("--trusted-time-client-private-key", required=True, type=Path)
    args = parser.parse_args()
    try:
        ca_data = read_regular(
            args.trusted_time_ca_certificate,
            128 * 1024,
            "trusted-time CA certificate",
        )
        client_certificate_data = read_regular(
            args.trusted_time_client_certificate,
            128 * 1024,
            "trusted-time client certificate",
        )
        record, path = consume_attempt_online(
            root=Path(os.path.abspath(args.root)),
            plan_data=read_regular(args.plan, 512 * 1024, "sacrificial plan"),
            authorization_public_key=read_regular(
                args.authorization_public_key,
                16 * 1024,
                "authorization public key",
            ),
            signing_request_data=read_regular(
                args.signing_request, 512 * 1024, "signing request"
            ),
            signed_artifact_data=read_regular(
                args.signed_artifact_verification,
                512 * 1024,
                "signed-artifact verification",
            ),
            trusted_time_public_key=read_regular(
                args.trusted_time_public_key,
                16 * 1024,
                "trusted-time public key",
            ),
            ca_certificate=Path(os.path.abspath(args.trusted_time_ca_certificate)),
            ca_certificate_data=ca_data,
            client_certificate=Path(
                os.path.abspath(args.trusted_time_client_certificate)
            ),
            client_certificate_data=client_certificate_data,
            client_private_key=private_key_path(
                args.trusted_time_client_private_key
            ),
        )
        payload = canonical_json(record)
    except (OSError, ValueError, AttemptLedgerError) as error:
        print(f"sacrificial attempt consumption rejected: {error}", file=sys.stderr)
        return 1
    print(
        "sacrificial attempt CONSUMED: "
        f"attempt={record['transaction']['attempt_id']} "
        f"sha256={hashlib.sha256(payload).hexdigest()}"
    )
    print("HANDOFF ONLY: executor_invoked=false; hardware_touched=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
