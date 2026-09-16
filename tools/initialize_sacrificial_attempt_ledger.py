#!/usr/bin/env python3
"""Create a new M59 local ledger root and canonical policy-signing request."""

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
from sacrificial_attempt_ledger import (  # noqa: E402
    AttemptLedgerError,
    build_policy_request,
    canonical_json,
    initialize_root,
    sha256,
)
import sacrificial_trusted_time as time_contract  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--policy-id", required=True)
    parser.add_argument("--ledger-id", required=True)
    parser.add_argument("--station-id", required=True)
    parser.add_argument("--fixture-id", required=True)
    parser.add_argument("--fixture-version", required=True)
    parser.add_argument("--authorization-key-id", required=True)
    parser.add_argument("--trusted-time-endpoint", required=True)
    parser.add_argument("--trusted-time-authority-key-id", required=True)
    parser.add_argument("--trusted-time-authority-public-key", required=True, type=Path)
    parser.add_argument("--trusted-time-ca-certificate", required=True, type=Path)
    parser.add_argument("--trusted-time-client-certificate", required=True, type=Path)
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--expires-at", required=True)
    parser.add_argument("--policy-request-output", required=True, type=Path)
    args = parser.parse_args()
    try:
        root = Path(os.path.abspath(args.root))
        output = Path(os.path.abspath(args.policy_request_output))
        if output == root or output.is_relative_to(root):
            raise AttemptLedgerError("policy request output must be outside ledger root")
        if os.path.lexists(output):
            raise AttemptLedgerError("policy request output already exists")
        trusted_time_public_key = read_regular(
            args.trusted_time_authority_public_key,
            16 * 1024,
            "trusted-time authority public key",
        )
        trusted_time_ca = read_regular(
            args.trusted_time_ca_certificate,
            128 * 1024,
            "trusted-time CA certificate",
        )
        trusted_time_client_certificate = read_regular(
            args.trusted_time_client_certificate,
            128 * 1024,
            "trusted-time client certificate",
        )
        trusted_time_public_key_sha256 = time_contract.public_key_sha256(
            trusted_time_public_key
        )
        time_contract.validate_endpoint(args.trusted_time_endpoint)
        info = initialize_root(root)
        request = build_policy_request(
            policy_id=args.policy_id,
            ledger_id=args.ledger_id,
            station_id=args.station_id,
            fixture_id=args.fixture_id,
            fixture_version=args.fixture_version,
            authorization_key_id=args.authorization_key_id,
            trusted_time_endpoint=args.trusted_time_endpoint,
            trusted_time_authority_key_id=args.trusted_time_authority_key_id,
            trusted_time_authority_public_key_sha256=trusted_time_public_key_sha256,
            trusted_time_ca_certificate_sha256=sha256(trusted_time_ca),
            trusted_time_client_certificate_sha256=sha256(
                trusted_time_client_certificate
            ),
            filesystem_device=info.st_dev,
            directory_inode=info.st_ino,
            created_at=args.created_at,
            expires_at=args.expires_at,
        )
        payload = canonical_json(request)
        write_new(output, payload)
    except (
        OSError,
        ValueError,
        AttemptLedgerError,
        time_contract.TrustedTimeError,
    ) as error:
        print(f"sacrificial attempt ledger initialization rejected: {error}", file=sys.stderr)
        return 1
    print(
        "sacrificial attempt ledger policy request READY: "
        f"ledger={request['ledger_id']} sha256={hashlib.sha256(payload).hexdigest()}"
    )
    print("NON-EXECUTING ledger: no eFuse or flash operation is included")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
