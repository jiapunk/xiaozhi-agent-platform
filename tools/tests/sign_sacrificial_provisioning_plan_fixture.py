#!/usr/bin/env python3
"""TEST ONLY: sign an M58 request with an ephemeral, untrusted key."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PROJECT = Path(__file__).resolve().parents[2]
TOOLS = PROJECT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from factory_flash_manifest import read_regular, write_new  # noqa: E402
from sacrificial_provisioning_plan import parse_canonical  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--signature-output", required=True, type=Path)
    parser.add_argument("--public-key-output", required=True, type=Path)
    args = parser.parse_args()
    try:
        request = read_regular(args.request, 512 * 1024, "sacrificial plan request")
        parse_canonical(request, signed=False)
        private_key = Ed25519PrivateKey.generate()
        write_new(args.signature_output, private_key.sign(request))
        write_new(
            args.public_key_output,
            private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            ),
        )
    except (OSError, ValueError) as error:
        print(f"TEST-ONLY sacrificial plan signing failed: {error}", file=sys.stderr)
        return 1
    print("TEST ONLY: ephemeral untrusted signature; no private key persisted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

