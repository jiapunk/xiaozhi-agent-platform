#!/usr/bin/env python3
"""Create one new raw 256-bit factory HMAC key without overwriting files."""

from __future__ import annotations

import argparse
import os
import secrets
import tempfile
from pathlib import Path


KEY_SIZE = 32


class KeyGenerationError(ValueError):
    pass


def write_new_key(output: Path) -> None:
    if output.exists() or output.is_symlink():
        raise KeyGenerationError("output already exists")
    if not output.parent.is_dir():
        raise KeyGenerationError("output directory does not exist")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.", dir=output.parent
    )
    temporary = Path(temporary_name)
    key = bytearray(secrets.token_bytes(KEY_SIZE))
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(key)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        # Hard-link publication is atomic and fails rather than replacing a file.
        os.link(temporary, output)
        directory = os.open(output.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except FileExistsError as error:
        raise KeyGenerationError("output already exists") from error
    finally:
        for index in range(len(key)):
            key[index] = 0
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate one non-overwriting, mode-0600 factory HMAC key"
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--purpose", required=True, choices=("identity", "nvs")
    )
    arguments = parser.parse_args()
    try:
        write_new_key(arguments.output)
    except (OSError, KeyGenerationError) as error:
        parser.error(str(error))
    print(
        f"new {arguments.purpose} HMAC key created at "
        f"{arguments.output}; handle as an ephemeral secret"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
