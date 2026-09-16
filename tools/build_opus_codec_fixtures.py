#!/usr/bin/env python3
"""Generate the deterministic M27 real-codec fixture manifest."""

from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path

from opus_codec_fixture import CodecFixtureError, canonical_json, make_manifest, verify_manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ffmpeg", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    output = args.output.resolve()
    if output.exists() and not args.force:
        raise CodecFixtureError(f"refusing to overwrite fixture manifest: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest = make_manifest(args.ffmpeg.resolve())
    verify_manifest(manifest, args.ffmpeg.resolve())
    data = canonical_json(manifest)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(data)
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary_name, output)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
    print(f"wrote {output} ({len(data)} bytes)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CodecFixtureError as error:
        raise SystemExit(f"ERROR: {error}")
