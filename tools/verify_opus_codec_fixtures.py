#!/usr/bin/env python3
"""Verify M27 libopus fixtures with the exact reviewed FFmpeg native decoder."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from opus_codec_fixture import CodecFixtureError, load_manifest, verify_manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ffmpeg", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()

    results = verify_manifest(load_manifest(args.manifest.resolve()), args.ffmpeg.resolve())
    print(json.dumps({"status": "PASS", "fixtures": results}, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CodecFixtureError as error:
        raise SystemExit(f"ERROR: {error}")
