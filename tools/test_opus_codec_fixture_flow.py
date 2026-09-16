#!/usr/bin/env python3
"""Exercise M27 reproducibility and fail-closed reference-codec verification."""

from __future__ import annotations

import argparse
import copy
import json
import tempfile
from pathlib import Path

from opus_codec_fixture import (
    CodecFixtureError,
    canonical_json,
    load_manifest,
    make_manifest,
    verify_manifest,
)


def expect_failure(label: str, action) -> None:
    try:
        action()
    except CodecFixtureError:
        return
    raise RuntimeError(f"negative test unexpectedly passed: {label}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ffmpeg", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    ffmpeg = args.ffmpeg.resolve()
    checked_in = load_manifest(args.manifest.resolve())

    first = make_manifest(ffmpeg)
    second = make_manifest(ffmpeg)
    if canonical_json(first) != canonical_json(second):
        raise RuntimeError("two generated M27 fixture manifests are not byte-identical")
    if canonical_json(first) != canonical_json(checked_in):
        raise RuntimeError("checked-in M27 fixtures differ from a clean generation")
    verify_manifest(checked_in, ffmpeg)

    tampered_packet = copy.deepcopy(checked_in)
    tampered_packet["fixtures"][0]["packet_base64"] = "GA=="
    expect_failure("packet tamper", lambda: verify_manifest(tampered_packet, ffmpeg))

    wrong_duration = copy.deepcopy(checked_in)
    wrong_duration["fixtures"][1]["duration_ms"] = 20
    expect_failure("duration drift", lambda: verify_manifest(wrong_duration, ffmpeg))

    wrong_decoder = copy.deepcopy(checked_in)
    wrong_decoder["reference_toolchain"]["ffmpeg_sha256"] = "0" * 64
    expect_failure("decoder identity drift", lambda: verify_manifest(wrong_decoder, ffmpeg))

    duplicate = copy.deepcopy(checked_in)
    duplicate["fixtures"][1] = copy.deepcopy(duplicate["fixtures"][0])
    expect_failure("duplicate profile", lambda: verify_manifest(duplicate, ffmpeg))

    with tempfile.TemporaryDirectory(prefix="xiaozhi-m27-") as temporary:
        receipt = Path(temporary) / "verified.json"
        receipt.write_bytes(canonical_json({"status": "PASS", "manifest": args.manifest.name}))
        json.loads(receipt.read_text(encoding="utf-8"))
    print("M27 codec fixture flow: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
