#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ffmpeg=${XIAOZHI_FFMPEG:-}

if [ -z "$ffmpeg" ]; then
    echo "set XIAOZHI_FFMPEG to the reviewed FFmpeg 7.0 qualification binary" >&2
    exit 1
fi

PYTHONDONTWRITEBYTECODE=1 python3 \
    "$project_dir/tools/verify_opus_codec_fixtures.py" \
    --ffmpeg "$ffmpeg" \
    --manifest "$project_dir/gateway/testdata/speech/opus-codec-fixtures.json"
