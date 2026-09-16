#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ffmpeg=${XIAOZHI_FFMPEG:-}

if [ -z "$ffmpeg" ]; then
    echo "set XIAOZHI_FFMPEG to the reviewed FFmpeg 7.0 qualification binary" >&2
    exit 1
fi
if ! command -v go >/dev/null 2>&1; then
    echo "Go 1.26.5 is required" >&2
    exit 1
fi

(
    cd "$project_dir/gateway"
    XIAOZHI_FFMPEG="$ffmpeg" go test -count=1 -run '^TestLiveHarnessWithPinnedReferenceDecoder$' \
        ./internal/speechqualification
)
