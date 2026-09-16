#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
go_bin=${XIAOZHI_GO:-$(command -v go || true)}
python_bin=${XIAOZHI_PYTHON:-$(command -v python3 || true)}

if [ -z "$go_bin" ] || [ ! -x "$go_bin" ]; then
    echo "M75 qualification requires Go 1.26.5" >&2
    exit 1
fi
if [ -z "$python_bin" ] || [ ! -x "$python_bin" ]; then
    echo "M75 qualification requires Python 3" >&2
    exit 1
fi
if [ "${REQUIRE_LIVE_SPEECH_MTLS:-false}" = "true" ]; then
    echo "M75 live qualification requires an independently signed M28 receipt; the software gate cannot synthesize live evidence" >&2
    exit 1
fi

PATH=$(dirname "$go_bin"):$PATH
export PATH

(
    cd "$project_dir/gateway"
    "$go_bin" test -count=1 \
        ./internal/speechidentity \
        ./internal/config \
        ./internal/gateway \
        ./internal/tts \
        ./internal/speechqualification \
        ./cmd/gateway \
        ./cmd/qualifyspeechadapter
    "$go_bin" test -race -count=1 \
        ./internal/speechidentity \
        ./internal/gateway \
        ./internal/tts \
        ./cmd/qualifyspeechadapter
    "$go_bin" vet \
        ./internal/speechidentity \
        ./internal/config \
        ./internal/gateway \
        ./internal/tts \
        ./internal/speechqualification \
        ./cmd/gateway \
        ./cmd/qualifyspeechadapter
)

PYTHONDONTWRITEBYTECODE=1 "$python_bin" -m unittest \
    tools.tests.test_speech_workload_identity_policy \
    tools.tests.test_speech_qualification_policy \
    tools.tests.test_kubernetes_deployment

echo "M75 private speech workload identity software gate PASS"
echo "Live provider, cluster, rotation, hardware and market evidence are not claimed"
