#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
go_bin=${XIAOZHI_GO:-$(command -v go || true)}
python_bin=${XIAOZHI_PYTHON:-$(command -v python3 || true)}

if [ -z "$go_bin" ] || [ ! -x "$go_bin" ]; then
    echo "M82 qualification requires Go 1.26.5" >&2
    exit 1
fi
if [ "$("$go_bin" env GOVERSION)" != "go1.26.5" ]; then
    echo "M82 qualification requires exact Go 1.26.5" >&2
    exit 1
fi
if [ -z "$python_bin" ] || [ ! -x "$python_bin" ]; then
    echo "M82 qualification requires Python 3" >&2
    exit 1
fi
if [ "${REQUIRE_LIVE_SPEECH_USAGE_BUDGET:-false}" = "true" ] &&
    [ -z "${OWNERSHIP_TEST_DATABASE_URL:-}" ]; then
    echo "M82 live qualification requires OWNERSHIP_TEST_DATABASE_URL" >&2
    exit 1
fi

PATH=$(dirname "$go_bin"):$PATH
export PATH

(
    cd "$project_dir/gateway"
    "$go_bin" test -count=1 \
        ./internal/speechbudget \
        ./internal/gateway \
        ./internal/config \
        ./internal/tts \
        ./cmd/gateway
    "$go_bin" test -race -count=1 \
        ./internal/speechbudget \
        ./internal/gateway \
        ./internal/tts
    "$go_bin" vet \
        ./internal/speechbudget \
        ./internal/gateway \
        ./internal/config \
        ./internal/tts \
        ./cmd/gateway
)

PYTHONDONTWRITEBYTECODE=1 "$python_bin" -m unittest \
    tools.tests.test_speech_usage_budget_policy \
    tools.tests.test_kubernetes_deployment \
    tools.tests.test_kubernetes_admission

echo "M82 speech usage budget software gate PASS"
if [ -n "${OWNERSHIP_TEST_DATABASE_URL:-}" ]; then
    echo "Live disposable PostgreSQL speech usage ledger test PASS"
else
    echo "Live PostgreSQL test skipped; no production database evidence is claimed"
fi
echo "No provider price, invoice, live speech traffic, hardware, cluster or market evidence is claimed"
