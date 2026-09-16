#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ -z "${FACTORY_TIME_TEST_DATABASE_URL:-}" ]; then
    echo "FACTORY_TIME_TEST_DATABASE_URL is required for the trusted-time PostgreSQL gate" >&2
    exit 1
fi
if ! command -v go >/dev/null 2>&1; then
    echo "trusted-time PostgreSQL gate requires Go 1.26.5 in PATH" >&2
    exit 1
fi

(
    cd "$project_dir/gateway"
    go test -count=1 -run '^TestPostgresFactoryTimeIntegration$' \
        ./internal/factorytime
)

echo "Live PostgreSQL trusted-time replay and station-authorization gate: PASS"
