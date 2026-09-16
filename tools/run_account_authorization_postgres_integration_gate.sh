#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ -z "${ACCOUNT_AUTHORIZATION_TEST_DATABASE_URL:-}" ]; then
    echo "ACCOUNT_AUTHORIZATION_TEST_DATABASE_URL is required" >&2
    exit 1
fi
if ! command -v go >/dev/null 2>&1; then
    echo "account authorization PostgreSQL gate requires Go 1.26.5 in PATH" >&2
    exit 1
fi

(
    cd "$project_dir/gateway"
    go test -count=1 -run TestPostgresCompanionAuthorizationIntegration \
        ./internal/accountauth
)

echo "Live PostgreSQL Companion account-authorization gate: PASS"
