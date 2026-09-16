#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ -z "${OWNERSHIP_TEST_DATABASE_URL:-}" ]; then
    echo "OWNERSHIP_TEST_DATABASE_URL is required for the PostgreSQL ownership gate" >&2
    exit 1
fi
if ! command -v go >/dev/null 2>&1; then
    echo "PostgreSQL ownership gate requires Go 1.26.5 in PATH" >&2
    exit 1
fi

(
    cd "$project_dir/gateway"
    go test -count=1 -run '^TestPostgresOwnershipStoreIntegration$' \
        ./internal/deviceclaim
    go test -count=1 -run '^TestPostgresActionConsentStoreIntegration$' \
        ./internal/actionconsent
)

echo "PostgreSQL multi-replica ownership and action-consent integration gate: PASS"
