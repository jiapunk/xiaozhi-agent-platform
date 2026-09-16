#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
go_bin=${XIAOZHI_GO:-$(command -v go || true)}
python_bin=${XIAOZHI_PYTHON:-$(command -v python3 || true)}

if [ -z "$go_bin" ] || [ ! -x "$go_bin" ]; then
    echo "M84 qualification requires Go 1.26.5" >&2
    exit 1
fi
if [ "$("$go_bin" env GOVERSION)" != "go1.26.5" ]; then
    echo "M84 qualification requires exact Go 1.26.5" >&2
    exit 1
fi
if [ -z "$python_bin" ] || [ ! -x "$python_bin" ]; then
    echo "M84 qualification requires Python 3" >&2
    exit 1
fi
if [ "${REQUIRE_LIVE_SERVICE_ENTITLEMENT:-false}" = "true" ] &&
    [ -z "${ACCOUNT_AUTHORIZATION_TEST_DATABASE_URL:-}" ]; then
    echo "M84 live qualification requires ACCOUNT_AUTHORIZATION_TEST_DATABASE_URL" >&2
    exit 1
fi

PATH=$(dirname "$go_bin"):$PATH
export PATH

(
    cd "$project_dir/gateway"
    "$go_bin" test -count=1 \
        ./internal/accountauth \
        ./internal/auth \
        ./internal/controlplane \
        ./internal/gateway \
        ./internal/databasequalification \
        ./cmd/accountauthorization \
        ./cmd/controlplane
    "$go_bin" test -race -count=1 \
        ./internal/accountauth \
        ./internal/auth \
        ./internal/controlplane \
        ./internal/gateway
    "$go_bin" vet \
        ./internal/accountauth \
        ./internal/auth \
        ./internal/controlplane \
        ./internal/gateway \
        ./internal/databasequalification \
        ./cmd/accountauthorization \
        ./cmd/controlplane
)

PYTHONDONTWRITEBYTECODE=1 "$python_bin" -m unittest \
    tools.tests.test_service_entitlement_policy \
    tools.tests.test_kubernetes_deployment \
    tools.tests.test_kubernetes_admission

echo "M84 signed service entitlement ingestion software gate PASS"
if [ -n "${ACCOUNT_AUTHORIZATION_TEST_DATABASE_URL:-}" ]; then
    echo "Live disposable PostgreSQL entitlement test PASS"
else
    echo "Live PostgreSQL test skipped; no production database evidence is claimed"
fi
echo "No live billing, IdP, signed App, hardware, cluster or market evidence is claimed"
