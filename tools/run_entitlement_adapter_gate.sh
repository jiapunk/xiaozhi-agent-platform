#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
go_bin=${XIAOZHI_GO:-$(command -v go || true)}
python_bin=${XIAOZHI_PYTHON:-$(command -v python3 || true)}

if [ -z "$go_bin" ] || [ ! -x "$go_bin" ]; then
    echo "M85 qualification requires Go 1.26.5" >&2
    exit 1
fi
if [ "$("$go_bin" env GOVERSION)" != "go1.26.5" ]; then
    echo "M85 qualification requires exact Go 1.26.5" >&2
    exit 1
fi
if [ -z "$python_bin" ] || [ ! -x "$python_bin" ]; then
    echo "M85 qualification requires Python 3" >&2
    exit 1
fi
if [ "${REQUIRE_LIVE_ENTITLEMENT_ADAPTER:-false}" = "true" ]; then
    echo "M85 live qualification is provider-specific and cannot use the local gate" >&2
    exit 1
fi

PATH=$(dirname "$go_bin"):$PATH
export PATH

(
    cd "$project_dir/gateway"
    "$go_bin" test -count=1 \
        ./internal/accountauth \
        ./internal/auth \
        ./cmd/accountauthorization
    "$go_bin" test -race -count=1 \
        ./internal/accountauth \
        ./internal/auth
    "$go_bin" vet \
        ./internal/accountauth \
        ./internal/auth \
        ./cmd/accountauthorization
)

PYTHONDONTWRITEBYTECODE=1 "$python_bin" -m unittest \
    tools.tests.test_entitlement_adapter_policy \
    tools.tests.test_service_entitlement_policy \
    tools.tests.test_kubernetes_deployment \
    tools.tests.test_kubernetes_admission

echo "M85 provider-neutral entitlement adapter SDK software gate PASS"
echo "No live billing/App Store provider, HSM/KMS, IdP, database, cluster, App, hardware or market evidence is claimed"
