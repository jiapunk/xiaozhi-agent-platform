#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
go_bin=${XIAOZHI_GO:-$(command -v go || true)}
python_bin=${XIAOZHI_PYTHON:-$(command -v python3 || true)}

if [ -z "$go_bin" ] || [ ! -x "$go_bin" ]; then
    echo "M86 qualification requires Go 1.26.5" >&2
    exit 1
fi
if [ "$("$go_bin" env GOVERSION)" != "go1.26.5" ]; then
    echo "M86 qualification requires exact Go 1.26.5" >&2
    exit 1
fi
if [ -z "$python_bin" ] || [ ! -x "$python_bin" ]; then
    echo "M86 qualification requires Python 3" >&2
    exit 1
fi
if [ "${REQUIRE_LIVE_ENTITLEMENT_ADAPTER:-false}" = "true" ]; then
    echo "M86 public SDK gate cannot qualify a live provider" >&2
    exit 1
fi

PATH=$(dirname "$go_bin"):$PATH
export PATH

(
    cd "$project_dir/gateway"
    "$go_bin" test -count=1 \
        ./entitlementadapter \
        ./internal/accountauth \
        ./internal/auth \
        ./cmd/accountauthorization
    "$go_bin" test -race -count=1 \
        ./entitlementadapter \
        ./internal/accountauth \
        ./internal/auth
    "$go_bin" vet \
        ./entitlementadapter \
        ./internal/accountauth \
        ./internal/auth \
        ./cmd/accountauthorization
)

PYTHONDONTWRITEBYTECODE=1 "$python_bin" -m unittest \
    tools.tests.test_entitlement_public_sdk_policy \
    tools.tests.test_entitlement_adapter_policy \
    tools.tests.test_service_entitlement_policy \
    tools.tests.test_kubernetes_deployment \
    tools.tests.test_kubernetes_admission

echo "M86 external-consumable entitlement adapter public SDK software gate PASS"
echo "No live provider, published module, HSM/KMS, IdP, database, cluster, App, hardware or market evidence is claimed"
