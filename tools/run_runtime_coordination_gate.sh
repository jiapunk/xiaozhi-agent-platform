#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
go_bin=${XIAOZHI_GO:-$(command -v go || true)}
python_bin=${XIAOZHI_PYTHON:-$(command -v python3 || true)}

if [ -z "$go_bin" ] || [ ! -x "$go_bin" ]; then
    echo "M74 qualification requires Go 1.26.5" >&2
    exit 1
fi
if [ -z "$python_bin" ] || [ ! -x "$python_bin" ]; then
    echo "M74 qualification requires Python 3" >&2
    exit 1
fi
if [ "${REQUIRE_LIVE_RUNTIME_COORDINATION:-false}" = "true" ] &&
    [ -z "${OWNERSHIP_TEST_DATABASE_URL:-}" ]; then
    echo "M74 live qualification requires OWNERSHIP_TEST_DATABASE_URL" >&2
    exit 1
fi

PATH=$(dirname "$go_bin"):$PATH
export PATH

(
    cd "$project_dir/gateway"
    "$go_bin" test -count=1 \
        ./internal/runtimecoordination \
        ./internal/provisioning \
        ./internal/gateway \
        ./internal/agentproxy \
        ./internal/controlplane \
        ./internal/ownershipruntime \
        ./cmd/gateway \
        ./cmd/agentproxy \
        ./cmd/controlplane
    "$go_bin" test -race -count=1 \
        ./internal/runtimecoordination \
        ./internal/provisioning \
        ./internal/gateway \
        ./internal/agentproxy
    "$go_bin" vet \
        ./internal/runtimecoordination \
        ./internal/provisioning \
        ./internal/gateway \
        ./internal/agentproxy \
        ./internal/controlplane \
        ./internal/ownershipruntime \
        ./cmd/gateway \
        ./cmd/agentproxy \
        ./cmd/controlplane
)

PYTHONDONTWRITEBYTECODE=1 "$python_bin" -m unittest \
    tools.tests.test_runtime_coordination_policy \
    tools.tests.test_kubernetes_deployment \
    tools.tests.test_kubernetes_admission

echo "M74 distributed runtime coordination software gate PASS"
if [ -n "${OWNERSHIP_TEST_DATABASE_URL:-}" ]; then
    echo "Live PostgreSQL multi-replica coordination test PASS"
else
    echo "Live PostgreSQL test skipped; no live database evidence is claimed"
fi
echo "No live cluster, hardware, Companion App or market evidence is claimed"
