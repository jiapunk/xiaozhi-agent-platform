#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if ! command -v go >/dev/null 2>&1; then
    echo "ownership persistence code gate requires Go 1.26.5 in PATH" >&2
    exit 1
fi

(
    cd "$project_dir/gateway"
    go test -count=1 \
        ./internal/deviceclaim ./internal/controlplane ./cmd/controlplane
    go vet ./internal/deviceclaim ./internal/controlplane ./cmd/controlplane
)

(
    cd "$project_dir"
    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
        tools.tests.test_ownership_persistence_policy
)

echo "Ownership persistence code gate: PASS"
echo "Live PostgreSQL evidence still requires run_ownership_postgres_integration_gate.sh"
