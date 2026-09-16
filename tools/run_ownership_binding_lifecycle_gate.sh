#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if ! command -v go >/dev/null 2>&1; then
    echo "ownership binding lifecycle gate requires Go 1.26.5 in PATH" >&2
    exit 1
fi

(
    cd "$project_dir/gateway"
    go test -count=1 \
        ./internal/auth \
        ./internal/deviceclaim \
        ./internal/controlplane \
        ./internal/gateway \
        ./internal/agentproxy
)

"$project_dir/tools/run_host_tests.sh"
"$project_dir/tools/run_companion_app_gate.sh"

(
    cd "$project_dir"
    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
        tools.tests.test_owner_authorization_policy \
        tools.tests.test_ownership_persistence_policy \
        tools.tests.test_ownership_binding_lifecycle_policy
)

echo "Ownership binding lifecycle gate: PASS"
echo "Live PostgreSQL and physical reset/transfer evidence remain mandatory"
