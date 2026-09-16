#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if ! command -v go >/dev/null 2>&1; then
    echo "owner authorization gate requires Go 1.26.5 in PATH" >&2
    exit 1
fi

(
    cd "$project_dir/gateway"
    go test -count=1 \
        ./internal/auth \
        ./internal/deviceclaim \
        ./internal/controlplane \
        ./internal/gateway \
        ./internal/agentproxy \
        ./internal/integration
)

(
    cd "$project_dir"
    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
        tools.tests.test_owner_authorization_policy
)

echo "Owner/tenant service authorization gate: PASS"
