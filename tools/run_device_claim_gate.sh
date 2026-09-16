#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
go_bin=${XIAOZHI_GO:-go}

if ! command -v "$go_bin" >/dev/null 2>&1; then
    echo "device claim gate requires Go 1.26.5" >&2
    exit 1
fi

"$project_dir/tools/run_host_tests.sh"

(
    cd "$project_dir"
    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
        tools.tests.test_device_claim_policy
)

"$project_dir/tools/run_companion_app_gate.sh"

(
    cd "$project_dir/gateway"
    "$go_bin" test -race -count=1 \
        ./internal/auth ./internal/deviceclaim ./internal/provisioning \
        ./internal/controlplane ./cmd/controlplane
    "$go_bin" vet \
        ./internal/auth ./internal/deviceclaim ./internal/provisioning \
        ./internal/controlplane ./cmd/controlplane
)

echo "Authenticated device ownership claim gate: PASS"
