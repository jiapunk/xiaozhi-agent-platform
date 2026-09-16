#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if ! command -v go >/dev/null 2>&1; then
    echo "App delivery qualification gate requires Go 1.26.5 in PATH" >&2
    exit 1
fi

go_bin=$(command -v go)
if [ "$("$go_bin" version | awk '{print $3}')" != "go1.26.5" ]; then
    echo "App delivery qualification gate requires exactly Go 1.26.5" >&2
    exit 1
fi

(
    cd "$project_dir/gateway"
    "$go_bin" test ./internal/appdeliveryqualification ./internal/pushqualification
    "$go_bin" vet ./internal/appdeliveryqualification \
        ./cmd/signappdeliveryattestation \
        ./cmd/buildappdeliveryqualification \
        ./cmd/validateappdeliveryqualification
)

PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
    tools.tests.test_app_delivery_qualification_policy

PYTHONDONTWRITEBYTECODE=1 python3 \
    "$project_dir/tools/smoke_app_delivery_qualification.py" \
    --project "$project_dir" --go "$go_bin"

echo "M70 App delivery qualification software gate PASS"
echo "No signed App, vendor attestation, or live provider delivery is claimed"
