#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

"$project_dir/tools/run_host_tests.sh"

(
    cd "$project_dir"
    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
        factory.tests.test_verify_reset_hardware_qualification \
        tools.tests.test_sign_release_manifest \
        tools.tests.test_ota_deployment_bundle \
        tools.tests.test_reset_qualification_policy \
        tools.tests.test_ota_policy
)

if ! command -v go >/dev/null 2>&1; then
    echo "reset qualification gate requires Go 1.26.5 in PATH" >&2
    exit 1
fi

(
    cd "$project_dir/gateway"
    go test ./internal/ota
)

echo "M40 reset-qualification release code gate PASS"
echo "Synthetic fixtures are contract tests only; signed physical lab evidence remains mandatory"
