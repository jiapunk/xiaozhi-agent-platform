#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

"$project_dir/tools/run_host_tests.sh"

PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
    -s "$project_dir/factory/tests" -p 'test_*.py'

PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
    -s "$project_dir/tools/tests" -p 'test_*.py'

PYTHONDONTWRITEBYTECODE=1 python3 \
    "$project_dir/tools/test_validate_generation_state.py"

"$project_dir/tools/run_companion_app_gate.sh"

if ! command -v go >/dev/null 2>&1; then
    echo "gateway tests require Go 1.26.5 in PATH" >&2
    exit 1
fi

(
    cd "$project_dir/gateway"
    go test ./...
    go vet ./...
)
