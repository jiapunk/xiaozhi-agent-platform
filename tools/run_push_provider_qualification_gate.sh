#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if ! command -v go >/dev/null 2>&1; then
    echo "push provider qualification gate requires Go 1.26.5 in PATH" >&2
    exit 1
fi

go_bin=$(command -v go)
if [ "$("$go_bin" version | awk '{print $3}')" != "go1.26.5" ]; then
    echo "push provider qualification gate requires exactly Go 1.26.5" >&2
    exit 1
fi

(
    cd "$project_dir/gateway"
    "$go_bin" test ./internal/pushqualification ./internal/pushdelivery
    "$go_bin" vet ./internal/pushqualification ./cmd/qualifypushprovider \
        ./cmd/generatepushqualificationfixture ./cmd/validatepushqualification
)

PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
    tools.tests.test_push_provider_qualification_policy

PYTHONDONTWRITEBYTECODE=1 python3 \
    "$project_dir/tools/smoke_push_provider_qualification.py" \
    --project "$project_dir" --go "$go_bin"

echo "M69 push provider qualification software gate PASS"
echo "No live provider credential or delivery is configured or claimed by this gate"

