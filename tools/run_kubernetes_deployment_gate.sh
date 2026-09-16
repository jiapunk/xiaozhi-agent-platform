#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

(
    cd "$project_dir"
    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v \
        tools.tests.test_kubernetes_deployment
)

if ! command -v go >/dev/null 2>&1; then
    echo "Kubernetes deployment gate requires Go 1.26.5 in PATH" >&2
    exit 1
fi

(cd "$project_dir/gateway" && \
    go test -count=1 \
        ./internal/accountauth ./cmd/accountauthorization \
        ./internal/factorytime ./cmd/factorytimeauthority && \
    go vet \
        ./internal/accountauth ./cmd/accountauthorization \
        ./internal/factorytime ./cmd/factorytimeauthority)

echo "Signed Kubernetes deployment bundle gate: PASS"
