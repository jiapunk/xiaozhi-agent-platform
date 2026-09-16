#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if ! command -v go >/dev/null 2>&1; then
    echo "remote identity source gate requires Go 1.26.5" >&2
    exit 2
fi

(
    cd "$project_dir/gateway"
    go test -count=1 \
        ./internal/identityconfig \
        ./internal/identityruntime
    go test -count=1 -run '^TestRemoteIdentity' ./internal/provisioning
    go test -race -count=1 \
        ./internal/identityconfig \
        ./internal/identityruntime \
        ./internal/provisioning
    go vet \
        ./internal/identityconfig \
        ./internal/identityruntime \
        ./internal/provisioning
)

PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
    tools.tests.test_identity_snapshot_policy

echo "remote identity source gate passed: HTTPS=mTLS conditional_fetch=ETag four_consumers=converged"
