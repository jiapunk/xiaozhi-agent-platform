#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if ! command -v go >/dev/null 2>&1; then
    echo "account authorization ledger gate requires Go 1.26.5 in PATH" >&2
    exit 1
fi

(
    cd "$project_dir/gateway"
    go test -count=1 ./internal/accountauth ./internal/auth \
        ./internal/controlplane ./cmd/accountauthorization
    go vet ./internal/accountauth ./internal/auth \
        ./internal/controlplane ./cmd/accountauthorization
)

(
    cd "$project_dir"
    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
        tools.tests.test_account_token_trust_policy \
        tools.tests.test_account_authorization_ledger_policy
)

echo "Durable Companion account-authorization ledger gate: PASS"
