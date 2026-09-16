#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
go_bin=${XIAOZHI_GO:-$(command -v go || true)}

if [ -z "$go_bin" ] || [ ! -x "$go_bin" ]; then
    echo "M73 qualification requires Go 1.26.5" >&2
    exit 1
fi

(
    cd "$project_dir/gateway"
    "$go_bin" test -count=1 \
        ./internal/databasequalification \
        ./cmd/qualifydatabasefailover \
        ./cmd/qualifydatabaserestore \
        ./cmd/signmanageddatabaseattestation \
        ./cmd/buildmanageddatabasequalification \
        ./cmd/validatemanageddatabasequalification
    "$go_bin" vet \
        ./internal/databasequalification \
        ./cmd/qualifydatabasefailover \
        ./cmd/qualifydatabaserestore \
        ./cmd/signmanageddatabaseattestation \
        ./cmd/buildmanageddatabasequalification \
        ./cmd/validatemanageddatabasequalification
)

PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
    tools.tests.test_managed_database_qualification_policy

PYTHONDONTWRITEBYTECODE=1 python3 \
    "$project_dir/tools/smoke_managed_database_qualification.py" \
    --project "$project_dir" --go "$go_bin"

for schema in "$project_dir"/gateway/managed-database-*.schema.json
do
    python3 -m json.tool "$schema" >/dev/null
done

echo "M73 managed database failover/restore software gate PASS"
echo "No live managed database, provider console, cluster, App or market evidence is claimed"
