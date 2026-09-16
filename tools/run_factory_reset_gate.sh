#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

"$project_dir/tools/run_host_tests.sh"

(
    cd "$project_dir"
    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
        tools.tests.test_product_local_action_policy \
        tools.tests.test_factory_reset_policy \
        tools.tests.test_ownership_binding_lifecycle_policy
)

echo "M39 factory-reset code gate PASS"
echo "Physical board, App/IdP, live PostgreSQL and power-cut fixture evidence remain mandatory"
