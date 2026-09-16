#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

"$project_dir/tools/run_host_tests.sh"

(
    cd "$project_dir"
    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
        tools.tests.test_device_claim_policy \
        tools.tests.test_device_claim_recovery_policy
)

echo "Power-loss-safe device claim recovery gate: PASS"
