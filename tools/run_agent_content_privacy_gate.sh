#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

"$project_dir/tools/run_host_tests.sh"

(
    cd "$project_dir"
    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
        tools.tests.test_agent_content_log_policy \
        tools.tests.test_agent_capability_policy \
        tools.tests.test_agent_memory_policy \
        tools.tests.test_product_runtime_policy
)

echo "M42 Agent content-privacy observability gate PASS"
echo "Live telemetry retention, device log capture, penetration and privacy review remain mandatory"
