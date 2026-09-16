#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
python_bin=${XIAOZHI_PYTHON:-$(command -v python3 || true)}
decision_file=${PRODUCT_LAUNCH_DECISION_FILE:-$project_dir/release/product-launch-decision.example.json}

if [ -z "$python_bin" ] || [ ! -x "$python_bin" ]; then
    echo "M87 qualification requires Python 3" >&2
    exit 1
fi

PYTHONDONTWRITEBYTECODE=1 "$python_bin" -m unittest \
    tools.tests.test_product_launch_decision_policy

if [ "${REQUIRE_APPROVED_PRODUCT_LAUNCH:-false}" = "true" ]; then
    PYTHONDONTWRITEBYTECODE=1 "$python_bin" \
        "$project_dir/tools/validate_product_launch_decision.py" \
        --decision "$decision_file" --require-approved
    echo "M87 approved product launch decision structure PASS"
else
    PYTHONDONTWRITEBYTECODE=1 "$python_bin" \
        "$project_dir/tools/validate_product_launch_decision.py" \
        --decision "$decision_file"
    if PYTHONDONTWRITEBYTECODE=1 "$python_bin" \
        "$project_dir/tools/validate_product_launch_decision.py" \
        --decision "$decision_file" --require-approved >/dev/null 2>&1; then
        echo "M87 default example unexpectedly authorizes product launch" >&2
        exit 1
    fi
    echo "M87 proposed decision is valid and production approval fails closed"
fi

echo "No approved market, billing, IdP, SDK distribution, legal, App, RF or market-release evidence is claimed"
