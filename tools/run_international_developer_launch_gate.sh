#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
python_bin=${XIAOZHI_PYTHON:-$(command -v python3 || true)}
decision_file=${PRODUCT_LAUNCH_DECISION_FILE:-$project_dir/release/product-launch-decision.international-developer-proposed.json}

if [ -z "$python_bin" ] || [ ! -x "$python_bin" ]; then
    echo "M88 qualification requires Python 3" >&2
    exit 1
fi

(
    cd "$project_dir"
    PYTHONDONTWRITEBYTECODE=1 "$python_bin" -m unittest \
        tools.tests.test_product_launch_decision_policy \
        tools.tests.test_international_developer_launch_policy
)

PYTHONDONTWRITEBYTECODE=1 "$python_bin" \
    "$project_dir/tools/validate_product_launch_decision.py" \
    --decision "$decision_file"

if PYTHONDONTWRITEBYTECODE=1 "$python_bin" \
    "$project_dir/tools/validate_product_launch_decision.py" \
    --decision "$decision_file" --require-approved >/dev/null 2>&1; then
    echo "M88 proposed international-developer profile authorized launch" >&2
    exit 1
fi

echo "M88 international individual-developer Lane B proposal is consistent"
echo "Production approval still fails closed: providers, owners, legal and market evidence remain unselected"
