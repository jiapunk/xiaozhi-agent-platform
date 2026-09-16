#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
python_bin=${XIAOZHI_PYTHON:-python3}

(
    cd "$project_dir"
    PYTHONDONTWRITEBYTECODE=1 "$python_bin" -m unittest -v \
        tools.tests.test_companion_app_supply_chain
)

echo "Companion App source supply-chain contract gate: PASS"
echo "The signed fixture receipt is not a distribution-signed App or market evidence."
