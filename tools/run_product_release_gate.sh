#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

(
    cd "$project_dir"
    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v \
        tools.tests.test_product_release \
        tools.tests.test_backend_slo_observation
)

echo "Product market-release evidence and backend SLO binding gate: PASS"
echo "Fixture signatures are contract tests and are not market-release evidence."
