#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

(
    cd "$project_dir"
    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v \
        tools.tests.test_kubernetes_admission
)

echo "Signed Kubernetes admission policy bundle gate: PASS"
