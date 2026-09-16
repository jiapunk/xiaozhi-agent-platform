#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

(
    cd "$project_dir"
    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v \
        tools.tests.test_kubernetes_admission_qualification
)

echo "Kubernetes admission live-qualification contract gate: PASS"
echo "Fixture evidence is not live kube-apiserver evidence."
