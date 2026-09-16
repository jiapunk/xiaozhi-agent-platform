#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
go_bin=${XIAOZHI_GO:-$(command -v go || true)}

if [ -z "$go_bin" ] || [ ! -x "$go_bin" ]; then
    echo "M71 qualification requires Go 1.26.5" >&2
    exit 1
fi

(
    cd "$project_dir/gateway"
    "$go_bin" test -count=1 \
        ./internal/mtlsdispatchqualification \
        ./internal/pushdelivery \
        ./cmd/controlplane \
        ./cmd/qualifymtlsdispatch \
        ./cmd/signmtlsdispatchattestation \
        ./cmd/buildmtlsdispatchqualification \
        ./cmd/validatemtlsdispatchqualification
    "$go_bin" vet \
        ./internal/mtlsdispatchqualification \
        ./internal/pushdelivery \
        ./cmd/controlplane \
        ./cmd/qualifymtlsdispatch \
        ./cmd/signmtlsdispatchattestation \
        ./cmd/buildmtlsdispatchqualification \
        ./cmd/validatemtlsdispatchqualification
)

PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
    tools.tests.test_mtls_dispatch_qualification_policy

PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
    tools.tests.test_kubernetes_deployment.KubernetesDeploymentTests.test_companion_push_is_profile_bound_without_an_eighth_workload

PYTHONDONTWRITEBYTECODE=1 python3 \
    "$project_dir/tools/smoke_mtls_dispatch_qualification.py" \
    --project "$project_dir" --go "$go_bin"

python3 -m json.tool \
    "$project_dir/gateway/mtls-dispatch-qualification-config.schema.json" >/dev/null
python3 -m json.tool \
    "$project_dir/gateway/mtls-dispatch-observation.schema.json" >/dev/null
python3 -m json.tool \
    "$project_dir/gateway/mtls-dispatch-deployment-attestation.schema.json" >/dev/null
python3 -m json.tool \
    "$project_dir/gateway/mtls-dispatch-qualification-receipt.schema.json" >/dev/null

echo "M71 mTLS dispatch qualification software gate PASS"
echo "No live cluster, workload identity, App or provider evidence is claimed"
