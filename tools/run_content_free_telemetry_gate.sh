#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
go_bin=${XIAOZHI_GO:-$(command -v go || true)}
python_bin=${XIAOZHI_PYTHON:-$(command -v python3 || true)}

if [ -z "$go_bin" ] || [ ! -x "$go_bin" ]; then
    echo "M78 qualification requires Go 1.26.5" >&2
    exit 1
fi
if [ "$("$go_bin" env GOVERSION)" != "go1.26.5" ]; then
    echo "M78 qualification requires exact Go 1.26.5" >&2
    exit 1
fi
if [ -z "$python_bin" ] || [ ! -x "$python_bin" ]; then
    echo "M78 qualification requires Python 3" >&2
    exit 1
fi

PATH=$(dirname "$go_bin"):$PATH
export PATH

(
    cd "$project_dir/gateway"
    "$go_bin" test -count=1 \
        ./internal/telemetry \
        ./internal/factorytime \
        ./cmd/gateway \
        ./cmd/controlplane \
        ./cmd/agentproxy \
        ./cmd/firmwareorigin \
        ./cmd/generationcoordinator \
        ./cmd/accountauthorization \
        ./cmd/factorytimeauthority
    "$go_bin" test -race -count=1 \
        ./internal/telemetry \
        ./internal/factorytime
    "$go_bin" vet \
        ./internal/telemetry \
        ./internal/factorytime \
        ./cmd/gateway \
        ./cmd/controlplane \
        ./cmd/agentproxy \
        ./cmd/firmwareorigin \
        ./cmd/generationcoordinator \
        ./cmd/accountauthorization \
        ./cmd/factorytimeauthority
)

PYTHONDONTWRITEBYTECODE=1 "$python_bin" -m unittest \
    tools.tests.test_content_free_telemetry_policy \
    tools.tests.test_backend_slo_observation \
    tools.tests.test_kubernetes_deployment \
    tools.tests.test_kubernetes_admission

if [ "${REQUIRE_LIVE_BACKEND_SLO:-false}" = "true" ]; then
    : "${BACKEND_SLO_OBSERVATION:?set BACKEND_SLO_OBSERVATION}"
    : "${BACKEND_SLO_TRUSTED_PUBLIC_KEY:?set BACKEND_SLO_TRUSTED_PUBLIC_KEY}"
    : "${BACKEND_SLO_SIGNING_KEY_ID:?set BACKEND_SLO_SIGNING_KEY_ID}"
    : "${BACKEND_SLO_DEPLOYMENT_ID:?set BACKEND_SLO_DEPLOYMENT_ID}"
    : "${BACKEND_SLO_COLLECTOR_ID:?set BACKEND_SLO_COLLECTOR_ID}"
    PYTHONDONTWRITEBYTECODE=1 "$python_bin" \
        "$project_dir/tools/validate_backend_slo_observation.py" \
        --observation "$BACKEND_SLO_OBSERVATION" \
        --policy "$project_dir/deployment/backend-slo-policy.json" \
        --trusted-public-key "$BACKEND_SLO_TRUSTED_PUBLIC_KEY" \
        --expected-signing-key-id "$BACKEND_SLO_SIGNING_KEY_ID" \
        --expected-deployment-id "$BACKEND_SLO_DEPLOYMENT_ID" \
        --expected-collector-id "$BACKEND_SLO_COLLECTOR_ID"
else
    echo "Live signed 28-day backend SLO observation was not requested or claimed"
fi

echo "M78 content-free telemetry and SLO contract gate PASS"
