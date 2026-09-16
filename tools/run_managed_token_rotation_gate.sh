#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
go_bin=${XIAOZHI_GO:-$(command -v go || true)}
python_bin=${XIAOZHI_PYTHON:-$(command -v python3 || true)}

if [ -z "$go_bin" ] || [ ! -x "$go_bin" ]; then
    echo "M76 qualification requires Go 1.26.5" >&2
    exit 1
fi
if [ "$("$go_bin" env GOVERSION)" != "go1.26.5" ]; then
    echo "M76 qualification requires exact Go 1.26.5" >&2
    exit 1
fi
if [ -z "$python_bin" ] || [ ! -x "$python_bin" ]; then
    echo "M76 qualification requires Python 3" >&2
    exit 1
fi
if [ "${REQUIRE_LIVE_TOKEN_ROTATION:-false}" = "true" ]; then
    echo "M76/M77 live qualification requires an independently reviewed multi-workload rotation receipt; the software gate cannot synthesize live evidence" >&2
    exit 1
fi

PATH=$(dirname "$go_bin"):$PATH
export PATH

(
    cd "$project_dir/gateway"
    "$go_bin" test -count=1 \
        ./internal/auth \
        ./internal/config \
        ./internal/controlplane \
        ./internal/agentproxy \
        ./internal/firmwareorigin \
        ./cmd/gateway \
        ./cmd/controlplane \
        ./cmd/agentproxy \
        ./cmd/firmwareorigin \
        ./cmd/validatemanagedtokenrotation
    "$go_bin" test -race -count=1 \
        ./internal/auth \
        ./internal/config \
        ./internal/controlplane \
        ./internal/agentproxy \
        ./internal/firmwareorigin \
        ./cmd/validatemanagedtokenrotation
    "$go_bin" vet \
        ./internal/auth \
        ./internal/config \
        ./internal/controlplane \
        ./internal/agentproxy \
        ./internal/firmwareorigin \
        ./cmd/gateway \
        ./cmd/controlplane \
        ./cmd/agentproxy \
        ./cmd/firmwareorigin \
        ./cmd/validatemanagedtokenrotation
)

PYTHONDONTWRITEBYTECODE=1 "$python_bin" -m unittest \
    tools.tests.test_managed_token_rotation_policy \
    tools.tests.test_managed_token_transition_policy \
    tools.tests.test_kubernetes_deployment

echo "M76/M77 managed bearer-token rotation and transition software gate PASS"
echo "Live secret-manager, cluster rollout, rollback and retirement evidence are not claimed"
