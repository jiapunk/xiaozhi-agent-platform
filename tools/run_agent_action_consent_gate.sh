#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
go_bin=${XIAOZHI_GO:-go}

"$project_dir/tools/run_host_tests.sh"

(
    cd "$project_dir"
    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
        tools.tests.test_agent_action_consent_policy \
        tools.tests.test_agent_capability_policy \
        tools.tests.test_push_delivery_policy
)

(
    cd "$project_dir/gateway"
    "$go_bin" test ./internal/actionconsent ./internal/accountauth ./internal/pushdelivery ./internal/auth \
        ./internal/provisioning ./internal/controlplane
    "$go_bin" vet ./internal/actionconsent ./internal/accountauth ./internal/pushdelivery ./internal/auth \
        ./internal/provisioning ./internal/controlplane
)

"$project_dir/tools/run_companion_app_gate.sh"

echo "M68 consent, encrypted installation, provider credential, and opt-in seven-service wiring gate PASS"
if [ -z "${OWNERSHIP_TEST_DATABASE_URL:-}" ]; then
    echo "Live PostgreSQL integration was not configured and is not claimed"
fi
echo "Selected IdP/live provider credentials, signed App integration, live mounted deployment, PostgreSQL/provider delivery, physical consent/action evidence, and release approval remain mandatory"
