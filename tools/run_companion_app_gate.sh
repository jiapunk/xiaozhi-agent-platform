#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
swift_bin=${XIAOZHI_SWIFT:-/usr/bin/swift}
swiftc_bin=${XIAOZHI_SWIFTC:-/usr/bin/swiftc}

if [ ! -x "$swift_bin" ] || [ ! -x "$swiftc_bin" ]; then
    echo "Swift toolchain is required for the Companion App gate" >&2
    exit 1
fi

(
    cd "$project_dir/companion-app"
    GIT_CONFIG_GLOBAL=/dev/null "$swift_bin" package resolve
)

PYTHONDONTWRITEBYTECODE=1 python3 \
    "$project_dir/tools/verify_companion_app_policy.py" \
    --project "$project_dir"

(
    cd "$project_dir/companion-app"
    GIT_CONFIG_GLOBAL=/dev/null "$swift_bin" build -Xswiftc -warnings-as-errors
    GIT_CONFIG_GLOBAL=/dev/null "$swift_bin" build \
        --target ProductActionConsentUI -Xswiftc -warnings-as-errors
    bin_path=$(GIT_CONFIG_GLOBAL=/dev/null "$swift_bin" build --show-bin-path)
    contract_tmp=$(mktemp -d "${TMPDIR:-/tmp}/xiaozhi-esp-provision-contract.XXXXXX")
    "$swiftc_bin" -emit-module -parse-as-library -warnings-as-errors \
        -module-name ESPProvisionContractStub \
        -emit-module-path "$contract_tmp/ESPProvisionContractStub.swiftmodule" \
        "$project_dir/companion-app/Tests/ESPProvisionContractStub.swift"
    "$swiftc_bin" -typecheck -warnings-as-errors \
        -D ESP_PROVISION_CONTRACT_CHECK \
        -I "$bin_path/Modules" -I "$contract_tmp" \
        "$project_dir/companion-app/Sources/ProductOnboardingESPProvision/ESPProvisionTransport.swift"
    rm -rf -- "$contract_tmp"
    GIT_CONFIG_GLOBAL=/dev/null "$swift_bin" run product-onboarding-core-tests
    GIT_CONFIG_GLOBAL=/dev/null "$swift_bin" run --sanitize=thread \
        product-onboarding-core-tests
)

echo "Companion App onboarding gate: PASS"
