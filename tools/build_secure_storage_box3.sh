#!/usr/bin/env sh
set -eu

product_project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
product_build_dir="$product_project_dir/build-box3-secure-storage"
product_sdkconfig="$product_build_dir/sdkconfig"
product_defaults="$product_project_dir/sdkconfig.box3.defaults;$product_project_dir/sdkconfig.secure-storage.defaults"

if ! command -v idf.py >/dev/null 2>&1; then
    echo "idf.py is unavailable; activate ESP-IDF 6.0.2 first" >&2
    exit 1
fi

if [ -z "${ESP_CLAW_ROOT:-}" ]; then
    ESP_CLAW_ROOT="$product_project_dir/third_party/esp-claw"
    export ESP_CLAW_ROOT
fi

if [ ! -f "$ESP_CLAW_ROOT/components/claw_modules/claw_core/CMakeLists.txt" ]; then
    echo "Pinned ESP-Claw sources are missing; run tools/sync_upstreams.sh" >&2
    exit 1
fi

idf.py -B "$product_build_dir" \
    -D "SDKCONFIG=$product_sdkconfig" \
    -D "SDKCONFIG_DEFAULTS=$product_defaults" \
    set-target esp32s3 build size

python3 "$product_project_dir/tools/check_memory_budget.py" \
    --map "$product_build_dir/xiaozhi_agent_platform.map"
