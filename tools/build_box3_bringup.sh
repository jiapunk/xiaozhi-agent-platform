#!/usr/bin/env sh
set -eu

product_project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
product_build_dir="$product_project_dir/build-box3-bringup"
product_sdkconfig="$product_build_dir/sdkconfig"
product_defaults="$product_project_dir/sdkconfig.box3.defaults;$product_project_dir/sdkconfig.box3-bringup.defaults"

. "$product_project_dir/tools/box3_bringup_toolchain.sh"
product_prepare_box3_toolchain

if [ -z "${ESP_CLAW_ROOT:-}" ]; then
    ESP_CLAW_ROOT="$product_project_dir/third_party/esp-claw"
    export ESP_CLAW_ROOT
fi

if [ ! -f "$ESP_CLAW_ROOT/components/claw_modules/claw_core/CMakeLists.txt" ]; then
    echo "Pinned ESP-Claw sources are missing; run tools/sync_upstreams.sh" >&2
    exit 1
fi

product_run_idf -B "$product_build_dir" \
    -D "SDKCONFIG=$product_sdkconfig" \
    -D "SDKCONFIG_DEFAULTS=$product_defaults" \
    set-target esp32s3 build size

"$product_project_dir/tools/package_box3_bringup.sh"

echo "BOX-3 bring-up firmware build PASS"
echo "Flash with: $product_project_dir/tools/flash_box3_bringup.sh /dev/cu.YOUR_DEVICE monitor"
