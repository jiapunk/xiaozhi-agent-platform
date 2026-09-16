#!/usr/bin/env sh
set -eu

product_project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
product_build_dir="$product_project_dir/build-waveshare-watch-bringup"
product_sdkconfig="$product_build_dir/sdkconfig"
product_defaults="$product_project_dir/sdkconfig.waveshare-watch.defaults"

. "$product_project_dir/tools/box3_bringup_toolchain.sh"
product_prepare_box3_toolchain

if [ -z "${ESP_CLAW_ROOT:-}" ]; then
    ESP_CLAW_ROOT="$product_project_dir/third_party/esp-claw"
    export ESP_CLAW_ROOT
fi

PRODUCT_WAVESHARE_WATCH_DIAGNOSTIC=1
export PRODUCT_WAVESHARE_WATCH_DIAGNOSTIC

if [ -f "$product_build_dir/CMakeCache.txt" ]; then
    product_run_idf -B "$product_build_dir" \
        -D "PRODUCT_WAVESHARE_WATCH_DIAGNOSTIC=ON" \
        -D "SDKCONFIG=$product_sdkconfig" \
        -D "SDKCONFIG_DEFAULTS=$product_defaults" \
        build size
else
    product_run_idf -B "$product_build_dir" \
        -D "PRODUCT_WAVESHARE_WATCH_DIAGNOSTIC=ON" \
        -D "SDKCONFIG=$product_sdkconfig" \
        -D "SDKCONFIG_DEFAULTS=$product_defaults" \
        set-target esp32s3 build size
fi

echo "Waveshare watch bring-up firmware build PASS"
echo "Flash with idf.py -B $product_build_dir -p /dev/cu.YOUR_DEVICE flash monitor"
