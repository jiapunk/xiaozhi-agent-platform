#!/usr/bin/env sh
set -eu

product_project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
product_port=${1:-}
product_after_flash=${2:-}
product_version=$(sed -n \
    's/^CONFIG_APP_PROJECT_VER="\(.*\)-box3-bringup"$/\1/p' \
    "$product_project_dir/sdkconfig.box3-bringup.defaults")
product_firmware="$product_project_dir/dist/box3-bringup/box3-bringup-$product_version.bin"

if [ -z "$product_port" ]; then
    echo "Usage: $0 /dev/cu.YOUR_DEVICE [monitor]" >&2
    exit 2
fi
if [ ! -f "$product_firmware" ]; then
    echo "Firmware is missing; run tools/build_box3_bringup.sh first" >&2
    exit 1
fi

. "$product_project_dir/tools/box3_bringup_toolchain.sh"
product_prepare_box3_toolchain

product_run_esptool --chip esp32s3 \
    --port "$product_port" \
    --baud 460800 \
    --before default-reset \
    --after hard-reset \
    write-flash \
    --flash-mode dio \
    --flash-size 16MB \
    --flash-freq 80m \
    0x0 "$product_firmware"

if [ "$product_after_flash" = monitor ]; then
    product_run_idf -B "$product_project_dir/build-box3-bringup" \
        -p "$product_port" monitor
fi
