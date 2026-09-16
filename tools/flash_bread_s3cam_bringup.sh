#!/usr/bin/env sh
set -eu

product_project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
product_port=${1:-}
product_after_flash=${2:-}
product_version=$(sed -n \
    's/^CONFIG_APP_PROJECT_VER="\(.*\)"$/\1/p' \
    "$product_project_dir/sdkconfig.bread-s3cam.defaults")
product_firmware="$product_project_dir/dist/bread-s3cam-bringup/bread-s3cam-bringup-$product_version.bin"
product_build_dir="$product_project_dir/build-bread-s3cam-bringup"
product_bootloader="$product_build_dir/bootloader/bootloader.bin"
product_partition_table="$product_build_dir/partition_table/partition-table.bin"
product_ota_data="$product_build_dir/ota_data_initial.bin"
product_application="$product_build_dir/xiaozhi_agent_platform.bin"

if [ -z "$product_port" ]; then
    echo "Usage: $0 /dev/cu.YOUR_DEVICE [monitor]" >&2
    exit 2
fi
if [ ! -f "$product_firmware" ] || [ ! -f "$product_bootloader" ] || \
   [ ! -f "$product_partition_table" ] || [ ! -f "$product_ota_data" ] || \
   [ ! -f "$product_application" ]; then
    echo "Firmware is missing; run tools/build_bread_s3cam_bringup.sh first" >&2
    exit 1
fi

. "$product_project_dir/tools/box3_bringup_toolchain.sh"
product_prepare_box3_toolchain
product_select_esptool_cli_style

# This CH34x link was qualified at 230400 baud after higher rates showed
# readback corruption. Flash only executable metadata and app partitions so
# encrypted product settings in the NVS partitions survive firmware updates.
product_run_esptool --chip esp32s3 \
    --port "$product_port" \
    --baud 230400 \
    --before "$product_esptool_default_reset" \
    --after "$product_esptool_hard_reset" \
    "$product_esptool_write_operation" \
    "$product_esptool_flash_mode_option" dio \
    "$product_esptool_flash_size_option" 16MB \
    "$product_esptool_flash_freq_option" 80m \
    0x0 "$product_bootloader" \
    0x8000 "$product_partition_table" \
    0x19000 "$product_ota_data" \
    0x30000 "$product_application"

if [ "$product_after_flash" = monitor ]; then
    product_run_idf -B "$product_project_dir/build-bread-s3cam-bringup" \
        -p "$product_port" monitor
fi
