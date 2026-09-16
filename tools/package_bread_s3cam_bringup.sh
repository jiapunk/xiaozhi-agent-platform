#!/usr/bin/env sh
set -eu

product_project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
product_build_dir="$product_project_dir/build-bread-s3cam-bringup"
product_dist_dir="$product_project_dir/dist/bread-s3cam-bringup"
product_version=$(sed -n \
    's/^CONFIG_APP_PROJECT_VER="\(.*\)"$/\1/p' \
    "$product_project_dir/sdkconfig.bread-s3cam.defaults")

. "$product_project_dir/tools/box3_bringup_toolchain.sh"
product_prepare_box3_toolchain

if [ -z "$product_version" ]; then
    echo "Unable to read the Bread S3CAM bring-up version" >&2
    exit 1
fi

for product_binary in \
    "$product_build_dir/bootloader/bootloader.bin" \
    "$product_build_dir/partition_table/partition-table.bin" \
    "$product_build_dir/ota_data_initial.bin" \
    "$product_build_dir/xiaozhi_agent_platform.bin"
do
    if [ ! -f "$product_binary" ]; then
        echo "Missing build artifact: $product_binary" >&2
        exit 1
    fi
done

mkdir -p "$product_dist_dir"
product_output="$product_dist_dir/bread-s3cam-bringup-$product_version.bin"
product_select_esptool_cli_style

product_run_esptool --chip esp32s3 "$product_esptool_merge_operation" \
    --output "$product_output" \
    --format raw \
    "$product_esptool_flash_mode_option" dio \
    "$product_esptool_flash_size_option" 16MB \
    "$product_esptool_flash_freq_option" 80m \
    0x0 "$product_build_dir/bootloader/bootloader.bin" \
    0x8000 "$product_build_dir/partition_table/partition-table.bin" \
    0x19000 "$product_build_dir/ota_data_initial.bin" \
    0x30000 "$product_build_dir/xiaozhi_agent_platform.bin"

echo "Packaged single-image firmware: $product_output"
shasum -a 256 "$product_output"
