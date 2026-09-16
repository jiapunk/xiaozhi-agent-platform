#!/usr/bin/env sh
set -eu
umask 077

if [ "$#" -ne 7 ]; then
    echo "usage: capture_factory_physical_readback.sh PORT NEW_OUTPUT_DIR SIGNED_BOOTLOADER PARTITION_TABLE NVS_FACTORY OTA_DATA SIGNED_APPLICATION" >&2
    exit 2
fi
product_port=$1
product_output_dir=$2
product_signed_bootloader=$3
product_partition_table=$4
product_nvs_factory=$5
product_ota_data=$6
product_signed_application=$7

case "$product_port" in
    /dev/tty*|/dev/cu.*) ;;
    *) echo "serial port must be an explicit /dev/tty* or /dev/cu.* path" >&2; exit 1 ;;
esac
if [ ! -e "$product_port" ] || [ -L "$product_port" ]; then
    echo "serial port must exist and must not be a symlink" >&2
    exit 1
fi
if [ -e "$product_output_dir" ] || [ -L "$product_output_dir" ]; then
    echo "physical readback output directory must not already exist" >&2
    exit 1
fi
if ! command -v python >/dev/null 2>&1 ||
   ! python -c 'import espsecure, esptool, espefuse' >/dev/null 2>&1; then
    echo "ESP-IDF esptool/espefuse Python environment is unavailable" >&2
    exit 1
fi
product_esptool_version=$(python -c "import importlib.metadata; print(importlib.metadata.version('esptool'))")
if [ "$product_esptool_version" != "5.3.1" ]; then
    echo "factory physical capture requires esptool/espefuse 5.3.1" >&2
    exit 1
fi

product_size() {
    product_path=$1
    product_label=$2
    if [ ! -f "$product_path" ] || [ -L "$product_path" ]; then
        echo "$product_label must be a regular non-symlink file" >&2
        exit 1
    fi
    product_bytes=$(wc -c <"$product_path" | tr -d ' ')
    case "$product_bytes" in
        ''|*[!0-9]*) echo "$product_label size is invalid" >&2; exit 1 ;;
    esac
    if [ "$product_bytes" -lt 1 ] || [ "$product_bytes" -gt 5771264 ]; then
        echo "$product_label size is outside the frozen capture bound" >&2
        exit 1
    fi
    printf '%s' "$product_bytes"
}

product_bootloader_size=$(product_size "$product_signed_bootloader" "signed bootloader")
product_partition_size=$(product_size "$product_partition_table" "partition table")
product_nvs_size=$(product_size "$product_nvs_factory" "nvs_factory")
product_ota_size=$(product_size "$product_ota_data" "OTA data")
product_application_size=$(product_size "$product_signed_application" "signed application")
if [ "$product_partition_size" -ne 3072 ] ||
   [ "$product_nvs_size" -ne 24576 ] ||
   [ "$product_ota_size" -ne 8192 ]; then
    echo "partition table, nvs_factory or OTA-data size differs from BOX-3 policy" >&2
    exit 1
fi

mkdir -m 700 -- "$product_output_dir"
product_incomplete="$product_output_dir/INCOMPLETE"
printf '%s\n' "physical readback capture did not complete" >"$product_incomplete"
date -u '+%Y-%m-%dT%H:%M:%SZ' >"$product_output_dir/started-at.txt"
ls -ldn "$product_port" >"$product_output_dir/port-fingerprint.txt"

python -m esptool --chip esp32s3 --port "$product_port" --baud 460800 \
    --before default-reset --after no-reset --no-stub chip-id \
    >"$product_output_dir/chip-probe.log" 2>&1
python -m espefuse --chip esp32s3 --port "$product_port" \
    --before no-reset --after no-reset summary \
    >"$product_output_dir/efuse-before.txt" 2>&1

python -m esptool --chip esp32s3 --port "$product_port" --baud 460800 \
    --before no-reset --after no-reset --no-stub read-flash --no-progress \
    0x0 "$product_bootloader_size" "$product_output_dir/bootloader-readback.bin"
python -m esptool --chip esp32s3 --port "$product_port" --baud 460800 \
    --before no-reset --after no-reset --no-stub read-flash --no-progress \
    0x10000 "$product_partition_size" "$product_output_dir/partition-table-readback.bin"
python -m esptool --chip esp32s3 --port "$product_port" --baud 460800 \
    --before no-reset --after no-reset --no-stub read-flash --no-progress \
    0x11000 "$product_nvs_size" "$product_output_dir/nvs-factory-readback.bin"
python -m esptool --chip esp32s3 --port "$product_port" --baud 460800 \
    --before no-reset --after no-reset --no-stub read-flash --no-progress \
    0x21000 "$product_ota_size" "$product_output_dir/ota-data-readback.bin"
python -m esptool --chip esp32s3 --port "$product_port" --baud 460800 \
    --before no-reset --after no-reset --no-stub read-flash --no-progress \
    0x40000 "$product_application_size" "$product_output_dir/application-readback.bin"

python -m espefuse --chip esp32s3 --port "$product_port" \
    --before no-reset --after no-reset summary \
    >"$product_output_dir/efuse-after.txt" 2>&1
if ! cmp -s "$product_output_dir/efuse-before.txt" "$product_output_dir/efuse-after.txt"; then
    echo "eFuse summary changed during physical readback; quarantine this attempt" >&2
    exit 1
fi
date -u '+%Y-%m-%dT%H:%M:%SZ' >"$product_output_dir/finished-at.txt"
unlink "$product_incomplete"
printf '%s\n' \
    "physical readback CAPTURED; not yet PASS" \
    "external station signature, manifest binding, final eFuse locks and v4 receipt remain required"

