#!/usr/bin/env sh
set -eu
umask 077

if [ "$#" -ne 2 ]; then
    echo "usage: capture_sacrificial_blank_preflight.sh PORT NEW_OUTPUT_DIR" >&2
    exit 2
fi
product_port=$1
product_output_dir=$2

case "$product_port" in
    /dev/tty*|/dev/cu.*) ;;
    *) echo "serial port must be an explicit /dev/tty* or /dev/cu.* path" >&2; exit 1 ;;
esac
if [ ! -e "$product_port" ] || [ -L "$product_port" ]; then
    echo "serial port must exist and must not be a symlink" >&2
    exit 1
fi
if [ -e "$product_output_dir" ] || [ -L "$product_output_dir" ]; then
    echo "preflight output directory must not already exist" >&2
    exit 1
fi
if ! command -v python >/dev/null 2>&1 ||
   ! python -c 'import esptool, espefuse' >/dev/null 2>&1; then
    echo "ESP-IDF esptool/espefuse Python environment is unavailable" >&2
    exit 1
fi
product_tool_version=$(python -c "import importlib.metadata; print(importlib.metadata.version('esptool'))")
if [ "$product_tool_version" != "5.3.1" ]; then
    echo "sacrificial preflight requires esptool/espefuse 5.3.1" >&2
    exit 1
fi

mkdir -m 700 -- "$product_output_dir"
product_incomplete="$product_output_dir/INCOMPLETE"
printf '%s\n' "sacrificial blank preflight did not complete" >"$product_incomplete"
date -u '+%Y-%m-%dT%H:%M:%SZ' >"$product_output_dir/started-at.txt"
ls -ldn "$product_port" >"$product_output_dir/port-fingerprint.txt"
printf '%s\n' "esptool=5.3.1" "espefuse=5.3.1" >"$product_output_dir/tool-versions.txt"

python -m esptool --chip esp32s3 --port "$product_port" --baud 460800 \
    --before default-reset --after no-reset --no-stub chip-id \
    >"$product_output_dir/chip-probe.log" 2>&1
python -m esptool --chip esp32s3 --port "$product_port" --baud 460800 \
    --before no-reset --after no-reset --no-stub flash-id \
    >"$product_output_dir/flash-probe.log" 2>&1
python -m espefuse --chip esp32s3 --port "$product_port" \
    --before no-reset --after no-reset summary --format json \
    --file "$product_output_dir/efuse-before.json" \
    >"$product_output_dir/efuse-before-command.log" 2>&1
python -m espefuse --chip esp32s3 --port "$product_port" \
    --before no-reset --after no-reset check-error \
    >"$product_output_dir/efuse-check-error.log" 2>&1
python -m espefuse --chip esp32s3 --port "$product_port" \
    --before no-reset --after no-reset summary --format json \
    --file "$product_output_dir/efuse-after.json" \
    >"$product_output_dir/efuse-after-command.log" 2>&1

if ! cmp -s "$product_output_dir/efuse-before.json" "$product_output_dir/efuse-after.json"; then
    echo "eFuse state changed during read-only preflight; quarantine this attempt" >&2
    exit 1
fi
date -u '+%Y-%m-%dT%H:%M:%SZ' >"$product_output_dir/finished-at.txt"
unlink "$product_incomplete"
printf '%s\n' \
    "sacrificial blank preflight CAPTURED; not authorized" \
    "external dual-person plan signature remains required; no eFuse or flash write ran"

