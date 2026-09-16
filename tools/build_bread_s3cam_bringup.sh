#!/usr/bin/env sh
set -eu

product_project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
product_build_dir="$product_project_dir/build-bread-s3cam-bringup"
product_sdkconfig="$product_build_dir/sdkconfig"
product_defaults="$product_project_dir/sdkconfig.bread-s3cam.defaults"
product_bootstrap_token_file=${PRODUCT_BREAD_S3CAM_BOOTSTRAP_TOKEN_FILE:-"$product_project_dir/.local-secrets/bread_s3cam_bootstrap_token"}
product_secret_defaults=

product_cleanup_secret_defaults()
{
    if [ -n "$product_secret_defaults" ] && [ -f "$product_secret_defaults" ]; then
        rm -f -- "$product_secret_defaults"
    fi
}
trap product_cleanup_secret_defaults EXIT HUP INT TERM

if [ ! -f "$product_bootstrap_token_file" ]; then
    echo "Bread S3CAM Gateway bootstrap token file is missing: $product_bootstrap_token_file" >&2
    echo "Set PRODUCT_BREAD_S3CAM_BOOTSTRAP_TOKEN_FILE to a private token file (mode 0600)." >&2
    exit 1
fi

product_bootstrap_token=$(sed -e 's/\r$//' "$product_bootstrap_token_file")
if [ "${#product_bootstrap_token}" -lt 32 ] ||
   [ "${#product_bootstrap_token}" -gt 256 ]; then
    echo "Bread S3CAM Gateway bootstrap token must contain 32 to 256 characters" >&2
    exit 1
fi
case "$product_bootstrap_token" in
    *[!A-Za-z0-9._~-]*)
        echo "Bread S3CAM Gateway bootstrap token contains unsupported characters" >&2
        exit 1
        ;;
esac

umask 077
product_secret_defaults=$(mktemp "${TMPDIR:-/tmp}/bread-s3cam-sdkconfig.XXXXXX")
printf 'CONFIG_PRODUCT_BREAD_S3CAM_BOOTSTRAP_TOKEN="%s"\n' \
    "$product_bootstrap_token" > "$product_secret_defaults"
product_sdkconfig_defaults="$product_defaults;$product_secret_defaults"
unset product_bootstrap_token

. "$product_project_dir/tools/box3_bringup_toolchain.sh"
product_prepare_box3_toolchain

if [ -z "${ESP_CLAW_ROOT:-}" ]; then
    ESP_CLAW_ROOT="$product_project_dir/third_party/esp-claw"
    export ESP_CLAW_ROOT
fi

PRODUCT_BREAD_S3CAM_DIAGNOSTIC=1
export PRODUCT_BREAD_S3CAM_DIAGNOSTIC

product_run_idf -B "$product_build_dir" \
    -D "PRODUCT_BREAD_S3CAM_DIAGNOSTIC=ON" \
    -D "SDKCONFIG=$product_sdkconfig" \
    -D "SDKCONFIG_DEFAULTS=$product_sdkconfig_defaults" \
    set-target esp32s3 build size

"$product_project_dir/tools/package_bread_s3cam_bringup.sh"

echo "Bread S3CAM bring-up firmware build PASS"
echo "Flash with: $product_project_dir/tools/flash_bread_s3cam_bringup.sh /dev/cu.YOUR_DEVICE monitor"
