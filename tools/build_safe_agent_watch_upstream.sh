#!/usr/bin/env sh
set -eu

product_project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
product_workspace_dir=$(CDPATH= cd -- "$product_project_dir/../.." && pwd)
product_upstream_dir="$product_workspace_dir/work/upstream/xiaozhi-esp32"
product_board_dir="$product_upstream_dir/main/boards/waveshare/esp32-s3-touch-amoled-2.06"
product_template="$product_board_dir/config.safe-agent-watch.json"
product_token_file=${SAFE_AGENT_WATCH_BOOTSTRAP_TOKEN_FILE:-"$product_project_dir/.local-secrets/watch_bootstrap_token"}

if [ ! -f "$product_template" ]; then
    echo "Safe Agent watch build template is missing: $product_template" >&2
    exit 1
fi
if [ ! -f "$product_token_file" ]; then
    echo "Safe Agent Gateway bootstrap token is missing: $product_token_file" >&2
    exit 1
fi

product_token=$(sed -e 's/\r$//' "$product_token_file")
if [ "${#product_token}" -lt 32 ] || [ "${#product_token}" -gt 256 ]; then
    echo "Safe Agent Gateway bootstrap token must contain 32 to 256 characters" >&2
    exit 1
fi
case "$product_token" in
    *[!A-Za-z0-9._-]*)
        echo "Safe Agent Gateway bootstrap token contains unsupported characters" >&2
        exit 1
        ;;
esac

umask 077
product_private_config="$product_board_dir/config.safe-agent-watch.local.json"
trap 'rm -f "$product_private_config"' EXIT HUP INT TERM
sed "s/__SAFE_AGENT_BOOTSTRAP_TOKEN__/$product_token/" \
    "$product_template" > "$product_private_config"
unset product_token

. "$product_project_dir/tools/box3_bringup_toolchain.sh"
product_prepare_box3_toolchain

cd "$product_upstream_dir"
python3 scripts/build.py \
    -c "$(basename "$product_private_config")" \
    waveshare/esp32-s3-touch-amoled-2.06 \
    --name safe-agent-watch-2.06-dev \
    --language zh-TW \
    --build-options-json '{"display_style":"default","multiline_chat":true,"aec_mode":"device","wifi_provisioning":"hotspot"}'

chmod 600 sdkconfig build/xiaozhi-build.sdkconfig.defaults 2>/dev/null || true
echo "Safe Agent watch firmware build PASS"
echo "Development bootstrap token remains confined to the private build output and firmware image."
