#!/usr/bin/env sh

# Sourced by the BOX-3 bring-up helpers. It first uses an already activated
# ESP-IDF environment, then falls back to the pinned local toolchain workspace.
product_prepare_box3_toolchain()
{
    if command -v idf.py >/dev/null 2>&1; then
        product_idf_mode=path
        product_python_command=$(command -v python)
        return 0
    fi

    product_workspace_dir=$(CDPATH= cd -- "$product_project_dir/../.." && pwd)
    product_idf_path="$product_workspace_dir/work/toolchains/esp-idf-v6.0.2"
    product_idf_tools_path="$product_workspace_dir/work/toolchains/idf-tools"
    product_python_env="$product_idf_tools_path/python_env/idf6.0_py3.11_env"
    product_python_command="$product_python_env/bin/python"
    product_xtensa_bin="$product_idf_tools_path/tools/xtensa-esp-elf/esp-15.2.0_20251204/xtensa-esp-elf/bin"

    if [ ! -x "$product_python_command" ] || \
       [ ! -f "$product_idf_path/tools/idf.py" ] || \
       [ ! -x "$product_xtensa_bin/xtensa-esp32s3-elf-gcc" ]; then
        echo "ESP-IDF 6.0.2 is unavailable; install/activate it before continuing" >&2
        return 1
    fi

    IDF_PATH="$product_idf_path"
    IDF_TOOLS_PATH="$product_idf_tools_path"
    IDF_PYTHON_ENV_PATH="$product_python_env"
    ESP_IDF_VERSION=6.0.2
    PATH="$product_python_env/bin:$product_xtensa_bin:$product_idf_path/tools:$PATH"
    export IDF_PATH IDF_TOOLS_PATH IDF_PYTHON_ENV_PATH ESP_IDF_VERSION PATH
    product_idf_mode=pinned
}

product_run_idf()
{
    if [ "$product_idf_mode" = path ]; then
        idf.py "$@"
    else
        "$product_python_command" "$IDF_PATH/tools/idf.py" "$@"
    fi
}

product_run_esptool()
{
    "$product_python_command" -m esptool "$@"
}

product_select_esptool_cli_style()
{
    product_esptool_version=$(
        "$product_python_command" -m esptool version 2>/dev/null | tail -n 1
    )
    case "$product_esptool_version" in
        4.*)
            product_esptool_merge_operation=merge_bin
            product_esptool_write_operation=write_flash
            product_esptool_default_reset=default_reset
            product_esptool_hard_reset=hard_reset
            product_esptool_flash_mode_option=--flash_mode
            product_esptool_flash_size_option=--flash_size
            product_esptool_flash_freq_option=--flash_freq
            ;;
        *)
            product_esptool_merge_operation=merge-bin
            product_esptool_write_operation=write-flash
            product_esptool_default_reset=default-reset
            product_esptool_hard_reset=hard-reset
            product_esptool_flash_mode_option=--flash-mode
            product_esptool_flash_size_option=--flash-size
            product_esptool_flash_freq_option=--flash-freq
            ;;
    esac
}
