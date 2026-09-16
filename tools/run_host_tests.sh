#!/usr/bin/env sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
host_test_dir=$(mktemp -d "${TMPDIR:-/tmp}/xiaozhi-agent-tests.XXXXXX")
trap 'rm -rf "$host_test_dir"' EXIT HUP INT TERM
bridge_test_binary="$host_test_dir/test_agent_bridge"
controller_test_binary="$host_test_dir/test_voice_agent_controller"
adapter_test_binary="$host_test_dir/test_xiaozhi_agent_adapter"
device_runtime_test_binary="$host_test_dir/test_device_voice_runtime"
device_client_protocol_test_binary="$host_test_dir/test_device_voice_client_protocol"
audio_protocol_test_binary="$host_test_dir/test_voice_audio_protocol"
audio_session_test_binary="$host_test_dir/test_voice_audio_session"
websocket_core_test_binary="$host_test_dir/test_device_websocket_transport_core"
supervisor_core_test_binary="$host_test_dir/test_box3_agent_supervisor_core"
product_runtime_core_test_binary="$host_test_dir/test_box3_product_runtime_core"
credentials_protocol_test_binary="$host_test_dir/test_box3_agent_credentials_protocol"
device_time_core_test_binary="$host_test_dir/test_agent_device_time_core"
device_proof_core_test_binary="$host_test_dir/test_agent_device_proof_core"
control_plane_protocol_test_binary="$host_test_dir/test_agent_control_plane_protocol"
product_wifi_core_test_binary="$host_test_dir/test_product_wifi_core"
product_time_bootstrap_core_test_binary="$host_test_dir/test_product_time_bootstrap_core"
product_local_action_core_test_binary="$host_test_dir/test_product_local_action_core"
product_factory_reset_core_test_binary="$host_test_dir/test_product_factory_reset_core"
product_provisioning_core_test_binary="$host_test_dir/test_product_provisioning_core"
product_storage_core_test_binary="$host_test_dir/test_product_storage_core"
product_agent_memory_core_test_binary="$host_test_dir/test_product_agent_memory_core"
esp_claw_memory_grant_core_test_binary="$host_test_dir/test_esp_claw_memory_grant_core"
esp_claw_capability_grant_core_test_binary="$host_test_dir/test_esp_claw_capability_grant_core"
product_agent_observability_test_binary="$host_test_dir/test_product_agent_observability"
product_ota_core_test_binary="$host_test_dir/test_product_ota_core"
product_ota_client_protocol_test_binary="$host_test_dir/test_product_ota_client_protocol"
product_sku_core_test_binary="$host_test_dir/test_product_sku_core"
cjson_dir="$project_dir/managed_components/espressif__cjson/cJSON"

cc -std=c11 -Wall -Wextra -Werror -pedantic \
    -I"$project_dir/components/agent_bridge/include" \
    "$project_dir/components/agent_bridge/agent_bridge.c" \
    "$project_dir/tests/host/test_agent_bridge.c" \
    -o "$bridge_test_binary"

"$bridge_test_binary"

cc -std=c11 -Wall -Wextra -Werror -pedantic \
    -I"$project_dir/components/agent_bridge/include" \
    -I"$project_dir/components/voice_agent_controller/include" \
    "$project_dir/components/agent_bridge/agent_bridge.c" \
    "$project_dir/components/voice_agent_controller/voice_agent_protocol.c" \
    "$project_dir/components/voice_agent_controller/voice_agent_controller.c" \
    "$project_dir/tests/host/test_voice_agent_controller.c" \
    -o "$controller_test_binary"

"$controller_test_binary"

cc -std=c11 -Wall -Wextra -Werror -pedantic \
    -I"$project_dir/components/voice_audio_protocol/include" \
    "$project_dir/components/voice_audio_protocol/voice_audio_protocol.c" \
    "$project_dir/tests/host/test_voice_audio_protocol.c" \
    -o "$audio_protocol_test_binary"

"$audio_protocol_test_binary"

cc -std=c11 -Wall -Wextra -Werror -pedantic \
    -I"$project_dir/components/voice_audio_session/include" \
    "$project_dir/components/voice_audio_session/voice_audio_session.c" \
    "$project_dir/tests/host/test_voice_audio_session.c" \
    -o "$audio_session_test_binary"

"$audio_session_test_binary"

cc -std=c11 -Wall -Wextra -Werror -pedantic \
    -I"$project_dir/components/device_websocket_transport/include" \
    -I"$project_dir/components/device_websocket_transport/private_include" \
    "$project_dir/components/device_websocket_transport/device_websocket_transport_core.c" \
    "$project_dir/tests/host/test_device_websocket_transport_core.c" \
    -o "$websocket_core_test_binary"

"$websocket_core_test_binary"

cc -std=c11 -Wall -Wextra -Werror -pedantic \
    -I"$project_dir/components/box3_agent_supervisor/include" \
    "$project_dir/components/box3_agent_supervisor/box3_agent_supervisor_core.c" \
    "$project_dir/tests/host/test_box3_agent_supervisor_core.c" \
    -o "$supervisor_core_test_binary"

"$supervisor_core_test_binary"

cc -std=c11 -Wall -Wextra -Werror -pedantic \
    -I"$project_dir/components/box3_product_runtime/include" \
    "$project_dir/components/box3_product_runtime/box3_product_runtime_core.c" \
    "$project_dir/tests/host/test_box3_product_runtime_core.c" \
    -o "$product_runtime_core_test_binary"

"$product_runtime_core_test_binary"

cc -std=c11 -Wall -Wextra -Werror -pedantic \
    -I"$project_dir/components/box3_agent_credentials_client/private_include" \
    -I"$cjson_dir" \
    "$project_dir/components/box3_agent_credentials_client/box3_agent_credentials_protocol.c" \
    "$cjson_dir/cJSON.c" \
    "$project_dir/tests/host/test_box3_agent_credentials_protocol.c" \
    -lm \
    -o "$credentials_protocol_test_binary"

"$credentials_protocol_test_binary"

cc -std=c11 -Wall -Wextra -Werror -pedantic \
    -I"$project_dir/components/agent_device_identity/private_include" \
    "$project_dir/components/agent_device_identity/agent_device_time_core.c" \
    "$project_dir/tests/host/test_agent_device_time_core.c" \
    -o "$device_time_core_test_binary"

"$device_time_core_test_binary"

cc -std=c11 -Wall -Wextra -Werror -pedantic \
    -I"$project_dir/components/agent_device_identity/private_include" \
    "$project_dir/components/agent_device_identity/agent_device_proof_core.c" \
    "$project_dir/tests/host/test_agent_device_proof_core.c" \
    -o "$device_proof_core_test_binary"

"$device_proof_core_test_binary"

cc -std=c11 -Wall -Wextra -Werror -pedantic \
    -I"$project_dir/components/agent_control_plane_client/private_include" \
    -I"$cjson_dir" \
    "$project_dir/components/agent_control_plane_client/agent_control_plane_protocol.c" \
    "$cjson_dir/cJSON.c" \
    "$project_dir/tests/host/test_agent_control_plane_protocol.c" \
    -lm \
    -o "$control_plane_protocol_test_binary"

"$control_plane_protocol_test_binary"

cc -std=c11 -Wall -Wextra -Werror -pedantic \
    -I"$project_dir/components/product_wifi/include" \
    -I"$project_dir/components/product_wifi/private_include" \
    "$project_dir/components/product_wifi/product_wifi_core.c" \
    "$project_dir/components/product_wifi/product_wifi_credential_set_core.c" \
    "$project_dir/components/product_wifi/product_wifi_credentials_core.c" \
    "$project_dir/components/product_wifi/product_wifi_state_core.c" \
    "$project_dir/tests/host/test_product_wifi_core.c" \
    -o "$product_wifi_core_test_binary"

"$product_wifi_core_test_binary"

cc -std=c11 -Wall -Wextra -Werror -pedantic \
    -I"$project_dir/components/product_time_bootstrap/include" \
    "$project_dir/components/product_time_bootstrap/product_time_bootstrap_core.c" \
    "$project_dir/tests/host/test_product_time_bootstrap_core.c" \
    -o "$product_time_bootstrap_core_test_binary"

"$product_time_bootstrap_core_test_binary"

cc -std=c11 -Wall -Wextra -Werror -pedantic \
    -I"$project_dir/components/product_local_action/include" \
    "$project_dir/components/product_local_action/product_local_action_core.c" \
    "$project_dir/tests/host/test_product_local_action_core.c" \
    -o "$product_local_action_core_test_binary"

"$product_local_action_core_test_binary"

cc -std=c11 -Wall -Wextra -Werror -pedantic \
    -I"$project_dir/components/product_factory_reset/include" \
    "$project_dir/components/product_factory_reset/product_factory_reset_core.c" \
    "$project_dir/tests/host/test_product_factory_reset_core.c" \
    -o "$product_factory_reset_core_test_binary"

"$product_factory_reset_core_test_binary"

cc -std=c11 -Wall -Wextra -Werror -pedantic \
    -I"$project_dir/components/product_provisioning/include" \
    -I"$project_dir/components/product_provisioning/private_include" \
    "$project_dir/components/product_provisioning/product_provisioning_core.c" \
    "$project_dir/components/product_provisioning/product_provisioning_material_core.c" \
    "$project_dir/tests/host/test_product_provisioning_core.c" \
    -o "$product_provisioning_core_test_binary"

"$product_provisioning_core_test_binary"

cc -std=c11 -Wall -Wextra -Werror -pedantic \
    -I"$project_dir/components/product_storage/private_include" \
    "$project_dir/components/product_storage/product_storage_core.c" \
    "$project_dir/tests/host/test_product_storage_core.c" \
    -o "$product_storage_core_test_binary"

"$product_storage_core_test_binary"

cc -std=c11 -Wall -Wextra -Werror -pedantic \
    -I"$project_dir/components/product_agent_memory/private_include" \
    "$project_dir/components/product_agent_memory/product_agent_memory_core.c" \
    "$project_dir/tests/host/test_product_agent_memory_core.c" \
    -o "$product_agent_memory_core_test_binary"

"$product_agent_memory_core_test_binary"

cc -std=c11 -Wall -Wextra -Werror -pedantic \
    -I"$project_dir/components/esp_claw_runtime/private_include" \
    "$project_dir/components/esp_claw_runtime/esp_claw_memory_grant_core.c" \
    "$project_dir/tests/host/test_esp_claw_memory_grant_core.c" \
    -o "$esp_claw_memory_grant_core_test_binary"

"$esp_claw_memory_grant_core_test_binary"

cc -std=c11 -Wall -Wextra -Werror -pedantic \
    -I"$project_dir/components/esp_claw_runtime/private_include" \
    "$project_dir/components/esp_claw_runtime/esp_claw_capability_grant_core.c" \
    "$project_dir/tests/host/test_esp_claw_capability_grant_core.c" \
    -o "$esp_claw_capability_grant_core_test_binary"

"$esp_claw_capability_grant_core_test_binary"

cc -std=c11 -Wall -Wextra -Werror -pedantic \
    -I"$project_dir/tests/host/mocks" \
    -I"$project_dir/components/product_agent_observability/include" \
    -I"$project_dir/components/esp_claw_runtime/include" \
    -I"$project_dir/components/product_agent_memory/include" \
    "$project_dir/components/product_agent_observability/product_agent_observability.c" \
    "$project_dir/tests/host/test_product_agent_observability.c" \
    -o "$product_agent_observability_test_binary"

"$product_agent_observability_test_binary"

cc -std=c11 -Wall -Wextra -Werror -pedantic \
    -I"$project_dir/components/product_ota/private_include" \
    -I"$cjson_dir" \
    "$project_dir/components/product_ota/product_ota_core.c" \
    "$cjson_dir/cJSON.c" \
    "$project_dir/tests/host/test_product_ota_core.c" \
    -lm \
    -o "$product_ota_core_test_binary"

"$product_ota_core_test_binary"

cc -std=c11 -Wall -Wextra -Werror -pedantic \
    -I"$project_dir/components/product_ota_client/private_include" \
    -I"$cjson_dir" \
    "$project_dir/components/product_ota_client/product_ota_client_protocol.c" \
    "$cjson_dir/cJSON.c" \
    "$project_dir/tests/host/test_product_ota_client_protocol.c" \
    -lm \
    -o "$product_ota_client_protocol_test_binary"

"$product_ota_client_protocol_test_binary"

cc -std=c11 -Wall -Wextra -Werror -pedantic \
    -I"$project_dir/components/product_sku/include" \
    "$project_dir/components/product_sku/product_sku_core.c" \
    "$project_dir/tests/host/test_product_sku_core.c" \
    -o "$product_sku_core_test_binary"

"$product_sku_core_test_binary"

if [ -f "$cjson_dir/cJSON.c" ]; then
    cc -std=c11 -Wall -Wextra -Werror -pedantic \
        -I"$project_dir/components/agent_bridge/include" \
        -I"$project_dir/components/voice_agent_controller/include" \
        -I"$project_dir/components/xiaozhi_agent_adapter/include" \
        -I"$cjson_dir" \
        "$project_dir/components/agent_bridge/agent_bridge.c" \
        "$project_dir/components/voice_agent_controller/voice_agent_protocol.c" \
        "$project_dir/components/voice_agent_controller/voice_agent_controller.c" \
        "$project_dir/components/xiaozhi_agent_adapter/xiaozhi_agent_adapter.c" \
        "$cjson_dir/cJSON.c" \
        "$project_dir/tests/host/test_xiaozhi_agent_adapter.c" \
        -lm \
        -o "$adapter_test_binary"

    "$adapter_test_binary"

    cc -std=c11 -Wall -Wextra -Werror -pedantic \
        -I"$project_dir/components/agent_bridge/include" \
        -I"$project_dir/components/voice_agent_controller/include" \
        -I"$project_dir/components/xiaozhi_agent_adapter/include" \
        -I"$project_dir/components/device_voice_runtime/include" \
        -I"$cjson_dir" \
        "$project_dir/components/agent_bridge/agent_bridge.c" \
        "$project_dir/components/voice_agent_controller/voice_agent_protocol.c" \
        "$project_dir/components/voice_agent_controller/voice_agent_controller.c" \
        "$project_dir/components/xiaozhi_agent_adapter/xiaozhi_agent_adapter.c" \
        "$project_dir/components/device_voice_runtime/device_voice_runtime.c" \
        "$cjson_dir/cJSON.c" \
        "$project_dir/tests/host/test_device_voice_runtime.c" \
        -lm \
        -o "$device_runtime_test_binary"

    "$device_runtime_test_binary"

    cc -std=c11 -Wall -Wextra -Werror -pedantic \
        -I"$project_dir/components/agent_bridge/include" \
        -I"$project_dir/components/voice_agent_controller/include" \
        -I"$project_dir/components/xiaozhi_agent_adapter/include" \
        -I"$project_dir/components/device_websocket_transport/include" \
        -I"$project_dir/components/device_voice_client/private_include" \
        -I"$cjson_dir" \
        "$project_dir/components/agent_bridge/agent_bridge.c" \
        "$project_dir/components/voice_agent_controller/voice_agent_protocol.c" \
        "$project_dir/components/voice_agent_controller/voice_agent_controller.c" \
        "$project_dir/components/xiaozhi_agent_adapter/xiaozhi_agent_adapter.c" \
        "$project_dir/components/device_voice_client/device_voice_client_protocol.c" \
        "$cjson_dir/cJSON.c" \
        "$project_dir/tests/host/test_device_voice_client_protocol.c" \
        -lm \
        -o "$device_client_protocol_test_binary"

    "$device_client_protocol_test_binary"
else
    echo "xiaozhi_agent_adapter: skipped (run an IDF build to fetch managed cJSON)"
fi

PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
    -s "$project_dir/gateway_contract" -p 'test_*.py'
