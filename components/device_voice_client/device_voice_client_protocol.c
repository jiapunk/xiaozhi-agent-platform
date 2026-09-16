#include "device_voice_client_protocol.h"

#include <ctype.h>
#include <limits.h>
#include <string.h>

#include "xiaozhi_agent_adapter.h"

agent_bridge_result_t device_voice_client_build_hello(
    int transport_version,
    int uplink_sample_rate,
    int frame_duration_ms,
    char *output,
    size_t output_capacity,
    size_t *output_size)
{
    cJSON *root = NULL;
    cJSON *features = NULL;
    cJSON *audio = NULL;
    agent_bridge_result_t result = AGENT_BRIDGE_ERR_OPERATION;

    if (output_size) {
        *output_size = 0;
    }
    if (transport_version < 1 || transport_version > 3 ||
        uplink_sample_rate <= 0 || uplink_sample_rate > 48000 ||
        frame_duration_ms < 20 || frame_duration_ms > 120 || !output ||
        output_capacity == 0 || output_capacity > INT_MAX || !output_size) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    output[0] = '\0';
    root = cJSON_CreateObject();
    features = cJSON_CreateObject();
    audio = cJSON_CreateObject();
    if (!root || !features || !audio ||
        !cJSON_AddStringToObject(root, "type", "hello") ||
        !cJSON_AddNumberToObject(root, "version", transport_version) ||
        !cJSON_AddStringToObject(root, "transport", "websocket") ||
        !cJSON_AddBoolToObject(features, "mcp", true) ||
        !cJSON_AddStringToObject(audio, "format", "opus") ||
        !cJSON_AddNumberToObject(audio, "sample_rate", uplink_sample_rate) ||
        !cJSON_AddNumberToObject(audio, "channels", 1) ||
        !cJSON_AddNumberToObject(audio, "frame_duration", frame_duration_ms)) {
        goto cleanup;
    }
    if (!cJSON_AddItemToObject(root, "features", features)) {
        goto cleanup;
    }
    features = NULL;
    if (!cJSON_AddItemToObject(root, "audio_params", audio)) {
        goto cleanup;
    }
    audio = NULL;
    result = xiaozhi_agent_adapter_add_client_hello_feature(root);
    if (result != AGENT_BRIDGE_OK) {
        goto cleanup;
    }
    if (!cJSON_PrintPreallocated(root, output, (int)output_capacity, false)) {
        output[0] = '\0';
        result = AGENT_BRIDGE_ERR_OPERATION;
        goto cleanup;
    }
    *output_size = strlen(output);
    result = *output_size > 0 ? AGENT_BRIDGE_OK
                              : AGENT_BRIDGE_ERR_OPERATION;

cleanup:
    cJSON_Delete(audio);
    cJSON_Delete(features);
    cJSON_Delete(root);
    return result;
}

cJSON *device_voice_client_parse_json_strict(const uint8_t *data,
                                             size_t size)
{
    const char *end = NULL;
    const char *limit;
    cJSON *root;

    if (!data || size == 0 || size > DEVICE_WEBSOCKET_CONTROL_MAX) {
        return NULL;
    }
    limit = (const char *)data + size;
    root = cJSON_ParseWithLengthOpts((const char *)data, size, &end, false);
    if (!root || !end) {
        cJSON_Delete(root);
        return NULL;
    }
    while (end < limit && isspace((unsigned char)*end)) {
        ++end;
    }
    if (end != limit) {
        cJSON_Delete(root);
        return NULL;
    }
    return root;
}
