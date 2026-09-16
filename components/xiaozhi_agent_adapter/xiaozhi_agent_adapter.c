#include "xiaozhi_agent_adapter.h"

#include <string.h>

agent_bridge_result_t xiaozhi_agent_adapter_add_client_hello_feature(
    cJSON *hello_root)
{
    cJSON *features;
    cJSON *device_agent;

    if (!hello_root || !cJSON_IsObject(hello_root)) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    features = cJSON_GetObjectItemCaseSensitive(hello_root, "features");
    if (!cJSON_IsObject(features)) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }

    cJSON_DeleteItemFromObjectCaseSensitive(features, "device_agent");
    device_agent = cJSON_CreateObject();
    if (!device_agent) {
        return AGENT_BRIDGE_ERR_OPERATION;
    }
    if (!cJSON_AddNumberToObject(device_agent,
                                 "version",
                                 XIAOZHI_DEVICE_AGENT_PROTOCOL_VERSION) ||
        !cJSON_AddBoolToObject(device_agent, "request_correlation", true)) {
        cJSON_Delete(device_agent);
        return AGENT_BRIDGE_ERR_OPERATION;
    }
    if (!cJSON_AddItemToObject(features, "device_agent", device_agent)) {
        cJSON_Delete(device_agent);
        return AGENT_BRIDGE_ERR_OPERATION;
    }
    return AGENT_BRIDGE_OK;
}

agent_bridge_result_t xiaozhi_agent_adapter_validate_server_hello(
    const cJSON *hello_root)
{
    const cJSON *type;
    const cJSON *features;
    const cJSON *device_agent;
    const cJSON *version;
    const cJSON *request_correlation;

    if (!hello_root || !cJSON_IsObject(hello_root)) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    type = cJSON_GetObjectItemCaseSensitive(hello_root, "type");
    if (!cJSON_IsString(type) || !type->valuestring ||
        strcmp(type->valuestring, "hello") != 0) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    features = cJSON_GetObjectItemCaseSensitive(hello_root, "features");
    if (!cJSON_IsObject(features)) {
        return AGENT_BRIDGE_ERR_INVALID_STATE;
    }
    device_agent = cJSON_GetObjectItemCaseSensitive(features, "device_agent");
    if (!cJSON_IsObject(device_agent)) {
        return AGENT_BRIDGE_ERR_INVALID_STATE;
    }
    version = cJSON_GetObjectItemCaseSensitive(device_agent, "version");
    request_correlation = cJSON_GetObjectItemCaseSensitive(
        device_agent, "request_correlation");
    if (!cJSON_IsNumber(version) ||
        version->valuedouble != XIAOZHI_DEVICE_AGENT_PROTOCOL_VERSION ||
        !cJSON_IsTrue(request_correlation)) {
        return AGENT_BRIDGE_ERR_INVALID_STATE;
    }
    return AGENT_BRIDGE_OK;
}

static agent_bridge_result_t resolve_session_id(const cJSON *root,
                                                const char *protocol_session_id,
                                                const char **session_id)
{
    const cJSON *message_session = cJSON_GetObjectItemCaseSensitive(
        root, "session_id");

    if (!protocol_session_id || !protocol_session_id[0]) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    if (message_session) {
        if (!cJSON_IsString(message_session) ||
            !message_session->valuestring || !message_session->valuestring[0]) {
            return AGENT_BRIDGE_ERR_INVALID_ARG;
        }
        if (strcmp(message_session->valuestring, protocol_session_id) != 0) {
            return AGENT_BRIDGE_ERR_STALE_EVENT;
        }
    }
    *session_id = protocol_session_id;
    return AGENT_BRIDGE_OK;
}

static agent_bridge_result_t parse_request_id(const cJSON *root,
                                              uint32_t *request_id)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(root, "request_id");
    double value;
    uint32_t parsed;

    if (!cJSON_IsNumber(item)) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    value = item->valuedouble;
    if (!(value > 0.0 && value <= (double)UINT32_MAX)) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    parsed = (uint32_t)value;
    if ((double)parsed != value) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    *request_id = parsed;
    return AGENT_BRIDGE_OK;
}

agent_bridge_result_t xiaozhi_agent_adapter_handle_json(
    voice_agent_controller_t *controller,
    const cJSON *root,
    const char *protocol_session_id,
    xiaozhi_agent_message_outcome_t *outcome)
{
    const cJSON *type;
    const char *session_id = NULL;
    agent_bridge_result_t result;

    if (!controller || !root || !cJSON_IsObject(root) || !outcome) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    outcome->handled = false;
    outcome->accepted_request_id = 0;
    outcome->service_error = XIAOZHI_AGENT_SERVICE_ERROR_NONE;

    type = cJSON_GetObjectItemCaseSensitive(root, "type");
    if (!cJSON_IsString(type) || !type->valuestring) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    if (strcmp(type->valuestring, "error") == 0) {
        const cJSON *code = cJSON_GetObjectItemCaseSensitive(root, "code");
        agent_bridge_state_t state;
        uint32_t request_id;

        if (!cJSON_IsString(code) || !code->valuestring) {
            return AGENT_BRIDGE_ERR_INVALID_ARG;
        }
        if (strcmp(code->valuestring, "speech_budget_exceeded") == 0) {
            outcome->service_error =
                XIAOZHI_AGENT_SERVICE_ERROR_SPEECH_BUDGET_EXCEEDED;
        } else if (strcmp(code->valuestring,
                          "speech_budget_unavailable") == 0) {
            outcome->service_error =
                XIAOZHI_AGENT_SERVICE_ERROR_SPEECH_BUDGET_UNAVAILABLE;
        } else {
            return AGENT_BRIDGE_OK;
        }
        outcome->handled = true;
        state = voice_agent_controller_state(controller);
        if (state != AGENT_BRIDGE_STATE_TTS_PENDING &&
            state != AGENT_BRIDGE_STATE_TTS_PLAYING) {
            return AGENT_BRIDGE_OK;
        }
        request_id = voice_agent_controller_active_request_id(controller);
        outcome->accepted_request_id = request_id;
        return voice_agent_controller_on_tts_event(
            controller, protocol_session_id, request_id,
            VOICE_AGENT_TTS_ERROR);
    }
    if (strcmp(type->valuestring, "stt") != 0 &&
        strcmp(type->valuestring, "tts") != 0) {
        return AGENT_BRIDGE_OK;
    }

    result = resolve_session_id(root, protocol_session_id, &session_id);
    if (result != AGENT_BRIDGE_OK) {
        return result;
    }

    if (strcmp(type->valuestring, "stt") == 0) {
        const cJSON *text = cJSON_GetObjectItemCaseSensitive(root, "text");
        if (!cJSON_IsString(text) || !text->valuestring || !text->valuestring[0]) {
            return AGENT_BRIDGE_ERR_INVALID_ARG;
        }
        outcome->handled = true;
        return voice_agent_controller_on_stt_final(
            controller,
            session_id,
            text->valuestring,
            &outcome->accepted_request_id);
    }

    const cJSON *state = cJSON_GetObjectItemCaseSensitive(root, "state");
    uint32_t request_id = 0;
    voice_agent_tts_event_t event;

    if (!cJSON_IsString(state) || !state->valuestring) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    if (strcmp(state->valuestring, "sentence_start") == 0) {
        return AGENT_BRIDGE_OK;
    }
    if (strcmp(state->valuestring, "start") == 0) {
        event = VOICE_AGENT_TTS_STARTED;
    } else if (strcmp(state->valuestring, "stop") == 0) {
        event = VOICE_AGENT_TTS_STOPPED;
    } else if (strcmp(state->valuestring, "error") == 0) {
        event = VOICE_AGENT_TTS_ERROR;
    } else {
        return AGENT_BRIDGE_OK;
    }

    result = parse_request_id(root, &request_id);
    if (result != AGENT_BRIDGE_OK) {
        return result;
    }
    outcome->handled = true;
    outcome->accepted_request_id = request_id;
    return voice_agent_controller_on_tts_event(controller,
                                                session_id,
                                                request_id,
                                                event);
}
