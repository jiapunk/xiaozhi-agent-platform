#include "device_voice_runtime.h"

#include <math.h>
#include <string.h>

static int submit_agent(void *ctx,
                        uint32_t request_id,
                        const char *session_id,
                        const char *text)
{
    device_voice_runtime_t *runtime = ctx;
    return runtime->ops.submit_agent(runtime->ops_ctx, request_id,
                                     session_id, text);
}

static int cancel_agent(void *ctx, uint32_t request_id)
{
    device_voice_runtime_t *runtime = ctx;
    return runtime->ops.cancel_agent(runtime->ops_ctx, request_id);
}

static int send_json(void *ctx, const char *json, size_t json_length)
{
    device_voice_runtime_t *runtime = ctx;
    return runtime->ops.send_json(runtime->ops_ctx, json, json_length);
}

static void playback_event(void *ctx,
                           voice_agent_playback_event_t event,
                           uint32_t request_id)
{
    device_voice_runtime_t *runtime = ctx;
    runtime->ops.playback_event(runtime->ops_ctx, event, request_id);
}

static void state_changed(void *ctx,
                          agent_bridge_state_t from,
                          agent_bridge_state_t to,
                          uint32_t request_id)
{
    device_voice_runtime_t *runtime = ctx;
    if (runtime->ops.state_changed) {
        runtime->ops.state_changed(runtime->ops_ctx, from, to, request_id);
    }
}

agent_bridge_result_t device_voice_runtime_init(
    device_voice_runtime_t *runtime,
    const device_voice_runtime_config_t *config)
{
    voice_agent_controller_config_t controller_config;

    if (!runtime || !config || !config->ops.submit_agent ||
        !config->ops.cancel_agent || !config->ops.send_json ||
        !config->ops.receive_binary || !config->ops.playback_event ||
        !config->tx_buffer || config->tx_buffer_size == 0 ||
        config->downlink_sample_rate <= 0 ||
        config->downlink_sample_rate > 48000 ||
        config->frame_duration_ms < 20 ||
        config->frame_duration_ms > 120) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    memset(runtime, 0, sizeof(*runtime));
    runtime->ops = config->ops;
    runtime->ops_ctx = config->ops_ctx;
    runtime->downlink_sample_rate = config->downlink_sample_rate;
    runtime->frame_duration_ms = config->frame_duration_ms;
    controller_config = (voice_agent_controller_config_t){
        .ops = {
            .submit_agent = submit_agent,
            .cancel_agent = cancel_agent,
            .send_json = send_json,
            .state_changed = state_changed,
            .playback_event = playback_event,
        },
        .ops_ctx = runtime,
        .tx_buffer = config->tx_buffer,
        .tx_buffer_size = config->tx_buffer_size,
    };
    return voice_agent_controller_init(&runtime->controller,
                                       &controller_config);
}

agent_bridge_result_t device_voice_runtime_add_client_hello(
    device_voice_runtime_t *runtime,
    cJSON *hello_root)
{
    if (!runtime) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    return xiaozhi_agent_adapter_add_client_hello_feature(hello_root);
}

static bool exact_positive_int(const cJSON *item, int expected)
{
    return cJSON_IsNumber(item) && isfinite(item->valuedouble) &&
           item->valuedouble == (double)expected;
}

agent_bridge_result_t device_voice_runtime_accept_server_hello(
    device_voice_runtime_t *runtime,
    const cJSON *hello_root)
{
    const cJSON *transport;
    const cJSON *session_id;
    const cJSON *audio_params;
    const cJSON *format;
    const cJSON *sample_rate;
    const cJSON *channels;
    const cJSON *frame_duration;
    size_t session_length;
    agent_bridge_result_t result;

    if (!runtime || !hello_root || runtime->protocol_ready) {
        return !runtime || !hello_root ? AGENT_BRIDGE_ERR_INVALID_ARG
                                       : AGENT_BRIDGE_ERR_INVALID_STATE;
    }
    result = xiaozhi_agent_adapter_validate_server_hello(hello_root);
    if (result != AGENT_BRIDGE_OK) {
        return result;
    }
    transport = cJSON_GetObjectItemCaseSensitive(hello_root, "transport");
    session_id = cJSON_GetObjectItemCaseSensitive(hello_root, "session_id");
    audio_params = cJSON_GetObjectItemCaseSensitive(hello_root, "audio_params");
    if (!cJSON_IsString(transport) || !transport->valuestring ||
        strcmp(transport->valuestring, "websocket") != 0 ||
        !cJSON_IsString(session_id) || !session_id->valuestring ||
        !session_id->valuestring[0] || !cJSON_IsObject(audio_params)) {
        return AGENT_BRIDGE_ERR_INVALID_STATE;
    }
    session_length = strlen(session_id->valuestring);
    if (session_length >= sizeof(runtime->session_id)) {
        return AGENT_BRIDGE_ERR_INVALID_STATE;
    }
    format = cJSON_GetObjectItemCaseSensitive(audio_params, "format");
    sample_rate = cJSON_GetObjectItemCaseSensitive(audio_params, "sample_rate");
    channels = cJSON_GetObjectItemCaseSensitive(audio_params, "channels");
    frame_duration = cJSON_GetObjectItemCaseSensitive(audio_params,
                                                       "frame_duration");
    if (!cJSON_IsString(format) || !format->valuestring ||
        strcmp(format->valuestring, "opus") != 0 ||
        !exact_positive_int(sample_rate, runtime->downlink_sample_rate) ||
        !exact_positive_int(channels, 1) ||
        !exact_positive_int(frame_duration, runtime->frame_duration_ms)) {
        return AGENT_BRIDGE_ERR_INVALID_STATE;
    }
    memcpy(runtime->session_id, session_id->valuestring, session_length + 1);
    runtime->protocol_ready = true;
    return AGENT_BRIDGE_OK;
}

agent_bridge_result_t device_voice_runtime_on_json(
    device_voice_runtime_t *runtime,
    const cJSON *root,
    xiaozhi_agent_message_outcome_t *outcome)
{
    if (!runtime || !root || !outcome) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    if (!runtime->protocol_ready) {
        return AGENT_BRIDGE_ERR_INVALID_STATE;
    }
    return xiaozhi_agent_adapter_handle_json(&runtime->controller, root,
                                              runtime->session_id, outcome);
}

agent_bridge_result_t device_voice_runtime_on_binary(
    device_voice_runtime_t *runtime,
    const uint8_t *packet,
    size_t packet_size)
{
    if (!runtime || !packet || packet_size == 0) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    if (!runtime->protocol_ready ||
        voice_agent_controller_state(&runtime->controller) !=
            AGENT_BRIDGE_STATE_TTS_PLAYING) {
        return AGENT_BRIDGE_ERR_INVALID_STATE;
    }
    return runtime->ops.receive_binary(runtime->ops_ctx, packet, packet_size) == 0
               ? AGENT_BRIDGE_OK
               : AGENT_BRIDGE_ERR_OPERATION;
}

agent_bridge_result_t device_voice_runtime_on_agent_final(
    device_voice_runtime_t *runtime,
    uint32_t request_id,
    const char *text)
{
    if (!runtime) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    if (!runtime->protocol_ready) {
        return AGENT_BRIDGE_ERR_STALE_EVENT;
    }
    return voice_agent_controller_on_agent_final(&runtime->controller,
                                                  request_id, text);
}

agent_bridge_result_t device_voice_runtime_on_agent_error(
    device_voice_runtime_t *runtime,
    uint32_t request_id)
{
    if (!runtime) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    if (!runtime->protocol_ready) {
        return AGENT_BRIDGE_ERR_STALE_EVENT;
    }
    return voice_agent_controller_on_agent_error(&runtime->controller,
                                                  request_id);
}

agent_bridge_result_t device_voice_runtime_interrupt(
    device_voice_runtime_t *runtime,
    agent_bridge_interrupt_reason_t reason)
{
    if (!runtime) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    return voice_agent_controller_interrupt(&runtime->controller, reason);
}

agent_bridge_result_t device_voice_runtime_on_disconnected(
    device_voice_runtime_t *runtime)
{
    agent_bridge_result_t result;

    if (!runtime) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    result = voice_agent_controller_interrupt(
        &runtime->controller, AGENT_BRIDGE_INTERRUPT_NETWORK_LOST);
    runtime->protocol_ready = false;
    runtime->session_id[0] = '\0';
    return result;
}

bool device_voice_runtime_ready(const device_voice_runtime_t *runtime)
{
    return runtime && runtime->protocol_ready;
}

const char *device_voice_runtime_session_id(
    const device_voice_runtime_t *runtime)
{
    return runtime && runtime->protocol_ready ? runtime->session_id : "";
}
