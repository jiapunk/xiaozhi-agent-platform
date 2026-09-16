#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cJSON.h"
#include "voice_agent_controller.h"
#include "xiaozhi_agent_adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int (*submit_agent)(void *ctx,
                        uint32_t request_id,
                        const char *session_id,
                        const char *text);
    int (*cancel_agent)(void *ctx, uint32_t request_id);
    int (*send_json)(void *ctx, const char *json, size_t json_length);
    int (*receive_binary)(void *ctx,
                          const uint8_t *packet,
                          size_t packet_size);
    void (*playback_event)(void *ctx,
                           voice_agent_playback_event_t event,
                           uint32_t request_id);
    void (*state_changed)(void *ctx,
                          agent_bridge_state_t from,
                          agent_bridge_state_t to,
                          uint32_t request_id);
} device_voice_runtime_ops_t;

typedef struct {
    device_voice_runtime_ops_t ops;
    void *ops_ctx;
    char *tx_buffer;
    size_t tx_buffer_size;
    int downlink_sample_rate;
    int frame_duration_ms;
} device_voice_runtime_config_t;

/* Product event-loop owned; all calls except operation callbacks are serialized. */
typedef struct {
    voice_agent_controller_t controller;
    device_voice_runtime_ops_t ops;
    void *ops_ctx;
    int downlink_sample_rate;
    int frame_duration_ms;
    bool protocol_ready;
    char session_id[AGENT_BRIDGE_SESSION_ID_MAX];
} device_voice_runtime_t;

agent_bridge_result_t device_voice_runtime_init(
    device_voice_runtime_t *runtime,
    const device_voice_runtime_config_t *config);

agent_bridge_result_t device_voice_runtime_add_client_hello(
    device_voice_runtime_t *runtime,
    cJSON *hello_root);

/* Validates Agent acknowledgement plus the fixed Opus downlink profile. */
agent_bridge_result_t device_voice_runtime_accept_server_hello(
    device_voice_runtime_t *runtime,
    const cJSON *hello_root);

agent_bridge_result_t device_voice_runtime_on_json(
    device_voice_runtime_t *runtime,
    const cJSON *root,
    xiaozhi_agent_message_outcome_t *outcome);

agent_bridge_result_t device_voice_runtime_on_binary(
    device_voice_runtime_t *runtime,
    const uint8_t *packet,
    size_t packet_size);

agent_bridge_result_t device_voice_runtime_on_agent_final(
    device_voice_runtime_t *runtime,
    uint32_t request_id,
    const char *text);
agent_bridge_result_t device_voice_runtime_on_agent_error(
    device_voice_runtime_t *runtime,
    uint32_t request_id);
agent_bridge_result_t device_voice_runtime_interrupt(
    device_voice_runtime_t *runtime,
    agent_bridge_interrupt_reason_t reason);

/* Always invalidates the negotiated session, even when abort transport fails. */
agent_bridge_result_t device_voice_runtime_on_disconnected(
    device_voice_runtime_t *runtime);

bool device_voice_runtime_ready(const device_voice_runtime_t *runtime);
const char *device_voice_runtime_session_id(
    const device_voice_runtime_t *runtime);

#ifdef __cplusplus
}
#endif
