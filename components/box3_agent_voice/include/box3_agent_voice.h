#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "box3_voice_audio.h"
#include "device_voice_client.h"
#include "esp_claw_runtime.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct box3_agent_voice *box3_agent_voice_handle_t;

typedef struct {
    device_websocket_transport_config_t websocket;
    esp_claw_runtime_config_t agent;
    int output_volume_percent;
    /* Zero selects the product default of 5 seconds. */
    uint32_t hello_timeout_ms;

    void (*state_changed)(void *ctx,
                          agent_bridge_state_t from,
                          agent_bridge_state_t to,
                          uint32_t request_id);
    void (*client_event)(void *ctx,
                         const device_voice_client_event_t *event);
    void (*audio_event)(void *ctx,
                        box3_voice_audio_event_t event,
                        uint32_t request_id);
    void *event_ctx;
} box3_agent_voice_config_t;

typedef struct {
    bool started;
    bool ready;
    device_voice_client_stats_t client;
    box3_voice_audio_stats_t audio;
} box3_agent_voice_stats_t;

/*
 * Builds the complete BOX-3 audio + ESP-Claw + XiaoZhi voice client graph but
 * does not open the WebSocket. The caller must leave websocket.event and
 * agent.response_cb unset because this aggregate owns both callbacks.
 *
 * All Agent configuration strings and an optional server certificate are
 * copied. Callback contexts in agent.device_ops, agent.capability_consent,
 * agent.capability_audit, agent.memory_consent, and event_ctx plus the
 * agent.memory handle remain owned by the caller and must
 * outlive this handle. On ordinary failure out_product is
 * NULL. If fail-safe cleanup itself times out, a retained partial handle is
 * returned and must be passed to stop().
 */
esp_err_t box3_agent_voice_create(
    const box3_agent_voice_config_t *config,
    box3_agent_voice_handle_t *out_product);

/* Wi-Fi and short-lived device credentials must already be available. */
esp_err_t box3_agent_voice_start(box3_agent_voice_handle_t product);

esp_err_t box3_agent_voice_interrupt(
    box3_agent_voice_handle_t product,
    agent_bridge_interrupt_reason_t reason);

bool box3_agent_voice_ready(box3_agent_voice_handle_t product);

esp_err_t box3_agent_voice_get_stats(
    box3_agent_voice_handle_t product,
    box3_agent_voice_stats_t *stats);

/*
 * ESP_OK consumes the handle. Any failure retains the complete remaining
 * callback graph so the caller can retry. A NULL handle is accepted.
 */
esp_err_t box3_agent_voice_stop(box3_agent_voice_handle_t product,
                                uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif
