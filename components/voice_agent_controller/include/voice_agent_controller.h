#pragma once

#include <stddef.h>
#include <stdint.h>

#include "agent_bridge.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    VOICE_AGENT_TTS_STARTED = 0,
    VOICE_AGENT_TTS_STOPPED,
    VOICE_AGENT_TTS_ERROR,
} voice_agent_tts_event_t;

typedef enum {
    /* Accept downlink audio for this request and start output. */
    VOICE_AGENT_PLAYBACK_BEGIN = 0,
    /* Stop accepting packets, then play already accepted packets to empty. */
    VOICE_AGENT_PLAYBACK_DRAIN,
    /* Immediately reject/flush queued audio for this request. */
    VOICE_AGENT_PLAYBACK_FLUSH,
} voice_agent_playback_event_t;

typedef struct {
    int (*submit_agent)(void *ctx,
                        uint32_t request_id,
                        const char *session_id,
                        const char *text);
    int (*cancel_agent)(void *ctx, uint32_t request_id);
    int (*send_json)(void *ctx, const char *json, size_t json_length);
    void (*state_changed)(void *ctx,
                          agent_bridge_state_t from,
                          agent_bridge_state_t to,
                          uint32_t request_id);
    void (*playback_event)(void *ctx,
                           voice_agent_playback_event_t event,
                           uint32_t request_id);
} voice_agent_controller_ops_t;

/*
 * Allocation-free controller owned by one serialized product event loop.
 * tx_buffer is caller-owned. send_json must consume or copy its contents
 * before returning. Agent/network callbacks from other tasks must be posted
 * onto the owner event loop before invoking this API.
 */
typedef struct {
    agent_bridge_t bridge;
    voice_agent_controller_ops_t ops;
    void *ops_ctx;
    char *tx_buffer;
    size_t tx_buffer_size;
    agent_bridge_interrupt_reason_t pending_interrupt_reason;
} voice_agent_controller_t;

typedef struct {
    voice_agent_controller_ops_t ops;
    void *ops_ctx;
    char *tx_buffer;
    size_t tx_buffer_size;
} voice_agent_controller_config_t;

agent_bridge_result_t voice_agent_controller_init(
    voice_agent_controller_t *controller,
    const voice_agent_controller_config_t *config);

agent_bridge_result_t voice_agent_controller_on_stt_final(
    voice_agent_controller_t *controller,
    const char *session_id,
    const char *text,
    uint32_t *out_request_id);

agent_bridge_result_t voice_agent_controller_on_agent_final(
    voice_agent_controller_t *controller,
    uint32_t request_id,
    const char *text);

agent_bridge_result_t voice_agent_controller_on_agent_error(
    voice_agent_controller_t *controller,
    uint32_t request_id);

agent_bridge_result_t voice_agent_controller_on_tts_event(
    voice_agent_controller_t *controller,
    const char *session_id,
    uint32_t request_id,
    voice_agent_tts_event_t event);

agent_bridge_result_t voice_agent_controller_interrupt(
    voice_agent_controller_t *controller,
    agent_bridge_interrupt_reason_t reason);

agent_bridge_state_t voice_agent_controller_state(
    const voice_agent_controller_t *controller);

uint32_t voice_agent_controller_active_request_id(
    const voice_agent_controller_t *controller);

#ifdef __cplusplus
}
#endif
