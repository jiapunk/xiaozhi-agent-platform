#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AGENT_BRIDGE_SESSION_ID_MAX 64

typedef enum {
    AGENT_BRIDGE_OK = 0,
    AGENT_BRIDGE_ERR_INVALID_ARG = -1,
    AGENT_BRIDGE_ERR_INVALID_STATE = -2,
    AGENT_BRIDGE_ERR_STALE_EVENT = -3,
    AGENT_BRIDGE_ERR_OPERATION = -4,
} agent_bridge_result_t;

typedef enum {
    AGENT_BRIDGE_STATE_IDLE = 0,
    AGENT_BRIDGE_STATE_AGENT_RUNNING,
    AGENT_BRIDGE_STATE_TTS_PENDING,
    AGENT_BRIDGE_STATE_TTS_PLAYING,
} agent_bridge_state_t;

typedef enum {
    AGENT_BRIDGE_INTERRUPT_USER_BARGE_IN = 0,
    AGENT_BRIDGE_INTERRUPT_BUTTON,
    AGENT_BRIDGE_INTERRUPT_NETWORK_LOST,
    AGENT_BRIDGE_INTERRUPT_SESSION_CLOSED,
} agent_bridge_interrupt_reason_t;

typedef struct {
    int (*submit_agent)(void *ctx,
                        uint32_t request_id,
                        const char *session_id,
                        const char *text);
    int (*cancel_agent)(void *ctx, uint32_t request_id);
    int (*request_tts)(void *ctx,
                       uint32_t request_id,
                       const char *session_id,
                       const char *text);
    int (*cancel_tts)(void *ctx, uint32_t request_id);
    void (*state_changed)(void *ctx,
                          agent_bridge_state_t from,
                          agent_bridge_state_t to,
                          uint32_t request_id);
} agent_bridge_ops_t;

/*
 * The bridge is allocation-free and intended to be owned by the product's
 * serialized event loop. Callers must marshal callbacks from audio, network,
 * and Agent tasks onto that event loop before invoking these functions.
 */
typedef struct {
    agent_bridge_ops_t ops;
    void *ops_ctx;
    agent_bridge_state_t state;
    uint32_t active_request_id;
    uint32_t next_request_id;
    char session_id[AGENT_BRIDGE_SESSION_ID_MAX];
} agent_bridge_t;

agent_bridge_result_t agent_bridge_init(agent_bridge_t *bridge,
                                        const agent_bridge_ops_t *ops,
                                        void *ops_ctx);

agent_bridge_result_t agent_bridge_on_stt_final(agent_bridge_t *bridge,
                                                const char *session_id,
                                                const char *text,
                                                uint32_t *out_request_id);

agent_bridge_result_t agent_bridge_on_agent_final(agent_bridge_t *bridge,
                                                  uint32_t request_id,
                                                  const char *text);

agent_bridge_result_t agent_bridge_on_agent_error(agent_bridge_t *bridge,
                                                  uint32_t request_id);

agent_bridge_result_t agent_bridge_on_tts_started(agent_bridge_t *bridge,
                                                  uint32_t request_id);

agent_bridge_result_t agent_bridge_on_tts_stopped(agent_bridge_t *bridge,
                                                  uint32_t request_id);

agent_bridge_result_t agent_bridge_on_tts_error(agent_bridge_t *bridge,
                                                uint32_t request_id);

agent_bridge_result_t agent_bridge_interrupt(agent_bridge_t *bridge,
                                             agent_bridge_interrupt_reason_t reason);

agent_bridge_state_t agent_bridge_state(const agent_bridge_t *bridge);
uint32_t agent_bridge_active_request_id(const agent_bridge_t *bridge);
const char *agent_bridge_active_session_id(const agent_bridge_t *bridge);

#ifdef __cplusplus
}
#endif
