#include "agent_bridge.h"

#include <stddef.h>
#include <string.h>

static void transition(agent_bridge_t *bridge, agent_bridge_state_t next)
{
    agent_bridge_state_t previous = bridge->state;

    if (previous == next) {
        return;
    }
    bridge->state = next;
    if (bridge->ops.state_changed) {
        bridge->ops.state_changed(bridge->ops_ctx,
                                  previous,
                                  next,
                                  bridge->active_request_id);
    }
}

static void clear_active_request(agent_bridge_t *bridge)
{
    transition(bridge, AGENT_BRIDGE_STATE_IDLE);
    bridge->active_request_id = 0;
    bridge->session_id[0] = '\0';
}

static uint32_t allocate_request_id(agent_bridge_t *bridge)
{
    uint32_t request_id = bridge->next_request_id;

    if (request_id == 0) {
        request_id = 1;
    }
    bridge->next_request_id = request_id + 1;
    if (bridge->next_request_id == 0) {
        bridge->next_request_id = 1;
    }
    return request_id;
}

static int valid_active_request(const agent_bridge_t *bridge,
                                uint32_t request_id)
{
    return bridge && request_id != 0 &&
           bridge->active_request_id == request_id;
}

agent_bridge_result_t agent_bridge_init(agent_bridge_t *bridge,
                                        const agent_bridge_ops_t *ops,
                                        void *ops_ctx)
{
    if (!bridge || !ops || !ops->submit_agent || !ops->cancel_agent ||
        !ops->request_tts || !ops->cancel_tts) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }

    memset(bridge, 0, sizeof(*bridge));
    bridge->ops = *ops;
    bridge->ops_ctx = ops_ctx;
    bridge->state = AGENT_BRIDGE_STATE_IDLE;
    bridge->next_request_id = 1;
    return AGENT_BRIDGE_OK;
}

agent_bridge_result_t agent_bridge_on_stt_final(agent_bridge_t *bridge,
                                                const char *session_id,
                                                const char *text,
                                                uint32_t *out_request_id)
{
    size_t session_len;
    uint32_t request_id;

    if (!bridge || !session_id || !session_id[0] || !text || !text[0]) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    session_len = strlen(session_id);
    if (session_len >= sizeof(bridge->session_id)) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }

    if (bridge->state != AGENT_BRIDGE_STATE_IDLE) {
        (void)agent_bridge_interrupt(
            bridge, AGENT_BRIDGE_INTERRUPT_USER_BARGE_IN);
    }

    request_id = allocate_request_id(bridge);
    memcpy(bridge->session_id, session_id, session_len + 1);
    bridge->active_request_id = request_id;
    transition(bridge, AGENT_BRIDGE_STATE_AGENT_RUNNING);

    if (bridge->ops.submit_agent(bridge->ops_ctx,
                                 request_id,
                                 bridge->session_id,
                                 text) != 0) {
        clear_active_request(bridge);
        return AGENT_BRIDGE_ERR_OPERATION;
    }

    if (out_request_id) {
        *out_request_id = request_id;
    }
    return AGENT_BRIDGE_OK;
}

agent_bridge_result_t agent_bridge_on_agent_final(agent_bridge_t *bridge,
                                                  uint32_t request_id,
                                                  const char *text)
{
    if (!bridge || !text || !text[0]) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    if (!valid_active_request(bridge, request_id)) {
        return AGENT_BRIDGE_ERR_STALE_EVENT;
    }
    if (bridge->state != AGENT_BRIDGE_STATE_AGENT_RUNNING) {
        return AGENT_BRIDGE_ERR_INVALID_STATE;
    }

    transition(bridge, AGENT_BRIDGE_STATE_TTS_PENDING);
    if (bridge->ops.request_tts(bridge->ops_ctx,
                                request_id,
                                bridge->session_id,
                                text) != 0) {
        clear_active_request(bridge);
        return AGENT_BRIDGE_ERR_OPERATION;
    }
    return AGENT_BRIDGE_OK;
}

agent_bridge_result_t agent_bridge_on_agent_error(agent_bridge_t *bridge,
                                                  uint32_t request_id)
{
    if (!bridge || request_id == 0) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    if (!valid_active_request(bridge, request_id)) {
        return AGENT_BRIDGE_ERR_STALE_EVENT;
    }
    if (bridge->state != AGENT_BRIDGE_STATE_AGENT_RUNNING) {
        return AGENT_BRIDGE_ERR_INVALID_STATE;
    }
    clear_active_request(bridge);
    return AGENT_BRIDGE_OK;
}

agent_bridge_result_t agent_bridge_on_tts_started(agent_bridge_t *bridge,
                                                  uint32_t request_id)
{
    if (!bridge || request_id == 0) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    if (!valid_active_request(bridge, request_id)) {
        return AGENT_BRIDGE_ERR_STALE_EVENT;
    }
    if (bridge->state == AGENT_BRIDGE_STATE_TTS_PLAYING) {
        return AGENT_BRIDGE_OK;
    }
    if (bridge->state != AGENT_BRIDGE_STATE_TTS_PENDING) {
        return AGENT_BRIDGE_ERR_INVALID_STATE;
    }
    transition(bridge, AGENT_BRIDGE_STATE_TTS_PLAYING);
    return AGENT_BRIDGE_OK;
}

agent_bridge_result_t agent_bridge_on_tts_stopped(agent_bridge_t *bridge,
                                                  uint32_t request_id)
{
    if (!bridge || request_id == 0) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    if (!valid_active_request(bridge, request_id)) {
        return AGENT_BRIDGE_ERR_STALE_EVENT;
    }
    if (bridge->state != AGENT_BRIDGE_STATE_TTS_PENDING &&
        bridge->state != AGENT_BRIDGE_STATE_TTS_PLAYING) {
        return AGENT_BRIDGE_ERR_INVALID_STATE;
    }
    clear_active_request(bridge);
    return AGENT_BRIDGE_OK;
}

agent_bridge_result_t agent_bridge_on_tts_error(agent_bridge_t *bridge,
                                                uint32_t request_id)
{
    if (!bridge || request_id == 0) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    if (!valid_active_request(bridge, request_id)) {
        return AGENT_BRIDGE_ERR_STALE_EVENT;
    }
    if (bridge->state != AGENT_BRIDGE_STATE_TTS_PENDING &&
        bridge->state != AGENT_BRIDGE_STATE_TTS_PLAYING) {
        return AGENT_BRIDGE_ERR_INVALID_STATE;
    }
    clear_active_request(bridge);
    return AGENT_BRIDGE_OK;
}

agent_bridge_result_t agent_bridge_interrupt(agent_bridge_t *bridge,
                                             agent_bridge_interrupt_reason_t reason)
{
    int operation_result = 0;

    (void)reason;
    if (!bridge) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    if (bridge->state == AGENT_BRIDGE_STATE_IDLE) {
        return AGENT_BRIDGE_OK;
    }

    if (bridge->state == AGENT_BRIDGE_STATE_AGENT_RUNNING) {
        operation_result = bridge->ops.cancel_agent(
            bridge->ops_ctx, bridge->active_request_id);
    } else {
        operation_result = bridge->ops.cancel_tts(
            bridge->ops_ctx, bridge->active_request_id);
    }
    clear_active_request(bridge);
    return operation_result == 0 ? AGENT_BRIDGE_OK
                                 : AGENT_BRIDGE_ERR_OPERATION;
}

agent_bridge_state_t agent_bridge_state(const agent_bridge_t *bridge)
{
    return bridge ? bridge->state : AGENT_BRIDGE_STATE_IDLE;
}

uint32_t agent_bridge_active_request_id(const agent_bridge_t *bridge)
{
    return bridge ? bridge->active_request_id : 0;
}

const char *agent_bridge_active_session_id(const agent_bridge_t *bridge)
{
    return bridge && bridge->active_request_id != 0 ? bridge->session_id : "";
}
