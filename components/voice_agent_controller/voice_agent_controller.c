#include "voice_agent_controller.h"

#include <string.h>

#include "voice_agent_protocol.h"

static voice_agent_abort_reason_t map_abort_reason(
    agent_bridge_interrupt_reason_t reason)
{
    switch (reason) {
    case AGENT_BRIDGE_INTERRUPT_BUTTON:
        return VOICE_AGENT_ABORT_BUTTON;
    case AGENT_BRIDGE_INTERRUPT_NETWORK_LOST:
        return VOICE_AGENT_ABORT_NETWORK_LOST;
    case AGENT_BRIDGE_INTERRUPT_SESSION_CLOSED:
        return VOICE_AGENT_ABORT_SESSION_CLOSED;
    case AGENT_BRIDGE_INTERRUPT_USER_BARGE_IN:
    default:
        return VOICE_AGENT_ABORT_BARGE_IN;
    }
}

static int submit_agent(void *ctx,
                        uint32_t request_id,
                        const char *session_id,
                        const char *text)
{
    voice_agent_controller_t *controller = ctx;
    return controller->ops.submit_agent(controller->ops_ctx,
                                        request_id,
                                        session_id,
                                        text);
}

static int cancel_agent(void *ctx, uint32_t request_id)
{
    voice_agent_controller_t *controller = ctx;
    return controller->ops.cancel_agent(controller->ops_ctx, request_id);
}

static int request_tts(void *ctx,
                       uint32_t request_id,
                       const char *session_id,
                       const char *text)
{
    voice_agent_controller_t *controller = ctx;
    size_t required_size = 0;
    voice_agent_protocol_result_t result = voice_agent_build_tts_request(
        controller->tx_buffer,
        controller->tx_buffer_size,
        session_id,
        request_id,
        text,
        &required_size);

    if (result != VOICE_AGENT_PROTOCOL_OK) {
        return -1;
    }
    return controller->ops.send_json(controller->ops_ctx,
                                     controller->tx_buffer,
                                     required_size - 1);
}

static int cancel_tts(void *ctx, uint32_t request_id)
{
    voice_agent_controller_t *controller = ctx;
    const char *session_id = agent_bridge_active_session_id(&controller->bridge);
    size_t required_size = 0;
    voice_agent_protocol_result_t result = voice_agent_build_tts_abort(
        controller->tx_buffer,
        controller->tx_buffer_size,
        session_id,
        request_id,
        map_abort_reason(controller->pending_interrupt_reason),
        &required_size);

    if (result != VOICE_AGENT_PROTOCOL_OK) {
        return -1;
    }
    return controller->ops.send_json(controller->ops_ctx,
                                     controller->tx_buffer,
                                     required_size - 1);
}

static void state_changed(void *ctx,
                          agent_bridge_state_t from,
                          agent_bridge_state_t to,
                          uint32_t request_id)
{
    voice_agent_controller_t *controller = ctx;
    if (controller->ops.state_changed) {
        controller->ops.state_changed(controller->ops_ctx,
                                      from,
                                      to,
                                      request_id);
    }
}

static void playback_event(voice_agent_controller_t *controller,
                           voice_agent_playback_event_t event,
                           uint32_t request_id)
{
    if (controller->ops.playback_event) {
        controller->ops.playback_event(controller->ops_ctx, event, request_id);
    }
}

agent_bridge_result_t voice_agent_controller_init(
    voice_agent_controller_t *controller,
    const voice_agent_controller_config_t *config)
{
    agent_bridge_ops_t bridge_ops = {
        .submit_agent = submit_agent,
        .cancel_agent = cancel_agent,
        .request_tts = request_tts,
        .cancel_tts = cancel_tts,
        .state_changed = state_changed,
    };

    if (!controller || !config || !config->ops.submit_agent ||
        !config->ops.cancel_agent || !config->ops.send_json ||
        !config->tx_buffer || config->tx_buffer_size == 0) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }

    memset(controller, 0, sizeof(*controller));
    controller->ops = config->ops;
    controller->ops_ctx = config->ops_ctx;
    controller->tx_buffer = config->tx_buffer;
    controller->tx_buffer_size = config->tx_buffer_size;
    controller->pending_interrupt_reason =
        AGENT_BRIDGE_INTERRUPT_USER_BARGE_IN;
    return agent_bridge_init(&controller->bridge, &bridge_ops, controller);
}

agent_bridge_result_t voice_agent_controller_on_stt_final(
    voice_agent_controller_t *controller,
    const char *session_id,
    const char *text,
    uint32_t *out_request_id)
{
    agent_bridge_result_t result;
    agent_bridge_state_t previous_state;
    uint32_t interrupted_request_id;
    size_t session_length;

    if (!controller || !session_id || !session_id[0] || !text || !text[0]) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    session_length = strlen(session_id);
    if (session_length >= AGENT_BRIDGE_SESSION_ID_MAX) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    previous_state = voice_agent_controller_state(controller);
    interrupted_request_id = voice_agent_controller_active_request_id(controller);
    if (previous_state == AGENT_BRIDGE_STATE_TTS_PENDING ||
        previous_state == AGENT_BRIDGE_STATE_TTS_PLAYING) {
        /* Local audio must stop before the bridge sends abort and submits the
         * replacement turn.  This also protects against transport failure. */
        playback_event(controller, VOICE_AGENT_PLAYBACK_FLUSH,
                       interrupted_request_id);
    }
    controller->pending_interrupt_reason =
        AGENT_BRIDGE_INTERRUPT_USER_BARGE_IN;
    result = agent_bridge_on_stt_final(&controller->bridge,
                                       session_id,
                                       text,
                                       out_request_id);
    controller->pending_interrupt_reason =
        AGENT_BRIDGE_INTERRUPT_USER_BARGE_IN;
    return result;
}

agent_bridge_result_t voice_agent_controller_on_agent_final(
    voice_agent_controller_t *controller,
    uint32_t request_id,
    const char *text)
{
    if (!controller) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    return agent_bridge_on_agent_final(&controller->bridge, request_id, text);
}

agent_bridge_result_t voice_agent_controller_on_agent_error(
    voice_agent_controller_t *controller,
    uint32_t request_id)
{
    if (!controller) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    return agent_bridge_on_agent_error(&controller->bridge, request_id);
}

agent_bridge_result_t voice_agent_controller_on_tts_event(
    voice_agent_controller_t *controller,
    const char *session_id,
    uint32_t request_id,
    voice_agent_tts_event_t event)
{
    const char *active_session;
    agent_bridge_result_t result;
    agent_bridge_state_t previous_state;

    if (!controller || !session_id || !session_id[0] || request_id == 0) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    active_session = agent_bridge_active_session_id(&controller->bridge);
    if (!active_session[0] || strcmp(active_session, session_id) != 0 ||
        request_id != agent_bridge_active_request_id(&controller->bridge)) {
        return AGENT_BRIDGE_ERR_STALE_EVENT;
    }

    previous_state = voice_agent_controller_state(controller);
    switch (event) {
    case VOICE_AGENT_TTS_STARTED:
        result = agent_bridge_on_tts_started(&controller->bridge, request_id);
        if (result == AGENT_BRIDGE_OK &&
            previous_state == AGENT_BRIDGE_STATE_TTS_PENDING) {
            playback_event(controller, VOICE_AGENT_PLAYBACK_BEGIN, request_id);
        }
        return result;
    case VOICE_AGENT_TTS_STOPPED:
        result = agent_bridge_on_tts_stopped(&controller->bridge, request_id);
        if (result == AGENT_BRIDGE_OK) {
            playback_event(controller, VOICE_AGENT_PLAYBACK_DRAIN, request_id);
        }
        return result;
    case VOICE_AGENT_TTS_ERROR:
        result = agent_bridge_on_tts_error(&controller->bridge, request_id);
        if (result == AGENT_BRIDGE_OK) {
            playback_event(controller, VOICE_AGENT_PLAYBACK_FLUSH, request_id);
        }
        return result;
    default:
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
}

agent_bridge_result_t voice_agent_controller_interrupt(
    voice_agent_controller_t *controller,
    agent_bridge_interrupt_reason_t reason)
{
    agent_bridge_result_t result;
    agent_bridge_state_t previous_state;
    uint32_t interrupted_request_id;

    if (!controller || reason < AGENT_BRIDGE_INTERRUPT_USER_BARGE_IN ||
        reason > AGENT_BRIDGE_INTERRUPT_SESSION_CLOSED) {
        return AGENT_BRIDGE_ERR_INVALID_ARG;
    }
    previous_state = voice_agent_controller_state(controller);
    interrupted_request_id = voice_agent_controller_active_request_id(controller);
    controller->pending_interrupt_reason = reason;
    result = agent_bridge_interrupt(&controller->bridge, reason);
    if (previous_state == AGENT_BRIDGE_STATE_TTS_PENDING ||
        previous_state == AGENT_BRIDGE_STATE_TTS_PLAYING) {
        playback_event(controller, VOICE_AGENT_PLAYBACK_FLUSH,
                       interrupted_request_id);
    }
    controller->pending_interrupt_reason =
        AGENT_BRIDGE_INTERRUPT_USER_BARGE_IN;
    return result;
}

agent_bridge_state_t voice_agent_controller_state(
    const voice_agent_controller_t *controller)
{
    return controller ? agent_bridge_state(&controller->bridge)
                      : AGENT_BRIDGE_STATE_IDLE;
}

uint32_t voice_agent_controller_active_request_id(
    const voice_agent_controller_t *controller)
{
    return controller ? agent_bridge_active_request_id(&controller->bridge) : 0;
}
