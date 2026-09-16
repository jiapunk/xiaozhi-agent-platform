#include "voice_audio_session.h"

#include <string.h>

static void advance_generation(voice_audio_session_t *session)
{
    session->generation++;
    if (session->generation == 0) {
        session->generation = 1;
    }
}

static void clear_active(voice_audio_session_t *session)
{
    session->state = VOICE_AUDIO_SESSION_IDLE;
    session->active_request_id = 0;
    advance_generation(session);
}

static bool same_token(voice_audio_token_t left, voice_audio_token_t right)
{
    return left.request_id == right.request_id &&
           left.generation == right.generation;
}

voice_audio_session_result_t voice_audio_session_init(
    voice_audio_session_t *session)
{
    if (!session) {
        return VOICE_AUDIO_SESSION_ERR_INVALID_ARG;
    }
    memset(session, 0, sizeof(*session));
    session->generation = 1;
    return VOICE_AUDIO_SESSION_OK;
}

voice_audio_session_result_t voice_audio_session_begin(
    voice_audio_session_t *session,
    uint32_t request_id)
{
    if (!session || request_id == 0) {
        return VOICE_AUDIO_SESSION_ERR_INVALID_ARG;
    }
    advance_generation(session);
    session->active_request_id = request_id;
    session->state = VOICE_AUDIO_SESSION_ACCEPTING;
    return VOICE_AUDIO_SESSION_OK;
}

voice_audio_session_result_t voice_audio_session_admit(
    const voice_audio_session_t *session,
    voice_audio_token_t *token)
{
    if (!session || !token) {
        return VOICE_AUDIO_SESSION_ERR_INVALID_ARG;
    }
    token->request_id = 0;
    token->generation = 0;
    if (session->state != VOICE_AUDIO_SESSION_ACCEPTING ||
        session->active_request_id == 0) {
        return VOICE_AUDIO_SESSION_ERR_INVALID_STATE;
    }
    token->request_id = session->active_request_id;
    token->generation = session->generation;
    return VOICE_AUDIO_SESSION_OK;
}

bool voice_audio_session_is_current(const voice_audio_session_t *session,
                                    voice_audio_token_t token)
{
    return session && token.request_id != 0 && token.generation != 0 &&
           session->state != VOICE_AUDIO_SESSION_IDLE &&
           session->active_request_id == token.request_id &&
           session->generation == token.generation;
}

voice_audio_session_result_t voice_audio_session_set_inflight(
    voice_audio_session_t *session,
    voice_audio_token_t token,
    bool inflight)
{
    if (!session || token.request_id == 0 || token.generation == 0) {
        return VOICE_AUDIO_SESSION_ERR_INVALID_ARG;
    }
    if (inflight) {
        if (session->inflight) {
            return VOICE_AUDIO_SESSION_ERR_INVALID_STATE;
        }
        if (!voice_audio_session_is_current(session, token)) {
            return VOICE_AUDIO_SESSION_ERR_STALE;
        }
        session->inflight = true;
        session->inflight_token = token;
        return VOICE_AUDIO_SESSION_OK;
    }
    if (!session->inflight ||
        !same_token(session->inflight_token, token)) {
        return VOICE_AUDIO_SESSION_ERR_STALE;
    }
    session->inflight = false;
    memset(&session->inflight_token, 0, sizeof(session->inflight_token));
    return VOICE_AUDIO_SESSION_OK;
}

voice_audio_session_result_t voice_audio_session_drain(
    voice_audio_session_t *session,
    uint32_t request_id)
{
    if (!session || request_id == 0) {
        return VOICE_AUDIO_SESSION_ERR_INVALID_ARG;
    }
    if (session->active_request_id != request_id ||
        session->state == VOICE_AUDIO_SESSION_IDLE) {
        return VOICE_AUDIO_SESSION_ERR_STALE;
    }
    session->state = VOICE_AUDIO_SESSION_DRAINING;
    return VOICE_AUDIO_SESSION_OK;
}

voice_audio_session_result_t voice_audio_session_flush(
    voice_audio_session_t *session,
    uint32_t request_id)
{
    if (!session || request_id == 0) {
        return VOICE_AUDIO_SESSION_ERR_INVALID_ARG;
    }
    if (session->active_request_id != 0 &&
        session->active_request_id != request_id) {
        return VOICE_AUDIO_SESSION_ERR_STALE;
    }
    clear_active(session);
    return VOICE_AUDIO_SESSION_OK;
}

voice_audio_session_result_t voice_audio_session_finish_drain(
    voice_audio_session_t *session,
    bool queue_empty,
    uint32_t *finished_request_id)
{
    if (!session || !finished_request_id) {
        return VOICE_AUDIO_SESSION_ERR_INVALID_ARG;
    }
    *finished_request_id = 0;
    if (session->state != VOICE_AUDIO_SESSION_DRAINING) {
        return VOICE_AUDIO_SESSION_ERR_INVALID_STATE;
    }
    if (!queue_empty || session->inflight) {
        return VOICE_AUDIO_SESSION_ERR_INVALID_STATE;
    }
    *finished_request_id = session->active_request_id;
    clear_active(session);
    return VOICE_AUDIO_SESSION_OK;
}
