#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    VOICE_AUDIO_SESSION_IDLE = 0,
    VOICE_AUDIO_SESSION_ACCEPTING,
    VOICE_AUDIO_SESSION_DRAINING,
} voice_audio_session_state_t;

typedef enum {
    VOICE_AUDIO_SESSION_OK = 0,
    VOICE_AUDIO_SESSION_ERR_INVALID_ARG = -1,
    VOICE_AUDIO_SESSION_ERR_INVALID_STATE = -2,
    VOICE_AUDIO_SESSION_ERR_STALE = -3,
} voice_audio_session_result_t;

typedef struct {
    uint32_t request_id;
    uint32_t generation;
} voice_audio_token_t;

/*
 * Allocation-free playback admission gate.  The owner serializes calls.  A
 * token travels with every queued packet so an already-dequeued packet is
 * still rejected after barge-in or replacement.
 */
typedef struct {
    voice_audio_session_state_t state;
    uint32_t active_request_id;
    uint32_t generation;
    bool inflight;
    voice_audio_token_t inflight_token;
} voice_audio_session_t;

voice_audio_session_result_t voice_audio_session_init(
    voice_audio_session_t *session);
voice_audio_session_result_t voice_audio_session_begin(
    voice_audio_session_t *session,
    uint32_t request_id);
voice_audio_session_result_t voice_audio_session_admit(
    const voice_audio_session_t *session,
    voice_audio_token_t *token);
bool voice_audio_session_is_current(const voice_audio_session_t *session,
                                    voice_audio_token_t token);
voice_audio_session_result_t voice_audio_session_set_inflight(
    voice_audio_session_t *session,
    voice_audio_token_t token,
    bool inflight);
voice_audio_session_result_t voice_audio_session_drain(
    voice_audio_session_t *session,
    uint32_t request_id);
voice_audio_session_result_t voice_audio_session_flush(
    voice_audio_session_t *session,
    uint32_t request_id);

/* Clears a draining request only when no queued or in-flight packet remains. */
voice_audio_session_result_t voice_audio_session_finish_drain(
    voice_audio_session_t *session,
    bool queue_empty,
    uint32_t *finished_request_id);

#ifdef __cplusplus
}
#endif
