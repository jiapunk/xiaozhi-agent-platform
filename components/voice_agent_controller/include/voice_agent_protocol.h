#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    VOICE_AGENT_PROTOCOL_OK = 0,
    VOICE_AGENT_PROTOCOL_ERR_INVALID_ARG = -1,
    VOICE_AGENT_PROTOCOL_ERR_BUFFER_TOO_SMALL = -2,
} voice_agent_protocol_result_t;

typedef enum {
    VOICE_AGENT_ABORT_BARGE_IN = 0,
    VOICE_AGENT_ABORT_BUTTON,
    VOICE_AGENT_ABORT_NETWORK_LOST,
    VOICE_AGENT_ABORT_SESSION_CLOSED,
} voice_agent_abort_reason_t;

/*
 * The returned required size includes the trailing NUL. On success the JSON
 * payload length passed to a transport is required_size - 1. On a buffer
 * error, output is reset to an empty string and required_size still reports
 * the exact allocation needed.
 */
voice_agent_protocol_result_t voice_agent_build_tts_request(
    char *output,
    size_t output_size,
    const char *session_id,
    uint32_t request_id,
    const char *text,
    size_t *required_size);

voice_agent_protocol_result_t voice_agent_build_tts_abort(
    char *output,
    size_t output_size,
    const char *session_id,
    uint32_t request_id,
    voice_agent_abort_reason_t reason,
    size_t *required_size);

#ifdef __cplusplus
}
#endif
