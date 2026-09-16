#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "cJSON.h"
#include "voice_agent_controller.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    XIAOZHI_AGENT_SERVICE_ERROR_NONE = 0,
    XIAOZHI_AGENT_SERVICE_ERROR_SPEECH_BUDGET_EXCEEDED,
    XIAOZHI_AGENT_SERVICE_ERROR_SPEECH_BUDGET_UNAVAILABLE,
} xiaozhi_agent_service_error_t;

typedef struct {
    bool handled;
    uint32_t accepted_request_id;
    xiaozhi_agent_service_error_t service_error;
} xiaozhi_agent_message_outcome_t;

#define XIAOZHI_DEVICE_AGENT_PROTOCOL_VERSION 1

/* Adds features.device_agent to a XiaoZhi client hello object. */
agent_bridge_result_t xiaozhi_agent_adapter_add_client_hello_feature(
    cJSON *hello_root);

/* Fails closed unless the server hello acknowledges the same feature. */
agent_bridge_result_t xiaozhi_agent_adapter_validate_server_hello(
    const cJSON *hello_root);

/*
 * Adapter for XiaoZhi Protocol::OnIncomingJson. protocol_session_id must be
 * Protocol::session_id(). Agent mode requires request_id on TTS start, stop,
 * and error events; legacy TTS lifecycle messages without it are rejected.
 * The two content-free speech budget error codes are handled and reported in
 * outcome.service_error. Unknown messages and TTS sentence_start remain
 * available to the UI handler.
 */
agent_bridge_result_t xiaozhi_agent_adapter_handle_json(
    voice_agent_controller_t *controller,
    const cJSON *root,
    const char *protocol_session_id,
    xiaozhi_agent_message_outcome_t *outcome);

#ifdef __cplusplus
}
#endif
