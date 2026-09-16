#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    AGENT_CONTROL_PLANE_RESPONSE_MAX = 4096,
    AGENT_CONTROL_PLANE_CANONICAL_MAX = 512,
    AGENT_CONTROL_PLANE_NONCE_BYTES = 16,
    AGENT_CONTROL_PLANE_SIGNATURE_BYTES = 32,
    AGENT_CONTROL_PLANE_URI_MAX = 512,
    AGENT_CONTROL_PLANE_ACTION_BODY_MAX = 512,
};

typedef enum {
    AGENT_CONTROL_PLANE_ACTION_PROOF_CHALLENGE = 1,
    AGENT_CONTROL_PLANE_ACTION_PROOF_RESULT = 2,
} agent_control_plane_action_proof_scope_t;

typedef enum {
    AGENT_CONTROL_PLANE_ACTION_PROTOCOL_PENDING = 0,
    AGENT_CONTROL_PLANE_ACTION_PROTOCOL_APPROVE,
    AGENT_CONTROL_PLANE_ACTION_PROTOCOL_DENY,
} agent_control_plane_action_protocol_decision_t;

bool agent_control_plane_validate_endpoints(
    const char *time_endpoint,
    const char *agent_token_endpoint,
    const char *device_claim_endpoint,
    const char *action_challenge_endpoint,
    const char *action_result_endpoint);

bool agent_control_plane_safe_identifier(const char *value);

bool agent_control_plane_base64url(
    const uint8_t *input,
    size_t input_size,
    char *output,
    size_t output_size);

bool agent_control_plane_build_agent_canonical(
    const char *device_id,
    const char *client_id,
    const char *timestamp,
    const char *nonce,
    char *output,
    size_t output_size);

bool agent_control_plane_device_claim_is_canonical(const char *claim);

/* Terminal means a retry with the same physical-window claim cannot help. */
bool agent_control_plane_device_claim_http_is_terminal(int status_code);

bool agent_control_plane_build_device_claim_canonical(
    const char *device_id,
    const char *client_id,
    const char *timestamp,
    const char *nonce,
    const char *claim,
    char *output,
    size_t output_size);

bool agent_control_plane_action_challenge_id_is_canonical(
    const char *challenge_id);

bool agent_control_plane_build_action_challenge_body(
    const char *challenge_id,
    const char *session_id,
    uint32_t request_id,
    bool indicator_on,
    int64_t expires_at_unix,
    char *output,
    size_t output_size);

bool agent_control_plane_build_action_result_body(
    const char *challenge_id,
    uint64_t owner_revision,
    const char *session_id,
    uint32_t request_id,
    bool indicator_on,
    char *output,
    size_t output_size);

bool agent_control_plane_build_action_canonical(
    agent_control_plane_action_proof_scope_t scope,
    const char *device_id,
    const char *client_id,
    const char *timestamp,
    const char *nonce,
    const char *body_sha256,
    char *output,
    size_t output_size);

/* json must have writable storage for a NUL byte at json[json_size]. */
bool agent_control_plane_parse_time_response(
    char *json,
    size_t json_size,
    const char *expected_device_id,
    const char *expected_client_id,
    const char *expected_nonce,
    int64_t *unix_seconds);

/* json must have writable storage for a NUL byte at json[json_size]. */
bool agent_control_plane_parse_agent_token_response(
    char *json,
    size_t json_size,
    const char *expected_device_id,
    char *token,
    size_t token_size,
    uint32_t *ttl_seconds,
    char *binding_id,
    size_t binding_id_size,
    uint64_t *binding_revision);

/* json must have writable storage for a NUL byte at json[json_size]. */
bool agent_control_plane_parse_device_claim_response(
    char *json,
    size_t json_size,
    const char *expected_device_id);

/* Every expected field is rebound and the response bytes must be canonical. */
bool agent_control_plane_parse_action_challenge_response(
    char *json,
    size_t json_size,
    const char *expected_challenge_id,
    const char *expected_device_id,
    const char *expected_session_id,
    uint32_t expected_request_id,
    bool expected_indicator_on,
    int64_t expected_expires_at_unix,
    uint64_t *owner_revision);

bool agent_control_plane_parse_action_result_response(
    char *json,
    size_t json_size,
    int status_code,
    const char *expected_challenge_id,
    agent_control_plane_action_protocol_decision_t *decision);
