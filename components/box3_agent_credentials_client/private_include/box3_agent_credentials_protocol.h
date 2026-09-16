#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    BOX3_AGENT_CREDENTIALS_RESPONSE_MAX = 4096,
    BOX3_AGENT_CREDENTIALS_CANONICAL_MAX = 512,
    BOX3_AGENT_CREDENTIALS_NONCE_BYTES = 16,
    BOX3_AGENT_CREDENTIALS_SIGNATURE_BYTES = 32,
    BOX3_AGENT_CREDENTIALS_URI_MAX = 512,
    BOX3_AGENT_CREDENTIALS_VOICE_TOKEN_MAX = 1024,
    BOX3_AGENT_CREDENTIALS_BINDING_ID_BYTES = 23,
};

typedef struct {
    char uri[BOX3_AGENT_CREDENTIALS_URI_MAX];
    char bearer_token[BOX3_AGENT_CREDENTIALS_VOICE_TOKEN_MAX];
    uint32_t ttl_seconds;
    char binding_id[BOX3_AGENT_CREDENTIALS_BINDING_ID_BYTES];
    uint64_t binding_revision;
} box3_agent_voice_credentials_t;

bool box3_agent_credentials_binding_id_is_canonical(const char *value);

bool box3_agent_credentials_validate_endpoint(const char *endpoint);
bool box3_agent_credentials_safe_identifier(const char *value);

bool box3_agent_credentials_base64url(
    const uint8_t *input,
    size_t input_size,
    char *output,
    size_t output_size);

bool box3_agent_credentials_build_canonical(
    const char *device_id,
    const char *client_id,
    const char *timestamp,
    const char *nonce,
    char *output,
    size_t output_size);

/* json must have writable storage for a NUL byte at json[json_size]. */
bool box3_agent_credentials_parse_voice_response(
    char *json,
    size_t json_size,
    const char *expected_device_id,
    box3_agent_voice_credentials_t *credentials);

bool box3_agent_credentials_validate_agent_token(
    const char *token,
    size_t token_capacity,
    uint32_t ttl_seconds);

bool box3_agent_credentials_tokens_are_separate(
    const char *voice_token,
    size_t voice_token_capacity,
    const char *agent_token,
    size_t agent_token_capacity);
