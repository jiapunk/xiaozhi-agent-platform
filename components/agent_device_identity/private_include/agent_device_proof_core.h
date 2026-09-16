#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool agent_device_proof_safe_identifier(const char *value);

typedef enum {
    AGENT_DEVICE_PROOF_SCOPE_SESSION = 1,
    AGENT_DEVICE_PROOF_SCOPE_AGENT_TOKEN = 2,
	AGENT_DEVICE_PROOF_SCOPE_OTA_OFFER = 3,
	AGENT_DEVICE_PROOF_SCOPE_DEVICE_CLAIM = 4,
	AGENT_DEVICE_PROOF_SCOPE_ACTION_CONSENT_CHALLENGE = 5,
	AGENT_DEVICE_PROOF_SCOPE_ACTION_CONSENT_RESULT = 6,
} agent_device_proof_scope_t;

bool agent_device_proof_validate_scoped(
    const uint8_t *message,
    size_t message_size,
    const char *expected_device_id,
    agent_device_proof_scope_t scope,
    int64_t *timestamp);

bool agent_device_proof_validate(
    const uint8_t *message,
    size_t message_size,
    const char *expected_device_id,
    int64_t *timestamp);

bool agent_device_proof_time_is_current(
    int64_t proof_time,
    int64_t current_time,
    uint32_t tolerance_seconds);
