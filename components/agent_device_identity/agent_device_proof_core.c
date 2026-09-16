#include "agent_device_proof_core.h"

#include <limits.h>
#include <string.h>

enum {
    IDENTIFIER_MAX = 64,
    NONCE_BASE64URL_SIZE = 22,
	DEVICE_CLAIM_BASE64URL_SIZE = 43,
	SHA256_HEX_SIZE = 64,
};

static const int64_t MINIMUM_UNIX_TIME = INT64_C(1609459200); /* 2021-01-01 */
static const int64_t MAXIMUM_UNIX_TIME = INT64_C(4102444800); /* 2100-01-01 */
static const char SESSION_PREFIX[] =
    "xiaozhi-session-proof-v1\nPOST\n/v1/session\n";
static const char AGENT_TOKEN_PREFIX[] =
    "xiaozhi-agent-token-proof-v1\nPOST\n/v1/agent-token\n";
static const char OTA_OFFER_PREFIX[] =
    "xiaozhi-ota-offer-proof-v1\nPOST\n/v1/ota/offer\n";
static const char DEVICE_CLAIM_PREFIX[] =
    "xiaozhi-device-claim-proof-v1\nPOST\n/v1/device-claim/device\n";
static const char ACTION_CONSENT_CHALLENGE_PREFIX[] =
    "xiaozhi-action-consent-challenge-proof-v1\nPOST\n"
    "/v1/action-consents/device/challenge\n";
static const char ACTION_CONSENT_RESULT_PREFIX[] =
    "xiaozhi-action-consent-result-proof-v1\nPOST\n"
    "/v1/action-consents/device/result\n";

bool agent_device_proof_safe_identifier(const char *value)
{
    if (!value || !value[0]) {
        return false;
    }
    const size_t size = strnlen(value, IDENTIFIER_MAX + 1);
    if (size == 0 || size > IDENTIFIER_MAX) {
        return false;
    }
    for (size_t index = 0; index < size; ++index) {
        const unsigned char c = (unsigned char)value[index];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == ':' || c == '-' ||
            c == '_' || c == '.') {
            continue;
        }
        return false;
    }
    return true;
}

static bool field(const uint8_t **cursor,
                  const uint8_t *end,
                  const uint8_t **value,
                  size_t *value_size)
{
    if (!cursor || !*cursor || !end || !value || !value_size ||
        *cursor >= end) {
        return false;
    }
    const uint8_t *newline = memchr(*cursor, '\n', (size_t)(end - *cursor));
    if (!newline || newline == *cursor) {
        return false;
    }
    *value = *cursor;
    *value_size = (size_t)(newline - *cursor);
    *cursor = newline + 1;
    return true;
}

static bool safe_identifier_field(const uint8_t *value, size_t size)
{
    if (!value || size == 0 || size > IDENTIFIER_MAX) {
        return false;
    }
    for (size_t index = 0; index < size; ++index) {
        const unsigned char c = value[index];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == ':' || c == '-' ||
            c == '_' || c == '.') {
            continue;
        }
        return false;
    }
    return true;
}

static bool safe_version_field(const uint8_t *value, size_t size)
{
    if (!value || size == 0 || size > 32) {
        return false;
    }
    for (size_t index = 0; index < size; ++index) {
        const unsigned char c = value[index];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '.' || c == '+' ||
            c == '-' || c == '_') {
            continue;
        }
        return false;
    }
    return true;
}

static bool release_sequence_field(const uint8_t *value, size_t size)
{
    if (!value || size == 0 || size > 10 ||
        value[0] < '1' || value[0] > '9') {
        return false;
    }
    uint32_t sequence = 0;
    for (size_t index = 0; index < size; ++index) {
        if (value[index] < '0' || value[index] > '9' ||
            sequence > (uint32_t)(INT32_MAX - (value[index] - '0')) / 10U) {
            return false;
        }
        sequence = sequence * 10U + (uint32_t)(value[index] - '0');
    }
    return sequence > 0 && sequence <= INT32_MAX;
}

static bool parse_timestamp(const uint8_t *value,
                            size_t size,
                            int64_t *timestamp)
{
    if (!value || !timestamp || size == 0 || size > 10 ||
        value[0] < '1' || value[0] > '9') {
        return false;
    }
    int64_t parsed = 0;
    for (size_t index = 0; index < size; ++index) {
        if (value[index] < '0' || value[index] > '9' ||
            parsed > (INT64_MAX - (value[index] - '0')) / 10) {
            return false;
        }
        parsed = parsed * 10 + (value[index] - '0');
    }
    if (parsed < MINIMUM_UNIX_TIME || parsed > MAXIMUM_UNIX_TIME) {
        return false;
    }
    *timestamp = parsed;
    return true;
}

static int base64url_value(uint8_t value)
{
    if (value >= 'A' && value <= 'Z') {
        return value - 'A';
    }
    if (value >= 'a' && value <= 'z') {
        return value - 'a' + 26;
    }
    if (value >= '0' && value <= '9') {
        return value - '0' + 52;
    }
    if (value == '-') {
        return 62;
    }
    if (value == '_') {
        return 63;
    }
    return -1;
}

static bool canonical_nonce(const uint8_t *value, size_t size)
{
    if (!value || size != NONCE_BASE64URL_SIZE) {
        return false;
    }
    for (size_t index = 0; index < size; ++index) {
        const int decoded = base64url_value(value[index]);
        if (decoded < 0 ||
            (index == size - 1 && (decoded & 0x0f) != 0)) {
            return false;
        }
    }
    return true;
}

static bool canonical_device_claim(const uint8_t *value, size_t size)
{
    if (!value || size != DEVICE_CLAIM_BASE64URL_SIZE) {
        return false;
    }
    for (size_t index = 0; index < size; ++index) {
        const int decoded = base64url_value(value[index]);
        if (decoded < 0 ||
            (index == size - 1 && (decoded & 0x03) != 0)) {
            return false;
        }
    }
    return true;
}

static bool canonical_sha256(const uint8_t *value, size_t size)
{
    if (!value || size != SHA256_HEX_SIZE) {
        return false;
    }
    for (size_t index = 0; index < size; ++index) {
        const uint8_t c = value[index];
        if ((c < '0' || c > '9') && (c < 'a' || c > 'f')) {
            return false;
        }
    }
    return true;
}

bool agent_device_proof_validate_scoped(
    const uint8_t *message,
    size_t message_size,
    const char *expected_device_id,
    agent_device_proof_scope_t scope,
    int64_t *timestamp)
{
    const char *prefix = NULL;
    size_t prefix_size = 0;
    if (scope == AGENT_DEVICE_PROOF_SCOPE_SESSION) {
        prefix = SESSION_PREFIX;
        prefix_size = sizeof(SESSION_PREFIX) - 1;
    } else if (scope == AGENT_DEVICE_PROOF_SCOPE_AGENT_TOKEN) {
        prefix = AGENT_TOKEN_PREFIX;
        prefix_size = sizeof(AGENT_TOKEN_PREFIX) - 1;
    } else if (scope == AGENT_DEVICE_PROOF_SCOPE_OTA_OFFER) {
        prefix = OTA_OFFER_PREFIX;
        prefix_size = sizeof(OTA_OFFER_PREFIX) - 1;
    } else if (scope == AGENT_DEVICE_PROOF_SCOPE_DEVICE_CLAIM) {
        prefix = DEVICE_CLAIM_PREFIX;
        prefix_size = sizeof(DEVICE_CLAIM_PREFIX) - 1;
    } else if (scope ==
               AGENT_DEVICE_PROOF_SCOPE_ACTION_CONSENT_CHALLENGE) {
        prefix = ACTION_CONSENT_CHALLENGE_PREFIX;
        prefix_size = sizeof(ACTION_CONSENT_CHALLENGE_PREFIX) - 1;
    } else if (scope ==
               AGENT_DEVICE_PROOF_SCOPE_ACTION_CONSENT_RESULT) {
        prefix = ACTION_CONSENT_RESULT_PREFIX;
        prefix_size = sizeof(ACTION_CONSENT_RESULT_PREFIX) - 1;
    }
    if (!message || !timestamp ||
        !agent_device_proof_safe_identifier(expected_device_id) ||
        !prefix || message_size <= prefix_size ||
        memcmp(message, prefix, prefix_size) != 0) {
        return false;
    }
    const uint8_t *cursor = message + prefix_size;
    const uint8_t *end = message + message_size;
    const uint8_t *device = NULL;
    const uint8_t *client = NULL;
    const uint8_t *time = NULL;
    size_t device_size = 0;
    size_t client_size = 0;
    size_t time_size = 0;
    if (!field(&cursor, end, &device, &device_size) ||
        !field(&cursor, end, &client, &client_size) ||
        !field(&cursor, end, &time, &time_size) || cursor >= end ||
        device_size != strlen(expected_device_id) ||
        memcmp(device, expected_device_id, device_size) != 0 ||
        !safe_identifier_field(client, client_size) ||
        !parse_timestamp(time, time_size, timestamp)) {
        return false;
    }
    if (scope == AGENT_DEVICE_PROOF_SCOPE_SESSION ||
        scope == AGENT_DEVICE_PROOF_SCOPE_AGENT_TOKEN) {
        return canonical_nonce(cursor, (size_t)(end - cursor));
    }

    if (scope == AGENT_DEVICE_PROOF_SCOPE_DEVICE_CLAIM) {
        const uint8_t *nonce = NULL;
        size_t nonce_size = 0;
        return field(&cursor, end, &nonce, &nonce_size) && cursor < end &&
               canonical_nonce(nonce, nonce_size) &&
               canonical_device_claim(cursor, (size_t)(end - cursor));
    }

    if (scope == AGENT_DEVICE_PROOF_SCOPE_ACTION_CONSENT_CHALLENGE ||
        scope == AGENT_DEVICE_PROOF_SCOPE_ACTION_CONSENT_RESULT) {
        const uint8_t *nonce = NULL;
        size_t nonce_size = 0;
        return field(&cursor, end, &nonce, &nonce_size) && cursor < end &&
               canonical_nonce(nonce, nonce_size) &&
               canonical_sha256(cursor, (size_t)(end - cursor));
    }

    const uint8_t *nonce = NULL;
    const uint8_t *board = NULL;
    const uint8_t *channel = NULL;
    const uint8_t *sequence = NULL;
    size_t nonce_size = 0;
    size_t board_size = 0;
    size_t channel_size = 0;
    size_t sequence_size = 0;
    return field(&cursor, end, &nonce, &nonce_size) &&
           field(&cursor, end, &board, &board_size) &&
           field(&cursor, end, &channel, &channel_size) &&
           field(&cursor, end, &sequence, &sequence_size) &&
           cursor < end && canonical_nonce(nonce, nonce_size) &&
           safe_identifier_field(board, board_size) && board_size <= 32 &&
           safe_identifier_field(channel, channel_size) && channel_size <= 32 &&
           release_sequence_field(sequence, sequence_size) &&
           safe_version_field(cursor, (size_t)(end - cursor));
}

bool agent_device_proof_validate(
    const uint8_t *message,
    size_t message_size,
    const char *expected_device_id,
    int64_t *timestamp)
{
    return agent_device_proof_validate_scoped(
        message, message_size, expected_device_id,
        AGENT_DEVICE_PROOF_SCOPE_SESSION, timestamp);
}

bool agent_device_proof_time_is_current(
    int64_t proof_time,
    int64_t current_time,
    uint32_t tolerance_seconds)
{
    if (proof_time < MINIMUM_UNIX_TIME || proof_time > MAXIMUM_UNIX_TIME ||
        current_time < MINIMUM_UNIX_TIME ||
        current_time > MAXIMUM_UNIX_TIME) {
        return false;
    }
    return proof_time < current_time
               ? (uint64_t)(current_time - proof_time) <= tolerance_seconds
               : (uint64_t)(proof_time - current_time) <= tolerance_seconds;
}
