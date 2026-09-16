#include "agent_control_plane_protocol.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "cJSON.h"

enum {
    IDENTIFIER_MAX = 64,
    MINIMUM_TTL_SECONDS = 60,
    MAXIMUM_TTL_SECONDS = 3600,
};

static const int64_t MINIMUM_UNIX_TIME = INT64_C(1609459200);
static const int64_t MAXIMUM_UNIX_TIME = INT64_C(4102444800);
static const char AGENT_AUDIENCE[] = "xiaozhi-agent-proxy";

static int base64url_value(unsigned char value);

static bool canonical_binding_id(const char *value)
{
    enum { ENCODED_SIZE = 22 };
    if (!value || strnlen(value, ENCODED_SIZE + 1) != ENCODED_SIZE) {
        return false;
    }
    for (size_t index = 0; index < ENCODED_SIZE; ++index) {
        const int decoded = base64url_value((unsigned char)value[index]);
        if (decoded < 0 ||
            (index == ENCODED_SIZE - 1 && (decoded & 0x0f) != 0)) {
            return false;
        }
    }
    return true;
}

static bool safe_ascii(const char *value, size_t capacity)
{
    if (!value || !value[0]) {
        return false;
    }
    const size_t size = strnlen(value, capacity);
    if (size == capacity) {
        return false;
    }
    for (size_t index = 0; index < size; ++index) {
        const unsigned char c = (unsigned char)value[index];
        if (c <= 0x20 || c >= 0x7f) {
            return false;
        }
    }
    return true;
}

static bool safe_authority(const char *begin, const char *end)
{
    if (!begin || !end || begin >= end) {
        return false;
    }
    for (const char *cursor = begin; cursor < end; ++cursor) {
        const unsigned char c = (unsigned char)*cursor;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '.' || c == '-' ||
            c == ':' || c == '[' || c == ']') {
            continue;
        }
        return false;
    }
    return true;
}

static bool endpoint_parts(const char *endpoint,
                           const char *expected_path,
                           const char **authority,
                           size_t *authority_size)
{
    if (!endpoint || !expected_path || !authority || !authority_size ||
        strncmp(endpoint, "https://", 8) != 0) {
        return false;
    }
    const size_t size = strnlen(endpoint, AGENT_CONTROL_PLANE_URI_MAX);
    if (size == AGENT_CONTROL_PLANE_URI_MAX) {
        return false;
    }
    const char *begin = endpoint + 8;
    const char *path = strchr(begin, '/');
    if (!path || !safe_authority(begin, path) ||
        strcmp(path, expected_path) != 0) {
        return false;
    }
    *authority = begin;
    *authority_size = (size_t)(path - begin);
    return true;
}

bool agent_control_plane_validate_endpoints(
    const char *time_endpoint,
    const char *agent_token_endpoint,
    const char *device_claim_endpoint,
    const char *action_challenge_endpoint,
    const char *action_result_endpoint)
{
    const char *time_authority = NULL;
    const char *agent_authority = NULL;
    const char *claim_authority = NULL;
    const char *challenge_authority = NULL;
    const char *result_authority = NULL;
    size_t time_authority_size = 0;
    size_t agent_authority_size = 0;
    size_t claim_authority_size = 0;
    size_t challenge_authority_size = 0;
    size_t result_authority_size = 0;
    return endpoint_parts(time_endpoint, "/v1/time", &time_authority,
                          &time_authority_size) &&
           endpoint_parts(agent_token_endpoint, "/v1/agent-token",
                          &agent_authority, &agent_authority_size) &&
           endpoint_parts(device_claim_endpoint,
                          "/v1/device-claim/device", &claim_authority,
                          &claim_authority_size) &&
           endpoint_parts(action_challenge_endpoint,
                          "/v1/action-consents/device/challenge",
                          &challenge_authority,
                          &challenge_authority_size) &&
           endpoint_parts(action_result_endpoint,
                          "/v1/action-consents/device/result",
                          &result_authority,
                          &result_authority_size) &&
           time_authority_size == agent_authority_size &&
           time_authority_size == claim_authority_size &&
           time_authority_size == challenge_authority_size &&
           time_authority_size == result_authority_size &&
           memcmp(time_authority, agent_authority,
                  time_authority_size) == 0 &&
           memcmp(time_authority, claim_authority,
                  time_authority_size) == 0 &&
           memcmp(time_authority, challenge_authority,
                  time_authority_size) == 0 &&
           memcmp(time_authority, result_authority,
                  time_authority_size) == 0;
}

static int base64url_value(unsigned char value)
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

bool agent_control_plane_device_claim_is_canonical(const char *claim)
{
    enum { CLAIM_ENCODED_BYTES = 43 };
    if (!claim || strnlen(claim, CLAIM_ENCODED_BYTES + 1) !=
                      CLAIM_ENCODED_BYTES) {
        return false;
    }
    for (size_t index = 0; index < CLAIM_ENCODED_BYTES; ++index) {
        const int decoded = base64url_value((unsigned char)claim[index]);
        if (decoded < 0 ||
            (index == CLAIM_ENCODED_BYTES - 1 &&
             (decoded & 0x03) != 0)) {
            return false;
        }
    }
    return true;
}

bool agent_control_plane_device_claim_http_is_terminal(int status_code)
{
    return status_code >= 300 && status_code < 500 &&
           status_code != 408 && status_code != 429;
}

bool agent_control_plane_safe_identifier(const char *value)
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

bool agent_control_plane_base64url(
    const uint8_t *input,
    size_t input_size,
    char *output,
    size_t output_size)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    if ((!input && input_size > 0) || !output) {
        return false;
    }
    const size_t required = (input_size / 3) * 4 +
                            (input_size % 3 == 0
                                 ? 0
                                 : input_size % 3 + 1);
    if (required + 1 > output_size) {
        return false;
    }
    size_t source = 0;
    size_t target = 0;
    while (source + 3 <= input_size) {
        const uint32_t value = ((uint32_t)input[source] << 16) |
                               ((uint32_t)input[source + 1] << 8) |
                               input[source + 2];
        output[target++] = alphabet[(value >> 18) & 0x3f];
        output[target++] = alphabet[(value >> 12) & 0x3f];
        output[target++] = alphabet[(value >> 6) & 0x3f];
        output[target++] = alphabet[value & 0x3f];
        source += 3;
    }
    const size_t remaining = input_size - source;
    if (remaining == 1) {
        const uint32_t value = (uint32_t)input[source] << 16;
        output[target++] = alphabet[(value >> 18) & 0x3f];
        output[target++] = alphabet[(value >> 12) & 0x3f];
    } else if (remaining == 2) {
        const uint32_t value = ((uint32_t)input[source] << 16) |
                               ((uint32_t)input[source + 1] << 8);
        output[target++] = alphabet[(value >> 18) & 0x3f];
        output[target++] = alphabet[(value >> 12) & 0x3f];
        output[target++] = alphabet[(value >> 6) & 0x3f];
    }
    output[target] = '\0';
    return target == required;
}

bool agent_control_plane_build_agent_canonical(
    const char *device_id,
    const char *client_id,
    const char *timestamp,
    const char *nonce,
    char *output,
    size_t output_size)
{
    if (!agent_control_plane_safe_identifier(device_id) ||
        !agent_control_plane_safe_identifier(client_id) ||
        !timestamp || !timestamp[0] || !nonce || !nonce[0] ||
        !output || output_size == 0) {
        return false;
    }
    const int written = snprintf(
        output, output_size,
        "xiaozhi-agent-token-proof-v1\nPOST\n/v1/agent-token\n"
        "%s\n%s\n%s\n%s",
        device_id, client_id, timestamp, nonce);
    return written > 0 && (size_t)written < output_size;
}

bool agent_control_plane_build_device_claim_canonical(
    const char *device_id,
    const char *client_id,
    const char *timestamp,
    const char *nonce,
    const char *claim,
    char *output,
    size_t output_size)
{
    if (!agent_control_plane_safe_identifier(device_id) ||
        !agent_control_plane_safe_identifier(client_id) ||
        !timestamp || !timestamp[0] || !nonce || !nonce[0] ||
        !agent_control_plane_device_claim_is_canonical(claim) ||
        !output || output_size == 0) {
        return false;
    }
    const int written = snprintf(
        output, output_size,
        "xiaozhi-device-claim-proof-v1\nPOST\n"
        "/v1/device-claim/device\n%s\n%s\n%s\n%s\n%s",
        device_id, client_id, timestamp, nonce, claim);
    return written > 0 && (size_t)written < output_size;
}

bool agent_control_plane_action_challenge_id_is_canonical(
    const char *challenge_id)
{
    return canonical_binding_id(challenge_id);
}

static bool sha256_hex_is_canonical(const char *value)
{
    enum { SHA256_HEX_SIZE = 64 };
    if (!value || strnlen(value, SHA256_HEX_SIZE + 1) !=
                      SHA256_HEX_SIZE) {
        return false;
    }
    for (size_t index = 0; index < SHA256_HEX_SIZE; ++index) {
        const unsigned char c = (unsigned char)value[index];
        if ((c < '0' || c > '9') && (c < 'a' || c > 'f')) {
            return false;
        }
    }
    return true;
}

bool agent_control_plane_build_action_challenge_body(
    const char *challenge_id,
    const char *session_id,
    uint32_t request_id,
    bool indicator_on,
    int64_t expires_at_unix,
    char *output,
    size_t output_size)
{
    if (!agent_control_plane_action_challenge_id_is_canonical(
            challenge_id) ||
        !agent_control_plane_safe_identifier(session_id) ||
        request_id == 0 || expires_at_unix < MINIMUM_UNIX_TIME ||
        expires_at_unix > MAXIMUM_UNIX_TIME || !output || output_size == 0) {
        return false;
    }
    const int written = snprintf(
        output, output_size,
        "{\"version\":1,\"challenge_id\":\"%s\","
        "\"session_id\":\"%s\",\"request_id\":%" PRIu32 ","
        "\"capability\":\"device.set_indicator\","
        "\"arguments\":{\"on\":%s},\"expires_at_unix\":%" PRId64 "}",
        challenge_id, session_id, request_id,
        indicator_on ? "true" : "false", expires_at_unix);
    return written > 0 && (size_t)written < output_size;
}

bool agent_control_plane_build_action_result_body(
    const char *challenge_id,
    uint64_t owner_revision,
    const char *session_id,
    uint32_t request_id,
    bool indicator_on,
    char *output,
    size_t output_size)
{
    if (!agent_control_plane_action_challenge_id_is_canonical(
            challenge_id) ||
        owner_revision == 0 || owner_revision > UINT32_MAX ||
        !agent_control_plane_safe_identifier(session_id) ||
        request_id == 0 || !output || output_size == 0) {
        return false;
    }
    const int written = snprintf(
        output, output_size,
        "{\"version\":1,\"challenge_id\":\"%s\","
        "\"owner_revision\":%" PRIu64 ",\"session_id\":\"%s\","
        "\"request_id\":%" PRIu32 ","
        "\"capability\":\"device.set_indicator\","
        "\"arguments\":{\"on\":%s}}",
        challenge_id, owner_revision, session_id, request_id,
        indicator_on ? "true" : "false");
    return written > 0 && (size_t)written < output_size;
}

bool agent_control_plane_build_action_canonical(
    agent_control_plane_action_proof_scope_t scope,
    const char *device_id,
    const char *client_id,
    const char *timestamp,
    const char *nonce,
    const char *body_sha256,
    char *output,
    size_t output_size)
{
    const char *domain = NULL;
    const char *path = NULL;
    if (scope == AGENT_CONTROL_PLANE_ACTION_PROOF_CHALLENGE) {
        domain = "xiaozhi-action-consent-challenge-proof-v1";
        path = "/v1/action-consents/device/challenge";
    } else if (scope == AGENT_CONTROL_PLANE_ACTION_PROOF_RESULT) {
        domain = "xiaozhi-action-consent-result-proof-v1";
        path = "/v1/action-consents/device/result";
    }
    if (!domain || !agent_control_plane_safe_identifier(device_id) ||
        !agent_control_plane_safe_identifier(client_id) ||
        !timestamp || !timestamp[0] || !nonce || !nonce[0] ||
        !sha256_hex_is_canonical(body_sha256) ||
        !output || output_size == 0) {
        return false;
    }
    const int written = snprintf(
        output, output_size, "%s\nPOST\n%s\n%s\n%s\n%s\n%s\n%s",
        domain, path, device_id, client_id, timestamp, nonce, body_sha256);
    return written > 0 && (size_t)written < output_size;
}

static const cJSON *single_member(const cJSON *object,
                                  const char *name)
{
    const cJSON *found = NULL;
    if (!cJSON_IsObject(object)) {
        return NULL;
    }
    for (const cJSON *item = object->child; item; item = item->next) {
        if (item->string && strcmp(item->string, name) == 0) {
            if (found) {
                return NULL;
            }
            found = item;
        }
    }
    return found;
}

static bool exact_members(const cJSON *object,
                          const char *const *names,
                          size_t name_count)
{
    size_t count = 0;
    if (!cJSON_IsObject(object)) {
        return false;
    }
    for (const cJSON *item = object->child; item; item = item->next) {
        bool known = false;
        for (size_t index = 0; index < name_count; ++index) {
            if (item->string && strcmp(item->string, names[index]) == 0) {
                known = true;
                break;
            }
        }
        if (!known) {
            return false;
        }
        ++count;
    }
    if (count != name_count) {
        return false;
    }
    for (size_t index = 0; index < name_count; ++index) {
        if (!single_member(object, names[index])) {
            return false;
        }
    }
    return true;
}

static cJSON *parse_exact(char *json, size_t json_size)
{
    if (!json || json_size == 0 ||
        json_size > AGENT_CONTROL_PLANE_RESPONSE_MAX) {
        return NULL;
    }
    json[json_size] = '\0';
    const char *parse_end = NULL;
    cJSON *root = cJSON_ParseWithLengthOpts(
        json, json_size + 1, &parse_end, true);
    if (!root || !parse_end || parse_end != json + json_size ||
        !cJSON_IsObject(root)) {
        cJSON_Delete(root);
        return NULL;
    }
    return root;
}

bool agent_control_plane_parse_time_response(
    char *json,
    size_t json_size,
    const char *expected_device_id,
    const char *expected_client_id,
    const char *expected_nonce,
    int64_t *unix_seconds)
{
    static const char *const members[] = {
        "version", "device_id", "client_id", "nonce", "unix_seconds",
    };
    if (!agent_control_plane_safe_identifier(expected_device_id) ||
        !agent_control_plane_safe_identifier(expected_client_id) ||
        !safe_ascii(expected_nonce, 32) || !unix_seconds) {
        return false;
    }
    cJSON *root = parse_exact(json, json_size);
    if (!root || !exact_members(root, members,
                                sizeof(members) / sizeof(members[0]))) {
        cJSON_Delete(root);
        return false;
    }
    const cJSON *version = single_member(root, "version");
    const cJSON *device = single_member(root, "device_id");
    const cJSON *client = single_member(root, "client_id");
    const cJSON *nonce = single_member(root, "nonce");
    const cJSON *seconds = single_member(root, "unix_seconds");
    const bool valid = cJSON_IsNumber(version) &&
                       version->valuedouble == 1 &&
                       cJSON_IsString(device) && device->valuestring &&
                       strcmp(device->valuestring,
                              expected_device_id) == 0 &&
                       cJSON_IsString(client) && client->valuestring &&
                       strcmp(client->valuestring,
                              expected_client_id) == 0 &&
                       cJSON_IsString(nonce) && nonce->valuestring &&
                       strcmp(nonce->valuestring,
                              expected_nonce) == 0 &&
                       cJSON_IsNumber(seconds) &&
                       seconds->valuedouble >= MINIMUM_UNIX_TIME &&
                       seconds->valuedouble <= MAXIMUM_UNIX_TIME &&
                       seconds->valuedouble ==
                           (double)(int64_t)seconds->valuedouble;
    if (valid) {
        *unix_seconds = (int64_t)seconds->valuedouble;
    }
    cJSON_Delete(root);
    return valid;
}

bool agent_control_plane_parse_agent_token_response(
    char *json,
    size_t json_size,
    const char *expected_device_id,
    char *token,
    size_t token_size,
    uint32_t *ttl_seconds,
    char *binding_id,
    size_t binding_id_size,
    uint64_t *binding_revision)
{
    static const char *const members[] = {
        "version", "device_id", "audience", "binding_id",
        "binding_revision", "bearer_token", "expires_in_seconds",
    };
    if (!agent_control_plane_safe_identifier(expected_device_id) ||
        !token || token_size == 0 || !ttl_seconds || !binding_id ||
        binding_id_size < 23 || !binding_revision) {
        return false;
    }
    token[0] = '\0';
    *ttl_seconds = 0;
    binding_id[0] = '\0';
    *binding_revision = 0;
    cJSON *root = parse_exact(json, json_size);
    if (!root || !exact_members(root, members,
                                sizeof(members) / sizeof(members[0]))) {
        cJSON_Delete(root);
        return false;
    }
    const cJSON *version = single_member(root, "version");
    const cJSON *device = single_member(root, "device_id");
    const cJSON *audience = single_member(root, "audience");
    const cJSON *binding = single_member(root, "binding_id");
    const cJSON *revision = single_member(root, "binding_revision");
    const cJSON *bearer = single_member(root, "bearer_token");
    const cJSON *ttl = single_member(root, "expires_in_seconds");
    const bool valid = cJSON_IsNumber(version) &&
                       version->valuedouble == 2 &&
                       cJSON_IsString(device) && device->valuestring &&
                       strcmp(device->valuestring,
                              expected_device_id) == 0 &&
                       cJSON_IsString(audience) && audience->valuestring &&
                       strcmp(audience->valuestring,
                              AGENT_AUDIENCE) == 0 &&
                       cJSON_IsString(binding) && binding->valuestring &&
                       canonical_binding_id(binding->valuestring) &&
                       cJSON_IsNumber(revision) &&
                       revision->valuedouble >= 1 &&
                       revision->valuedouble <= UINT32_MAX &&
                       revision->valuedouble ==
                           (double)(uint64_t)revision->valuedouble &&
                       cJSON_IsString(bearer) && bearer->valuestring &&
                       safe_ascii(bearer->valuestring, token_size) &&
                       cJSON_IsNumber(ttl) &&
                       ttl->valuedouble >= MINIMUM_TTL_SECONDS &&
                       ttl->valuedouble <= MAXIMUM_TTL_SECONDS &&
                       ttl->valuedouble == (double)ttl->valueint;
    if (valid) {
        const size_t size = strlen(bearer->valuestring);
        memcpy(token, bearer->valuestring, size + 1);
        *ttl_seconds = (uint32_t)ttl->valueint;
        memcpy(binding_id, binding->valuestring, 23);
        *binding_revision = (uint64_t)revision->valuedouble;
    }
    cJSON_Delete(root);
    return valid;
}

bool agent_control_plane_parse_device_claim_response(
    char *json,
    size_t json_size,
    const char *expected_device_id)
{
    static const char *const members[] = {
        "version", "device_id", "status",
    };
    if (!agent_control_plane_safe_identifier(expected_device_id)) {
        return false;
    }
    cJSON *root = parse_exact(json, json_size);
    if (!root || !exact_members(root, members,
                                sizeof(members) / sizeof(members[0]))) {
        cJSON_Delete(root);
        return false;
    }
    const cJSON *version = single_member(root, "version");
    const cJSON *device = single_member(root, "device_id");
    const cJSON *status = single_member(root, "status");
    const bool valid = cJSON_IsNumber(version) &&
                       version->valuedouble == 1 &&
                       cJSON_IsString(device) && device->valuestring &&
                       strcmp(device->valuestring,
                              expected_device_id) == 0 &&
                       cJSON_IsString(status) && status->valuestring &&
                       strcmp(status->valuestring, "bound") == 0;
    cJSON_Delete(root);
    return valid;
}

bool agent_control_plane_parse_action_challenge_response(
    char *json,
    size_t json_size,
    const char *expected_challenge_id,
    const char *expected_device_id,
    const char *expected_session_id,
    uint32_t expected_request_id,
    bool expected_indicator_on,
    int64_t expected_expires_at_unix,
    uint64_t *owner_revision)
{
    static const char *const members[] = {
        "version", "challenge_id", "device_id", "owner_revision",
        "session_id", "request_id", "capability", "arguments",
        "expires_at_unix",
    };
    static const char *const argument_members[] = {"on"};
    if (owner_revision) {
        *owner_revision = 0;
    }
    if (!owner_revision ||
        !agent_control_plane_action_challenge_id_is_canonical(
            expected_challenge_id) ||
        !agent_control_plane_safe_identifier(expected_device_id) ||
        !agent_control_plane_safe_identifier(expected_session_id) ||
        expected_request_id == 0 ||
        expected_expires_at_unix < MINIMUM_UNIX_TIME ||
        expected_expires_at_unix > MAXIMUM_UNIX_TIME) {
        return false;
    }
    cJSON *root = parse_exact(json, json_size);
    if (!root || !exact_members(root, members,
                                sizeof(members) / sizeof(members[0]))) {
        cJSON_Delete(root);
        return false;
    }
    const cJSON *version = single_member(root, "version");
    const cJSON *challenge = single_member(root, "challenge_id");
    const cJSON *device = single_member(root, "device_id");
    const cJSON *revision = single_member(root, "owner_revision");
    const cJSON *session = single_member(root, "session_id");
    const cJSON *request = single_member(root, "request_id");
    const cJSON *capability = single_member(root, "capability");
    const cJSON *arguments = single_member(root, "arguments");
    const cJSON *expires = single_member(root, "expires_at_unix");
    const cJSON *indicator = single_member(arguments, "on");
    const bool valid =
        cJSON_IsNumber(version) && version->valuedouble == 1 &&
        cJSON_IsString(challenge) && challenge->valuestring &&
        strcmp(challenge->valuestring, expected_challenge_id) == 0 &&
        cJSON_IsString(device) && device->valuestring &&
        strcmp(device->valuestring, expected_device_id) == 0 &&
        cJSON_IsNumber(revision) && revision->valuedouble >= 1 &&
        revision->valuedouble <= UINT32_MAX &&
        revision->valuedouble == (double)(uint64_t)revision->valuedouble &&
        cJSON_IsString(session) && session->valuestring &&
        strcmp(session->valuestring, expected_session_id) == 0 &&
        cJSON_IsNumber(request) &&
        request->valuedouble == (double)expected_request_id &&
        cJSON_IsString(capability) && capability->valuestring &&
        strcmp(capability->valuestring, "device.set_indicator") == 0 &&
        exact_members(arguments, argument_members, 1) &&
        cJSON_IsBool(indicator) &&
        cJSON_IsTrue(indicator) == expected_indicator_on &&
        cJSON_IsNumber(expires) &&
        expires->valuedouble == (double)expected_expires_at_unix;
    char canonical[AGENT_CONTROL_PLANE_ACTION_BODY_MAX + 1] = {0};
    int written = -1;
    if (valid) {
        written = snprintf(
            canonical, sizeof(canonical),
            "{\"version\":1,\"challenge_id\":\"%s\","
            "\"device_id\":\"%s\",\"owner_revision\":%" PRIu64 ","
            "\"session_id\":\"%s\",\"request_id\":%" PRIu32 ","
            "\"capability\":\"device.set_indicator\","
            "\"arguments\":{\"on\":%s},\"expires_at_unix\":%" PRId64 "}",
            expected_challenge_id, expected_device_id,
            (uint64_t)revision->valuedouble, expected_session_id,
            expected_request_id,
            expected_indicator_on ? "true" : "false",
            expected_expires_at_unix);
    }
    const bool canonical_valid =
        valid && written > 0 && (size_t)written == json_size &&
        memcmp(canonical, json, json_size) == 0;
    if (canonical_valid) {
        *owner_revision = (uint64_t)revision->valuedouble;
    }
    cJSON_Delete(root);
    return canonical_valid;
}

bool agent_control_plane_parse_action_result_response(
    char *json,
    size_t json_size,
    int status_code,
    const char *expected_challenge_id,
    agent_control_plane_action_protocol_decision_t *decision)
{
    static const char *const pending_members[] = {
        "version", "challenge_id", "status", "retry_after_seconds",
    };
    static const char *const decision_members[] = {
        "version", "challenge_id", "decision",
    };
    if (decision) {
        *decision = AGENT_CONTROL_PLANE_ACTION_PROTOCOL_PENDING;
    }
    if (!decision ||
        !agent_control_plane_action_challenge_id_is_canonical(
            expected_challenge_id) ||
        (status_code != 200 && status_code != 202)) {
        return false;
    }
    cJSON *root = parse_exact(json, json_size);
    if (!root) {
        return false;
    }
    const cJSON *version = single_member(root, "version");
    const cJSON *challenge = single_member(root, "challenge_id");
    bool valid = cJSON_IsNumber(version) && version->valuedouble == 1 &&
                 cJSON_IsString(challenge) && challenge->valuestring &&
                 strcmp(challenge->valuestring,
                        expected_challenge_id) == 0;
    char canonical[AGENT_CONTROL_PLANE_ACTION_BODY_MAX + 1] = {0};
    int written = -1;
    agent_control_plane_action_protocol_decision_t parsed =
        AGENT_CONTROL_PLANE_ACTION_PROTOCOL_PENDING;
    if (status_code == 202) {
        const cJSON *status = single_member(root, "status");
        const cJSON *retry = single_member(root, "retry_after_seconds");
        valid = valid &&
                exact_members(root, pending_members,
                              sizeof(pending_members) /
                                  sizeof(pending_members[0])) &&
                cJSON_IsString(status) && status->valuestring &&
                strcmp(status->valuestring, "pending") == 0 &&
                cJSON_IsNumber(retry) && retry->valuedouble == 1;
        if (valid) {
            written = snprintf(
                canonical, sizeof(canonical),
                "{\"version\":1,\"challenge_id\":\"%s\","
                "\"status\":\"pending\",\"retry_after_seconds\":1}",
                expected_challenge_id);
        }
    } else {
        const cJSON *choice = single_member(root, "decision");
        valid = valid &&
                exact_members(root, decision_members,
                              sizeof(decision_members) /
                                  sizeof(decision_members[0])) &&
                cJSON_IsString(choice) && choice->valuestring &&
                (strcmp(choice->valuestring, "approve") == 0 ||
                 strcmp(choice->valuestring, "deny") == 0);
        if (valid) {
            parsed = strcmp(choice->valuestring, "approve") == 0
                         ? AGENT_CONTROL_PLANE_ACTION_PROTOCOL_APPROVE
                         : AGENT_CONTROL_PLANE_ACTION_PROTOCOL_DENY;
            written = snprintf(
                canonical, sizeof(canonical),
                "{\"version\":1,\"challenge_id\":\"%s\","
                "\"decision\":\"%s\"}",
                expected_challenge_id, choice->valuestring);
        }
    }
    const bool canonical_valid =
        valid && written > 0 && (size_t)written == json_size &&
        memcmp(canonical, json, json_size) == 0;
    if (canonical_valid) {
        *decision = parsed;
    }
    cJSON_Delete(root);
    return canonical_valid;
}
