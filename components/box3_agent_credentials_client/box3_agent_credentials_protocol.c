#include "box3_agent_credentials_protocol.h"

#include <stdio.h>
#include <string.h>

#include "cJSON.h"

enum {
    IDENTIFIER_MAX = 64,
    MINIMUM_TTL_SECONDS = 60,
    MAXIMUM_TTL_SECONDS = 3600,
};

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

static bool safe_voice_uri(const char *value)
{
    if (!safe_ascii(value, BOX3_AGENT_CREDENTIALS_URI_MAX) ||
        strncmp(value, "wss://", 6) != 0) {
        return false;
    }
    const char *authority = value + 6;
    const char *path = strchr(authority, '/');
    return path && safe_authority(authority, path) &&
           strcmp(path, "/v1/device") == 0;
}

bool box3_agent_credentials_binding_id_is_canonical(const char *value)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    enum { ENCODED_SIZE = 22 };
    if (!value || strnlen(value, ENCODED_SIZE + 1) != ENCODED_SIZE) {
        return false;
    }
    for (size_t index = 0; index < ENCODED_SIZE; ++index) {
        const char *found = strchr(alphabet, value[index]);
        if (!found || (index == ENCODED_SIZE - 1 &&
                       (((size_t)(found - alphabet)) & 0x0fU) != 0)) {
            return false;
        }
    }
    return true;
}

bool box3_agent_credentials_validate_endpoint(const char *endpoint)
{
    if (!endpoint || strncmp(endpoint, "https://", 8) != 0) {
        return false;
    }
    const size_t size = strnlen(endpoint, BOX3_AGENT_CREDENTIALS_URI_MAX);
    if (size == BOX3_AGENT_CREDENTIALS_URI_MAX) {
        return false;
    }
    const char *authority = endpoint + 8;
    const char *path = strchr(authority, '/');
    return path && safe_authority(authority, path) &&
           strcmp(path, "/v1/session") == 0;
}

bool box3_agent_credentials_safe_identifier(const char *value)
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

bool box3_agent_credentials_base64url(
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

bool box3_agent_credentials_build_canonical(
    const char *device_id,
    const char *client_id,
    const char *timestamp,
    const char *nonce,
    char *output,
    size_t output_size)
{
    if (!box3_agent_credentials_safe_identifier(device_id) ||
        !box3_agent_credentials_safe_identifier(client_id) ||
        !timestamp || !timestamp[0] || !nonce || !nonce[0] ||
        !output || output_size == 0) {
        return false;
    }
    const int written = snprintf(
        output, output_size,
        "xiaozhi-session-proof-v1\nPOST\n/v1/session\n%s\n%s\n%s\n%s",
        device_id, client_id, timestamp, nonce);
    return written > 0 && (size_t)written < output_size;
}

static const cJSON *single_member(const cJSON *object, const char *name)
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

static bool copy_string(char *output,
                        size_t output_size,
                        const cJSON *value)
{
    if (!output || !cJSON_IsString(value) || !value->valuestring ||
        !safe_ascii(value->valuestring, output_size)) {
        return false;
    }
    const size_t size = strlen(value->valuestring);
    memcpy(output, value->valuestring, size + 1);
    return true;
}

bool box3_agent_credentials_parse_voice_response(
    char *json,
    size_t json_size,
    const char *expected_device_id,
    box3_agent_voice_credentials_t *credentials)
{
    static const char *const root_members[] = {
        "version", "device_id", "binding_id", "binding_revision", "voice",
    };
    static const char *const voice_members[] = {
        "uri", "bearer_token", "expires_in_seconds",
    };
    if (!json || json_size == 0 ||
        json_size > BOX3_AGENT_CREDENTIALS_RESPONSE_MAX ||
        !box3_agent_credentials_safe_identifier(expected_device_id) ||
        !credentials) {
        return false;
    }
    json[json_size] = '\0';
    const char *parse_end = NULL;
    cJSON *root = cJSON_ParseWithLengthOpts(
        json, json_size + 1, &parse_end, true);
    if (!root || !parse_end || parse_end != json + json_size ||
        !exact_members(root, root_members,
                       sizeof(root_members) / sizeof(root_members[0]))) {
        cJSON_Delete(root);
        return false;
    }
    const cJSON *version = single_member(root, "version");
    const cJSON *device_id = single_member(root, "device_id");
    const cJSON *binding_id = single_member(root, "binding_id");
    const cJSON *binding_revision = single_member(root, "binding_revision");
    const cJSON *voice = single_member(root, "voice");
    const cJSON *uri = single_member(voice, "uri");
    const cJSON *token = single_member(voice, "bearer_token");
    const cJSON *ttl = single_member(voice, "expires_in_seconds");

    box3_agent_voice_credentials_t parsed = {0};
    const bool valid = cJSON_IsNumber(version) && version->valuedouble == 2 &&
                       cJSON_IsString(device_id) && device_id->valuestring &&
                       strcmp(device_id->valuestring,
                              expected_device_id) == 0 &&
                       cJSON_IsString(binding_id) &&
                       binding_id->valuestring &&
                       box3_agent_credentials_binding_id_is_canonical(
                           binding_id->valuestring) &&
                       cJSON_IsNumber(binding_revision) &&
                       binding_revision->valuedouble >= 1 &&
                       binding_revision->valuedouble <= UINT32_MAX &&
                       binding_revision->valuedouble ==
                           (double)(uint64_t)binding_revision->valuedouble &&
                       exact_members(voice, voice_members,
                                     sizeof(voice_members) /
                                         sizeof(voice_members[0])) &&
                       copy_string(parsed.uri, sizeof(parsed.uri), uri) &&
                       safe_voice_uri(parsed.uri) &&
                       copy_string(parsed.bearer_token,
                                   sizeof(parsed.bearer_token), token) &&
                       cJSON_IsNumber(ttl) &&
                       ttl->valuedouble >= MINIMUM_TTL_SECONDS &&
                       ttl->valuedouble <= MAXIMUM_TTL_SECONDS &&
                       ttl->valuedouble == (double)ttl->valueint;
    if (valid) {
        parsed.ttl_seconds = (uint32_t)ttl->valueint;
        memcpy(parsed.binding_id, binding_id->valuestring,
               sizeof(parsed.binding_id));
        parsed.binding_revision =
            (uint64_t)binding_revision->valuedouble;
        *credentials = parsed;
    }
    cJSON_Delete(root);
    return valid;
}

bool box3_agent_credentials_validate_agent_token(
    const char *token,
    size_t token_capacity,
    uint32_t ttl_seconds)
{
    return safe_ascii(token, token_capacity) &&
           ttl_seconds >= MINIMUM_TTL_SECONDS &&
           ttl_seconds <= MAXIMUM_TTL_SECONDS;
}

bool box3_agent_credentials_tokens_are_separate(
    const char *voice_token,
    size_t voice_token_capacity,
    const char *agent_token,
    size_t agent_token_capacity)
{
    return safe_ascii(voice_token, voice_token_capacity) &&
           safe_ascii(agent_token, agent_token_capacity) &&
           strcmp(voice_token, agent_token) != 0;
}
