#include "product_ota_client_protocol.h"

#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "cJSON.h"

static const char OTA_PATH[] = "/v1/ota/offer";

bool product_ota_client_safe_identifier(const char *value, size_t maximum)
{
    if (!value || !value[0] || maximum == 0) {
        return false;
    }
    const size_t size = strnlen(value, maximum + 1);
    if (size == 0 || size > maximum) {
        return false;
    }
    for (size_t index = 0; index < size; ++index) {
        const unsigned char byte = (unsigned char)value[index];
        if (isalnum(byte) || byte == ':' || byte == '_' || byte == '-' ||
            byte == '.') {
            continue;
        }
        return false;
    }
    return true;
}

bool product_ota_client_safe_version(const char *value)
{
    if (!value || !value[0]) {
        return false;
    }
    const size_t size = strnlen(value, 33);
    if (size == 0 || size > 32) {
        return false;
    }
    for (size_t index = 0; index < size; ++index) {
        const unsigned char byte = (unsigned char)value[index];
        if (isalnum(byte) || byte == '.' || byte == '+' || byte == '-' ||
            byte == '_') {
            continue;
        }
        return false;
    }
    return true;
}

static bool authority_valid(const char *begin, const char *end)
{
    if (!begin || !end || begin >= end || (size_t)(end - begin) > 253) {
        return false;
    }
    const char *colon = memchr(begin, ':', (size_t)(end - begin));
    const char *host_end = colon ? colon : end;
    if (host_end == begin || begin[0] == '.' || host_end[-1] == '.') {
        return false;
    }
    size_t label_size = 0;
    for (const char *cursor = begin; cursor < host_end; ++cursor) {
        const unsigned char byte = (unsigned char)*cursor;
        if (byte == '.') {
            if (label_size == 0 || label_size > 63 || cursor[-1] == '-') {
                return false;
            }
            label_size = 0;
            continue;
        }
        if (!isalnum(byte) && byte != '-') {
            return false;
        }
        if (label_size == 0 && byte == '-') {
            return false;
        }
        ++label_size;
    }
    if (label_size == 0 || label_size > 63 || host_end[-1] == '-') {
        return false;
    }
    if (!colon) {
        return true;
    }
    if (colon + 1 >= end || memchr(colon + 1, ':', (size_t)(end - colon - 1))) {
        return false;
    }
    uint32_t port = 0;
    for (const char *cursor = colon + 1; cursor < end; ++cursor) {
        if (!isdigit((unsigned char)*cursor)) {
            return false;
        }
        port = port * 10U + (uint32_t)(*cursor - '0');
        if (port > 65535U) {
            return false;
        }
    }
    return port > 0;
}

bool product_ota_client_endpoint_valid(const char *endpoint)
{
    if (!endpoint || strncmp(endpoint, "https://", 8) != 0 ||
        strnlen(endpoint, PRODUCT_OTA_CLIENT_ENDPOINT_MAX) ==
            PRODUCT_OTA_CLIENT_ENDPOINT_MAX) {
        return false;
    }
    const char *authority = endpoint + 8;
    const char *path = strchr(authority, '/');
    return path && authority_valid(authority, path) &&
           strcmp(path, OTA_PATH) == 0;
}

bool product_ota_client_base64url_encode(
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
                            (input_size % 3 == 0 ? 0 : input_size % 3 + 1);
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
    if (input_size - source == 1) {
        const uint32_t value = (uint32_t)input[source] << 16;
        output[target++] = alphabet[(value >> 18) & 0x3f];
        output[target++] = alphabet[(value >> 12) & 0x3f];
    } else if (input_size - source == 2) {
        const uint32_t value = ((uint32_t)input[source] << 16) |
                               ((uint32_t)input[source + 1] << 8);
        output[target++] = alphabet[(value >> 18) & 0x3f];
        output[target++] = alphabet[(value >> 12) & 0x3f];
        output[target++] = alphabet[(value >> 6) & 0x3f];
    }
    output[target] = '\0';
    return target == required;
}

bool product_ota_client_build_canonical(
    const char *device_id,
    const char *client_id,
    const char *timestamp,
    const char *nonce,
    const char *board,
    const char *channel,
    uint32_t release_sequence,
    const char *version,
    char *output,
    size_t output_size)
{
    if (!product_ota_client_safe_identifier(device_id, 64) ||
        !product_ota_client_safe_identifier(client_id, 64) ||
        !product_ota_client_safe_identifier(board, 32) ||
        !product_ota_client_safe_identifier(channel, 32) ||
        !product_ota_client_safe_version(version) || release_sequence == 0 ||
        release_sequence > INT32_MAX || !timestamp || !timestamp[0] ||
        !nonce || !nonce[0] || !output || output_size == 0) {
        return false;
    }
    const int size = snprintf(
        output, output_size,
        "xiaozhi-ota-offer-proof-v1\nPOST\n/v1/ota/offer\n"
        "%s\n%s\n%s\n%s\n%s\n%s\n%" PRIu32 "\n%s",
        device_id, client_id, timestamp, nonce, board, channel,
        release_sequence, version);
    return size > 0 && (size_t)size < output_size;
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

static int base64url_value(unsigned char byte)
{
    if (byte >= 'A' && byte <= 'Z') {
        return byte - 'A';
    }
    if (byte >= 'a' && byte <= 'z') {
        return byte - 'a' + 26;
    }
    if (byte >= '0' && byte <= '9') {
        return byte - '0' + 52;
    }
    return byte == '-' ? 62 : byte == '_' ? 63 : -1;
}

static bool base64url_decode(const char *input,
                             uint8_t *output,
                             size_t capacity,
                             size_t *output_size)
{
    if (!input || !output || !output_size || strchr(input, '=')) {
        return false;
    }
    const size_t size = strlen(input);
    if (size == 0 || size % 4 == 1) {
        return false;
    }
    size_t produced = 0;
    uint32_t accumulator = 0;
    unsigned bits = 0;
    for (size_t index = 0; index < size; ++index) {
        const int value = base64url_value((unsigned char)input[index]);
        if (value < 0) {
            return false;
        }
        accumulator = (accumulator << 6) | (uint32_t)value;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (produced >= capacity) {
                return false;
            }
            output[produced++] = (uint8_t)(accumulator >> bits);
            accumulator &= bits == 0 ? 0U : ((1U << bits) - 1U);
        }
    }
    if (accumulator != 0U) {
        return false;
    }
    *output_size = produced;
    return true;
}

static bool safe_token(const char *value, size_t capacity)
{
    if (!value || !value[0] || capacity == 0) {
        return false;
    }
    const size_t size = strnlen(value, capacity);
    if (size == capacity || size > PRODUCT_OTA_CLIENT_TOKEN_MAX) {
        return false;
    }
    for (size_t index = 0; index < size; ++index) {
        const unsigned char byte = (unsigned char)value[index];
        if (byte <= 0x20 || byte >= 0x7f) {
            return false;
        }
    }
    return true;
}

static bool exact_uint(const cJSON *item, uint32_t minimum,
                       uint32_t maximum, uint32_t *output)
{
    if (!cJSON_IsNumber(item) || !output || item->valuedouble < minimum ||
        item->valuedouble > maximum ||
        item->valuedouble != (double)(uint32_t)item->valuedouble) {
        return false;
    }
    *output = (uint32_t)item->valuedouble;
    return true;
}

bool product_ota_client_parse_offer(
    char *json,
    size_t json_size,
    const char *expected_device_id,
    product_ota_client_offer_status_t *status,
    char *manifest,
    size_t manifest_capacity,
    size_t *manifest_size,
    char *token,
    size_t token_capacity,
    uint32_t *ttl_seconds,
    uint32_t *retry_after_seconds)
{
    if (!json || json_size == 0 ||
        json_size > PRODUCT_OTA_CLIENT_RESPONSE_MAX ||
        !product_ota_client_safe_identifier(expected_device_id, 64) ||
        !status || !manifest || manifest_capacity < 2 || !manifest_size ||
        !token || token_capacity < 2 || !ttl_seconds || !retry_after_seconds) {
        return false;
    }
    *status = 0;
    manifest[0] = '\0';
    *manifest_size = 0;
    token[0] = '\0';
    *ttl_seconds = 0;
    *retry_after_seconds = 0;
    json[json_size] = '\0';
    const char *parse_end = NULL;
    cJSON *root = cJSON_ParseWithLengthOpts(
        json, json_size + 1, &parse_end, true);
    if (!root || !parse_end || parse_end != json + json_size ||
        !cJSON_IsObject(root)) {
        cJSON_Delete(root);
        return false;
    }
    const cJSON *status_item = single_member(root, "status");
    const cJSON *device = single_member(root, "device_id");
    const cJSON *version = single_member(root, "version");
    if (!cJSON_IsString(status_item) || !status_item->valuestring ||
        !cJSON_IsString(device) || !device->valuestring ||
        strcmp(device->valuestring, expected_device_id) != 0 ||
        !cJSON_IsNumber(version) || version->valuedouble != 1) {
        cJSON_Delete(root);
        return false;
    }
    bool valid = false;
    if (strcmp(status_item->valuestring, "available") == 0) {
        static const char *const names[] = {
            "version", "status", "device_id", "manifest_b64url",
            "download_token", "expires_in_seconds",
        };
        const cJSON *encoded = single_member(root, "manifest_b64url");
        const cJSON *download = single_member(root, "download_token");
        uint32_t ttl = 0;
        size_t decoded_size = 0;
        valid = exact_members(root, names, sizeof(names) / sizeof(names[0])) &&
                cJSON_IsString(encoded) && encoded->valuestring &&
                cJSON_IsString(download) && download->valuestring &&
                safe_token(download->valuestring, token_capacity) &&
                exact_uint(single_member(root, "expires_in_seconds"),
                           60, 900, &ttl) &&
                base64url_decode(
                    encoded->valuestring, (uint8_t *)manifest,
                    manifest_capacity - 1 < PRODUCT_OTA_CLIENT_MANIFEST_MAX
                        ? manifest_capacity - 1
                        : PRODUCT_OTA_CLIENT_MANIFEST_MAX,
                    &decoded_size) &&
                decoded_size > 0 &&
                decoded_size <= PRODUCT_OTA_CLIENT_MANIFEST_MAX;
        if (valid) {
            manifest[decoded_size] = '\0';
            *manifest_size = decoded_size;
            memcpy(token, download->valuestring,
                   strlen(download->valuestring) + 1);
            *ttl_seconds = ttl;
            *status = PRODUCT_OTA_CLIENT_OFFER_AVAILABLE;
        }
    } else if (strcmp(status_item->valuestring, "up_to_date") == 0 ||
               strcmp(status_item->valuestring, "deferred") == 0) {
        static const char *const names[] = {
            "version", "status", "device_id", "retry_after_seconds",
        };
        uint32_t retry = 0;
        valid = exact_members(root, names, sizeof(names) / sizeof(names[0])) &&
                exact_uint(single_member(root, "retry_after_seconds"),
                           60, 86400, &retry);
        if (valid) {
            *retry_after_seconds = retry;
            *status = strcmp(status_item->valuestring, "up_to_date") == 0
                          ? PRODUCT_OTA_CLIENT_OFFER_UP_TO_DATE
                          : PRODUCT_OTA_CLIENT_OFFER_DEFERRED;
        }
    }
    cJSON_Delete(root);
    return valid;
}
