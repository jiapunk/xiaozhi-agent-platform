#include "product_ota_core.h"

#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "cJSON.h"

enum {
    FIELD_SCHEMA = 1U << 0,
    FIELD_RELEASE_ID = 1U << 1,
    FIELD_PROJECT = 1U << 2,
    FIELD_BOARD = 1U << 3,
    FIELD_CHANNEL = 1U << 4,
    FIELD_VERSION = 1U << 5,
    FIELD_RELEASE_SEQUENCE = 1U << 6,
    FIELD_SECURE_VERSION = 1U << 7,
    FIELD_IMAGE_URL = 1U << 8,
    FIELD_IMAGE_SIZE = 1U << 9,
    FIELD_IMAGE_SHA256 = 1U << 10,
    FIELD_NOT_BEFORE = 1U << 11,
    FIELD_EXPIRES_AT = 1U << 12,
    FIELD_SIGNING_KEY_ID = 1U << 13,
    FIELD_SIGNATURE_ALGORITHM = 1U << 14,
    FIELD_SIGNATURE = 1U << 15,
    FIELD_RESET_QUALIFICATION_SHA256 = 1U << 16,
    ALL_FIELDS = 0x1FFFFU,
};

static bool copy_string(char *output,
                        size_t output_size,
                        const cJSON *item)
{
    if (!output || output_size == 0 || !cJSON_IsString(item) ||
        !item->valuestring) {
        return false;
    }
    const size_t size = strlen(item->valuestring);
    if (size == 0 || size >= output_size) {
        return false;
    }
    memcpy(output, item->valuestring, size + 1);
    return true;
}

static bool identifier_valid(const char *value, size_t maximum)
{
    if (!value) {
        return false;
    }
    const size_t size = strlen(value);
    if (size == 0 || size > maximum) {
        return false;
    }
    for (size_t index = 0; index < size; ++index) {
        const unsigned char byte = (unsigned char)value[index];
        if (!isalnum(byte) && byte != ':' && byte != '_' && byte != '-' &&
            byte != '.') {
            return false;
        }
    }
    return true;
}

static bool version_valid(const char *value)
{
    if (!value) {
        return false;
    }
    const size_t size = strlen(value);
    if (size == 0 || size > 32) {
        return false;
    }
    for (size_t index = 0; index < size; ++index) {
        const unsigned char byte = (unsigned char)value[index];
        if (!isalnum(byte) && byte != '.' && byte != '+' && byte != '-' &&
            byte != '_') {
            return false;
        }
    }
    return true;
}

static bool exact_uint(const cJSON *item,
                       uint64_t minimum,
                       uint64_t maximum,
                       uint64_t *output)
{
    if (!cJSON_IsNumber(item) || !output || item->valuedouble < 0.0) {
        return false;
    }
    const uint64_t value = (uint64_t)item->valuedouble;
    if ((double)value != item->valuedouble || value < minimum ||
        value > maximum) {
        return false;
    }
    *output = value;
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
    if (byte == '-') {
        return 62;
    }
    if (byte == '_') {
        return 63;
    }
    return -1;
}

static bool decode_base64url(const char *input,
                             uint8_t *output,
                             size_t output_capacity,
                             size_t *output_size)
{
    if (!input || !output || !output_size || strchr(input, '=')) {
        return false;
    }
    const size_t input_size = strlen(input);
    if (input_size == 0 || input_size % 4 == 1) {
        return false;
    }
    size_t produced = 0;
    uint32_t accumulator = 0;
    unsigned bits = 0;
    for (size_t index = 0; index < input_size; ++index) {
        const int value = base64url_value((unsigned char)input[index]);
        if (value < 0) {
            return false;
        }
        accumulator = (accumulator << 6) | (uint32_t)value;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (produced >= output_capacity) {
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

static bool sha256_hex_decode(const char *input, uint8_t output[32])
{
    if (!input || strlen(input) != 64 || !output) {
        return false;
    }
    for (size_t index = 0; index < 32; ++index) {
        const unsigned char high = (unsigned char)input[index * 2];
        const unsigned char low = (unsigned char)input[index * 2 + 1];
        if (!((high >= '0' && high <= '9') ||
              (high >= 'a' && high <= 'f')) ||
            !((low >= '0' && low <= '9') ||
              (low >= 'a' && low <= 'f'))) {
            return false;
        }
        const unsigned high_value = high <= '9' ? high - '0' : high - 'a' + 10;
        const unsigned low_value = low <= '9' ? low - '0' : low - 'a' + 10;
        output[index] = (uint8_t)((high_value << 4) | low_value);
    }
    return true;
}

static bool contains_escaped_nul(const char *json, size_t size)
{
    for (size_t index = 0; index + 5 < size; ++index) {
        if (json[index] == '\\' && (json[index + 1] == 'u' ||
                                     json[index + 1] == 'U') &&
            json[index + 2] == '0' && json[index + 3] == '0' &&
            json[index + 4] == '0' && json[index + 5] == '0') {
            return true;
        }
    }
    return false;
}

static uint32_t field_bit(const char *name)
{
    static const struct {
        const char *name;
        uint32_t bit;
    } fields[] = {
        {"schema", FIELD_SCHEMA},
        {"release_id", FIELD_RELEASE_ID},
        {"project", FIELD_PROJECT},
        {"board", FIELD_BOARD},
        {"channel", FIELD_CHANNEL},
        {"version", FIELD_VERSION},
        {"release_sequence", FIELD_RELEASE_SEQUENCE},
        {"secure_version", FIELD_SECURE_VERSION},
        {"image_url", FIELD_IMAGE_URL},
        {"image_size", FIELD_IMAGE_SIZE},
        {"image_sha256", FIELD_IMAGE_SHA256},
        {"reset_qualification_sha256", FIELD_RESET_QUALIFICATION_SHA256},
        {"not_before", FIELD_NOT_BEFORE},
        {"expires_at", FIELD_EXPIRES_AT},
        {"signing_key_id", FIELD_SIGNING_KEY_ID},
        {"signature_algorithm", FIELD_SIGNATURE_ALGORITHM},
        {"signature_b64url", FIELD_SIGNATURE},
    };
    for (size_t index = 0; index < sizeof(fields) / sizeof(fields[0]); ++index) {
        if (strcmp(name, fields[index].name) == 0) {
            return fields[index].bit;
        }
    }
    return 0;
}

static bool root_fields_exact(const cJSON *root)
{
    uint32_t seen = 0;
    for (const cJSON *item = root ? root->child : NULL; item;
         item = item->next) {
        if (!item->string) {
            return false;
        }
        const uint32_t bit = field_bit(item->string);
        if (bit == 0 || (seen & bit) != 0) {
            return false;
        }
        seen |= bit;
    }
    return seen == ALL_FIELDS;
}

static bool parse_fields(const cJSON *root, product_ota_manifest_t *manifest)
{
    uint64_t number = 0;
    if (!exact_uint(cJSON_GetObjectItemCaseSensitive(root, "schema"),
                    2, 2, &number)) {
        return false;
    }
    manifest->schema = (uint32_t)number;
    if (!copy_string(manifest->release_id, sizeof(manifest->release_id),
                     cJSON_GetObjectItemCaseSensitive(root, "release_id")) ||
        !copy_string(manifest->project, sizeof(manifest->project),
                     cJSON_GetObjectItemCaseSensitive(root, "project")) ||
        !copy_string(manifest->board, sizeof(manifest->board),
                     cJSON_GetObjectItemCaseSensitive(root, "board")) ||
        !copy_string(manifest->channel, sizeof(manifest->channel),
                     cJSON_GetObjectItemCaseSensitive(root, "channel")) ||
        !copy_string(manifest->version, sizeof(manifest->version),
                     cJSON_GetObjectItemCaseSensitive(root, "version")) ||
        !copy_string(manifest->image_url, sizeof(manifest->image_url),
                     cJSON_GetObjectItemCaseSensitive(root, "image_url")) ||
        !copy_string(manifest->image_sha256_hex,
                     sizeof(manifest->image_sha256_hex),
                     cJSON_GetObjectItemCaseSensitive(root, "image_sha256")) ||
        !copy_string(
            manifest->reset_qualification_sha256_hex,
            sizeof(manifest->reset_qualification_sha256_hex),
            cJSON_GetObjectItemCaseSensitive(root,
                                             "reset_qualification_sha256")) ||
        !copy_string(manifest->signing_key_id,
                     sizeof(manifest->signing_key_id),
                     cJSON_GetObjectItemCaseSensitive(root, "signing_key_id"))) {
        return false;
    }

    if (!exact_uint(cJSON_GetObjectItemCaseSensitive(root, "release_sequence"),
                    1, INT32_MAX, &number)) {
        return false;
    }
    manifest->release_sequence = (uint32_t)number;
    if (!exact_uint(cJSON_GetObjectItemCaseSensitive(root, "secure_version"),
                    0, UINT32_MAX, &number)) {
        return false;
    }
    manifest->secure_version = (uint32_t)number;
    if (!exact_uint(cJSON_GetObjectItemCaseSensitive(root, "image_size"),
                    1024, INT32_MAX, &number)) {
        return false;
    }
    manifest->image_size = (size_t)number;
    if (!exact_uint(cJSON_GetObjectItemCaseSensitive(root, "not_before"),
                    1609459200ULL, 4102444800ULL, &number)) {
        return false;
    }
    manifest->not_before = (int64_t)number;
    if (!exact_uint(cJSON_GetObjectItemCaseSensitive(root, "expires_at"),
                    1609459200ULL, 4102444800ULL, &number)) {
        return false;
    }
    manifest->expires_at = (int64_t)number;

    const cJSON *algorithm =
        cJSON_GetObjectItemCaseSensitive(root, "signature_algorithm");
    if (!cJSON_IsString(algorithm) || !algorithm->valuestring ||
        strcmp(algorithm->valuestring, "ECDSA_P256_SHA256") != 0) {
        return false;
    }
    const cJSON *signature =
        cJSON_GetObjectItemCaseSensitive(root, "signature_b64url");
    if (!cJSON_IsString(signature) || !signature->valuestring ||
        !decode_base64url(signature->valuestring, manifest->signature,
                          sizeof(manifest->signature),
                          &manifest->signature_size) ||
        manifest->signature_size < 8) {
        return false;
    }

    return identifier_valid(manifest->release_id, 64) &&
           identifier_valid(manifest->project, 32) &&
           identifier_valid(manifest->board, 32) &&
           identifier_valid(manifest->channel, 32) &&
           version_valid(manifest->version) &&
           identifier_valid(manifest->signing_key_id, 64) &&
           sha256_hex_decode(manifest->image_sha256_hex,
                             manifest->image_sha256) &&
           sha256_hex_decode(manifest->reset_qualification_sha256_hex,
                             manifest->reset_qualification_sha256);
}

bool product_ota_manifest_parse(const char *json,
                                size_t json_size,
                                product_ota_manifest_t *manifest)
{
    if (!json || !manifest || json_size == 0 ||
        json_size > PRODUCT_OTA_MANIFEST_MAX_BYTES ||
        contains_escaped_nul(json, json_size)) {
        return false;
    }
    const char *end = NULL;
    cJSON *root = cJSON_ParseWithLengthOpts(json, json_size, &end, false);
    if (!root || !cJSON_IsObject(root) || !root_fields_exact(root)) {
        cJSON_Delete(root);
        return false;
    }
    const char *limit = json + json_size;
    while (end && end < limit && isspace((unsigned char)*end)) {
        ++end;
    }
    product_ota_manifest_t parsed = {0};
    const bool valid = end == limit && parse_fields(root, &parsed) &&
                       product_ota_url_has_authority(parsed.image_url, NULL);
    cJSON_Delete(root);
    if (!valid) {
        return false;
    }
    *manifest = parsed;
    return true;
}

bool product_ota_manifest_canonicalize(
    const product_ota_manifest_t *manifest,
    char *output,
    size_t output_size,
    size_t *written)
{
    if (!manifest || !output || output_size == 0 || !written) {
        return false;
    }
    const int size = snprintf(
        output, output_size,
        "xiaozhi-product-ota-v2\n"
        "board=%s\n"
        "channel=%s\n"
        "expires_at=%" PRId64 "\n"
        "image_sha256=%s\n"
        "image_size=%zu\n"
        "image_url=%s\n"
        "not_before=%" PRId64 "\n"
        "project=%s\n"
        "release_id=%s\n"
        "release_sequence=%" PRIu32 "\n"
        "reset_qualification_sha256=%s\n"
        "schema=%" PRIu32 "\n"
        "secure_version=%" PRIu32 "\n"
        "signature_algorithm=ECDSA_P256_SHA256\n"
        "signing_key_id=%s\n"
        "version=%s\n",
        manifest->board, manifest->channel, manifest->expires_at,
        manifest->image_sha256_hex, manifest->image_size,
        manifest->image_url, manifest->not_before, manifest->project,
        manifest->release_id, manifest->release_sequence,
        manifest->reset_qualification_sha256_hex, manifest->schema,
        manifest->secure_version, manifest->signing_key_id,
        manifest->version);
    if (size < 0 || (size_t)size >= output_size) {
        return false;
    }
    *written = (size_t)size;
    return true;
}

static bool ascii_case_equal_n(const char *left,
                               const char *right,
                               size_t size)
{
    for (size_t index = 0; index < size; ++index) {
        const unsigned char a = (unsigned char)left[index];
        const unsigned char b = (unsigned char)right[index];
        if (tolower(a) != tolower(b)) {
            return false;
        }
    }
    return true;
}

bool product_ota_url_has_authority(const char *url,
                                   const char *allowed_authority)
{
    static const char scheme[] = "https://";
    if (!url || strncmp(url, scheme, sizeof(scheme) - 1) != 0) {
        return false;
    }
    const char *authority = url + sizeof(scheme) - 1;
    const char *path = strchr(authority, '/');
    if (!path || path == authority || path[1] == '\0') {
        return false;
    }
    const size_t authority_size = (size_t)(path - authority);
    if (authority_size > PRODUCT_OTA_AUTHORITY_MAX ||
        memchr(authority, '@', authority_size) ||
        memchr(authority, '\\', authority_size) ||
        strchr(path, '?') || strchr(path, '#')) {
        return false;
    }

    const char *colon = memchr(authority, ':', authority_size);
    const size_t host_size = colon ? (size_t)(colon - authority)
                                   : authority_size;
    if (host_size == 0 || authority[0] == '.' ||
        authority[host_size - 1] == '.') {
        return false;
    }
    size_t label_size = 0;
    for (size_t index = 0; index < host_size; ++index) {
        const unsigned char byte = (unsigned char)authority[index];
        if (byte == '.') {
            if (label_size == 0 || label_size > 63 ||
                authority[index - 1] == '-') {
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
    if (label_size == 0 || label_size > 63 ||
        authority[host_size - 1] == '-') {
        return false;
    }
    if (colon) {
        const size_t port_offset = host_size + 1;
        if (port_offset >= authority_size ||
            memchr(authority + port_offset, ':',
                   authority_size - port_offset)) {
            return false;
        }
        uint32_t port = 0;
        for (size_t index = port_offset; index < authority_size; ++index) {
            const unsigned char byte = (unsigned char)authority[index];
            if (!isdigit(byte)) {
                return false;
            }
            port = port * 10U + (uint32_t)(byte - '0');
            if (port > 65535U) {
                return false;
            }
        }
        if (port == 0U) {
            return false;
        }
    }
    for (const char *cursor = path; *cursor; ++cursor) {
        const unsigned char byte = (unsigned char)*cursor;
        if (byte <= 0x20 || byte >= 0x7f || byte == '\\') {
            return false;
        }
    }
    if (!allowed_authority) {
        return true;
    }
    const size_t allowed_size = strlen(allowed_authority);
    return allowed_size == authority_size && allowed_size > 0 &&
           ascii_case_equal_n(authority, allowed_authority, authority_size);
}

bool product_ota_manifest_validate_policy(
    const product_ota_manifest_t *manifest,
    const product_ota_policy_t *policy)
{
    if (!manifest || !policy || !policy->project || !policy->board ||
        !policy->channel || !policy->allowed_image_authority ||
        policy->authenticated_time < 1609459200LL ||
        policy->authenticated_time > 4102444800LL ||
        policy->maximum_image_size < 1024) {
        return false;
    }
    if (strcmp(manifest->project, policy->project) != 0 ||
        strcmp(manifest->board, policy->board) != 0 ||
        strcmp(manifest->channel, policy->channel) != 0 ||
        manifest->release_sequence <= policy->current_release_sequence ||
        manifest->secure_version < policy->current_secure_version ||
        manifest->image_size > policy->maximum_image_size ||
        manifest->expires_at <= manifest->not_before ||
        manifest->expires_at - manifest->not_before >
            PRODUCT_OTA_MANIFEST_MAX_VALIDITY_SECONDS ||
        policy->authenticated_time < manifest->not_before ||
        policy->authenticated_time > manifest->expires_at ||
        !product_ota_url_has_authority(manifest->image_url,
                                       policy->allowed_image_authority)) {
        return false;
    }
    return true;
}

bool product_ota_health_satisfied(uint32_t passed, uint32_t required)
{
    const uint32_t known = (1U << 5) - 1U;
    return required != 0 && (required & ~known) == 0 &&
           (passed & required) == required;
}
