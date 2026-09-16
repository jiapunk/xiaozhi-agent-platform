#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    PRODUCT_OTA_MANIFEST_MAX_BYTES = 8192,
    PRODUCT_OTA_CANONICAL_MAX_BYTES = 2048,
    PRODUCT_OTA_SIGNATURE_MAX_BYTES = 80,
    PRODUCT_OTA_IMAGE_URL_MAX = 512,
    PRODUCT_OTA_AUTHORITY_MAX = 253,
    PRODUCT_OTA_MANIFEST_MAX_VALIDITY_SECONDS = 30 * 24 * 60 * 60,
};

typedef struct {
    uint32_t schema;
    char release_id[65];
    char project[33];
    char board[33];
    char channel[33];
    char version[33];
    uint32_t release_sequence;
    uint32_t secure_version;
    char image_url[PRODUCT_OTA_IMAGE_URL_MAX + 1];
    size_t image_size;
    char image_sha256_hex[65];
    uint8_t image_sha256[32];
    char reset_qualification_sha256_hex[65];
    uint8_t reset_qualification_sha256[32];
    int64_t not_before;
    int64_t expires_at;
    char signing_key_id[65];
    uint8_t signature[PRODUCT_OTA_SIGNATURE_MAX_BYTES];
    size_t signature_size;
} product_ota_manifest_t;

typedef struct {
    const char *project;
    const char *board;
    const char *channel;
    const char *allowed_image_authority;
    uint32_t current_release_sequence;
    uint32_t current_secure_version;
    int64_t authenticated_time;
    size_t maximum_image_size;
} product_ota_policy_t;

bool product_ota_manifest_parse(const char *json,
                                size_t json_size,
                                product_ota_manifest_t *manifest);

bool product_ota_manifest_canonicalize(
    const product_ota_manifest_t *manifest,
    char *output,
    size_t output_size,
    size_t *written);

bool product_ota_manifest_validate_policy(
    const product_ota_manifest_t *manifest,
    const product_ota_policy_t *policy);

bool product_ota_url_has_authority(const char *url,
                                   const char *allowed_authority);

bool product_ota_health_satisfied(uint32_t passed, uint32_t required);
