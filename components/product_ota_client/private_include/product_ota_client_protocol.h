#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    PRODUCT_OTA_CLIENT_ENDPOINT_MAX = 512,
    PRODUCT_OTA_CLIENT_RESPONSE_MAX = 14336,
    PRODUCT_OTA_CLIENT_MANIFEST_MAX = 8192,
    PRODUCT_OTA_CLIENT_TOKEN_MAX = 2048,
    PRODUCT_OTA_CLIENT_CANONICAL_MAX = 768,
    PRODUCT_OTA_CLIENT_NONCE_BYTES = 16,
    PRODUCT_OTA_CLIENT_SIGNATURE_BYTES = 32,
};

typedef enum {
    PRODUCT_OTA_CLIENT_OFFER_AVAILABLE = 1,
    PRODUCT_OTA_CLIENT_OFFER_UP_TO_DATE = 2,
    PRODUCT_OTA_CLIENT_OFFER_DEFERRED = 3,
} product_ota_client_offer_status_t;

bool product_ota_client_endpoint_valid(const char *endpoint);

bool product_ota_client_safe_identifier(const char *value, size_t maximum);

bool product_ota_client_safe_version(const char *value);

bool product_ota_client_base64url_encode(
    const uint8_t *input,
    size_t input_size,
    char *output,
    size_t output_size);

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
    size_t output_size);

/* json must provide writable storage at json[json_size]. */
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
    uint32_t *retry_after_seconds);
