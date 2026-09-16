#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "product_ota.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct product_ota_client *product_ota_client_handle_t;

typedef esp_err_t (*product_ota_client_sign_proof_fn)(
    void *ctx,
    const uint8_t *message,
    size_t message_size,
    uint8_t signature[32]);

typedef esp_err_t (*product_ota_client_get_time_fn)(
    void *ctx,
    int64_t *unix_seconds);

typedef struct {
    const char *offer_endpoint; /* Exact HTTPS /v1/ota/offer path. */
    const char *device_id;
    const char *client_id;

    /* Exactly one server verification source must be selected. */
    const char *server_cert_pem;
    bool use_crt_bundle;
    uint32_t network_timeout_ms; /* 0 selects 10 s; valid 1000..30000 ms. */

    /* Must accept only the OTA-offer proof domain. */
    product_ota_client_sign_proof_fn sign_ota_proof;
    void *sign_ctx;
    /* Use product-authenticated guarded time, optionally sync-on-demand. */
    product_ota_client_get_time_fn get_authenticated_time;
    void *time_ctx;
} product_ota_client_config_t;

typedef enum {
    PRODUCT_OTA_FLEET_AVAILABLE = 1,
    PRODUCT_OTA_FLEET_UP_TO_DATE = 2,
    PRODUCT_OTA_FLEET_DEFERRED = 3,
} product_ota_fleet_status_t;

typedef struct {
    /* Caller-owned buffers. The manifest needs at least 8193 bytes and the
     * token at least 2049 bytes to accept every bounded protocol value. */
    char *manifest;
    size_t manifest_capacity;
    char *download_token;
    size_t download_token_capacity;

    product_ota_fleet_status_t status;
    size_t manifest_size;
    uint32_t token_ttl_seconds;
    uint32_t retry_after_seconds;
    product_ota_release_summary_t release;
} product_ota_offer_t;

esp_err_t product_ota_client_create(
    const product_ota_client_config_t *config,
    product_ota_client_handle_t *out_client);

/*
 * Authenticates compiled board/channel/sequence/version state, obtains one
 * fleet decision, and re-verifies an available signed manifest locally before
 * exposing its short-lived download token.
 */
esp_err_t product_ota_client_fetch_offer(
    product_ota_client_handle_t client,
    const product_ota_config_t *ota_config,
    product_ota_offer_t *offer);

/* Wipes both caller buffers and result metadata while preserving pointers. */
void product_ota_client_clear_offer(product_ota_offer_t *offer);

/* Lifecycle owner must serialize destroy against fetch_offer. */
esp_err_t product_ota_client_destroy(product_ota_client_handle_t client);

#ifdef __cplusplus
}
#endif
