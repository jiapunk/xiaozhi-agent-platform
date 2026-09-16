#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    PRODUCT_OTA_SHA256_SIZE = 32,
    PRODUCT_OTA_MAX_SIGNING_KEYS = 2,
    PRODUCT_OTA_HEALTH_STORAGE = 1U << 0,
    PRODUCT_OTA_HEALTH_NETWORK = 1U << 1,
    PRODUCT_OTA_HEALTH_CONTROL_PLANE = 1U << 2,
    PRODUCT_OTA_HEALTH_AGENT = 1U << 3,
    PRODUCT_OTA_HEALTH_AUDIO = 1U << 4,
};

typedef struct {
    const char *key_id;
    const char *public_key_pem;
} product_ota_signing_key_t;

typedef esp_err_t (*product_ota_get_time_fn)(void *ctx,
                                             int64_t *unix_seconds);

typedef enum {
    PRODUCT_OTA_EVENT_MANIFEST_ACCEPTED = 0,
    PRODUCT_OTA_EVENT_DOWNLOAD_STARTED,
    PRODUCT_OTA_EVENT_DOWNLOAD_PROGRESS,
    PRODUCT_OTA_EVENT_IMAGE_VERIFIED,
    PRODUCT_OTA_EVENT_READY_TO_REBOOT,
    PRODUCT_OTA_EVENT_FAILED,
} product_ota_event_t;

typedef void (*product_ota_event_fn)(void *ctx,
                                     product_ota_event_t event,
                                     size_t completed_bytes,
                                     size_t total_bytes,
                                     esp_err_t error);

typedef struct {
    const char *allowed_image_authority;
    product_ota_signing_key_t signing_keys[PRODUCT_OTA_MAX_SIGNING_KEYS];
    size_t signing_key_count;
    product_ota_get_time_fn get_authenticated_time;
    void *time_ctx;
    const char *server_cert_pem;
    uint32_t network_timeout_ms;
    product_ota_event_fn event;
    void *event_ctx;
} product_ota_config_t;

typedef struct {
    char release_id[65];
    char version[33];
    uint32_t release_sequence;
    uint32_t secure_version;
    size_t image_size;
    uint8_t image_sha256[PRODUCT_OTA_SHA256_SIZE];
    int64_t not_before;
    int64_t expires_at;
} product_ota_release_summary_t;

typedef struct {
    bool pending_verification;
    uint32_t required_health_checks;
    uint32_t running_partition_subtype;
} product_ota_boot_status_t;

/*
 * Verifies exact manifest syntax, target/channel/time/sequence policy, and an
 * ECDSA P-256/SHA-256 signature. No network or flash write occurs.
 */
esp_err_t product_ota_check_manifest(
    const product_ota_config_t *config,
    const char *manifest_json,
    size_t manifest_size,
    product_ota_release_summary_t *summary);

/*
 * Repeats manifest verification, downloads over verified HTTPS without
 * redirects, validates the image descriptor and exact body SHA-256, then
 * selects the passive OTA slot. The bearer token is copied only for this
 * blocking call and wiped before return.
 */
esp_err_t product_ota_install(const product_ota_config_t *config,
                              const char *manifest_json,
                              size_t manifest_size,
                              const char *bearer_token);

esp_err_t product_ota_get_boot_status(product_ota_boot_status_t *status);

uint32_t product_ota_required_health_checks(void);

/* Marks a PENDING_VERIFY image valid only after every compiled health gate. */
esp_err_t product_ota_confirm_running_image(uint32_t passed_health_checks);

/* Explicit fatal-health path; reboots to the previous valid image on success. */
esp_err_t product_ota_reject_running_image_and_reboot(void);

#ifdef __cplusplus
}
#endif
