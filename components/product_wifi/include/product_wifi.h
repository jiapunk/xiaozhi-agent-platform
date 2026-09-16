#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "product_wifi_core.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    PRODUCT_WIFI_HOSTNAME_MAX = 32,
    PRODUCT_WIFI_SOFTAP_SSID_MAX = 32,
    PRODUCT_WIFI_SOFTAP_PASSWORD_MIN = 8,
    PRODUCT_WIFI_SOFTAP_PASSWORD_MAX = 63,
    PRODUCT_WIFI_DEVICE_CLAIM_MAX = 43,
    PRODUCT_WIFI_NETWORK_SSID_MAX = 32,
    PRODUCT_WIFI_SCAN_RESULT_LIMIT = 16,
    PRODUCT_WIFI_SAVED_NETWORK_LIMIT = 5,
};

typedef struct product_wifi *product_wifi_handle_t;

typedef enum {
    PRODUCT_WIFI_EVENT_STATE_CHANGED = 0,
    PRODUCT_WIFI_EVENT_NETWORK_CHANGED,
    PRODUCT_WIFI_EVENT_ONBOARDING_REQUIRED,
    PRODUCT_WIFI_EVENT_CREDENTIALS_ACCEPTED,
    PRODUCT_WIFI_EVENT_CREDENTIALS_REJECTED,
    PRODUCT_WIFI_EVENT_CREDENTIALS_CLEARED,
    PRODUCT_WIFI_EVENT_ONBOARDING_TRANSPORT_CHANGED,
    PRODUCT_WIFI_EVENT_ERROR,
} product_wifi_event_type_t;

typedef struct {
    char ssid[PRODUCT_WIFI_SOFTAP_SSID_MAX + 1];
    char password[PRODUCT_WIFI_SOFTAP_PASSWORD_MAX + 1];
    /* Zero selects channel 1. Valid explicit range is 1..13. */
    uint8_t channel;
} product_wifi_softap_config_t;

typedef struct {
    char ssid[PRODUCT_WIFI_NETWORK_SSID_MAX + 1];
    int8_t rssi;
    bool secured;
} product_wifi_scan_result_t;

typedef struct {
    product_wifi_event_type_t type;
    product_wifi_state_t state;
    bool network_available;
    bool onboarding_required;
    uint32_t retry_in_ms;
    uint16_t disconnect_reason;
    esp_err_t error;
} product_wifi_event_t;

/* Called only from the product Wi-Fi worker; never from the ESP event loop. */
typedef void (*product_wifi_event_fn)(void *ctx,
                                     const product_wifi_event_t *event);

typedef struct {
    /* Safe DHCP hostname: ASCII letters, digits, or '-' only. */
    const char *hostname;
    product_wifi_event_fn event;
    void *event_ctx;

    /* Zero selects 2 s / 5 min / 3 defaults. */
    uint32_t minimum_backoff_ms;
    uint32_t maximum_backoff_ms;
    uint32_t authentication_failure_limit;

    /* Zero selects 6144 bytes and priority 4. */
    uint32_t task_stack_size;
    uint32_t task_priority;
} product_wifi_config_t;

typedef struct {
    product_wifi_state_t state;
    bool started;
    bool network_available;
    bool has_credentials;
    bool onboarding_active;
    bool onboarding_softap_active;
    uint8_t saved_networks;
    uint32_t reconnects;
    uint32_t station_recoveries;
    uint32_t authentication_failures;
    uint32_t queue_overflows;
    uint32_t onboarding_entries;
    uint32_t credential_updates;
    uint32_t candidate_rejections;
    bool device_claim_pending;
    uint32_t device_claims_committed;
    uint32_t device_claims_completed;
    uint32_t device_claims_abandoned;
    uint16_t last_disconnect_reason;
    esp_err_t last_error;
} product_wifi_stats_t;

esp_err_t product_wifi_create(const product_wifi_config_t *config,
                              product_wifi_handle_t *out_wifi);

esp_err_t product_wifi_start(product_wifi_handle_t wifi);

/*
 * Only the physical-presence/button owner may call this. No AP, BLE service,
 * or web portal is started automatically by this component.
 */
esp_err_t product_wifi_begin_onboarding(product_wifi_handle_t wifi);

/* Starts a WPA2-only, one-client SoftAP while explicit onboarding is active. */
esp_err_t product_wifi_start_onboarding_softap(
    product_wifi_handle_t wifi,
    const product_wifi_softap_config_t *config);

/*
 * Scans nearby 2.4 GHz networks only while the explicit onboarding SoftAP is
 * open. Results are strongest-first, deduplicated by SSID, and never include
 * credentials. The caller supplies space for at most 16 results.
 */
esp_err_t product_wifi_scan_networks(
    product_wifi_handle_t wifi,
    product_wifi_scan_result_t *results,
    size_t result_capacity,
    size_t *result_count);

/* Accepted only after begin_onboarding; credentials are copied and wiped. */
esp_err_t product_wifi_submit_credentials(product_wifi_handle_t wifi,
                                          const char *ssid,
                                          const char *password);

/*
 * Product onboarding must use this variant. Once the candidate obtains IP,
 * credentials and the exact one-time claim are committed as one encrypted NVS
 * blob so a restart can safely resume the ownership handshake.
 */
esp_err_t product_wifi_submit_claimed_credentials(
    product_wifi_handle_t wifi,
    const char *ssid,
    const char *password,
    const char *device_claim);

/* Copies the boot/current recovery claim; ESP_ERR_NOT_FOUND means none. */
esp_err_t product_wifi_get_pending_device_claim(
    product_wifi_handle_t wifi,
    char output[PRODUCT_WIFI_DEVICE_CLAIM_MAX + 1]);

/*
 * Both APIs compare the exact pending claim before changing storage. Complete
 * follows an authenticated "bound" response; abandon follows a terminal
 * control-plane rejection and requires a new physical onboarding window.
 */
esp_err_t product_wifi_complete_device_claim(
    product_wifi_handle_t wifi,
    const char *device_claim);

esp_err_t product_wifi_abandon_device_claim(
    product_wifi_handle_t wifi,
    const char *device_claim);

/* Accepted only while onboarding; erases only the product Wi-Fi NVS key. */
esp_err_t product_wifi_clear_credentials(product_wifi_handle_t wifi);

/*
 * Closes the onboarding radio. A validated candidate remains online; otherwise
 * the previous persisted credentials are restored, if any.
 */
esp_err_t product_wifi_finish_onboarding(product_wifi_handle_t wifi);

esp_err_t product_wifi_get_stats(product_wifi_handle_t wifi,
                                 product_wifi_stats_t *stats);

/*
 * Self-healing hook for a product supervisor after prolonged transient loss.
 * It preserves credentials, performs a full all-channel station-radio restart,
 * and is rejected while online, onboarding, stopped, or fatally failed.
 */
esp_err_t product_wifi_recover_station(product_wifi_handle_t wifi);

/*
 * Must not be called from the event callback. ESP_OK consumes the handle;
 * timeout retains it for a later retry. Concurrent lifecycle calls are invalid.
 */
esp_err_t product_wifi_stop(product_wifi_handle_t wifi, uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif
