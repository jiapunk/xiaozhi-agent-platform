#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "box3_agent_supervisor.h"
#include "esp_err.h"
#include "product_local_action.h"
#include "product_provisioning.h"
#include "product_time_bootstrap.h"
#include "product_wifi.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct box3_product_runtime *box3_product_runtime_handle_t;

typedef enum {
    BOX3_PRODUCT_RUNTIME_STARTING = 0,
    BOX3_PRODUCT_RUNTIME_WAIT_NETWORK,
    BOX3_PRODUCT_RUNTIME_ONBOARDING_REQUIRED,
    BOX3_PRODUCT_RUNTIME_ONBOARDING,
    BOX3_PRODUCT_RUNTIME_ONLINE,
    BOX3_PRODUCT_RUNTIME_ENTITLEMENT_REQUIRED,
    BOX3_PRODUCT_RUNTIME_DEGRADED,
    BOX3_PRODUCT_RUNTIME_STOPPING,
} box3_product_runtime_state_t;

typedef enum {
    BOX3_PRODUCT_RUNTIME_EVENT_STATE_CHANGED = 0,
    BOX3_PRODUCT_RUNTIME_EVENT_WIFI,
    BOX3_PRODUCT_RUNTIME_EVENT_PROVISIONING,
    BOX3_PRODUCT_RUNTIME_EVENT_TIME_BOOTSTRAP,
    BOX3_PRODUCT_RUNTIME_EVENT_SUPERVISOR,
    BOX3_PRODUCT_RUNTIME_EVENT_LOCAL_ACTION,
    BOX3_PRODUCT_RUNTIME_EVENT_ERROR,
} box3_product_runtime_event_type_t;

typedef struct {
    box3_product_runtime_event_type_t type;
    box3_product_runtime_state_t state;
    esp_err_t error;
    bool network_available;
    bool onboarding_required;
    bool approximate_time_available;
    bool local_action_armed;
    bool local_action_pressed;
    uint32_t local_action_held_ms;
    product_wifi_event_type_t wifi_event;
    product_provisioning_event_type_t provisioning_event;
    product_local_action_event_type_t local_action_event;
    box3_agent_supervisor_state_t supervisor_state;
} box3_product_runtime_event_t;

typedef void (*box3_product_runtime_event_fn)(
    void *ctx,
    const box3_product_runtime_event_t *event);

typedef struct {
    /* Must match the factory registry. Product builds derive xz-<base-mac>. */
    const char *device_id;
    /* New random safe identifier for each boot; not a credential. */
    const char *client_id;
    const char *hostname;
    uint8_t identity_hmac_key_id;

    /* Exact https://authority; runtime owns time/token/session/claim paths. */
    const char *control_authority;
    const char *control_server_cert_pem;
    bool control_use_crt_bundle;
    uint32_t control_network_timeout_ms;

    /*
     * Exact-action approval waits at most this long. Zero selects 20 s.
     * Polling is local-state/cancellation aware and every HTTPS request is
     * capped by the remaining deadline. Zero poll interval selects 500 ms.
     */
    uint32_t action_consent_timeout_ms;
    uint32_t action_consent_poll_interval_ms;

    /* Exact https://authority; the runtime supplies the exact /v1 prefix. */
    const char *agent_proxy_authority;

    /* Unauthenticated availability bootstrap; never trusted by identity. */
    const char *sntp_servers[PRODUCT_TIME_BOOTSTRAP_SERVER_LIMIT];
    size_t sntp_server_count;
    uint32_t sntp_sync_timeout_ms;

    /*
     * Static BOX-3 template. The runtime fills websocket.device_id/client_id
     * and agent.base_url; websocket.uri/bearer_token, agent.api_key, and
     * agent.base_url must remain NULL. Product callback contexts, Agent
     * memory, and consent state are caller-owned.
     */
    box3_agent_voice_config_t product;

    /* Zero selects lower-component product defaults. */
    uint32_t supervisor_minimum_backoff_ms;
    uint32_t supervisor_maximum_backoff_ms;
    uint32_t supervisor_refresh_margin_seconds;
    uint32_t product_stop_timeout_ms;
    uint32_t wifi_minimum_backoff_ms;
    uint32_t wifi_maximum_backoff_ms;
    uint32_t wifi_authentication_failure_limit;
    uint32_t provisioning_window_ms;
    uint32_t provisioning_authentication_failure_limit;

    /*
     * Sole owner of the reviewed physical onboarding input. A boot-held input
     * cannot trigger; a debounced release must arm it first.
     */
    gpio_num_t onboarding_button_gpio;
    bool onboarding_button_active_high;
    uint32_t onboarding_button_sample_period_ms;
    uint32_t onboarding_button_debounce_ms;
    uint32_t onboarding_button_long_press_ms;
    uint32_t onboarding_button_factory_reset_press_ms;

    box3_product_runtime_event_fn event;
    void *event_ctx;
} box3_product_runtime_config_t;

typedef struct {
    box3_product_runtime_state_t state;
    uint32_t cleanup_retries;
    product_wifi_stats_t wifi;
    product_time_bootstrap_stats_t time_bootstrap;
    product_provisioning_stats_t provisioning;
    product_local_action_stats_t local_action;
    box3_agent_supervisor_stats_t supervisor;
    uint32_t action_consents_requested;
    uint32_t action_consents_registered;
    uint32_t action_consents_approved;
    uint32_t action_consents_denied;
    uint32_t action_consents_expired;
    uint32_t action_consents_canceled;
    uint32_t action_consents_failed;
} box3_product_runtime_stats_t;

/*
 * Creates the complete identity -> control plane -> credential -> supervisor
 * -> approximate time -> Wi-Fi -> provisioning -> local-action graph. ESP_OK
 * returns a live handle waiting for network. On startup failure, out_runtime
 * is NULL unless fail-safe cleanup timed out; a retained handle must then be
 * passed to stop().
 */
esp_err_t box3_product_runtime_start(
    const box3_product_runtime_config_t *config,
    box3_product_runtime_handle_t *out_runtime);

/*
 * Call only from the product's reviewed physical-presence/button owner. The
 * one-use grant is consumed synchronously by product_provisioning_open().
 */
esp_err_t box3_product_runtime_open_onboarding(
    box3_product_runtime_handle_t runtime);

esp_err_t box3_product_runtime_close_onboarding(
    box3_product_runtime_handle_t runtime);

esp_err_t box3_product_runtime_interrupt(
    box3_product_runtime_handle_t runtime,
    agent_bridge_interrupt_reason_t reason);

/* Call after the product has authenticated a service-entitlement change. */
esp_err_t box3_product_runtime_entitlement_changed(
    box3_product_runtime_handle_t runtime);

esp_err_t box3_product_runtime_get_stats(
    box3_product_runtime_handle_t runtime,
    box3_product_runtime_stats_t *stats);

/*
 * Lifecycle owner only; do not race with callbacks or other public APIs.
 * ESP_OK consumes the handle. Any failure retains it for an exact retry.
 */
esp_err_t box3_product_runtime_stop(
    box3_product_runtime_handle_t runtime,
    uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif
