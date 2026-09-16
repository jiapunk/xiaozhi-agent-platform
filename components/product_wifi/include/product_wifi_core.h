#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PRODUCT_WIFI_STATE_STOPPED = 0,
    PRODUCT_WIFI_STATE_UNPROVISIONED,
    PRODUCT_WIFI_STATE_ONBOARDING,
    PRODUCT_WIFI_STATE_CONNECTING,
    PRODUCT_WIFI_STATE_ONLINE,
    PRODUCT_WIFI_STATE_BACKOFF,
    PRODUCT_WIFI_STATE_CREDENTIAL_REJECTED,
    PRODUCT_WIFI_STATE_FATAL,
} product_wifi_state_t;

typedef enum {
    PRODUCT_WIFI_ACTION_NONE = 0,
    PRODUCT_WIFI_ACTION_START_STATION = 1U << 0,
    PRODUCT_WIFI_ACTION_CONNECT = 1U << 1,
    PRODUCT_WIFI_ACTION_STOP_STATION = 1U << 2,
    PRODUCT_WIFI_ACTION_NETWORK_UP = 1U << 3,
    PRODUCT_WIFI_ACTION_NETWORK_DOWN = 1U << 4,
    PRODUCT_WIFI_ACTION_REQUIRE_ONBOARDING = 1U << 5,
    PRODUCT_WIFI_ACTION_START_CANDIDATE = 1U << 6,
    PRODUCT_WIFI_ACTION_REJECT_CANDIDATE = 1U << 7,
    PRODUCT_WIFI_ACTION_RESTART_STATION = 1U << 8,
} product_wifi_action_t;

typedef struct {
    uint32_t minimum_backoff_ms;
    uint32_t maximum_backoff_ms;
    uint32_t authentication_failure_limit;
} product_wifi_core_config_t;

typedef struct {
    product_wifi_state_t state;
    uint32_t minimum_backoff_ms;
    uint32_t maximum_backoff_ms;
    uint32_t authentication_failure_limit;
    uint32_t consecutive_failures;
    uint32_t consecutive_authentication_failures;
    uint64_t retry_at_ms;
    bool has_credentials;
    bool station_started;
    bool network_available;
    bool onboarding_active;
    bool candidate_credentials;
} product_wifi_core_t;

bool product_wifi_core_init(product_wifi_core_t *core,
                            const product_wifi_core_config_t *config);

product_wifi_action_t product_wifi_core_start(product_wifi_core_t *core,
                                              bool has_credentials);

product_wifi_action_t product_wifi_core_station_started(
    product_wifi_core_t *core);

product_wifi_action_t product_wifi_core_got_ip(product_wifi_core_t *core);

product_wifi_action_t product_wifi_core_disconnected(
    product_wifi_core_t *core,
    bool authentication_failure,
    uint64_t now_ms,
    uint32_t random_value);

product_wifi_action_t product_wifi_core_poll(product_wifi_core_t *core,
                                             uint64_t now_ms);

/*
 * Restarts only the station radio after prolonged transient loss. Stored
 * credentials are retained and onboarding is never opened implicitly.
 */
product_wifi_action_t product_wifi_core_recover_station(
    product_wifi_core_t *core);

product_wifi_action_t product_wifi_core_begin_onboarding(
    product_wifi_core_t *core);

product_wifi_action_t product_wifi_core_candidate_submitted(
    product_wifi_core_t *core);

product_wifi_action_t product_wifi_core_credentials_cleared(
    product_wifi_core_t *core);

/* Close the explicit onboarding window, retaining a validated connection. */
product_wifi_action_t product_wifi_core_finish_onboarding(
    product_wifi_core_t *core);

product_wifi_action_t product_wifi_core_stop(product_wifi_core_t *core);

product_wifi_action_t product_wifi_core_fatal(product_wifi_core_t *core);

uint32_t product_wifi_core_wait_ms(const product_wifi_core_t *core,
                                   uint64_t now_ms,
                                   uint32_t ceiling_ms);

#ifdef __cplusplus
}
#endif
