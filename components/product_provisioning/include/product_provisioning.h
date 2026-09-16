#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "product_provisioning_core.h"
#include "product_wifi.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct product_provisioning *product_provisioning_handle_t;

/* Must verify the product-specific long-press or equivalent local action. */
typedef esp_err_t (*product_provisioning_physical_presence_fn)(void *ctx);

/*
 * Derives exactly the fixed onboarding AP-key domain for service_name. The
 * implementation must not expose a generic signing primitive.
 */
typedef esp_err_t (*product_provisioning_derive_ap_key_fn)(
    void *ctx,
    const char *service_name,
    uint8_t output[32]);

typedef enum {
    PRODUCT_PROVISIONING_CLAIM_RETRY = 0,
    PRODUCT_PROVISIONING_CLAIM_BOUND,
    PRODUCT_PROVISIONING_CLAIM_REJECTED,
} product_provisioning_claim_outcome_t;

/* Publishes the one-time claim with a device-authenticated control-plane proof. */
typedef esp_err_t (*product_provisioning_publish_claim_fn)(
    void *ctx,
    const char *claim,
    product_provisioning_claim_outcome_t *outcome);

typedef enum {
    PRODUCT_PROVISIONING_EVENT_STATE_CHANGED = 0,
    PRODUCT_PROVISIONING_EVENT_WINDOW_OPENED,
    PRODUCT_PROVISIONING_EVENT_CANDIDATE_ACCEPTED,
    PRODUCT_PROVISIONING_EVENT_CANDIDATE_REJECTED,
    PRODUCT_PROVISIONING_EVENT_CLAIM_DISCLOSED,
    PRODUCT_PROVISIONING_EVENT_CLAIM_BOUND,
    PRODUCT_PROVISIONING_EVENT_CLAIM_RECOVERED,
    PRODUCT_PROVISIONING_EVENT_CLAIM_RECOVERY_REQUIRED,
    PRODUCT_PROVISIONING_EVENT_WINDOW_CLOSED,
    PRODUCT_PROVISIONING_EVENT_LOCKED_OUT,
    PRODUCT_PROVISIONING_EVENT_ERROR,
} product_provisioning_event_type_t;

typedef struct {
    product_provisioning_event_type_t type;
    product_provisioning_state_t state;
    esp_err_t error;
} product_provisioning_event_t;

typedef void (*product_provisioning_event_fn)(
    void *ctx,
    const product_provisioning_event_t *event);

typedef struct {
    product_wifi_handle_t wifi;
    product_provisioning_physical_presence_fn physical_presence;
    void *physical_presence_ctx;
    product_provisioning_derive_ap_key_fn derive_ap_key;
    void *derive_ap_key_ctx;
    const char *device_id;
    product_provisioning_publish_claim_fn publish_claim;
    void *publish_claim_ctx;
    product_provisioning_event_fn event;
    void *event_ctx;

    /* Zero selects 5 minutes / 5 failures / 500 ms / 5 seconds. */
    uint32_t window_ms;
    uint32_t authentication_failure_limit;
    uint32_t commit_delay_ms;
    uint32_t success_grace_ms;

    /* Zero selects 7168 bytes and priority 4. */
    uint32_t task_stack_size;
    uint32_t task_priority;
} product_provisioning_config_t;

typedef struct {
    product_provisioning_state_t state;
    bool window_open;
    bool transport_active;
    uint32_t windows_opened;
    uint32_t authentication_failures;
    uint32_t candidates_submitted;
    uint32_t candidates_accepted;
    uint32_t candidates_rejected;
    uint32_t lockouts;
    uint32_t claims_disclosed;
    uint32_t claim_publish_attempts;
    uint32_t claims_bound;
    uint32_t claim_publish_failures;
    uint32_t claim_recovery_attempts;
    uint32_t claims_recovered;
    uint32_t claim_recovery_rejections;
    esp_err_t last_error;
} product_provisioning_stats_t;

esp_err_t product_provisioning_create(
    const product_provisioning_config_t *config,
    product_provisioning_handle_t *out_provisioning);

/* Fails unless physical_presence confirms a current local action. */
esp_err_t product_provisioning_open(product_provisioning_handle_t provisioning);

esp_err_t product_provisioning_close(product_provisioning_handle_t provisioning);

esp_err_t product_provisioning_get_stats(
    product_provisioning_handle_t provisioning,
    product_provisioning_stats_t *stats);

/* Timeout retains the handle for a later retry. */
esp_err_t product_provisioning_destroy(
    product_provisioning_handle_t provisioning,
    uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif
