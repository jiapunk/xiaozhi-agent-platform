#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    PRODUCT_TIME_BOOTSTRAP_SERVER_LIMIT = 3,
    PRODUCT_TIME_BOOTSTRAP_SERVER_BYTES = 254,
};

typedef struct product_time_bootstrap *product_time_bootstrap_handle_t;

typedef struct {
    bool approximate_time_available;
    esp_err_t error;
    uint32_t attempts;
    uint32_t retry_in_ms;
} product_time_bootstrap_event_t;

typedef void (*product_time_bootstrap_event_fn)(
    void *ctx,
    const product_time_bootstrap_event_t *event);

typedef struct {
    const char *servers[PRODUCT_TIME_BOOTSTRAP_SERVER_LIMIT];
    size_t server_count;
    product_time_bootstrap_event_fn event;
    void *event_ctx;

    /* Zero selects 10 s, 5 s, 5 min, 4096 bytes, and priority 4. */
    uint32_t sync_timeout_ms;
    uint32_t minimum_backoff_ms;
    uint32_t maximum_backoff_ms;
    uint32_t task_stack_size;
    uint32_t task_priority;
} product_time_bootstrap_config_t;

typedef struct {
    bool network_available;
    bool approximate_time_available;
    uint32_t attempts;
    uint32_t failures;
    uint32_t retries;
    esp_err_t last_error;
} product_time_bootstrap_stats_t;

/*
 * This service sets only the process/system clock so CA validity checks can
 * run. SNTP is not authenticated product time and is never passed to the
 * protected device identity. One product owner may use esp-netif SNTP.
 */
esp_err_t product_time_bootstrap_create(
    const product_time_bootstrap_config_t *config,
    product_time_bootstrap_handle_t *out_bootstrap);

/* Nonblocking; the worker performs bounded synchronization and retry. */
esp_err_t product_time_bootstrap_set_network_available(
    product_time_bootstrap_handle_t bootstrap,
    bool available);

esp_err_t product_time_bootstrap_get_stats(
    product_time_bootstrap_handle_t bootstrap,
    product_time_bootstrap_stats_t *stats);

/* ESP_OK consumes the handle; timeout retains it for an exact retry. */
esp_err_t product_time_bootstrap_destroy(
    product_time_bootstrap_handle_t bootstrap,
    uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif
