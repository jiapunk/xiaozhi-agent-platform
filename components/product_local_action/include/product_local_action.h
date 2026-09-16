#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "driver/gpio.h"
#include "esp_err.h"
#include "product_local_action_core.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct product_local_action *product_local_action_handle_t;

typedef enum {
    PRODUCT_LOCAL_ACTION_EVENT_ARMED = 0,
    PRODUCT_LOCAL_ACTION_EVENT_PRESS_STARTED,
    PRODUCT_LOCAL_ACTION_EVENT_SHORT_PRESS,
    PRODUCT_LOCAL_ACTION_EVENT_LONG_PRESS,
    PRODUCT_LOCAL_ACTION_EVENT_FACTORY_RESET,
    PRODUCT_LOCAL_ACTION_EVENT_RELEASED,
    PRODUCT_LOCAL_ACTION_EVENT_ERROR,
} product_local_action_event_type_t;

typedef struct {
    product_local_action_event_type_t type;
    esp_err_t error;
    bool armed;
    bool pressed;
    uint32_t held_ms;
} product_local_action_event_t;

typedef void (*product_local_action_event_fn)(
    void *ctx,
    const product_local_action_event_t *event);

typedef enum {
    PRODUCT_LOCAL_ACTION_ONBOARDING = 1,
    PRODUCT_LOCAL_ACTION_FACTORY_RESET = 2,
} product_local_action_kind_t;

/* Called from the dedicated polling task, never from a GPIO ISR. */
typedef esp_err_t (*product_local_action_trigger_fn)(
    void *ctx,
    product_local_action_kind_t action);

typedef struct {
    gpio_num_t gpio_num;
    bool active_high;
    product_local_action_trigger_fn trigger;
    void *trigger_ctx;
    product_local_action_event_fn event;
    void *event_ctx;

    /* Zero selects 10 ms / 50 ms / 3 seconds / 10 seconds. */
    uint32_t sample_period_ms;
    uint32_t debounce_ms;
    uint32_t long_press_ms;
    uint32_t factory_reset_press_ms;

    /* Zero selects 3072 bytes and priority 4. */
    uint32_t task_stack_size;
    uint32_t task_priority;
} product_local_action_config_t;

typedef struct {
    bool started;
    bool armed;
    bool pressed;
    uint32_t presses;
    uint32_t short_presses;
    uint32_t long_presses;
    uint32_t factory_resets;
    uint32_t clock_resets;
    uint32_t trigger_failures;
    esp_err_t last_error;
} product_local_action_stats_t;

/* Configures one input owner but does not begin sampling. */
esp_err_t product_local_action_create(
    const product_local_action_config_t *config,
    product_local_action_handle_t *out_action);

esp_err_t product_local_action_start(product_local_action_handle_t action);

esp_err_t product_local_action_get_stats(
    product_local_action_handle_t action,
    product_local_action_stats_t *stats);

/* ESP_OK consumes the handle; timeout retains it for an exact retry. */
esp_err_t product_local_action_destroy(
    product_local_action_handle_t action,
    uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif
