#include "product_local_action.h"

#include <stdatomic.h>
#include <stdlib.h>

#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"

enum {
    SIGNAL_READY = 1U << 0,
    SIGNAL_STOP = 1U << 1,
    SIGNAL_STOPPED = 1U << 2,
    DEFAULT_SAMPLE_PERIOD_MS = 10,
    DEFAULT_DEBOUNCE_MS = 50,
    DEFAULT_LONG_PRESS_MS = 3000,
    DEFAULT_FACTORY_RESET_PRESS_MS = 10000,
    DEFAULT_TASK_STACK_SIZE = 3072,
    DEFAULT_TASK_PRIORITY = 4,
    MAXIMUM_TASK_STACK_SIZE = 8192,
    START_TIMEOUT_MS = 5000,
};

struct product_local_action {
    gpio_num_t gpio_num;
    bool active_high;
    product_local_action_trigger_fn trigger;
    void *trigger_ctx;
    product_local_action_event_fn event;
    void *event_ctx;
    uint32_t sample_period_ms;
    uint32_t task_stack_size;
    uint32_t task_priority;
    product_local_action_core_t core;
    EventGroupHandle_t signals;
    TaskHandle_t worker;
    atomic_bool task_created;
    atomic_bool started;
    atomic_bool stopping;
    atomic_bool armed;
    atomic_bool pressed;
    atomic_uint presses;
    atomic_uint short_presses;
    atomic_uint long_presses;
    atomic_uint factory_resets;
    atomic_uint clock_resets;
    atomic_uint trigger_failures;
    atomic_int last_error;
};

static void secure_zero(void *memory, size_t size)
{
    volatile unsigned char *bytes = memory;
    while (bytes && size > 0) {
        *bytes++ = 0;
        --size;
    }
}

static bool stopping(product_local_action_handle_t action)
{
    return atomic_load_explicit(&action->stopping, memory_order_acquire);
}

static uint32_t bounded_held_ms(uint64_t held_ms)
{
    return held_ms > UINT32_MAX ? UINT32_MAX : (uint32_t)held_ms;
}

static void publish(product_local_action_handle_t action,
                    product_local_action_event_type_t type,
                    esp_err_t error,
                    uint32_t held_ms)
{
    atomic_store_explicit(&action->last_error, error,
                          memory_order_release);
    if (!action->event || stopping(action)) {
        return;
    }
    const product_local_action_event_t event = {
        .type = type,
        .error = error,
        .armed = atomic_load_explicit(&action->armed,
                                      memory_order_acquire),
        .pressed = atomic_load_explicit(&action->pressed,
                                        memory_order_acquire),
        .held_ms = held_ms,
    };
    action->event(action->event_ctx, &event);
}

static void handle_transition(
    product_local_action_handle_t action,
    product_local_action_transition_t transition,
    uint32_t held_ms)
{
    switch (transition) {
    case PRODUCT_LOCAL_ACTION_TRANSITION_NONE:
        break;
    case PRODUCT_LOCAL_ACTION_TRANSITION_ARMED:
        publish(action, PRODUCT_LOCAL_ACTION_EVENT_ARMED, ESP_OK, 0);
        break;
    case PRODUCT_LOCAL_ACTION_TRANSITION_PRESS_STARTED:
        atomic_fetch_add_explicit(&action->presses, 1,
                                  memory_order_relaxed);
        publish(action, PRODUCT_LOCAL_ACTION_EVENT_PRESS_STARTED,
                ESP_OK, 0);
        break;
    case PRODUCT_LOCAL_ACTION_TRANSITION_SHORT_PRESS:
        atomic_fetch_add_explicit(&action->short_presses, 1,
                                  memory_order_relaxed);
        publish(action, PRODUCT_LOCAL_ACTION_EVENT_SHORT_PRESS,
                ESP_OK, held_ms);
        break;
    case PRODUCT_LOCAL_ACTION_TRANSITION_LONG_PRESS: {
        atomic_fetch_add_explicit(&action->long_presses, 1,
                                  memory_order_relaxed);
        esp_err_t error = ESP_ERR_INVALID_STATE;
        if (!stopping(action)) {
            error = action->trigger(
                action->trigger_ctx, PRODUCT_LOCAL_ACTION_ONBOARDING);
        }
        if (error != ESP_OK) {
            atomic_fetch_add_explicit(&action->trigger_failures, 1,
                                      memory_order_relaxed);
        }
        publish(action, PRODUCT_LOCAL_ACTION_EVENT_LONG_PRESS,
                error, held_ms);
        break;
    }
    case PRODUCT_LOCAL_ACTION_TRANSITION_FACTORY_RESET: {
        atomic_fetch_add_explicit(&action->factory_resets, 1,
                                  memory_order_relaxed);
        esp_err_t error = ESP_ERR_INVALID_STATE;
        if (!stopping(action)) {
            error = action->trigger(
                action->trigger_ctx, PRODUCT_LOCAL_ACTION_FACTORY_RESET);
        }
        if (error != ESP_OK) {
            atomic_fetch_add_explicit(&action->trigger_failures, 1,
                                      memory_order_relaxed);
        }
        publish(action, PRODUCT_LOCAL_ACTION_EVENT_FACTORY_RESET,
                error, held_ms);
        break;
    }
    case PRODUCT_LOCAL_ACTION_TRANSITION_RELEASED:
        publish(action, PRODUCT_LOCAL_ACTION_EVENT_RELEASED,
                ESP_OK, held_ms);
        break;
    case PRODUCT_LOCAL_ACTION_TRANSITION_CLOCK_RESET:
        atomic_fetch_add_explicit(&action->clock_resets, 1,
                                  memory_order_relaxed);
        publish(action, PRODUCT_LOCAL_ACTION_EVENT_ERROR,
                ESP_ERR_INVALID_STATE, 0);
        break;
    case PRODUCT_LOCAL_ACTION_TRANSITION_INVALID:
    default:
        publish(action, PRODUCT_LOCAL_ACTION_EVENT_ERROR,
                ESP_ERR_INVALID_ARG, 0);
        break;
    }
}

static void worker_entry(void *argument)
{
    product_local_action_handle_t action = argument;
    atomic_store_explicit(&action->started, true, memory_order_release);
    xEventGroupSetBits(action->signals, SIGNAL_READY);

    while (!stopping(action)) {
        const int64_t now_us = esp_timer_get_time();
        if (now_us < 0) {
            atomic_fetch_add_explicit(&action->clock_resets, 1,
                                      memory_order_relaxed);
            publish(action, PRODUCT_LOCAL_ACTION_EVENT_ERROR,
                    ESP_ERR_INVALID_STATE, 0);
        } else {
            const bool raw_pressed =
                (gpio_get_level(action->gpio_num) != 0) ==
                action->active_high;
            const uint64_t now_ms = (uint64_t)now_us / 1000U;
            const product_local_action_transition_t transition =
                product_local_action_core_sample(
                    &action->core, now_ms, raw_pressed);
            atomic_store_explicit(&action->armed, action->core.armed,
                                  memory_order_release);
            atomic_store_explicit(&action->pressed,
                                  action->core.stable_pressed,
                                  memory_order_release);
            uint64_t held_ms = action->core.completed_hold_ms;
            if (action->core.press_in_progress &&
                now_ms >= action->core.pressed_at_ms) {
                held_ms = now_ms - action->core.pressed_at_ms;
            }
            handle_transition(action, transition,
                              bounded_held_ms(held_ms));
        }

        const EventBits_t bits = xEventGroupWaitBits(
            action->signals, SIGNAL_STOP, pdFALSE, pdTRUE,
            pdMS_TO_TICKS(action->sample_period_ms));
        if ((bits & SIGNAL_STOP) != 0) {
            break;
        }
    }

    atomic_store_explicit(&action->started, false, memory_order_release);
    atomic_store_explicit(&action->armed, false, memory_order_release);
    atomic_store_explicit(&action->pressed, false, memory_order_release);
    xEventGroupSetBits(action->signals, SIGNAL_STOPPED);
    vTaskDelete(NULL);
}

esp_err_t product_local_action_create(
    const product_local_action_config_t *config,
    product_local_action_handle_t *out_action)
{
    if (!config || !out_action || *out_action || !config->trigger ||
        config->gpio_num < 0 || config->gpio_num >= GPIO_NUM_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    const uint32_t sample_period_ms = config->sample_period_ms
                                          ? config->sample_period_ms
                                          : DEFAULT_SAMPLE_PERIOD_MS;
    const uint32_t debounce_ms = config->debounce_ms
                                     ? config->debounce_ms
                                     : DEFAULT_DEBOUNCE_MS;
    const uint32_t long_press_ms = config->long_press_ms
                                       ? config->long_press_ms
                                       : DEFAULT_LONG_PRESS_MS;
    const uint32_t factory_reset_press_ms =
        config->factory_reset_press_ms
            ? config->factory_reset_press_ms
            : DEFAULT_FACTORY_RESET_PRESS_MS;
    const uint32_t task_stack_size = config->task_stack_size
                                         ? config->task_stack_size
                                         : DEFAULT_TASK_STACK_SIZE;
    const uint32_t task_priority = config->task_priority
                                       ? config->task_priority
                                       : DEFAULT_TASK_PRIORITY;
    if (sample_period_ms < 5 || sample_period_ms > 100 ||
        debounce_ms < sample_period_ms || debounce_ms > 500 ||
        task_stack_size < 2048 ||
        task_stack_size > MAXIMUM_TASK_STACK_SIZE || task_priority == 0 ||
        task_priority >= configMAX_PRIORITIES) {
        return ESP_ERR_INVALID_ARG;
    }

    product_local_action_handle_t action = heap_caps_calloc(
        1, sizeof(*action), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!action) {
        return ESP_ERR_NO_MEM;
    }
    if (!product_local_action_core_init(
            &action->core, debounce_ms, long_press_ms,
            factory_reset_press_ms)) {
        heap_caps_free(action);
        return ESP_ERR_INVALID_ARG;
    }
    action->gpio_num = config->gpio_num;
    action->active_high = config->active_high;
    action->trigger = config->trigger;
    action->trigger_ctx = config->trigger_ctx;
    action->event = config->event;
    action->event_ctx = config->event_ctx;
    action->sample_period_ms = sample_period_ms;
    action->task_stack_size = task_stack_size;
    action->task_priority = task_priority;
    atomic_init(&action->started, false);
    atomic_init(&action->task_created, false);
    atomic_init(&action->stopping, false);
    atomic_init(&action->armed, false);
    atomic_init(&action->pressed, false);
    atomic_init(&action->presses, 0);
    atomic_init(&action->short_presses, 0);
    atomic_init(&action->long_presses, 0);
    atomic_init(&action->factory_resets, 0);
    atomic_init(&action->clock_resets, 0);
    atomic_init(&action->trigger_failures, 0);
    atomic_init(&action->last_error, ESP_OK);

    const gpio_config_t input_config = {
        .pin_bit_mask = UINT64_C(1) << (unsigned)action->gpio_num,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = action->active_high ? GPIO_PULLUP_DISABLE
                                          : GPIO_PULLUP_ENABLE,
        .pull_down_en = action->active_high ? GPIO_PULLDOWN_ENABLE
                                            : GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    esp_err_t error = gpio_config(&input_config);
    if (error == ESP_OK) {
        action->signals = xEventGroupCreate();
        if (!action->signals) {
            error = ESP_ERR_NO_MEM;
        }
    }
    if (error != ESP_OK) {
        (void)gpio_reset_pin(action->gpio_num);
        secure_zero(action, sizeof(*action));
        heap_caps_free(action);
        return error;
    }
    *out_action = action;
    return ESP_OK;
}

esp_err_t product_local_action_start(product_local_action_handle_t action)
{
    if (!action || stopping(action) ||
        atomic_load_explicit(&action->started, memory_order_acquire) ||
        atomic_load_explicit(&action->task_created,
                             memory_order_acquire)) {
        return ESP_ERR_INVALID_STATE;
    }
    xEventGroupClearBits(action->signals,
                         SIGNAL_READY | SIGNAL_STOP | SIGNAL_STOPPED);
    if (xTaskCreate(worker_entry, "local_action",
                    action->task_stack_size, action,
                    action->task_priority, &action->worker) != pdPASS) {
        action->worker = NULL;
        return ESP_ERR_NO_MEM;
    }
    atomic_store_explicit(&action->task_created, true,
                          memory_order_release);
    const EventBits_t ready = xEventGroupWaitBits(
        action->signals, SIGNAL_READY, pdFALSE, pdTRUE,
        pdMS_TO_TICKS(START_TIMEOUT_MS));
    if ((ready & SIGNAL_READY) == 0) {
        atomic_store_explicit(&action->stopping, true,
                              memory_order_release);
        xEventGroupSetBits(action->signals, SIGNAL_STOP);
        return ESP_ERR_TIMEOUT;
    }
    return ESP_OK;
}

esp_err_t product_local_action_get_stats(
    product_local_action_handle_t action,
    product_local_action_stats_t *stats)
{
    if (!action || !stats || stopping(action)) {
        return ESP_ERR_INVALID_ARG;
    }
    *stats = (product_local_action_stats_t){
        .started = atomic_load_explicit(&action->started,
                                        memory_order_acquire),
        .armed = atomic_load_explicit(&action->armed,
                                      memory_order_acquire),
        .pressed = atomic_load_explicit(&action->pressed,
                                        memory_order_acquire),
        .presses = atomic_load_explicit(&action->presses,
                                        memory_order_relaxed),
        .short_presses = atomic_load_explicit(&action->short_presses,
                                              memory_order_relaxed),
        .long_presses = atomic_load_explicit(&action->long_presses,
                                             memory_order_relaxed),
        .factory_resets = atomic_load_explicit(&action->factory_resets,
                                               memory_order_relaxed),
        .clock_resets = atomic_load_explicit(&action->clock_resets,
                                             memory_order_relaxed),
        .trigger_failures = atomic_load_explicit(
            &action->trigger_failures, memory_order_relaxed),
        .last_error = (esp_err_t)atomic_load_explicit(
            &action->last_error, memory_order_acquire),
    };
    return ESP_OK;
}

esp_err_t product_local_action_destroy(
    product_local_action_handle_t action,
    uint32_t timeout_ms)
{
    if (!action || timeout_ms == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    atomic_store_explicit(&action->stopping, true, memory_order_release);
    if (atomic_load_explicit(&action->task_created,
                             memory_order_acquire)) {
        xEventGroupSetBits(action->signals, SIGNAL_STOP);
        const EventBits_t stopped = xEventGroupWaitBits(
            action->signals, SIGNAL_STOPPED, pdFALSE, pdTRUE,
            pdMS_TO_TICKS(timeout_ms));
        if ((stopped & SIGNAL_STOPPED) == 0) {
            return ESP_ERR_TIMEOUT;
        }
    }
    (void)gpio_reset_pin(action->gpio_num);
    vEventGroupDelete(action->signals);
    secure_zero(action, sizeof(*action));
    heap_caps_free(action);
    return ESP_OK;
}
