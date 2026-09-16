#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PRODUCT_LOCAL_ACTION_TRANSITION_NONE = 0,
    PRODUCT_LOCAL_ACTION_TRANSITION_ARMED,
    PRODUCT_LOCAL_ACTION_TRANSITION_PRESS_STARTED,
    PRODUCT_LOCAL_ACTION_TRANSITION_SHORT_PRESS,
    PRODUCT_LOCAL_ACTION_TRANSITION_LONG_PRESS,
    PRODUCT_LOCAL_ACTION_TRANSITION_FACTORY_RESET,
    PRODUCT_LOCAL_ACTION_TRANSITION_RELEASED,
    PRODUCT_LOCAL_ACTION_TRANSITION_CLOCK_RESET,
    PRODUCT_LOCAL_ACTION_TRANSITION_INVALID,
} product_local_action_transition_t;

typedef struct {
    uint32_t debounce_ms;
    uint32_t long_press_ms;
    uint32_t factory_reset_press_ms;
    bool configured;
    bool raw_initialized;
    bool stable_initialized;
    bool raw_pressed;
    bool stable_pressed;
    bool armed;
    bool press_in_progress;
    uint64_t raw_changed_at_ms;
    uint64_t pressed_at_ms;
    uint64_t completed_hold_ms;
    uint64_t last_sample_at_ms;
} product_local_action_core_t;

bool product_local_action_core_init(product_local_action_core_t *core,
                                    uint32_t debounce_ms,
                                    uint32_t long_press_ms,
                                    uint32_t factory_reset_press_ms);

/*
 * The input owner must sample a monotonic clock and the raw pressed state.
 * No action can fire until a debounced release has armed the core. Both the
 * onboarding and factory-reset classifications occur only after release.
 */
product_local_action_transition_t product_local_action_core_sample(
    product_local_action_core_t *core,
    uint64_t now_ms,
    bool raw_pressed);

#ifdef __cplusplus
}
#endif
