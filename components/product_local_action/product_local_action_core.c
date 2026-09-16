#include "product_local_action_core.h"

#include <string.h>

enum {
    MINIMUM_DEBOUNCE_MS = 5,
    MAXIMUM_DEBOUNCE_MS = 500,
    MINIMUM_LONG_PRESS_MS = 1000,
    MAXIMUM_LONG_PRESS_MS = 10000,
    MINIMUM_FACTORY_RESET_PRESS_MS = 5000,
    MAXIMUM_FACTORY_RESET_PRESS_MS = 30000,
};

static void reset_tracking(product_local_action_core_t *core,
                           uint64_t now_ms,
                           bool raw_pressed)
{
    const uint32_t debounce_ms = core->debounce_ms;
    const uint32_t long_press_ms = core->long_press_ms;
    const uint32_t factory_reset_press_ms =
        core->factory_reset_press_ms;
    memset(core, 0, sizeof(*core));
    core->debounce_ms = debounce_ms;
    core->long_press_ms = long_press_ms;
    core->factory_reset_press_ms = factory_reset_press_ms;
    core->configured = true;
    core->raw_initialized = true;
    core->raw_pressed = raw_pressed;
    core->raw_changed_at_ms = now_ms;
    core->last_sample_at_ms = now_ms;
}

bool product_local_action_core_init(product_local_action_core_t *core,
                                    uint32_t debounce_ms,
                                    uint32_t long_press_ms,
                                    uint32_t factory_reset_press_ms)
{
    if (!core || debounce_ms < MINIMUM_DEBOUNCE_MS ||
        debounce_ms > MAXIMUM_DEBOUNCE_MS ||
        long_press_ms < MINIMUM_LONG_PRESS_MS ||
        long_press_ms > MAXIMUM_LONG_PRESS_MS ||
        factory_reset_press_ms < MINIMUM_FACTORY_RESET_PRESS_MS ||
        factory_reset_press_ms > MAXIMUM_FACTORY_RESET_PRESS_MS ||
        long_press_ms <= debounce_ms ||
        factory_reset_press_ms <= long_press_ms) {
        return false;
    }
    memset(core, 0, sizeof(*core));
    core->debounce_ms = debounce_ms;
    core->long_press_ms = long_press_ms;
    core->factory_reset_press_ms = factory_reset_press_ms;
    core->configured = true;
    return true;
}

product_local_action_transition_t product_local_action_core_sample(
    product_local_action_core_t *core,
    uint64_t now_ms,
    bool raw_pressed)
{
    if (!core || !core->configured) {
        return PRODUCT_LOCAL_ACTION_TRANSITION_INVALID;
    }
    if (!core->raw_initialized) {
        reset_tracking(core, now_ms, raw_pressed);
        return PRODUCT_LOCAL_ACTION_TRANSITION_NONE;
    }
    if (now_ms < core->last_sample_at_ms) {
        reset_tracking(core, now_ms, raw_pressed);
        return PRODUCT_LOCAL_ACTION_TRANSITION_CLOCK_RESET;
    }
    core->last_sample_at_ms = now_ms;

    if (raw_pressed != core->raw_pressed) {
        core->raw_pressed = raw_pressed;
        core->raw_changed_at_ms = now_ms;
    }
    const uint64_t raw_stable_ms = now_ms - core->raw_changed_at_ms;

    if (!core->stable_initialized) {
        if (raw_stable_ms < core->debounce_ms) {
            return PRODUCT_LOCAL_ACTION_TRANSITION_NONE;
        }
        core->stable_initialized = true;
        core->stable_pressed = core->raw_pressed;
        if (!core->stable_pressed) {
            core->armed = true;
            return PRODUCT_LOCAL_ACTION_TRANSITION_ARMED;
        }
        return PRODUCT_LOCAL_ACTION_TRANSITION_NONE;
    }

    if (core->raw_pressed != core->stable_pressed &&
        raw_stable_ms >= core->debounce_ms) {
        core->stable_pressed = core->raw_pressed;
        if (core->stable_pressed) {
            if (!core->armed) {
                return PRODUCT_LOCAL_ACTION_TRANSITION_NONE;
            }
            core->armed = false;
            core->press_in_progress = true;
            core->completed_hold_ms = 0;
            core->pressed_at_ms = now_ms;
            return PRODUCT_LOCAL_ACTION_TRANSITION_PRESS_STARTED;
        }

        const bool completed_press = core->press_in_progress;
        core->completed_hold_ms =
            completed_press && core->raw_changed_at_ms >= core->pressed_at_ms
                ? core->raw_changed_at_ms - core->pressed_at_ms
                : 0;
        core->armed = true;
        core->press_in_progress = false;
        core->pressed_at_ms = 0;
        if (!completed_press) {
            return PRODUCT_LOCAL_ACTION_TRANSITION_ARMED;
        }
        if (core->completed_hold_ms >= core->factory_reset_press_ms) {
            return PRODUCT_LOCAL_ACTION_TRANSITION_FACTORY_RESET;
        }
        if (core->completed_hold_ms >= core->long_press_ms) {
            return PRODUCT_LOCAL_ACTION_TRANSITION_LONG_PRESS;
        }
        return PRODUCT_LOCAL_ACTION_TRANSITION_SHORT_PRESS;
    }
    return PRODUCT_LOCAL_ACTION_TRANSITION_NONE;
}
