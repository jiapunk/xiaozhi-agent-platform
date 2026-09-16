#include "product_local_action_core.h"

#include <assert.h>
#include <stdio.h>

static product_local_action_transition_t sample(
    product_local_action_core_t *core,
    uint64_t now_ms,
    bool pressed)
{
    return product_local_action_core_sample(core, now_ms, pressed);
}

static void test_boot_held_requires_release(void)
{
    product_local_action_core_t core;
    assert(product_local_action_core_init(&core, 30, 3000, 10000));
    assert(sample(&core, 0, true) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 30, true) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(!core.armed);
    assert(sample(&core, 4000, true) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);

    assert(sample(&core, 4010, false) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 4040, false) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_ARMED);
    assert(core.armed);

    assert(sample(&core, 4050, true) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 4080, true) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_PRESS_STARTED);
    assert(sample(&core, 7079, true) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 7080, true) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(!core.armed);

    assert(sample(&core, 7100, false) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 7130, false) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_LONG_PRESS);
    assert(core.armed);

    assert(sample(&core, 8000, true) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 8030, true) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_PRESS_STARTED);
    assert(sample(&core, 18030, true) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 18040, false) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 18070, false) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_FACTORY_RESET);
    assert(core.completed_hold_ms == 10010);
    assert(core.armed);
}

static void test_bounce_short_press_and_rearm(void)
{
    product_local_action_core_t core;
    assert(product_local_action_core_init(&core, 30, 3000, 10000));
    assert(sample(&core, 0, false) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 30, false) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_ARMED);

    assert(sample(&core, 100, true) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 110, false) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 120, true) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 150, true) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_PRESS_STARTED);
    assert(sample(&core, 400, false) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 410, true) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 420, false) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 450, false) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_SHORT_PRESS);
    assert(core.armed);

    assert(sample(&core, 500, true) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 530, true) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_PRESS_STARTED);
    assert(sample(&core, 3530, true) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 3540, false) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 3570, false) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_LONG_PRESS);
}

static void test_clock_rollback_disarms_until_release(void)
{
    product_local_action_core_t core;
    assert(product_local_action_core_init(&core, 20, 2000, 10000));
    assert(sample(&core, 100, false) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 120, false) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_ARMED);
    assert(sample(&core, 200, true) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 220, true) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_PRESS_STARTED);
    assert(sample(&core, 10, true) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_CLOCK_RESET);
    assert(!core.armed);
    assert(sample(&core, 30, true) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 5000, true) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 5010, false) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 5030, false) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_ARMED);
}

static void test_release_before_threshold_cannot_fire_during_debounce(void)
{
    product_local_action_core_t core;
    assert(product_local_action_core_init(&core, 50, 3000, 10000));
    assert(sample(&core, 0, false) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 50, false) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_ARMED);
    assert(sample(&core, 100, true) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 150, true) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_PRESS_STARTED);
    assert(sample(&core, 3140, false) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 3150, false) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 3190, false) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_SHORT_PRESS);
    assert(core.completed_hold_ms == 2990);
    assert(core.armed);
}

static void test_release_time_not_debounce_time_selects_action(void)
{
    product_local_action_core_t core;
    assert(product_local_action_core_init(&core, 50, 3000, 10000));
    assert(sample(&core, 0, false) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 50, false) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_ARMED);
    assert(sample(&core, 100, true) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 150, true) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_PRESS_STARTED);

    /* Actual release is below reset threshold. Debounce must not promote it. */
    assert(sample(&core, 10140, false) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_NONE);
    assert(sample(&core, 10190, false) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_LONG_PRESS);
    assert(core.completed_hold_ms == 9990);
}

static void test_invalid_configuration(void)
{
    product_local_action_core_t core;
    assert(!product_local_action_core_init(NULL, 30, 3000, 10000));
    assert(!product_local_action_core_init(&core, 4, 3000, 10000));
    assert(!product_local_action_core_init(&core, 30, 999, 10000));
    assert(!product_local_action_core_init(&core, 500, 500, 10000));
    assert(!product_local_action_core_init(&core, 30, 3000, 3000));
    assert(!product_local_action_core_init(&core, 30, 3000, 30001));
    assert(product_local_action_core_sample(NULL, 0, false) ==
           PRODUCT_LOCAL_ACTION_TRANSITION_INVALID);
}

int main(void)
{
    test_boot_held_requires_release();
    test_bounce_short_press_and_rearm();
    test_clock_rollback_disarms_until_release();
    test_release_before_threshold_cannot_fire_during_debounce();
    test_release_time_not_debounce_time_selects_action();
    test_invalid_configuration();
    puts("product_local_action_core: all tests passed");
    return 0;
}
