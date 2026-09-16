#include "agent_device_time_core.h"

#include <assert.h>
#include <stdio.h>

static agent_device_time_core_t new_core(void)
{
    agent_device_time_core_t core;
    assert(agent_device_time_core_init(&core, 3600, 5));
    return core;
}

static void test_configuration_and_unsynchronized_state(void)
{
    agent_device_time_core_t core;
    int64_t unix_seconds = 1;
    agent_device_time_status_t status;
    assert(!agent_device_time_core_init(NULL, 3600, 5));
    assert(!agent_device_time_core_init(&core, 59, 5));
    assert(!agent_device_time_core_init(&core, 3600, 301));
    core = new_core();
    assert(!agent_device_time_core_now(&core, 0, &unix_seconds));
    assert(agent_device_time_core_status(&core, 0, &status));
    assert(!status.synchronized && status.age_seconds == 0);
}

static void test_accept_interpolate_and_expire(void)
{
    agent_device_time_core_t core = new_core();
    int64_t unix_seconds = 0;
    agent_device_time_status_t status;
    assert(agent_device_time_core_accept(&core, 1800000000, 1000));
    assert(agent_device_time_core_now(&core, 1999, &unix_seconds));
    assert(unix_seconds == 1800000000);
    assert(agent_device_time_core_now(&core, 2000, &unix_seconds));
    assert(unix_seconds == 1800000001);
    assert(agent_device_time_core_now(&core, 3601000, &unix_seconds));
    assert(unix_seconds == 1800003600);
    assert(!agent_device_time_core_now(&core, 3601001, &unix_seconds));
    assert(agent_device_time_core_status(&core, 3601001, &status));
    assert(!status.synchronized && status.age_seconds == 3600);
}

static void test_rollback_and_monotonic_regression_fail_closed(void)
{
    agent_device_time_core_t core = new_core();
    assert(agent_device_time_core_accept(&core, 1800000000, 1000));
    assert(agent_device_time_core_accept(&core, 1800000005, 11000));
    assert(!agent_device_time_core_accept(&core, 1799999999, 12000));
    assert(!agent_device_time_core_accept(&core, 1800000010, 10000));
}

static void test_resync_refreshes_age_and_allows_forward_step(void)
{
    agent_device_time_core_t core = new_core();
    int64_t unix_seconds = 0;
    assert(agent_device_time_core_accept(&core, 1800000000, 1000));
    assert(agent_device_time_core_accept(&core, 1800007200, 7201000));
    assert(agent_device_time_core_now(&core, 7202000, &unix_seconds));
    assert(unix_seconds == 1800007201);
    assert(!agent_device_time_core_accept(&core, 1609459199, 7203000));
    assert(!agent_device_time_core_accept(&core, 4102444801, 7203000));
}

static void test_year_2100_overflow_is_not_synchronized(void)
{
    agent_device_time_core_t core = new_core();
    int64_t unix_seconds = 0;
    agent_device_time_status_t status;
    assert(agent_device_time_core_accept(&core, 4102444800, 1000));
    assert(!agent_device_time_core_now(&core, 2000, &unix_seconds));
    assert(agent_device_time_core_status(&core, 2000, &status));
    assert(!status.synchronized);
}

int main(void)
{
    test_configuration_and_unsynchronized_state();
    test_accept_interpolate_and_expire();
    test_rollback_and_monotonic_regression_fail_closed();
    test_resync_refreshes_age_and_allows_forward_step();
    test_year_2100_overflow_is_not_synchronized();
    puts("agent_device_time_core: all host tests passed");
    return 0;
}
