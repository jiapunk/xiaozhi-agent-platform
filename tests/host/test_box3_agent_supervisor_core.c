#include "box3_agent_supervisor_core.h"

#include <assert.h>
#include <stdio.h>

static box3_agent_supervisor_core_t new_core(void)
{
    box3_agent_supervisor_core_t core;
    const box3_agent_supervisor_core_config_t config = {
        .minimum_backoff_ms = 1000,
        .maximum_backoff_ms = 8000,
        .refresh_margin_seconds = 30,
    };
    assert(box3_agent_supervisor_core_init(&core, &config));
    return core;
}

static void test_expiry_refresh_recreates_session(void)
{
    box3_agent_supervisor_core_t core = new_core();
    assert(box3_agent_supervisor_core_set_network(&core, true, 1000) ==
           BOX3_AGENT_SUPERVISOR_ACTION_REFRESH);
    assert(core.state == BOX3_AGENT_SUPERVISOR_REFRESHING);
    assert(box3_agent_supervisor_core_credentials_result(
               &core, true, 120, 300, 1000, 0) ==
           BOX3_AGENT_SUPERVISOR_ACTION_START);
    assert(core.refresh_at_ms == 91000);
    assert(box3_agent_supervisor_core_ready(&core));
    assert(core.state == BOX3_AGENT_SUPERVISOR_ONLINE);
    assert(box3_agent_supervisor_core_poll(&core, 90999) ==
           BOX3_AGENT_SUPERVISOR_ACTION_NONE);
    assert(box3_agent_supervisor_core_poll(&core, 91000) ==
           BOX3_AGENT_SUPERVISOR_ACTION_STOP);
    assert(box3_agent_supervisor_core_session_stopped(&core) ==
           BOX3_AGENT_SUPERVISOR_ACTION_REFRESH);
    assert(core.state == BOX3_AGENT_SUPERVISOR_REFRESHING);
}

static void test_network_loss_and_return(void)
{
    box3_agent_supervisor_core_t core = new_core();
    assert(box3_agent_supervisor_core_set_network(&core, true, 0) ==
           BOX3_AGENT_SUPERVISOR_ACTION_REFRESH);
    assert(box3_agent_supervisor_core_credentials_result(
               &core, true, 300, 300, 0, 0) ==
           BOX3_AGENT_SUPERVISOR_ACTION_START);
    assert(box3_agent_supervisor_core_ready(&core));
    assert(box3_agent_supervisor_core_set_network(&core, false, 10) ==
           BOX3_AGENT_SUPERVISOR_ACTION_STOP);
    assert(box3_agent_supervisor_core_session_stopped(&core) ==
           BOX3_AGENT_SUPERVISOR_ACTION_NONE);
    assert(core.state == BOX3_AGENT_SUPERVISOR_WAIT_NETWORK);
    assert(box3_agent_supervisor_core_set_network(&core, true, 20) ==
           BOX3_AGENT_SUPERVISOR_ACTION_REFRESH);
}

static void test_disconnect_uses_jittered_exponential_backoff(void)
{
    box3_agent_supervisor_core_t core = new_core();
    assert(box3_agent_supervisor_core_set_network(&core, true, 0) ==
           BOX3_AGENT_SUPERVISOR_ACTION_REFRESH);
    assert(box3_agent_supervisor_core_credentials_result(
               &core, true, 300, 300, 0, 0) ==
           BOX3_AGENT_SUPERVISOR_ACTION_START);
    assert(box3_agent_supervisor_core_disconnected(&core, 100, 0) ==
           BOX3_AGENT_SUPERVISOR_ACTION_STOP);
    assert(core.retry_at_ms == 600); /* First cap 1000, lower half jitter. */
    assert(box3_agent_supervisor_core_session_stopped(&core) ==
           BOX3_AGENT_SUPERVISOR_ACTION_NONE);
    assert(core.state == BOX3_AGENT_SUPERVISOR_BACKOFF);
    assert(box3_agent_supervisor_core_poll(&core, 599) ==
           BOX3_AGENT_SUPERVISOR_ACTION_NONE);
    assert(box3_agent_supervisor_core_poll(&core, 600) ==
           BOX3_AGENT_SUPERVISOR_ACTION_REFRESH);

    assert(box3_agent_supervisor_core_credentials_result(
               &core, false, 0, 0, 600, 0) ==
           BOX3_AGENT_SUPERVISOR_ACTION_NONE);
    assert(core.retry_at_ms == 1600); /* Second cap 2000. */
    assert(core.consecutive_failures == 2);
}

static void test_ready_resets_backoff_and_invalid_ttl_fails_closed(void)
{
    box3_agent_supervisor_core_t core = new_core();
    assert(box3_agent_supervisor_core_set_network(&core, true, 0) ==
           BOX3_AGENT_SUPERVISOR_ACTION_REFRESH);
    assert(box3_agent_supervisor_core_credentials_result(
               &core, false, 0, 0, 0, 500) ==
           BOX3_AGENT_SUPERVISOR_ACTION_NONE);
    assert(core.state == BOX3_AGENT_SUPERVISOR_BACKOFF);
    assert(core.consecutive_failures == 1);
    assert(box3_agent_supervisor_core_poll(&core, core.retry_at_ms) ==
           BOX3_AGENT_SUPERVISOR_ACTION_REFRESH);
    assert(box3_agent_supervisor_core_credentials_result(
               &core, true, 59, 300, core.retry_at_ms, 0) ==
           BOX3_AGENT_SUPERVISOR_ACTION_NONE);
    assert(core.state == BOX3_AGENT_SUPERVISOR_BACKOFF);
    assert(core.consecutive_failures == 2);
    assert(box3_agent_supervisor_core_poll(&core, core.retry_at_ms) ==
           BOX3_AGENT_SUPERVISOR_ACTION_REFRESH);
    assert(box3_agent_supervisor_core_credentials_result(
               &core, true, 60, 60, core.retry_at_ms, 0) ==
           BOX3_AGENT_SUPERVISOR_ACTION_START);
    assert(box3_agent_supervisor_core_ready(&core));
    assert(core.consecutive_failures == 0);
}

static void test_configuration_and_wait_bounds(void)
{
    box3_agent_supervisor_core_t core;
    box3_agent_supervisor_core_config_t invalid = {
        .minimum_backoff_ms = 0,
        .maximum_backoff_ms = 1000,
        .refresh_margin_seconds = 30,
    };
    assert(!box3_agent_supervisor_core_init(&core, &invalid));
    core = new_core();
    assert(box3_agent_supervisor_core_wait_ms(&core, 0, 1000) == 1000);
    assert(box3_agent_supervisor_core_set_network(&core, true, 0) ==
           BOX3_AGENT_SUPERVISOR_ACTION_REFRESH);
    assert(box3_agent_supervisor_core_credentials_result(
               &core, false, 0, 0, 0, 1000) ==
           BOX3_AGENT_SUPERVISOR_ACTION_NONE);
    assert(box3_agent_supervisor_core_wait_ms(&core, 0, 1000) <= 1000);
    assert(box3_agent_supervisor_core_wait_ms(
               &core, core.retry_at_ms, 1000) == 0);
}

static void test_partial_start_failure_is_cleaned_before_retry(void)
{
    box3_agent_supervisor_core_t core = new_core();
    assert(box3_agent_supervisor_core_set_network(&core, true, 0) ==
           BOX3_AGENT_SUPERVISOR_ACTION_REFRESH);
    assert(box3_agent_supervisor_core_credentials_result(
               &core, true, 300, 300, 0, 0) ==
           BOX3_AGENT_SUPERVISOR_ACTION_START);
    assert(box3_agent_supervisor_core_start_failed(
               &core, true, 100, 0) ==
           BOX3_AGENT_SUPERVISOR_ACTION_STOP);
    assert(core.state == BOX3_AGENT_SUPERVISOR_STOPPING);
    assert(core.after_stop == BOX3_AGENT_SUPERVISOR_BACKOFF);
    assert(box3_agent_supervisor_core_session_stopped(&core) ==
           BOX3_AGENT_SUPERVISOR_ACTION_NONE);
    assert(core.state == BOX3_AGENT_SUPERVISOR_BACKOFF);
}

static void test_network_return_during_stop_refreshes_after_cleanup(void)
{
    box3_agent_supervisor_core_t core = new_core();
    assert(box3_agent_supervisor_core_set_network(&core, true, 0) ==
           BOX3_AGENT_SUPERVISOR_ACTION_REFRESH);
    assert(box3_agent_supervisor_core_credentials_result(
               &core, true, 300, 300, 0, 0) ==
           BOX3_AGENT_SUPERVISOR_ACTION_START);
    assert(box3_agent_supervisor_core_ready(&core));
    assert(box3_agent_supervisor_core_set_network(&core, false, 10) ==
           BOX3_AGENT_SUPERVISOR_ACTION_STOP);
    assert(box3_agent_supervisor_core_set_network(&core, true, 11) ==
           BOX3_AGENT_SUPERVISOR_ACTION_NONE);
    assert(core.after_stop == BOX3_AGENT_SUPERVISOR_REFRESHING);
    assert(box3_agent_supervisor_core_session_stopped(&core) ==
           BOX3_AGENT_SUPERVISOR_ACTION_REFRESH);
}

static void test_entitlement_denial_stops_retry_until_change_or_network_cycle(void)
{
    box3_agent_supervisor_core_t core = new_core();
    assert(box3_agent_supervisor_core_set_network(&core, true, 0) ==
           BOX3_AGENT_SUPERVISOR_ACTION_REFRESH);
    assert(box3_agent_supervisor_core_entitlement_denied(&core) ==
           BOX3_AGENT_SUPERVISOR_ACTION_NONE);
    assert(core.state == BOX3_AGENT_SUPERVISOR_ENTITLEMENT_BLOCKED);
    assert(core.retry_at_ms == 0);
    assert(box3_agent_supervisor_core_poll(&core, UINT64_MAX) ==
           BOX3_AGENT_SUPERVISOR_ACTION_NONE);
    assert(box3_agent_supervisor_core_wait_ms(&core, UINT64_MAX, 1000) ==
           1000);

    assert(box3_agent_supervisor_core_entitlement_changed(&core) ==
           BOX3_AGENT_SUPERVISOR_ACTION_REFRESH);
    assert(core.state == BOX3_AGENT_SUPERVISOR_REFRESHING);
    assert(box3_agent_supervisor_core_entitlement_denied(&core) ==
           BOX3_AGENT_SUPERVISOR_ACTION_NONE);
    assert(box3_agent_supervisor_core_set_network(&core, false, 10) ==
           BOX3_AGENT_SUPERVISOR_ACTION_NONE);
    assert(core.state == BOX3_AGENT_SUPERVISOR_WAIT_NETWORK);
    assert(box3_agent_supervisor_core_set_network(&core, true, 20) ==
           BOX3_AGENT_SUPERVISOR_ACTION_REFRESH);
}

int main(void)
{
    test_expiry_refresh_recreates_session();
    test_network_loss_and_return();
    test_disconnect_uses_jittered_exponential_backoff();
    test_ready_resets_backoff_and_invalid_ttl_fails_closed();
    test_configuration_and_wait_bounds();
    test_partial_start_failure_is_cleaned_before_retry();
    test_network_return_during_stop_refreshes_after_cleanup();
    test_entitlement_denial_stops_retry_until_change_or_network_cycle();
    puts("box3_agent_supervisor_core: all host tests passed");
    return 0;
}
