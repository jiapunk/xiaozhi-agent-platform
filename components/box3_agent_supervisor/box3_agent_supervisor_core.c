#include "box3_agent_supervisor_core.h"

#include <limits.h>
#include <stddef.h>
#include <string.h>

enum {
    MINIMUM_TOKEN_TTL_SECONDS = 60,
    MAXIMUM_TOKEN_TTL_SECONDS = 3600,
    MINIMUM_REFRESH_DELAY_MS = 1000,
    MAXIMUM_BACKOFF_LIMIT_MS = 300000,
};

static uint32_t bounded_backoff(box3_agent_supervisor_core_t *core,
                                uint32_t random_value)
{
    uint64_t cap = core->minimum_backoff_ms;
    uint32_t shifts = core->consecutive_failures;
    while (shifts > 0 && cap < core->maximum_backoff_ms) {
        cap *= 2;
        if (cap > core->maximum_backoff_ms) {
            cap = core->maximum_backoff_ms;
        }
        --shifts;
    }
    if (core->consecutive_failures < UINT32_MAX) {
        ++core->consecutive_failures;
    }
    const uint32_t maximum = (uint32_t)cap;
    const uint32_t minimum = maximum / 2;
    const uint32_t span = maximum - minimum;
    return minimum + (span == UINT32_MAX
                          ? random_value
                          : random_value % (span + 1));
}

static box3_agent_supervisor_state_t retry_target(
    box3_agent_supervisor_core_t *core,
    uint64_t now_ms,
    uint32_t random_value)
{
    if (!core->network_available) {
        return BOX3_AGENT_SUPERVISOR_WAIT_NETWORK;
    }
    core->retry_at_ms = now_ms + bounded_backoff(core, random_value);
    return BOX3_AGENT_SUPERVISOR_BACKOFF;
}

bool box3_agent_supervisor_core_init(
    box3_agent_supervisor_core_t *core,
    const box3_agent_supervisor_core_config_t *config)
{
    if (!core || !config || config->minimum_backoff_ms == 0 ||
        config->maximum_backoff_ms < config->minimum_backoff_ms ||
        config->maximum_backoff_ms > MAXIMUM_BACKOFF_LIMIT_MS ||
        config->refresh_margin_seconds < 5 ||
        config->refresh_margin_seconds > 300) {
        return false;
    }
    memset(core, 0, sizeof(*core));
    core->state = BOX3_AGENT_SUPERVISOR_WAIT_NETWORK;
    core->after_stop = BOX3_AGENT_SUPERVISOR_WAIT_NETWORK;
    core->minimum_backoff_ms = config->minimum_backoff_ms;
    core->maximum_backoff_ms = config->maximum_backoff_ms;
    core->refresh_margin_seconds = config->refresh_margin_seconds;
    return true;
}

box3_agent_supervisor_action_t box3_agent_supervisor_core_set_network(
    box3_agent_supervisor_core_t *core,
    bool available,
    uint64_t now_ms)
{
    (void)now_ms;
    if (!core) {
        return BOX3_AGENT_SUPERVISOR_ACTION_NONE;
    }
    core->network_available = available;
    if (!available) {
        if (core->state == BOX3_AGENT_SUPERVISOR_STARTING ||
            core->state == BOX3_AGENT_SUPERVISOR_ONLINE) {
            core->state = BOX3_AGENT_SUPERVISOR_STOPPING;
            core->after_stop = BOX3_AGENT_SUPERVISOR_WAIT_NETWORK;
            return BOX3_AGENT_SUPERVISOR_ACTION_STOP;
        }
        if (core->state == BOX3_AGENT_SUPERVISOR_STOPPING) {
            core->after_stop = BOX3_AGENT_SUPERVISOR_WAIT_NETWORK;
        } else {
            core->state = BOX3_AGENT_SUPERVISOR_WAIT_NETWORK;
        }
        return BOX3_AGENT_SUPERVISOR_ACTION_NONE;
    }

    if (core->state == BOX3_AGENT_SUPERVISOR_WAIT_NETWORK) {
        core->state = BOX3_AGENT_SUPERVISOR_REFRESHING;
        return BOX3_AGENT_SUPERVISOR_ACTION_REFRESH;
    }
    if (core->state == BOX3_AGENT_SUPERVISOR_STOPPING &&
        core->after_stop == BOX3_AGENT_SUPERVISOR_WAIT_NETWORK) {
        core->after_stop = BOX3_AGENT_SUPERVISOR_REFRESHING;
    }
    return BOX3_AGENT_SUPERVISOR_ACTION_NONE;
}

box3_agent_supervisor_action_t box3_agent_supervisor_core_credentials_result(
    box3_agent_supervisor_core_t *core,
    bool success,
    uint32_t voice_ttl_seconds,
    uint32_t agent_ttl_seconds,
    uint64_t now_ms,
    uint32_t random_value)
{
    if (!core || core->state != BOX3_AGENT_SUPERVISOR_REFRESHING) {
        return BOX3_AGENT_SUPERVISOR_ACTION_NONE;
    }
    if (!success || voice_ttl_seconds < MINIMUM_TOKEN_TTL_SECONDS ||
        voice_ttl_seconds > MAXIMUM_TOKEN_TTL_SECONDS ||
        agent_ttl_seconds < MINIMUM_TOKEN_TTL_SECONDS ||
        agent_ttl_seconds > MAXIMUM_TOKEN_TTL_SECONDS) {
        core->state = retry_target(core, now_ms, random_value);
        return BOX3_AGENT_SUPERVISOR_ACTION_NONE;
    }

    const uint32_t ttl_seconds = voice_ttl_seconds < agent_ttl_seconds
                                     ? voice_ttl_seconds
                                     : agent_ttl_seconds;
    const uint64_t ttl_ms = (uint64_t)ttl_seconds * 1000;
    const uint64_t margin_ms =
        (uint64_t)core->refresh_margin_seconds * 1000;
    uint64_t refresh_delay = ttl_ms > margin_ms
                                 ? ttl_ms - margin_ms
                                 : ttl_ms / 2;
    if (refresh_delay < MINIMUM_REFRESH_DELAY_MS) {
        refresh_delay = MINIMUM_REFRESH_DELAY_MS;
    }
    core->refresh_at_ms = now_ms + refresh_delay;
    core->state = BOX3_AGENT_SUPERVISOR_STARTING;
    return BOX3_AGENT_SUPERVISOR_ACTION_START;
}

box3_agent_supervisor_action_t box3_agent_supervisor_core_entitlement_denied(
    box3_agent_supervisor_core_t *core)
{
    if (!core || core->state != BOX3_AGENT_SUPERVISOR_REFRESHING) {
        return BOX3_AGENT_SUPERVISOR_ACTION_NONE;
    }
    core->state = BOX3_AGENT_SUPERVISOR_ENTITLEMENT_BLOCKED;
    core->consecutive_failures = 0;
    core->retry_at_ms = 0;
    return BOX3_AGENT_SUPERVISOR_ACTION_NONE;
}

box3_agent_supervisor_action_t box3_agent_supervisor_core_entitlement_changed(
    box3_agent_supervisor_core_t *core)
{
    if (!core || !core->network_available ||
        core->state != BOX3_AGENT_SUPERVISOR_ENTITLEMENT_BLOCKED) {
        return BOX3_AGENT_SUPERVISOR_ACTION_NONE;
    }
    core->state = BOX3_AGENT_SUPERVISOR_REFRESHING;
    return BOX3_AGENT_SUPERVISOR_ACTION_REFRESH;
}

box3_agent_supervisor_action_t box3_agent_supervisor_core_start_failed(
    box3_agent_supervisor_core_t *core,
    bool session_present,
    uint64_t now_ms,
    uint32_t random_value)
{
    if (!core || core->state != BOX3_AGENT_SUPERVISOR_STARTING) {
        return BOX3_AGENT_SUPERVISOR_ACTION_NONE;
    }
    const box3_agent_supervisor_state_t target =
        retry_target(core, now_ms, random_value);
    if (session_present) {
        core->state = BOX3_AGENT_SUPERVISOR_STOPPING;
        core->after_stop = target;
        return BOX3_AGENT_SUPERVISOR_ACTION_STOP;
    }
    core->state = target;
    return BOX3_AGENT_SUPERVISOR_ACTION_NONE;
}

bool box3_agent_supervisor_core_ready(box3_agent_supervisor_core_t *core)
{
    if (!core || core->state != BOX3_AGENT_SUPERVISOR_STARTING) {
        return false;
    }
    core->state = BOX3_AGENT_SUPERVISOR_ONLINE;
    core->consecutive_failures = 0;
    return true;
}

box3_agent_supervisor_action_t box3_agent_supervisor_core_disconnected(
    box3_agent_supervisor_core_t *core,
    uint64_t now_ms,
    uint32_t random_value)
{
    if (!core || (core->state != BOX3_AGENT_SUPERVISOR_STARTING &&
                  core->state != BOX3_AGENT_SUPERVISOR_ONLINE)) {
        return BOX3_AGENT_SUPERVISOR_ACTION_NONE;
    }
    core->after_stop = retry_target(core, now_ms, random_value);
    core->state = BOX3_AGENT_SUPERVISOR_STOPPING;
    return BOX3_AGENT_SUPERVISOR_ACTION_STOP;
}

box3_agent_supervisor_action_t box3_agent_supervisor_core_session_stopped(
    box3_agent_supervisor_core_t *core)
{
    if (!core || core->state != BOX3_AGENT_SUPERVISOR_STOPPING) {
        return BOX3_AGENT_SUPERVISOR_ACTION_NONE;
    }
    core->state = core->after_stop;
    return core->state == BOX3_AGENT_SUPERVISOR_REFRESHING
               ? BOX3_AGENT_SUPERVISOR_ACTION_REFRESH
               : BOX3_AGENT_SUPERVISOR_ACTION_NONE;
}

box3_agent_supervisor_action_t box3_agent_supervisor_core_poll(
    box3_agent_supervisor_core_t *core,
    uint64_t now_ms)
{
    if (!core || !core->network_available) {
        return BOX3_AGENT_SUPERVISOR_ACTION_NONE;
    }
    if (core->state == BOX3_AGENT_SUPERVISOR_BACKOFF &&
        now_ms >= core->retry_at_ms) {
        core->state = BOX3_AGENT_SUPERVISOR_REFRESHING;
        return BOX3_AGENT_SUPERVISOR_ACTION_REFRESH;
    }
    if ((core->state == BOX3_AGENT_SUPERVISOR_STARTING ||
         core->state == BOX3_AGENT_SUPERVISOR_ONLINE) &&
        now_ms >= core->refresh_at_ms) {
        core->state = BOX3_AGENT_SUPERVISOR_STOPPING;
        core->after_stop = BOX3_AGENT_SUPERVISOR_REFRESHING;
        return BOX3_AGENT_SUPERVISOR_ACTION_STOP;
    }
    return BOX3_AGENT_SUPERVISOR_ACTION_NONE;
}

uint32_t box3_agent_supervisor_core_wait_ms(
    const box3_agent_supervisor_core_t *core,
    uint64_t now_ms,
    uint32_t ceiling_ms)
{
    if (!core || ceiling_ms == 0) {
        return 0;
    }
    uint64_t deadline = 0;
    if (core->state == BOX3_AGENT_SUPERVISOR_BACKOFF) {
        deadline = core->retry_at_ms;
    } else if (core->state == BOX3_AGENT_SUPERVISOR_STARTING ||
               core->state == BOX3_AGENT_SUPERVISOR_ONLINE) {
        deadline = core->refresh_at_ms;
    } else {
        return ceiling_ms;
    }
    if (deadline <= now_ms) {
        return 0;
    }
    const uint64_t remaining = deadline - now_ms;
    return remaining < ceiling_ms ? (uint32_t)remaining : ceiling_ms;
}
