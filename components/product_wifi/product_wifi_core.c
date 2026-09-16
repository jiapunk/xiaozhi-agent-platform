#include "product_wifi_core.h"

#include <limits.h>
#include <string.h>

enum {
    PRODUCT_WIFI_MAXIMUM_BACKOFF_LIMIT_MS = 15U * 60U * 1000U,
    PRODUCT_WIFI_MAXIMUM_AUTH_FAILURE_LIMIT = 20,
};

static product_wifi_action_t network_down(product_wifi_core_t *core)
{
    if (!core->network_available) {
        return PRODUCT_WIFI_ACTION_NONE;
    }
    core->network_available = false;
    return PRODUCT_WIFI_ACTION_NETWORK_DOWN;
}

static uint32_t bounded_backoff(product_wifi_core_t *core,
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

bool product_wifi_core_init(product_wifi_core_t *core,
                            const product_wifi_core_config_t *config)
{
    if (!core || !config || config->minimum_backoff_ms == 0 ||
        config->maximum_backoff_ms < config->minimum_backoff_ms ||
        config->maximum_backoff_ms > PRODUCT_WIFI_MAXIMUM_BACKOFF_LIMIT_MS ||
        config->authentication_failure_limit == 0 ||
        config->authentication_failure_limit >
            PRODUCT_WIFI_MAXIMUM_AUTH_FAILURE_LIMIT) {
        return false;
    }
    memset(core, 0, sizeof(*core));
    core->state = PRODUCT_WIFI_STATE_STOPPED;
    core->minimum_backoff_ms = config->minimum_backoff_ms;
    core->maximum_backoff_ms = config->maximum_backoff_ms;
    core->authentication_failure_limit =
        config->authentication_failure_limit;
    return true;
}

product_wifi_action_t product_wifi_core_start(product_wifi_core_t *core,
                                              bool has_credentials)
{
    if (!core || core->state != PRODUCT_WIFI_STATE_STOPPED) {
        return PRODUCT_WIFI_ACTION_NONE;
    }
    core->has_credentials = has_credentials;
    if (!has_credentials) {
        core->state = PRODUCT_WIFI_STATE_UNPROVISIONED;
        return PRODUCT_WIFI_ACTION_REQUIRE_ONBOARDING;
    }
    core->state = PRODUCT_WIFI_STATE_CONNECTING;
    core->station_started = true;
    return PRODUCT_WIFI_ACTION_START_STATION;
}

product_wifi_action_t product_wifi_core_station_started(
    product_wifi_core_t *core)
{
    if (!core || core->state != PRODUCT_WIFI_STATE_CONNECTING ||
        !core->has_credentials) {
        return PRODUCT_WIFI_ACTION_NONE;
    }
    core->station_started = true;
    return PRODUCT_WIFI_ACTION_CONNECT;
}

product_wifi_action_t product_wifi_core_got_ip(product_wifi_core_t *core)
{
    if (!core || (core->state != PRODUCT_WIFI_STATE_CONNECTING &&
                  core->state != PRODUCT_WIFI_STATE_BACKOFF)) {
        return PRODUCT_WIFI_ACTION_NONE;
    }
    core->state = PRODUCT_WIFI_STATE_ONLINE;
    core->network_available = true;
    if (core->candidate_credentials) {
        core->has_credentials = true;
        core->candidate_credentials = false;
    }
    core->consecutive_failures = 0;
    core->consecutive_authentication_failures = 0;
    core->retry_at_ms = 0;
    return PRODUCT_WIFI_ACTION_NETWORK_UP;
}

product_wifi_action_t product_wifi_core_disconnected(
    product_wifi_core_t *core,
    bool authentication_failure,
    uint64_t now_ms,
    uint32_t random_value)
{
    if (!core) {
        return PRODUCT_WIFI_ACTION_NONE;
    }
    const bool candidate_connection =
        core->onboarding_active && core->candidate_credentials &&
        core->state == PRODUCT_WIFI_STATE_CONNECTING;
    const bool regular_connection =
        core->has_credentials &&
        (core->state == PRODUCT_WIFI_STATE_CONNECTING ||
         core->state == PRODUCT_WIFI_STATE_ONLINE ||
         core->state == PRODUCT_WIFI_STATE_BACKOFF);
    if (!candidate_connection && !regular_connection) {
        return PRODUCT_WIFI_ACTION_NONE;
    }

    product_wifi_action_t actions = network_down(core);
    if (core->onboarding_active && core->candidate_credentials) {
        core->candidate_credentials = false;
        core->station_started = false;
        core->state = PRODUCT_WIFI_STATE_ONBOARDING;
        core->retry_at_ms = 0;
        core->consecutive_failures = 0;
        if (authentication_failure &&
            core->consecutive_authentication_failures < UINT32_MAX) {
            ++core->consecutive_authentication_failures;
        }
        return actions | PRODUCT_WIFI_ACTION_REJECT_CANDIDATE;
    }
    if (authentication_failure) {
        if (core->consecutive_authentication_failures < UINT32_MAX) {
            ++core->consecutive_authentication_failures;
        }
        if (core->consecutive_authentication_failures >=
            core->authentication_failure_limit) {
            core->state = PRODUCT_WIFI_STATE_CREDENTIAL_REJECTED;
            core->station_started = false;
            core->retry_at_ms = 0;
            return actions | PRODUCT_WIFI_ACTION_STOP_STATION |
                   PRODUCT_WIFI_ACTION_REQUIRE_ONBOARDING;
        }
    } else {
        core->consecutive_authentication_failures = 0;
    }

    core->retry_at_ms = now_ms + bounded_backoff(core, random_value);
    core->state = PRODUCT_WIFI_STATE_BACKOFF;
    return actions;
}

product_wifi_action_t product_wifi_core_poll(product_wifi_core_t *core,
                                             uint64_t now_ms)
{
    if (!core || core->state != PRODUCT_WIFI_STATE_BACKOFF ||
        now_ms < core->retry_at_ms) {
        return PRODUCT_WIFI_ACTION_NONE;
    }
    core->retry_at_ms = 0;
    core->state = PRODUCT_WIFI_STATE_CONNECTING;
    return PRODUCT_WIFI_ACTION_CONNECT;
}

product_wifi_action_t product_wifi_core_recover_station(
    product_wifi_core_t *core)
{
    if (!core || !core->has_credentials || core->onboarding_active ||
        (core->state != PRODUCT_WIFI_STATE_CONNECTING &&
         core->state != PRODUCT_WIFI_STATE_BACKOFF)) {
        return PRODUCT_WIFI_ACTION_NONE;
    }
    product_wifi_action_t actions = network_down(core);
    core->state = PRODUCT_WIFI_STATE_CONNECTING;
    core->station_started = true;
    core->retry_at_ms = 0;
    core->consecutive_failures = 0;
    core->consecutive_authentication_failures = 0;
    return actions | PRODUCT_WIFI_ACTION_RESTART_STATION;
}

product_wifi_action_t product_wifi_core_begin_onboarding(
    product_wifi_core_t *core)
{
    if (!core || core->state == PRODUCT_WIFI_STATE_STOPPED ||
        core->state == PRODUCT_WIFI_STATE_FATAL) {
        return PRODUCT_WIFI_ACTION_NONE;
    }
    product_wifi_action_t actions = network_down(core);
    if (core->station_started) {
        actions |= PRODUCT_WIFI_ACTION_STOP_STATION;
    }
    core->station_started = false;
    core->state = PRODUCT_WIFI_STATE_ONBOARDING;
    core->onboarding_active = true;
    core->candidate_credentials = false;
    core->retry_at_ms = 0;
    core->consecutive_failures = 0;
    core->consecutive_authentication_failures = 0;
    return actions | PRODUCT_WIFI_ACTION_REQUIRE_ONBOARDING;
}

product_wifi_action_t product_wifi_core_candidate_submitted(
    product_wifi_core_t *core)
{
    if (!core || core->state != PRODUCT_WIFI_STATE_ONBOARDING ||
        !core->onboarding_active || core->candidate_credentials) {
        return PRODUCT_WIFI_ACTION_NONE;
    }
    core->candidate_credentials = true;
    core->station_started = true;
    core->state = PRODUCT_WIFI_STATE_CONNECTING;
    core->consecutive_failures = 0;
    core->consecutive_authentication_failures = 0;
    core->retry_at_ms = 0;
    return PRODUCT_WIFI_ACTION_START_CANDIDATE;
}

product_wifi_action_t product_wifi_core_credentials_cleared(
    product_wifi_core_t *core)
{
    if (!core || core->state != PRODUCT_WIFI_STATE_ONBOARDING) {
        return PRODUCT_WIFI_ACTION_NONE;
    }
    core->has_credentials = false;
    core->candidate_credentials = false;
    core->station_started = false;
    core->network_available = false;
    core->state = PRODUCT_WIFI_STATE_ONBOARDING;
    core->retry_at_ms = 0;
    return PRODUCT_WIFI_ACTION_REQUIRE_ONBOARDING;
}

product_wifi_action_t product_wifi_core_finish_onboarding(
    product_wifi_core_t *core)
{
    if (!core || !core->onboarding_active) {
        return PRODUCT_WIFI_ACTION_NONE;
    }
    core->onboarding_active = false;
    core->candidate_credentials = false;
    core->retry_at_ms = 0;
    core->consecutive_failures = 0;
    core->consecutive_authentication_failures = 0;
    if (core->state == PRODUCT_WIFI_STATE_ONLINE &&
        core->network_available && core->has_credentials) {
        core->station_started = true;
        return PRODUCT_WIFI_ACTION_NONE;
    }
    product_wifi_action_t actions = network_down(core);
    if (core->has_credentials) {
        core->station_started = true;
        core->state = PRODUCT_WIFI_STATE_CONNECTING;
        return actions | PRODUCT_WIFI_ACTION_START_STATION;
    }
    core->station_started = false;
    core->state = PRODUCT_WIFI_STATE_UNPROVISIONED;
    return actions | PRODUCT_WIFI_ACTION_REQUIRE_ONBOARDING;
}

product_wifi_action_t product_wifi_core_stop(product_wifi_core_t *core)
{
    if (!core || core->state == PRODUCT_WIFI_STATE_STOPPED) {
        return PRODUCT_WIFI_ACTION_NONE;
    }
    product_wifi_action_t actions = network_down(core);
    if (core->station_started || core->onboarding_active) {
        actions |= PRODUCT_WIFI_ACTION_STOP_STATION;
    }
    core->station_started = false;
    core->onboarding_active = false;
    core->candidate_credentials = false;
    core->state = PRODUCT_WIFI_STATE_STOPPED;
    core->retry_at_ms = 0;
    return actions;
}

product_wifi_action_t product_wifi_core_fatal(product_wifi_core_t *core)
{
    if (!core) {
        return PRODUCT_WIFI_ACTION_NONE;
    }
    product_wifi_action_t actions = network_down(core);
    if (core->station_started || core->onboarding_active) {
        actions |= PRODUCT_WIFI_ACTION_STOP_STATION;
    }
    core->station_started = false;
    core->onboarding_active = false;
    core->candidate_credentials = false;
    core->state = PRODUCT_WIFI_STATE_FATAL;
    core->retry_at_ms = 0;
    return actions;
}

uint32_t product_wifi_core_wait_ms(const product_wifi_core_t *core,
                                   uint64_t now_ms,
                                   uint32_t ceiling_ms)
{
    if (!core || ceiling_ms == 0 ||
        core->state != PRODUCT_WIFI_STATE_BACKOFF) {
        return ceiling_ms;
    }
    if (core->retry_at_ms <= now_ms) {
        return 0;
    }
    const uint64_t remaining = core->retry_at_ms - now_ms;
    return remaining < ceiling_ms ? (uint32_t)remaining : ceiling_ms;
}
