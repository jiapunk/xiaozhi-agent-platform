#include "agent_device_time_core.h"

#include <limits.h>
#include <string.h>

enum {
    MINIMUM_AGE_SECONDS = 60,
    MAXIMUM_AGE_SECONDS = 7 * 24 * 60 * 60,
    MAXIMUM_BACKWARD_TOLERANCE_SECONDS = 300,
};

static const int64_t MINIMUM_UNIX_TIME = INT64_C(1609459200); /* 2021-01-01 */
static const int64_t MAXIMUM_UNIX_TIME = INT64_C(4102444800); /* 2100-01-01 */

static bool estimate(const agent_device_time_core_t *core,
                     uint64_t monotonic_ms,
                     int64_t *unix_seconds,
                     uint64_t *age_ms)
{
    if (!core || !core->synchronized || !unix_seconds ||
        monotonic_ms < core->monotonic_at_sync_ms) {
        return false;
    }
    const uint64_t elapsed_ms = monotonic_ms - core->monotonic_at_sync_ms;
    const uint64_t elapsed_seconds = elapsed_ms / 1000;
    if (elapsed_seconds > (uint64_t)(MAXIMUM_UNIX_TIME -
                                     core->unix_at_sync)) {
        return false;
    }
    *unix_seconds = core->unix_at_sync + (int64_t)elapsed_seconds;
    if (age_ms) {
        *age_ms = elapsed_ms;
    }
    return *unix_seconds >= MINIMUM_UNIX_TIME &&
           *unix_seconds <= MAXIMUM_UNIX_TIME;
}

bool agent_device_time_core_init(
    agent_device_time_core_t *core,
    uint32_t maximum_age_seconds,
    uint32_t backward_tolerance_seconds)
{
    if (!core || maximum_age_seconds < MINIMUM_AGE_SECONDS ||
        maximum_age_seconds > MAXIMUM_AGE_SECONDS ||
        backward_tolerance_seconds >
            MAXIMUM_BACKWARD_TOLERANCE_SECONDS) {
        return false;
    }
    memset(core, 0, sizeof(*core));
    core->maximum_age_seconds = maximum_age_seconds;
    core->backward_tolerance_seconds = backward_tolerance_seconds;
    return true;
}

bool agent_device_time_core_accept(
    agent_device_time_core_t *core,
    int64_t unix_seconds,
    uint64_t monotonic_ms)
{
    if (!core || unix_seconds < MINIMUM_UNIX_TIME ||
        unix_seconds > MAXIMUM_UNIX_TIME) {
        return false;
    }
    if (core->synchronized) {
        int64_t estimated = 0;
        if (!estimate(core, monotonic_ms, &estimated, NULL) ||
            (unix_seconds < estimated &&
             (uint64_t)(estimated - unix_seconds) >
                 core->backward_tolerance_seconds)) {
            return false;
        }
    }
    core->synchronized = true;
    core->unix_at_sync = unix_seconds;
    core->monotonic_at_sync_ms = monotonic_ms;
    return true;
}

bool agent_device_time_core_now(
    const agent_device_time_core_t *core,
    uint64_t monotonic_ms,
    int64_t *unix_seconds)
{
    uint64_t age_ms = 0;
    if (!estimate(core, monotonic_ms, unix_seconds, &age_ms)) {
        return false;
    }
    return age_ms <= (uint64_t)core->maximum_age_seconds * 1000;
}

bool agent_device_time_core_status(
    const agent_device_time_core_t *core,
    uint64_t monotonic_ms,
    agent_device_time_status_t *status)
{
    if (!core || !status) {
        return false;
    }
    memset(status, 0, sizeof(*status));
    if (!core->synchronized || monotonic_ms < core->monotonic_at_sync_ms) {
        return true;
    }
    uint64_t age_ms = 0;
    int64_t unused_time = 0;
    const bool estimated = estimate(core, monotonic_ms,
                                    &unused_time, &age_ms);
    status->synchronized = estimated &&
        age_ms <= (uint64_t)core->maximum_age_seconds * 1000;
    status->age_seconds = age_ms / 1000;
    return true;
}
