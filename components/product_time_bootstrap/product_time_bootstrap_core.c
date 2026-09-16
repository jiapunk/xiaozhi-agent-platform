#include "product_time_bootstrap_core.h"

#include <limits.h>

bool product_time_bootstrap_plausible(int64_t unix_seconds)
{
    return unix_seconds >= PRODUCT_TIME_BOOTSTRAP_MINIMUM_UNIX &&
           unix_seconds <= (int64_t)PRODUCT_TIME_BOOTSTRAP_MAXIMUM_UNIX;
}

uint32_t product_time_bootstrap_retry_ms(
    uint32_t consecutive_failures,
    uint32_t minimum_backoff_ms,
    uint32_t maximum_backoff_ms,
    uint32_t random_value)
{
    if (consecutive_failures == 0 || minimum_backoff_ms == 0 ||
        maximum_backoff_ms < minimum_backoff_ms) {
        return 0;
    }
    uint64_t ceiling = minimum_backoff_ms;
    uint32_t shifts = consecutive_failures - 1;
    while (shifts > 0 && ceiling < maximum_backoff_ms) {
        ceiling = ceiling > UINT32_MAX / 2U
                      ? UINT32_MAX
                      : ceiling * 2U;
        --shifts;
    }
    if (ceiling > maximum_backoff_ms) {
        ceiling = maximum_backoff_ms;
    }
    const uint32_t cap = (uint32_t)ceiling;
    const uint32_t floor = cap / 2U;
    const uint32_t span = cap - floor;
    return floor + (span == UINT32_MAX
                        ? random_value
                        : random_value % (span + 1U));
}
