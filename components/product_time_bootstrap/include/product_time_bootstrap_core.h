#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PRODUCT_TIME_BOOTSTRAP_MINIMUM_UNIX INT64_C(1609459200)
#define PRODUCT_TIME_BOOTSTRAP_MAXIMUM_UNIX INT64_C(4102444800)

bool product_time_bootstrap_plausible(int64_t unix_seconds);

uint32_t product_time_bootstrap_retry_ms(
    uint32_t consecutive_failures,
    uint32_t minimum_backoff_ms,
    uint32_t maximum_backoff_ms,
    uint32_t random_value);

#ifdef __cplusplus
}
#endif
