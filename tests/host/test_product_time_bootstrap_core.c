#include "product_time_bootstrap_core.h"

#include <assert.h>
#include <stdio.h>

int main(void)
{
    assert(!product_time_bootstrap_plausible(
        PRODUCT_TIME_BOOTSTRAP_MINIMUM_UNIX - 1));
    assert(product_time_bootstrap_plausible(
        PRODUCT_TIME_BOOTSTRAP_MINIMUM_UNIX));
    assert(product_time_bootstrap_plausible(
        PRODUCT_TIME_BOOTSTRAP_MAXIMUM_UNIX));
    assert(!product_time_bootstrap_plausible(
        PRODUCT_TIME_BOOTSTRAP_MAXIMUM_UNIX + 1));

    assert(product_time_bootstrap_retry_ms(0, 1000, 8000, 0) == 0);
    assert(product_time_bootstrap_retry_ms(1, 1000, 8000, 0) == 500);
    assert(product_time_bootstrap_retry_ms(2, 1000, 8000, 0) == 1000);
    assert(product_time_bootstrap_retry_ms(4, 1000, 8000, 0) == 4000);
    assert(product_time_bootstrap_retry_ms(20, 1000, 8000, 0) == 4000);
    assert(product_time_bootstrap_retry_ms(1, 0, 8000, 0) == 0);
    assert(product_time_bootstrap_retry_ms(1, 8000, 1000, 0) == 0);

    puts("product_time_bootstrap_core: all tests passed");
    return 0;
}
