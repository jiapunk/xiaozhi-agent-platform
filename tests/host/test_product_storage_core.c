#include "product_storage_core.h"

#include <assert.h>
#include <stdio.h>

int main(void)
{
    assert(!product_storage_core_key_id_valid(-1));
    assert(product_storage_core_key_id_valid(0));
    assert(product_storage_core_key_id_valid(5));
    assert(!product_storage_core_key_id_valid(6));

    assert(product_storage_core_identity_key_allowed(false, -1, 4));
    assert(product_storage_core_identity_key_allowed(true, 4, 5));
    assert(!product_storage_core_identity_key_allowed(true, 4, 4));
    assert(!product_storage_core_identity_key_allowed(true, 4, 6));

    puts("product_storage_core: all tests passed");
    return 0;
}
