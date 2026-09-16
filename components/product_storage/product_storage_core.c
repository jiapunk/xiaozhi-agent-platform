#include "product_storage_core.h"

bool product_storage_core_key_id_valid(int32_t key_id)
{
    return key_id >= 0 && key_id <= 5;
}

bool product_storage_core_identity_key_allowed(bool encryption_required,
                                               int32_t nvs_key_id,
                                               uint8_t identity_key_id)
{
    if (identity_key_id > 5) {
        return false;
    }
    return !encryption_required ||
           !product_storage_core_key_id_valid(nvs_key_id) ||
           (int32_t)identity_key_id != nvs_key_id;
}
