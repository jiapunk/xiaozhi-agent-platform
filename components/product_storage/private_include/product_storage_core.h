#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

bool product_storage_core_key_id_valid(int32_t key_id);

bool product_storage_core_identity_key_allowed(bool encryption_required,
                                               int32_t nvs_key_id,
                                               uint8_t identity_key_id);

#ifdef __cplusplus
}
#endif
