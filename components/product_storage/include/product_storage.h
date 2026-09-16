#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PRODUCT_STORAGE_STATE_UNINITIALIZED = 0,
    PRODUCT_STORAGE_STATE_INITIALIZING,
    PRODUCT_STORAGE_STATE_READY,
    PRODUCT_STORAGE_STATE_ERROR,
} product_storage_state_t;

typedef struct {
    product_storage_state_t state;
    bool credentials_encryption_required;
    bool credentials_encrypted;
    bool factory_material_encrypted;
    int8_t nvs_hmac_key_id;
    esp_err_t last_error;
} product_storage_status_t;

/*
 * Initializes the product's NVS partitions exactly once. In the production
 * profile this reads an already-provisioned HMAC_UP key and never generates,
 * burns, erases, or repairs eFuse/NVS state.
 */
esp_err_t product_storage_initialize(void);

/* Product components call this instead of initializing NVS themselves. */
esp_err_t product_storage_require_ready(void);

esp_err_t product_storage_get_status(product_storage_status_t *status);

/* Rejects sharing the production NVS HMAC slot with the device identity. */
bool product_storage_identity_hmac_key_allowed(uint8_t identity_key_id);

#ifdef __cplusplus
}
#endif
