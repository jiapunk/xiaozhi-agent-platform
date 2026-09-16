#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "product_wifi_credentials_core.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    PRODUCT_WIFI_DEVICE_CLAIM_SIZE = 43,
    PRODUCT_WIFI_STATE_BLOB_SIZE = 163,
};

typedef struct {
    product_wifi_credentials_t credentials;
    char device_claim[PRODUCT_WIFI_DEVICE_CLAIM_SIZE + 1];
    bool claim_pending;
} product_wifi_persisted_state_t;

bool product_wifi_device_claim_is_canonical(const char *claim);

bool product_wifi_state_encode(
    const product_wifi_persisted_state_t *state,
    uint8_t output[PRODUCT_WIFI_STATE_BLOB_SIZE]);

bool product_wifi_state_decode(
    const uint8_t *input,
    size_t input_size,
    product_wifi_persisted_state_t *state);

#ifdef __cplusplus
}
#endif
