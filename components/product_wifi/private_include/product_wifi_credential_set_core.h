#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "product_wifi_credentials_core.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    PRODUCT_WIFI_CREDENTIAL_SET_LIMIT = 5,
    PRODUCT_WIFI_CREDENTIAL_SET_BLOB_SIZE =
        12 + PRODUCT_WIFI_CREDENTIAL_SET_LIMIT *
                 PRODUCT_WIFI_CREDENTIAL_BLOB_SIZE,
};

typedef struct {
    product_wifi_credentials_t entries[PRODUCT_WIFI_CREDENTIAL_SET_LIMIT];
    uint8_t count;
    uint8_t active_index;
} product_wifi_credential_set_t;

bool product_wifi_credential_set_encode(
    const product_wifi_credential_set_t *set,
    uint8_t output[PRODUCT_WIFI_CREDENTIAL_SET_BLOB_SIZE]);

bool product_wifi_credential_set_decode(
    const uint8_t *input,
    size_t input_size,
    product_wifi_credential_set_t *set);

/* Inserts or updates by SSID, promotes the entry, and bounds the set to five. */
bool product_wifi_credential_set_upsert(
    product_wifi_credential_set_t *set,
    const product_wifi_credentials_t *credentials);

/* Selects the next saved network without exposing credentials to callers. */
bool product_wifi_credential_set_select_next(
    product_wifi_credential_set_t *set,
    product_wifi_credentials_t *credentials);

#ifdef __cplusplus
}
#endif
