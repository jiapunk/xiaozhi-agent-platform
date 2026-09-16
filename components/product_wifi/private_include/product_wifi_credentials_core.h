#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    PRODUCT_WIFI_SSID_MAX = 32,
    PRODUCT_WIFI_PASSWORD_MIN = 8,
    PRODUCT_WIFI_PASSWORD_MAX = 63,
    PRODUCT_WIFI_CREDENTIAL_BLOB_SIZE = 108,
};

typedef struct {
    char ssid[PRODUCT_WIFI_SSID_MAX + 1];
    char password[PRODUCT_WIFI_PASSWORD_MAX + 1];
} product_wifi_credentials_t;

bool product_wifi_credentials_valid(const char *ssid, const char *password);

bool product_wifi_credentials_encode(
    const product_wifi_credentials_t *credentials,
    uint8_t output[PRODUCT_WIFI_CREDENTIAL_BLOB_SIZE]);

bool product_wifi_credentials_decode(
    const uint8_t *input,
    size_t input_size,
    product_wifi_credentials_t *credentials);

#ifdef __cplusplus
}
#endif
