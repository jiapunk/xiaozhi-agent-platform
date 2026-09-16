#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    PRODUCT_PROVISIONING_SALT_MIN = 16,
    PRODUCT_PROVISIONING_SALT_MAX = 32,
    PRODUCT_PROVISIONING_VERIFIER_SIZE = 384,
    PRODUCT_PROVISIONING_MATERIAL_AUTHENTICATED_SIZE = 428,
    PRODUCT_PROVISIONING_MATERIAL_AUTH_TAG_SIZE = 32,
    PRODUCT_PROVISIONING_MATERIAL_BLOB_SIZE = 460,
    PRODUCT_PROVISIONING_AP_SECRET_SIZE = 20,
    PRODUCT_PROVISIONING_SERVICE_NAME_SIZE = 10,
};

typedef struct {
    uint8_t salt[PRODUCT_PROVISIONING_SALT_MAX];
    uint16_t salt_size;
    uint8_t verifier[PRODUCT_PROVISIONING_VERIFIER_SIZE];
    uint8_t auth_tag[PRODUCT_PROVISIONING_MATERIAL_AUTH_TAG_SIZE];
} product_provisioning_material_t;

bool product_provisioning_material_encode(
    const product_provisioning_material_t *material,
    uint8_t output[PRODUCT_PROVISIONING_MATERIAL_BLOB_SIZE]);

bool product_provisioning_material_decode(
    const uint8_t *input,
    size_t input_size,
    product_provisioning_material_t *material);

bool product_provisioning_format_service_name(
    const uint8_t mac[6],
    char output[PRODUCT_PROVISIONING_SERVICE_NAME_SIZE]);

bool product_provisioning_format_ap_secret(
    const uint8_t derived_key[32],
    char output[PRODUCT_PROVISIONING_AP_SECRET_SIZE + 1]);

#ifdef __cplusplus
}
#endif
