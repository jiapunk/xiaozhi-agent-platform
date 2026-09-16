#pragma once

#include "esp_err.h"
#include "product_sku_core.h"

#ifdef __cplusplus
extern "C" {
#endif

const product_sku_profile_t *product_sku_get_compiled_profile(void);

/*
 * Checks only hardware facts readable by the running ESP32: chip model/
 * revision and initialized flash/PSRAM geometry. Board revision, button
 * electrical behavior, acoustic performance and eFuse state require signed
 * factory/hardware qualification and are deliberately not inferred here.
 */
esp_err_t product_sku_validate_hardware(
    product_sku_validation_result_t *detail);

/*
 * After product_storage initializes nvs_factory, verifies the exact
 * prod_sku/manifest against the compiled profile, base MAC, observed silicon
 * revision, and the factory-provisioned HMAC_UP identity key. The normal
 * product API deliberately provides no manifest signing or rewrite path.
 */
esp_err_t product_sku_validate_factory_identity(
    product_sku_factory_validation_result_t *detail,
    product_sku_factory_manifest_t *manifest);

#ifdef __cplusplus
}
#endif
