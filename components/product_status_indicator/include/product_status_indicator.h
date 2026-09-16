#pragma once

#include <stdbool.h>

#include "esp_err.h"
#include "product_sku_core.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct product_status_indicator *product_status_indicator_handle_t;

/*
 * Owns the SKU-frozen status-indicator GPIO and drives it inactive before
 * returning. The profile must explicitly allow device.set_indicator.
 */
esp_err_t product_status_indicator_create(
    const product_sku_profile_t *profile,
    product_status_indicator_handle_t *out_indicator);

/* Direct product adapter for the consent-protected Agent capability. */
esp_err_t product_status_indicator_set(
    product_status_indicator_handle_t indicator,
    bool on);

esp_err_t product_status_indicator_get(
    product_status_indicator_handle_t indicator,
    bool *on);

/* Drives the output inactive, releases the GPIO, and consumes the handle. */
esp_err_t product_status_indicator_destroy(
    product_status_indicator_handle_t indicator);

#ifdef __cplusplus
}
#endif
