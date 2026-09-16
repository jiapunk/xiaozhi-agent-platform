#include "product_status_indicator.h"

#include <stdatomic.h>
#include <string.h>

#include "driver/gpio.h"
#include "esp_heap_caps.h"

struct product_status_indicator {
    gpio_num_t gpio_num;
    bool active_high;
    atomic_bool on;
};

static int output_level(const product_status_indicator_handle_t indicator,
                        bool on)
{
    return on == indicator->active_high ? 1 : 0;
}

static void secure_zero(void *memory, size_t size)
{
    volatile unsigned char *bytes = memory;
    while (bytes && size > 0) {
        *bytes++ = 0;
        --size;
    }
}

esp_err_t product_status_indicator_create(
    const product_sku_profile_t *profile,
    product_status_indicator_handle_t *out_indicator)
{
    if (!out_indicator) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_indicator = NULL;
    if (!product_sku_profile_valid(profile) ||
        !profile->status_indicator_present ||
        !product_sku_capability_allowed(
            profile, PRODUCT_SKU_CAPABILITY_DEVICE_SET_INDICATOR, true) ||
        profile->status_indicator_gpio >= GPIO_NUM_MAX) {
        return ESP_ERR_NOT_SUPPORTED;
    }

    product_status_indicator_handle_t indicator = heap_caps_calloc(
        1, sizeof(*indicator), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!indicator) {
        return ESP_ERR_NO_MEM;
    }
    indicator->gpio_num = (gpio_num_t)profile->status_indicator_gpio;
    indicator->active_high = profile->status_indicator_active_high;
    atomic_init(&indicator->on, false);

    esp_err_t error = gpio_reset_pin(indicator->gpio_num);
    if (error == ESP_OK) {
        error = gpio_set_level(indicator->gpio_num,
                               output_level(indicator, false));
    }
    if (error == ESP_OK) {
        error = gpio_set_direction(indicator->gpio_num,
                                   GPIO_MODE_OUTPUT);
    }
    if (error != ESP_OK) {
        (void)gpio_reset_pin(indicator->gpio_num);
        secure_zero(indicator, sizeof(*indicator));
        heap_caps_free(indicator);
        return error;
    }

    *out_indicator = indicator;
    return ESP_OK;
}

esp_err_t product_status_indicator_set(
    product_status_indicator_handle_t indicator,
    bool on)
{
    if (!indicator) {
        return ESP_ERR_INVALID_ARG;
    }
    const esp_err_t error = gpio_set_level(
        indicator->gpio_num, output_level(indicator, on));
    if (error == ESP_OK) {
        atomic_store_explicit(&indicator->on, on, memory_order_release);
    }
    return error;
}

esp_err_t product_status_indicator_get(
    product_status_indicator_handle_t indicator,
    bool *on)
{
    if (!indicator || !on) {
        return ESP_ERR_INVALID_ARG;
    }
    *on = atomic_load_explicit(&indicator->on, memory_order_acquire);
    return ESP_OK;
}

esp_err_t product_status_indicator_destroy(
    product_status_indicator_handle_t indicator)
{
    if (!indicator) {
        return ESP_OK;
    }
    esp_err_t error = gpio_set_level(
        indicator->gpio_num, output_level(indicator, false));
    if (error != ESP_OK) {
        return error;
    }
    error = gpio_reset_pin(indicator->gpio_num);
    if (error != ESP_OK) {
        return error;
    }
    secure_zero(indicator, sizeof(*indicator));
    heap_caps_free(indicator);
    return ESP_OK;
}
