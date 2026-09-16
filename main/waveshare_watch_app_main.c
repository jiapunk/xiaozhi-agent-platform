#include "esp_log.h"
#include "product_sku.h"
#include "waveshare_watch_bringup.h"

static const char *TAG = "watch_app";

void app_main(void)
{
    product_sku_validation_result_t detail =
        PRODUCT_SKU_VALIDATION_INVALID_ARGUMENT;
    esp_err_t error = product_sku_validate_hardware(&detail);
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "Watch hardware profile rejected: %s",
                 product_sku_validation_result_name(detail));
        return;
    }
    ESP_LOGI(TAG, "Watch hardware profile accepted: ESP32-S3, 32MB Flash, 8MB PSRAM");

    error = waveshare_watch_bringup_start();
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "Watch bring-up failed: %s", esp_err_to_name(error));
        return;
    }
    ESP_LOGI(TAG, "Watch display, touch, microphone and speaker test active");
}
