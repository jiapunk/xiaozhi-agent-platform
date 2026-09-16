#include "bread_s3cam_bringup.h"

#include "esp_err.h"
#include "esp_log.h"
#include "product_sku.h"

static const char *TAG = "agent_platform";

void app_main(void)
{
    ESP_LOGI(TAG, "Product-owned Agent hardware diagnostic booted");
    const product_sku_profile_t *sku = product_sku_get_compiled_profile();
    product_sku_validation_result_t detail =
        PRODUCT_SKU_VALIDATION_INVALID_PROFILE;
    const esp_err_t sku_error = product_sku_validate_hardware(&detail);
    if (!sku || sku_error != ESP_OK) {
        ESP_LOGE(TAG, "Product SKU hardware geometry failed closed: %s (%s)",
                 esp_err_to_name(sku_error),
                 product_sku_validation_result_name(detail));
        return;
    }
    ESP_LOGI(TAG,
             "Product SKU=%s board-contract=%s revision=%u; readable "
             "silicon and memory geometry verified",
             sku->sku, sku->board,
             (unsigned)sku->product_hardware_revision);
    ESP_LOGW(TAG,
             "DEVELOPMENT-ONLY Bread S3CAM firmware: browser Wi-Fi onboarding "
             "uses plaintext development NVS; XiaoZhi voice bootstrap tokens "
             "are RAM-only and omitted from logs; eFuse writes and remote "
             "state-changing commands remain disabled");
    const esp_err_t error = bread_s3cam_bringup_start();
    if (error != ESP_OK) {
        ESP_LOGE(TAG, "Bread S3CAM diagnostic failed: %s",
                 esp_err_to_name(error));
        return;
    }
    ESP_LOGI(TAG,
             "Bread S3CAM test UI active: short-press BOOT opens the live "
             "camera page, then microphone meter, then the consent-bound "
             "ESP-Claw action; hold 1.5 seconds to retest or 4 seconds to "
             "open the physical-presence Wi-Fi setup window. Once Wi-Fi is "
             "online, the UI securely starts XiaoZhi voice activation");
}
