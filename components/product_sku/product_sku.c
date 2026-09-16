#include "product_sku.h"

#include "sdkconfig.h"

#include "esp_chip_info.h"
#include "esp_efuse.h"
#include "esp_flash.h"
#include "esp_hmac.h"
#include "esp_mac.h"
#include "esp_psram.h"
#include "nvs.h"
#include "product_storage.h"

#include <string.h>

static const char *FACTORY_PARTITION = "nvs_factory";
static const char *FACTORY_SKU_NAMESPACE = "prod_sku";
static const char *FACTORY_SKU_KEY = "manifest";

static void secure_zero(void *memory, size_t size)
{
    volatile uint8_t *bytes = memory;
    while (bytes && size > 0) {
        *bytes++ = 0;
        --size;
    }
}

static bool identity_efuse_policy_valid(uint8_t key_id)
{
    if (key_id > 5) {
        return false;
    }
    const esp_efuse_block_t block =
        (esp_efuse_block_t)(EFUSE_BLK_KEY0 + key_id);
    return esp_efuse_get_key_purpose(block) ==
               ESP_EFUSE_KEY_PURPOSE_HMAC_UP &&
           esp_efuse_get_key_dis_read(block) &&
           esp_efuse_get_key_dis_write(block) &&
           esp_efuse_get_keypurpose_dis_write(block);
}

const product_sku_profile_t *product_sku_get_compiled_profile(void)
{
#if CONFIG_PRODUCT_SKU_VOICE_AGENT_KIT_BOX3
    return product_sku_profile_for_id(PRODUCT_SKU_ID_VOICE_AGENT_KIT_BOX3);
#elif CONFIG_PRODUCT_SKU_BREAD_COMPACT_WIFI_S3CAM_DEVKIT
    return product_sku_profile_for_id(
        PRODUCT_SKU_ID_BREAD_COMPACT_WIFI_S3CAM_DEVKIT);
#elif CONFIG_PRODUCT_SKU_WAVESHARE_S3_TOUCH_AMOLED_206_DEVKIT
    return product_sku_profile_for_id(
        PRODUCT_SKU_ID_WAVESHARE_S3_TOUCH_AMOLED_206_DEVKIT);
#elif CONFIG_PRODUCT_SKU_S3_N32R16_REFERENCE
    return product_sku_profile_for_id(PRODUCT_SKU_ID_S3_N32R16_REFERENCE);
#else
#error "A product-owned SKU must be selected"
#endif
}

esp_err_t product_sku_validate_hardware(
    product_sku_validation_result_t *detail)
{
    const product_sku_profile_t *profile = product_sku_get_compiled_profile();
    esp_chip_info_t chip_info = {0};
    esp_chip_info(&chip_info);
    uint32_t flash_bytes = 0;
    esp_err_t error = esp_flash_get_size(NULL, &flash_bytes);
    if (error != ESP_OK) {
        if (detail) {
            *detail = PRODUCT_SKU_VALIDATION_WRONG_FLASH_SIZE;
        }
        return error;
    }
    const product_sku_hardware_observation_t observation = {
        .chip = chip_info.model == CHIP_ESP32S3
                    ? PRODUCT_SKU_CHIP_ESP32S3
                    : PRODUCT_SKU_CHIP_UNKNOWN,
        .chip_revision = chip_info.revision,
        .flash_bytes = flash_bytes,
        .psram_bytes = (uint32_t)esp_psram_get_size(),
    };
    const product_sku_validation_result_t result =
        product_sku_validate_observation(profile, &observation);
    if (detail) {
        *detail = result;
    }
    return result == PRODUCT_SKU_VALIDATION_OK ? ESP_OK
                                                : ESP_ERR_INVALID_STATE;
}

esp_err_t product_sku_validate_factory_identity(
    product_sku_factory_validation_result_t *detail,
    product_sku_factory_manifest_t *manifest)
{
    if (detail) {
        *detail = PRODUCT_SKU_FACTORY_VALIDATION_INVALID_ARGUMENT;
    }
    if (manifest) {
        memset(manifest, 0, sizeof(*manifest));
    }
    const product_sku_profile_t *profile = product_sku_get_compiled_profile();
    if (!profile) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!profile->factory_qualification_required) {
        if (detail) {
            *detail = PRODUCT_SKU_FACTORY_VALIDATION_NOT_REQUIRED;
        }
        return ESP_OK;
    }
    if (product_storage_require_ready() != ESP_OK) {
        if (detail) {
            *detail = PRODUCT_SKU_FACTORY_VALIDATION_STORAGE_UNAVAILABLE;
        }
        return ESP_ERR_INVALID_STATE;
    }

    uint8_t blob[PRODUCT_SKU_FACTORY_MANIFEST_BYTES] = {0};
    uint8_t auth_message[PRODUCT_SKU_FACTORY_AUTH_MESSAGE_BYTES] = {0};
    uint8_t computed_tag[PRODUCT_SKU_FACTORY_MANIFEST_TAG_BYTES] = {0};
    uint8_t base_mac[6] = {0};
    nvs_handle_t nvs = 0;
    esp_err_t error = nvs_open_from_partition(
        FACTORY_PARTITION, FACTORY_SKU_NAMESPACE, NVS_READONLY, &nvs);
    if (error != ESP_OK) {
        if (detail) {
            *detail = error == ESP_ERR_NVS_NOT_FOUND
                          ? PRODUCT_SKU_FACTORY_VALIDATION_MANIFEST_MISSING
                          : PRODUCT_SKU_FACTORY_VALIDATION_STORAGE_UNAVAILABLE;
        }
        goto cleanup;
    }
    size_t blob_size = 0;
    error = nvs_get_blob(nvs, FACTORY_SKU_KEY, NULL, &blob_size);
    if (error != ESP_OK) {
        if (detail) {
            *detail = error == ESP_ERR_NVS_NOT_FOUND
                          ? PRODUCT_SKU_FACTORY_VALIDATION_MANIFEST_MISSING
                          : PRODUCT_SKU_FACTORY_VALIDATION_STORAGE_UNAVAILABLE;
        }
        goto cleanup;
    }
    if (blob_size != sizeof(blob)) {
        if (detail) {
            *detail = PRODUCT_SKU_FACTORY_VALIDATION_MANIFEST_FORMAT_INVALID;
        }
        error = ESP_ERR_INVALID_SIZE;
        goto cleanup;
    }
    error = nvs_get_blob(nvs, FACTORY_SKU_KEY, blob, &blob_size);
    if (error != ESP_OK) {
        if (detail) {
            *detail = PRODUCT_SKU_FACTORY_VALIDATION_STORAGE_UNAVAILABLE;
        }
        goto cleanup;
    }
    if (
        !product_sku_factory_manifest_auth_message(
            blob, blob_size, auth_message)) {
        if (detail) {
            *detail = PRODUCT_SKU_FACTORY_VALIDATION_MANIFEST_FORMAT_INVALID;
        }
        error = ESP_ERR_INVALID_SIZE;
        goto cleanup;
    }
    if (!identity_efuse_policy_valid(profile->identity_hmac_key_id)) {
        if (detail) {
            *detail = PRODUCT_SKU_FACTORY_VALIDATION_KEY_POLICY_INVALID;
        }
        error = ESP_ERR_INVALID_STATE;
        goto cleanup;
    }
    error = esp_hmac_calculate(
        (hmac_key_id_t)profile->identity_hmac_key_id,
        auth_message, sizeof(auth_message), computed_tag);
    if (error != ESP_OK) {
        if (detail) {
            *detail = PRODUCT_SKU_FACTORY_VALIDATION_AUTHENTICATION_FAILED;
        }
        goto cleanup;
    }
    error = esp_read_mac(base_mac, ESP_MAC_BASE);
    if (error != ESP_OK) {
        if (detail) {
            *detail = PRODUCT_SKU_FACTORY_VALIDATION_WRONG_BASE_MAC;
        }
        goto cleanup;
    }
    esp_chip_info_t chip_info = {0};
    esp_chip_info(&chip_info);
    const product_sku_factory_validation_result_t result =
        product_sku_factory_manifest_validate(
            profile, blob, blob_size, base_mac, chip_info.revision,
            computed_tag, manifest);
    if (detail) {
        *detail = result;
    }
    error = result == PRODUCT_SKU_FACTORY_VALIDATION_OK
                ? ESP_OK
                : ESP_ERR_INVALID_STATE;

cleanup:
    if (nvs != 0) {
        nvs_close(nvs);
    }
    secure_zero(blob, sizeof(blob));
    secure_zero(auth_message, sizeof(auth_message));
    secure_zero(computed_tag, sizeof(computed_tag));
    secure_zero(base_mac, sizeof(base_mac));
    if (error != ESP_OK && manifest) {
        memset(manifest, 0, sizeof(*manifest));
    }
    return error;
}
