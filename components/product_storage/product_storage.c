#include "product_storage.h"

#include <stdatomic.h>
#include <stddef.h>

#include "esp_efuse.h"
#include "esp_hmac.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs_sec_provider.h"
#include "product_storage_core.h"
#include "sdkconfig.h"

#if CONFIG_PRODUCT_STORAGE_REQUIRE_HMAC_NVS_ENCRYPTION && \
    CONFIG_NVS_ENCRYPTION
#error "Use product_storage manual HMAC initialization; CONFIG_NVS_ENCRYPTION may auto-burn eFuse"
#endif

static const char *TAG = "product_storage";
static const char *CREDENTIAL_PARTITION = "nvs";
static const char *FACTORY_PARTITION = "nvs_factory";

static atomic_int storage_state = PRODUCT_STORAGE_STATE_UNINITIALIZED;
static atomic_int storage_error = ESP_OK;

#if CONFIG_PRODUCT_STORAGE_REQUIRE_HMAC_NVS_ENCRYPTION
static void secure_zero(void *memory, size_t size)
{
    volatile uint8_t *bytes = memory;
    while (bytes && size > 0) {
        *bytes++ = 0;
        --size;
    }
}

static bool efuse_policy_valid(hmac_key_id_t key_id)
{
    if (key_id < HMAC_KEY0 || key_id > HMAC_KEY5) {
        return false;
    }
    const esp_efuse_block_t block =
        (esp_efuse_block_t)(EFUSE_BLK_KEY0 + (int)key_id);
    return esp_efuse_get_key_purpose(block) ==
               ESP_EFUSE_KEY_PURPOSE_HMAC_UP &&
           esp_efuse_get_key_dis_read(block) &&
           esp_efuse_get_key_dis_write(block) &&
           esp_efuse_get_keypurpose_dis_write(block);
}
#endif

#if !CONFIG_PRODUCT_STORAGE_REQUIRE_HMAC_NVS_ENCRYPTION
static esp_err_t initialize_plaintext_development(void)
{
    ESP_LOGW(TAG,
             "development profile: product credential NVS is not encrypted");
    esp_err_t error = nvs_flash_init_partition(CREDENTIAL_PARTITION);
    if (error != ESP_OK) {
        return error;
    }
    error = nvs_flash_init_partition(FACTORY_PARTITION);
    if (error != ESP_OK) {
        (void)nvs_flash_deinit_partition(CREDENTIAL_PARTITION);
    }
    return error;
}
#endif

#if CONFIG_PRODUCT_STORAGE_REQUIRE_HMAC_NVS_ENCRYPTION
static esp_err_t initialize_encrypted_credentials(void)
{
    const int32_t configured_key_id =
        CONFIG_PRODUCT_STORAGE_NVS_HMAC_KEY_ID;
    if (!product_storage_core_key_id_valid(configured_key_id)) {
        return ESP_ERR_INVALID_ARG;
    }
    const hmac_key_id_t key_id = (hmac_key_id_t)configured_key_id;
    if (!efuse_policy_valid(key_id)) {
        ESP_LOGE(TAG,
                 "production NVS HMAC key is missing or not fully protected");
        return ESP_ERR_INVALID_STATE;
    }

    nvs_sec_scheme_t *scheme = NULL;
    const nvs_sec_config_hmac_t scheme_config = {
        .hmac_key_id = key_id,
    };
    esp_err_t error =
        nvs_sec_provider_register_hmac(&scheme_config, &scheme);
    nvs_sec_cfg_t keys = {0};
    if (error == ESP_OK) {
        /* Deliberately never call nvs_flash_generate_keys_v2(): it can burn. */
        error = nvs_flash_read_security_cfg_v2(scheme, &keys);
    }
    if (error == ESP_OK) {
        error = nvs_flash_secure_init_partition(CREDENTIAL_PARTITION,
                                                &keys);
    }
    secure_zero(&keys, sizeof(keys));
    if (scheme) {
        const esp_err_t deregister =
            nvs_sec_provider_deregister(scheme);
        if (error == ESP_OK && deregister != ESP_OK) {
            error = deregister;
        }
    }
    if (error != ESP_OK) {
        return error;
    }

    /*
     * nvs_factory contains only public SRP salt/verifier plus per-device HMAC
     * tags and the public, HMAC-authenticated factory SKU manifest. Keeping it
     * plaintext lets the factory generate one image without consuming another
     * eFuse slot; secrets are forbidden there.
     */
    error = nvs_flash_init_partition(FACTORY_PARTITION);
    if (error != ESP_OK) {
        (void)nvs_flash_deinit_partition(CREDENTIAL_PARTITION);
        return error;
    }
    ESP_LOGI(TAG, "product credential NVS initialized with HMAC XTS-AES");
    return ESP_OK;
}
#endif

esp_err_t product_storage_initialize(void)
{
    int state = atomic_load_explicit(&storage_state,
                                     memory_order_acquire);
    if (state == PRODUCT_STORAGE_STATE_READY) {
        return ESP_OK;
    }
    if (state == PRODUCT_STORAGE_STATE_ERROR) {
        return atomic_load_explicit(&storage_error,
                                    memory_order_acquire);
    }
    int expected = PRODUCT_STORAGE_STATE_UNINITIALIZED;
    if (!atomic_compare_exchange_strong_explicit(
            &storage_state, &expected,
            PRODUCT_STORAGE_STATE_INITIALIZING,
            memory_order_acq_rel, memory_order_acquire)) {
        return ESP_ERR_INVALID_STATE;
    }

#if CONFIG_PRODUCT_STORAGE_REQUIRE_HMAC_NVS_ENCRYPTION
    const esp_err_t error = initialize_encrypted_credentials();
#else
    const esp_err_t error = initialize_plaintext_development();
#endif
    atomic_store_explicit(&storage_error, error, memory_order_release);
    atomic_store_explicit(
        &storage_state,
        error == ESP_OK ? PRODUCT_STORAGE_STATE_READY
                        : PRODUCT_STORAGE_STATE_ERROR,
        memory_order_release);
    return error;
}

esp_err_t product_storage_require_ready(void)
{
    return atomic_load_explicit(&storage_state, memory_order_acquire) ==
                   PRODUCT_STORAGE_STATE_READY
               ? ESP_OK
               : ESP_ERR_INVALID_STATE;
}

esp_err_t product_storage_get_status(product_storage_status_t *status)
{
    if (!status) {
        return ESP_ERR_INVALID_ARG;
    }
    const product_storage_state_t state =
        (product_storage_state_t)atomic_load_explicit(
            &storage_state, memory_order_acquire);
    *status = (product_storage_status_t){
        .state = state,
#if CONFIG_PRODUCT_STORAGE_REQUIRE_HMAC_NVS_ENCRYPTION
        .credentials_encryption_required = true,
        .credentials_encrypted = state == PRODUCT_STORAGE_STATE_READY,
        .factory_material_encrypted = false,
        .nvs_hmac_key_id = CONFIG_PRODUCT_STORAGE_NVS_HMAC_KEY_ID,
#else
        .credentials_encryption_required = false,
        .credentials_encrypted = false,
        .factory_material_encrypted = false,
        .nvs_hmac_key_id = -1,
#endif
        .last_error = atomic_load_explicit(&storage_error,
                                           memory_order_acquire),
    };
    return ESP_OK;
}

bool product_storage_identity_hmac_key_allowed(uint8_t identity_key_id)
{
#if CONFIG_PRODUCT_STORAGE_REQUIRE_HMAC_NVS_ENCRYPTION
    return product_storage_core_identity_key_allowed(
        true, CONFIG_PRODUCT_STORAGE_NVS_HMAC_KEY_ID, identity_key_id);
#else
    return product_storage_core_identity_key_allowed(
        false, -1, identity_key_id);
#endif
}
