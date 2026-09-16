#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  PRODUCT_SKU_ID_S3_N32R16_REFERENCE = 1,
  PRODUCT_SKU_ID_VOICE_AGENT_KIT_BOX3 = 2,
  PRODUCT_SKU_ID_BREAD_COMPACT_WIFI_S3CAM_DEVKIT = 3,
  PRODUCT_SKU_ID_WAVESHARE_S3_TOUCH_AMOLED_206_DEVKIT = 4,
} product_sku_id_t;

typedef enum {
  PRODUCT_SKU_LIFECYCLE_DEVELOPMENT_ONLY = 1,
  PRODUCT_SKU_LIFECYCLE_CANDIDATE = 2,
} product_sku_lifecycle_t;

typedef enum {
  PRODUCT_SKU_CHIP_UNKNOWN = 0,
  PRODUCT_SKU_CHIP_ESP32S3 = 1,
} product_sku_chip_t;

enum {
  PRODUCT_SKU_CAPABILITY_DEVICE_GET_STATUS = UINT64_C(1) << 0,
  PRODUCT_SKU_CAPABILITY_DEVICE_SET_INDICATOR = UINT64_C(1) << 1,
  PRODUCT_SKU_CAPABILITY_DEVICE_SET_VOLUME = UINT64_C(1) << 2,
  PRODUCT_SKU_NO_HMAC_KEY = 255,
  PRODUCT_SKU_NO_GPIO = 255,
  PRODUCT_SKU_FACTORY_MANIFEST_ID_BYTES = 16,
  PRODUCT_SKU_FACTORY_MANIFEST_AUTHENTICATED_BYTES = 38,
  PRODUCT_SKU_FACTORY_MANIFEST_TAG_BYTES = 32,
  PRODUCT_SKU_FACTORY_MANIFEST_BYTES = 70,
  PRODUCT_SKU_FACTORY_AUTH_MESSAGE_BYTES = 70,
};

typedef struct {
  product_sku_id_t id;
  const char *sku;
  const char *board;
  product_sku_lifecycle_t lifecycle;
  product_sku_chip_t chip;
  uint16_t chip_revision_min;
  uint16_t chip_revision_max;
  uint16_t product_hardware_revision;
  uint32_t flash_bytes;
  uint32_t psram_bytes;
  bool live_runtime_allowed;
  bool audio_input_present;
  bool audio_output_present;
  bool full_duplex_audio_designed;
  bool display_present;
  bool status_indicator_present;
  uint8_t status_indicator_gpio;
  bool status_indicator_active_high;
  bool physical_presence_input_present;
  uint8_t physical_presence_gpio;
  bool physical_presence_active_high;
  uint32_t onboarding_hold_ms;
  uint32_t factory_reset_hold_ms;
  uint64_t allowed_read_capabilities;
  uint64_t allowed_action_capabilities;
  uint8_t identity_hmac_key_id;
  uint32_t factory_record_version_min;
  bool factory_qualification_required;
  bool production_security_required;
} product_sku_profile_t;

typedef struct {
  product_sku_chip_t chip;
  uint16_t chip_revision;
  uint32_t flash_bytes;
  uint32_t psram_bytes;
} product_sku_hardware_observation_t;

typedef enum {
  PRODUCT_SKU_VALIDATION_OK = 0,
  PRODUCT_SKU_VALIDATION_INVALID_ARGUMENT,
  PRODUCT_SKU_VALIDATION_INVALID_PROFILE,
  PRODUCT_SKU_VALIDATION_WRONG_CHIP,
  PRODUCT_SKU_VALIDATION_CHIP_REVISION_OUT_OF_RANGE,
  PRODUCT_SKU_VALIDATION_WRONG_FLASH_SIZE,
  PRODUCT_SKU_VALIDATION_WRONG_PSRAM_SIZE,
} product_sku_validation_result_t;

typedef struct {
  product_sku_id_t sku_id;
  uint16_t product_hardware_revision;
  uint16_t chip_revision;
  uint8_t base_mac[6];
  uint32_t factory_record_version;
  uint8_t manifest_id[PRODUCT_SKU_FACTORY_MANIFEST_ID_BYTES];
} product_sku_factory_manifest_t;

typedef enum {
  PRODUCT_SKU_FACTORY_VALIDATION_OK = 0,
  PRODUCT_SKU_FACTORY_VALIDATION_INVALID_ARGUMENT,
  PRODUCT_SKU_FACTORY_VALIDATION_NOT_REQUIRED,
  PRODUCT_SKU_FACTORY_VALIDATION_STORAGE_UNAVAILABLE,
  PRODUCT_SKU_FACTORY_VALIDATION_MANIFEST_MISSING,
  PRODUCT_SKU_FACTORY_VALIDATION_MANIFEST_FORMAT_INVALID,
  PRODUCT_SKU_FACTORY_VALIDATION_KEY_POLICY_INVALID,
  PRODUCT_SKU_FACTORY_VALIDATION_AUTHENTICATION_FAILED,
  PRODUCT_SKU_FACTORY_VALIDATION_WRONG_SKU,
  PRODUCT_SKU_FACTORY_VALIDATION_WRONG_HARDWARE_REVISION,
  PRODUCT_SKU_FACTORY_VALIDATION_WRONG_CHIP_REVISION,
  PRODUCT_SKU_FACTORY_VALIDATION_WRONG_BASE_MAC,
  PRODUCT_SKU_FACTORY_VALIDATION_INVALID_RECORD_VERSION,
  PRODUCT_SKU_FACTORY_VALIDATION_INVALID_MANIFEST_ID,
} product_sku_factory_validation_result_t;

const product_sku_profile_t *product_sku_profile_for_id(product_sku_id_t id);

bool product_sku_profile_valid(const product_sku_profile_t *profile);

product_sku_validation_result_t product_sku_validate_observation(
    const product_sku_profile_t *profile,
    const product_sku_hardware_observation_t *observation);

bool product_sku_capability_allowed(const product_sku_profile_t *profile,
                                    uint64_t capability, bool state_changing);

const char *
product_sku_validation_result_name(product_sku_validation_result_t result);

bool product_sku_factory_manifest_auth_message(
    const uint8_t *blob, size_t blob_size,
    uint8_t output[PRODUCT_SKU_FACTORY_AUTH_MESSAGE_BYTES]);

product_sku_factory_validation_result_t product_sku_factory_manifest_validate(
    const product_sku_profile_t *profile, const uint8_t *blob, size_t blob_size,
    const uint8_t observed_base_mac[6], uint16_t observed_chip_revision,
    const uint8_t computed_tag[PRODUCT_SKU_FACTORY_MANIFEST_TAG_BYTES],
    product_sku_factory_manifest_t *manifest);

const char *product_sku_factory_validation_result_name(
    product_sku_factory_validation_result_t result);

#ifdef __cplusplus
}
#endif
