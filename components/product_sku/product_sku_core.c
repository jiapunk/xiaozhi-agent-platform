#include "product_sku_core.h"

#include <ctype.h>
#include <string.h>

static const uint8_t FACTORY_MANIFEST_MAGIC[4] = {'X', 'S', 'K', 'U'};
static const uint8_t FACTORY_MANIFEST_DOMAIN[] =
    "XIAOZHI-PRODUCT-SKU-MANIFEST-V1";

_Static_assert(sizeof(FACTORY_MANIFEST_DOMAIN) == 32,
               "factory SKU manifest domain changed");

static const uint64_t SUPPORTED_READ_CAPABILITIES =
    PRODUCT_SKU_CAPABILITY_DEVICE_GET_STATUS;
static const uint64_t SUPPORTED_ACTION_CAPABILITIES =
    PRODUCT_SKU_CAPABILITY_DEVICE_SET_INDICATOR |
    PRODUCT_SKU_CAPABILITY_DEVICE_SET_VOLUME;

static const product_sku_profile_t S3_N32R16_REFERENCE = {
    .id = PRODUCT_SKU_ID_S3_N32R16_REFERENCE,
    .sku = "XIAOZHI_AGENT_S3_REFERENCE",
    .board = "esp32s3-n32r16",
    .lifecycle = PRODUCT_SKU_LIFECYCLE_DEVELOPMENT_ONLY,
    .chip = PRODUCT_SKU_CHIP_ESP32S3,
    .chip_revision_min = 0,
    .chip_revision_max = 999,
    .product_hardware_revision = 0,
    .flash_bytes = 32U * 1024U * 1024U,
    .psram_bytes = 16U * 1024U * 1024U,
    .live_runtime_allowed = false,
    .audio_input_present = false,
    .audio_output_present = false,
    .full_duplex_audio_designed = false,
    .display_present = false,
    .status_indicator_present = false,
    .status_indicator_gpio = PRODUCT_SKU_NO_GPIO,
    .status_indicator_active_high = false,
    .physical_presence_input_present = false,
    .physical_presence_gpio = PRODUCT_SKU_NO_GPIO,
    .physical_presence_active_high = false,
    .onboarding_hold_ms = 0,
    .factory_reset_hold_ms = 0,
    .allowed_read_capabilities = 0,
    .allowed_action_capabilities = 0,
    .identity_hmac_key_id = PRODUCT_SKU_NO_HMAC_KEY,
    .factory_record_version_min = 0,
    .factory_qualification_required = false,
    .production_security_required = false,
};

static const product_sku_profile_t VOICE_AGENT_KIT_BOX3 = {
    .id = PRODUCT_SKU_ID_VOICE_AGENT_KIT_BOX3,
    .sku = "VOICE_AGENT_KIT_BOX3",
    .board = "esp32s3-box3",
    .lifecycle = PRODUCT_SKU_LIFECYCLE_CANDIDATE,
    .chip = PRODUCT_SKU_CHIP_ESP32S3,
    .chip_revision_min = 0,
    .chip_revision_max = 999,
    .product_hardware_revision = 1,
    .flash_bytes = 16U * 1024U * 1024U,
    .psram_bytes = 8U * 1024U * 1024U,
    .live_runtime_allowed = true,
    .audio_input_present = true,
    .audio_output_present = true,
    .full_duplex_audio_designed = true,
    .display_present = true,
    .status_indicator_present = true,
    .status_indicator_gpio = 47,
    .status_indicator_active_high = true,
    .physical_presence_input_present = true,
    .physical_presence_gpio = 0,
    .physical_presence_active_high = false,
    .onboarding_hold_ms = 3000,
    .factory_reset_hold_ms = 10000,
    .allowed_read_capabilities = PRODUCT_SKU_CAPABILITY_DEVICE_GET_STATUS,
    .allowed_action_capabilities = PRODUCT_SKU_CAPABILITY_DEVICE_SET_INDICATOR |
                                   PRODUCT_SKU_CAPABILITY_DEVICE_SET_VOLUME,
    .identity_hmac_key_id = 5,
    .factory_record_version_min = 1,
    .factory_qualification_required = true,
    .production_security_required = true,
};

static const product_sku_profile_t BREAD_COMPACT_WIFI_S3CAM_DEVKIT = {
    .id = PRODUCT_SKU_ID_BREAD_COMPACT_WIFI_S3CAM_DEVKIT,
    .sku = "BREAD_COMPACT_WIFI_S3CAM_DEVKIT",
    .board = "bread-compact-wifi-s3cam",
    .lifecycle = PRODUCT_SKU_LIFECYCLE_DEVELOPMENT_ONLY,
    .chip = PRODUCT_SKU_CHIP_ESP32S3,
    .chip_revision_min = 0,
    .chip_revision_max = 999,
    .product_hardware_revision = 1,
    .flash_bytes = 16U * 1024U * 1024U,
    .psram_bytes = 8U * 1024U * 1024U,
    .live_runtime_allowed = false,
    .audio_input_present = true,
    .audio_output_present = true,
    .full_duplex_audio_designed = false,
    .display_present = true,
    .status_indicator_present = true,
    .status_indicator_gpio = 38,
    .status_indicator_active_high = true,
    .physical_presence_input_present = true,
    .physical_presence_gpio = 0,
    .physical_presence_active_high = false,
    .onboarding_hold_ms = 3000,
    .factory_reset_hold_ms = 10000,
    .allowed_read_capabilities = PRODUCT_SKU_CAPABILITY_DEVICE_GET_STATUS,
    .allowed_action_capabilities = PRODUCT_SKU_CAPABILITY_DEVICE_SET_INDICATOR |
                                   PRODUCT_SKU_CAPABILITY_DEVICE_SET_VOLUME,
    .identity_hmac_key_id = PRODUCT_SKU_NO_HMAC_KEY,
    .factory_record_version_min = 0,
    .factory_qualification_required = false,
    .production_security_required = false,
};

static const product_sku_profile_t WAVESHARE_S3_TOUCH_AMOLED_206_DEVKIT = {
    .id = PRODUCT_SKU_ID_WAVESHARE_S3_TOUCH_AMOLED_206_DEVKIT,
    .sku = "WAVESHARE_S3_TOUCH_AMOLED_206_DEVKIT",
    .board = "waveshare-s3-amoled-206",
    .lifecycle = PRODUCT_SKU_LIFECYCLE_DEVELOPMENT_ONLY,
    .chip = PRODUCT_SKU_CHIP_ESP32S3,
    .chip_revision_min = 0,
    .chip_revision_max = 999,
    .product_hardware_revision = 1,
    .flash_bytes = 32U * 1024U * 1024U,
    .psram_bytes = 8U * 1024U * 1024U,
    .live_runtime_allowed = false,
    .audio_input_present = true,
    .audio_output_present = true,
    .full_duplex_audio_designed = true,
    .display_present = true,
    .status_indicator_present = false,
    .status_indicator_gpio = PRODUCT_SKU_NO_GPIO,
    .status_indicator_active_high = false,
    .physical_presence_input_present = true,
    .physical_presence_gpio = 0,
    .physical_presence_active_high = false,
    .onboarding_hold_ms = 3000,
    .factory_reset_hold_ms = 10000,
    .allowed_read_capabilities = PRODUCT_SKU_CAPABILITY_DEVICE_GET_STATUS,
    .allowed_action_capabilities = PRODUCT_SKU_CAPABILITY_DEVICE_SET_VOLUME,
    .identity_hmac_key_id = PRODUCT_SKU_NO_HMAC_KEY,
    .factory_record_version_min = 0,
    .factory_qualification_required = false,
    .production_security_required = false,
};

static bool sku_name_valid(const char *value) {
  if (!value) {
    return false;
  }
  const size_t length = strlen(value);
  if (length < 1 || length > 63 ||
      !((value[0] >= 'A' && value[0] <= 'Z') ||
        (value[0] >= '0' && value[0] <= '9'))) {
    return false;
  }
  for (size_t index = 0; index < length; ++index) {
    const unsigned char byte = (unsigned char)value[index];
    if (!(isupper(byte) || isdigit(byte) || byte == '_' || byte == '-')) {
      return false;
    }
  }
  return true;
}

static bool board_name_valid(const char *value) {
  if (!value) {
    return false;
  }
  const size_t length = strlen(value);
  if (length < 1 || length > 31 || !(value[0] >= 'a' && value[0] <= 'z')) {
    return false;
  }
  for (size_t index = 0; index < length; ++index) {
    const unsigned char byte = (unsigned char)value[index];
    if (!(islower(byte) || isdigit(byte) || byte == '-')) {
      return false;
    }
  }
  return true;
}

const product_sku_profile_t *product_sku_profile_for_id(product_sku_id_t id) {
  switch (id) {
  case PRODUCT_SKU_ID_S3_N32R16_REFERENCE:
    return &S3_N32R16_REFERENCE;
  case PRODUCT_SKU_ID_VOICE_AGENT_KIT_BOX3:
    return &VOICE_AGENT_KIT_BOX3;
  case PRODUCT_SKU_ID_BREAD_COMPACT_WIFI_S3CAM_DEVKIT:
    return &BREAD_COMPACT_WIFI_S3CAM_DEVKIT;
  case PRODUCT_SKU_ID_WAVESHARE_S3_TOUCH_AMOLED_206_DEVKIT:
    return &WAVESHARE_S3_TOUCH_AMOLED_206_DEVKIT;
  default:
    return NULL;
  }
}

bool product_sku_profile_valid(const product_sku_profile_t *profile) {
  if (!profile || !sku_name_valid(profile->sku) ||
      !board_name_valid(profile->board) ||
      profile->chip != PRODUCT_SKU_CHIP_ESP32S3 ||
      profile->chip_revision_min > profile->chip_revision_max ||
      profile->flash_bytes < 4U * 1024U * 1024U ||
      profile->psram_bytes > 64U * 1024U * 1024U ||
      (profile->allowed_read_capabilities & ~SUPPORTED_READ_CAPABILITIES) !=
          0 ||
      (profile->allowed_action_capabilities & ~SUPPORTED_ACTION_CAPABILITIES) !=
          0 ||
      (profile->full_duplex_audio_designed &&
       (!profile->audio_input_present || !profile->audio_output_present)) ||
      (!profile->audio_output_present &&
       (profile->allowed_action_capabilities &
        PRODUCT_SKU_CAPABILITY_DEVICE_SET_VOLUME) != 0)) {
    return false;
  }
  if (profile->status_indicator_present) {
    if (!profile->display_present || profile->status_indicator_gpio > 48 ||
        (profile->allowed_action_capabilities &
         PRODUCT_SKU_CAPABILITY_DEVICE_SET_INDICATOR) == 0) {
      return false;
    }
  } else if (profile->status_indicator_gpio != PRODUCT_SKU_NO_GPIO ||
             profile->status_indicator_active_high ||
             (profile->allowed_action_capabilities &
              PRODUCT_SKU_CAPABILITY_DEVICE_SET_INDICATOR) != 0) {
    return false;
  }
  if (profile->physical_presence_input_present) {
    if (profile->physical_presence_gpio > 48 ||
        (profile->status_indicator_present &&
         profile->physical_presence_gpio == profile->status_indicator_gpio) ||
        profile->onboarding_hold_ms < 2000 ||
        profile->factory_reset_hold_ms <= profile->onboarding_hold_ms) {
      return false;
    }
  } else if (profile->physical_presence_gpio != PRODUCT_SKU_NO_GPIO ||
             profile->physical_presence_active_high ||
             profile->onboarding_hold_ms != 0 ||
             profile->factory_reset_hold_ms != 0) {
    return false;
  }
  if (profile->lifecycle == PRODUCT_SKU_LIFECYCLE_DEVELOPMENT_ONLY) {
    return !profile->live_runtime_allowed &&
           profile->identity_hmac_key_id == PRODUCT_SKU_NO_HMAC_KEY &&
           profile->factory_record_version_min == 0 &&
           !profile->factory_qualification_required &&
           !profile->production_security_required;
  }
  if (profile->lifecycle == PRODUCT_SKU_LIFECYCLE_CANDIDATE) {
    return profile->product_hardware_revision > 0 &&
           profile->identity_hmac_key_id <= 5 &&
           profile->factory_record_version_min > 0 &&
           profile->factory_qualification_required &&
           profile->production_security_required;
  }
  return false;
}

static uint16_t read_le16(const uint8_t *value) {
  return (uint16_t)value[0] | ((uint16_t)value[1] << 8);
}

static uint32_t read_le32(const uint8_t *value) {
  return (uint32_t)value[0] | ((uint32_t)value[1] << 8) |
         ((uint32_t)value[2] << 16) | ((uint32_t)value[3] << 24);
}

static bool bytes_all(const uint8_t *value, size_t size, uint8_t expected) {
  if (!value) {
    return false;
  }
  for (size_t index = 0; index < size; ++index) {
    if (value[index] != expected) {
      return false;
    }
  }
  return true;
}

static bool base_mac_valid(const uint8_t value[6]) {
  return value && (value[0] & 1U) == 0 && !bytes_all(value, 6, 0) &&
         !bytes_all(value, 6, 0xff);
}

static bool constant_time_equal(const uint8_t *left, const uint8_t *right,
                                size_t size) {
  if (!left || !right) {
    return false;
  }
  uint8_t difference = 0;
  for (size_t index = 0; index < size; ++index) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}

bool product_sku_factory_manifest_auth_message(
    const uint8_t *blob, size_t blob_size,
    uint8_t output[PRODUCT_SKU_FACTORY_AUTH_MESSAGE_BYTES]) {
  if (!blob || blob_size != PRODUCT_SKU_FACTORY_MANIFEST_BYTES || !output ||
      memcmp(blob, FACTORY_MANIFEST_MAGIC, sizeof(FACTORY_MANIFEST_MAGIC)) !=
          0 ||
      blob[4] != 1) {
    if (output) {
      memset(output, 0, PRODUCT_SKU_FACTORY_AUTH_MESSAGE_BYTES);
    }
    return false;
  }
  memcpy(output, FACTORY_MANIFEST_DOMAIN, sizeof(FACTORY_MANIFEST_DOMAIN));
  memcpy(output + sizeof(FACTORY_MANIFEST_DOMAIN), blob,
         PRODUCT_SKU_FACTORY_MANIFEST_AUTHENTICATED_BYTES);
  return true;
}

product_sku_factory_validation_result_t product_sku_factory_manifest_validate(
    const product_sku_profile_t *profile, const uint8_t *blob, size_t blob_size,
    const uint8_t observed_base_mac[6], uint16_t observed_chip_revision,
    const uint8_t computed_tag[PRODUCT_SKU_FACTORY_MANIFEST_TAG_BYTES],
    product_sku_factory_manifest_t *manifest) {
  if (manifest) {
    memset(manifest, 0, sizeof(*manifest));
  }
  if (!profile || !blob || !observed_base_mac || !computed_tag) {
    return PRODUCT_SKU_FACTORY_VALIDATION_INVALID_ARGUMENT;
  }
  if (!profile->factory_qualification_required) {
    return PRODUCT_SKU_FACTORY_VALIDATION_NOT_REQUIRED;
  }
  if (!product_sku_profile_valid(profile) ||
      blob_size != PRODUCT_SKU_FACTORY_MANIFEST_BYTES ||
      memcmp(blob, FACTORY_MANIFEST_MAGIC, sizeof(FACTORY_MANIFEST_MAGIC)) !=
          0 ||
      blob[4] != 1 || blob[10] != 0 || blob[11] != 0) {
    return PRODUCT_SKU_FACTORY_VALIDATION_MANIFEST_FORMAT_INVALID;
  }
  if (!constant_time_equal(
          blob + PRODUCT_SKU_FACTORY_MANIFEST_AUTHENTICATED_BYTES, computed_tag,
          PRODUCT_SKU_FACTORY_MANIFEST_TAG_BYTES)) {
    return PRODUCT_SKU_FACTORY_VALIDATION_AUTHENTICATION_FAILED;
  }
  product_sku_factory_manifest_t parsed = {
      .sku_id = (product_sku_id_t)blob[5],
      .product_hardware_revision = read_le16(blob + 6),
      .chip_revision = read_le16(blob + 8),
      .factory_record_version = read_le32(blob + 18),
  };
  memcpy(parsed.base_mac, blob + 12, sizeof(parsed.base_mac));
  memcpy(parsed.manifest_id, blob + 22, sizeof(parsed.manifest_id));
  if (parsed.sku_id != profile->id) {
    return PRODUCT_SKU_FACTORY_VALIDATION_WRONG_SKU;
  }
  if (parsed.product_hardware_revision != profile->product_hardware_revision) {
    return PRODUCT_SKU_FACTORY_VALIDATION_WRONG_HARDWARE_REVISION;
  }
  if (parsed.chip_revision != observed_chip_revision ||
      parsed.chip_revision < profile->chip_revision_min ||
      parsed.chip_revision > profile->chip_revision_max) {
    return PRODUCT_SKU_FACTORY_VALIDATION_WRONG_CHIP_REVISION;
  }
  if (!base_mac_valid(parsed.base_mac) || !base_mac_valid(observed_base_mac) ||
      !constant_time_equal(parsed.base_mac, observed_base_mac,
                           sizeof(parsed.base_mac))) {
    return PRODUCT_SKU_FACTORY_VALIDATION_WRONG_BASE_MAC;
  }
  if (parsed.factory_record_version < profile->factory_record_version_min) {
    return PRODUCT_SKU_FACTORY_VALIDATION_INVALID_RECORD_VERSION;
  }
  if (bytes_all(parsed.manifest_id, sizeof(parsed.manifest_id), 0) ||
      bytes_all(parsed.manifest_id, sizeof(parsed.manifest_id), 0xff)) {
    return PRODUCT_SKU_FACTORY_VALIDATION_INVALID_MANIFEST_ID;
  }
  if (manifest) {
    *manifest = parsed;
  }
  return PRODUCT_SKU_FACTORY_VALIDATION_OK;
}

const char *product_sku_factory_validation_result_name(
    product_sku_factory_validation_result_t result) {
  switch (result) {
  case PRODUCT_SKU_FACTORY_VALIDATION_OK:
    return "ok";
  case PRODUCT_SKU_FACTORY_VALIDATION_INVALID_ARGUMENT:
    return "invalid_argument";
  case PRODUCT_SKU_FACTORY_VALIDATION_NOT_REQUIRED:
    return "not_required";
  case PRODUCT_SKU_FACTORY_VALIDATION_STORAGE_UNAVAILABLE:
    return "storage_unavailable";
  case PRODUCT_SKU_FACTORY_VALIDATION_MANIFEST_MISSING:
    return "manifest_missing";
  case PRODUCT_SKU_FACTORY_VALIDATION_MANIFEST_FORMAT_INVALID:
    return "manifest_format_invalid";
  case PRODUCT_SKU_FACTORY_VALIDATION_KEY_POLICY_INVALID:
    return "key_policy_invalid";
  case PRODUCT_SKU_FACTORY_VALIDATION_AUTHENTICATION_FAILED:
    return "authentication_failed";
  case PRODUCT_SKU_FACTORY_VALIDATION_WRONG_SKU:
    return "wrong_sku";
  case PRODUCT_SKU_FACTORY_VALIDATION_WRONG_HARDWARE_REVISION:
    return "wrong_hardware_revision";
  case PRODUCT_SKU_FACTORY_VALIDATION_WRONG_CHIP_REVISION:
    return "wrong_chip_revision";
  case PRODUCT_SKU_FACTORY_VALIDATION_WRONG_BASE_MAC:
    return "wrong_base_mac";
  case PRODUCT_SKU_FACTORY_VALIDATION_INVALID_RECORD_VERSION:
    return "invalid_record_version";
  case PRODUCT_SKU_FACTORY_VALIDATION_INVALID_MANIFEST_ID:
    return "invalid_manifest_id";
  default:
    return "unknown";
  }
}

product_sku_validation_result_t product_sku_validate_observation(
    const product_sku_profile_t *profile,
    const product_sku_hardware_observation_t *observation) {
  if (!profile || !observation) {
    return PRODUCT_SKU_VALIDATION_INVALID_ARGUMENT;
  }
  if (!product_sku_profile_valid(profile)) {
    return PRODUCT_SKU_VALIDATION_INVALID_PROFILE;
  }
  if (observation->chip != profile->chip) {
    return PRODUCT_SKU_VALIDATION_WRONG_CHIP;
  }
  if (observation->chip_revision < profile->chip_revision_min ||
      observation->chip_revision > profile->chip_revision_max) {
    return PRODUCT_SKU_VALIDATION_CHIP_REVISION_OUT_OF_RANGE;
  }
  if (observation->flash_bytes != profile->flash_bytes) {
    return PRODUCT_SKU_VALIDATION_WRONG_FLASH_SIZE;
  }
  if (observation->psram_bytes != profile->psram_bytes) {
    return PRODUCT_SKU_VALIDATION_WRONG_PSRAM_SIZE;
  }
  return PRODUCT_SKU_VALIDATION_OK;
}

bool product_sku_capability_allowed(const product_sku_profile_t *profile,
                                    uint64_t capability, bool state_changing) {
  if (!product_sku_profile_valid(profile) || capability == 0 ||
      (capability & (capability - 1U)) != 0) {
    return false;
  }
  const uint64_t allowed = state_changing ? profile->allowed_action_capabilities
                                          : profile->allowed_read_capabilities;
  return (allowed & capability) == capability;
}

const char *
product_sku_validation_result_name(product_sku_validation_result_t result) {
  switch (result) {
  case PRODUCT_SKU_VALIDATION_OK:
    return "ok";
  case PRODUCT_SKU_VALIDATION_INVALID_ARGUMENT:
    return "invalid_argument";
  case PRODUCT_SKU_VALIDATION_INVALID_PROFILE:
    return "invalid_profile";
  case PRODUCT_SKU_VALIDATION_WRONG_CHIP:
    return "wrong_chip";
  case PRODUCT_SKU_VALIDATION_CHIP_REVISION_OUT_OF_RANGE:
    return "chip_revision_out_of_range";
  case PRODUCT_SKU_VALIDATION_WRONG_FLASH_SIZE:
    return "wrong_flash_size";
  case PRODUCT_SKU_VALIDATION_WRONG_PSRAM_SIZE:
    return "wrong_psram_size";
  default:
    return "unknown";
  }
}
