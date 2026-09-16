#include "product_sku_core.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static product_sku_hardware_observation_t
observation_for(const product_sku_profile_t *profile) {
  return (product_sku_hardware_observation_t){
      .chip = profile->chip,
      .chip_revision = profile->chip_revision_min,
      .flash_bytes = profile->flash_bytes,
      .psram_bytes = profile->psram_bytes,
  };
}

static void write_le16(uint8_t *output, uint16_t value) {
  output[0] = (uint8_t)(value & 0xffU);
  output[1] = (uint8_t)(value >> 8);
}

static void write_le32(uint8_t *output, uint32_t value) {
  output[0] = (uint8_t)(value & 0xffU);
  output[1] = (uint8_t)((value >> 8) & 0xffU);
  output[2] = (uint8_t)((value >> 16) & 0xffU);
  output[3] = (uint8_t)(value >> 24);
}

static void make_factory_manifest(
    uint8_t blob[PRODUCT_SKU_FACTORY_MANIFEST_BYTES],
    uint8_t computed_tag[PRODUCT_SKU_FACTORY_MANIFEST_TAG_BYTES],
    const uint8_t base_mac[6], uint16_t chip_revision) {
  memset(blob, 0, PRODUCT_SKU_FACTORY_MANIFEST_BYTES);
  memcpy(blob, "XSKU", 4);
  blob[4] = 1;
  blob[5] = PRODUCT_SKU_ID_VOICE_AGENT_KIT_BOX3;
  write_le16(blob + 6, 1);
  write_le16(blob + 8, chip_revision);
  memcpy(blob + 12, base_mac, 6);
  write_le32(blob + 18, 7);
  for (size_t index = 0; index < PRODUCT_SKU_FACTORY_MANIFEST_ID_BYTES;
       ++index) {
    blob[22 + index] = (uint8_t)(index + 1);
  }
  for (size_t index = 0; index < PRODUCT_SKU_FACTORY_MANIFEST_TAG_BYTES;
       ++index) {
    computed_tag[index] = (uint8_t)(0xa0U + index);
  }
  memcpy(blob + PRODUCT_SKU_FACTORY_MANIFEST_AUTHENTICATED_BYTES, computed_tag,
         PRODUCT_SKU_FACTORY_MANIFEST_TAG_BYTES);
}

static void test_frozen_profiles(void) {
  const product_sku_profile_t *reference =
      product_sku_profile_for_id(PRODUCT_SKU_ID_S3_N32R16_REFERENCE);
  const product_sku_profile_t *box3 =
      product_sku_profile_for_id(PRODUCT_SKU_ID_VOICE_AGENT_KIT_BOX3);
  const product_sku_profile_t *s3cam = product_sku_profile_for_id(
      PRODUCT_SKU_ID_BREAD_COMPACT_WIFI_S3CAM_DEVKIT);
  const product_sku_profile_t *watch = product_sku_profile_for_id(
      PRODUCT_SKU_ID_WAVESHARE_S3_TOUCH_AMOLED_206_DEVKIT);
  assert(reference && box3 && s3cam && watch);
  assert(product_sku_profile_for_id((product_sku_id_t)99) == NULL);
  assert(product_sku_profile_valid(reference));
  assert(product_sku_profile_valid(box3));
  assert(strcmp(reference->sku, "XIAOZHI_AGENT_S3_REFERENCE") == 0);
  assert(!reference->live_runtime_allowed);
  assert(reference->allowed_read_capabilities == 0);
  assert(strcmp(box3->sku, "VOICE_AGENT_KIT_BOX3") == 0);
  assert(strcmp(box3->board, "esp32s3-box3") == 0);
  assert(box3->lifecycle == PRODUCT_SKU_LIFECYCLE_CANDIDATE);
  assert(box3->product_hardware_revision == 1);
  assert(box3->flash_bytes == 16U * 1024U * 1024U);
  assert(box3->psram_bytes == 8U * 1024U * 1024U);
  assert(box3->full_duplex_audio_designed);
  assert(box3->status_indicator_present);
  assert(box3->status_indicator_gpio == 47);
  assert(box3->status_indicator_active_high);
  assert(box3->allowed_action_capabilities ==
         (PRODUCT_SKU_CAPABILITY_DEVICE_SET_INDICATOR |
          PRODUCT_SKU_CAPABILITY_DEVICE_SET_VOLUME));
  assert(box3->factory_qualification_required);
  assert(box3->production_security_required);
  assert(box3->identity_hmac_key_id == 5);
  assert(reference->identity_hmac_key_id == PRODUCT_SKU_NO_HMAC_KEY);
  assert(strcmp(s3cam->sku, "BREAD_COMPACT_WIFI_S3CAM_DEVKIT") == 0);
  assert(strcmp(s3cam->board, "bread-compact-wifi-s3cam") == 0);
  assert(s3cam->lifecycle == PRODUCT_SKU_LIFECYCLE_DEVELOPMENT_ONLY);
  assert(s3cam->flash_bytes == 16U * 1024U * 1024U);
  assert(s3cam->psram_bytes == 8U * 1024U * 1024U);
  assert(s3cam->audio_input_present && s3cam->audio_output_present);
  assert(!s3cam->full_duplex_audio_designed);
  assert(s3cam->status_indicator_gpio == 38);
  assert(s3cam->physical_presence_gpio == 0);
  assert(!s3cam->live_runtime_allowed);
  assert(!s3cam->factory_qualification_required);
  assert(product_sku_capability_allowed(
      s3cam, PRODUCT_SKU_CAPABILITY_DEVICE_GET_STATUS, false));
  assert(product_sku_capability_allowed(
      s3cam, PRODUCT_SKU_CAPABILITY_DEVICE_SET_INDICATOR, true));
  assert(product_sku_capability_allowed(
      s3cam, PRODUCT_SKU_CAPABILITY_DEVICE_SET_VOLUME, true));
  assert(strcmp(watch->sku, "WAVESHARE_S3_TOUCH_AMOLED_206_DEVKIT") == 0);
  assert(strcmp(watch->board, "waveshare-s3-amoled-206") == 0);
  assert(watch->lifecycle == PRODUCT_SKU_LIFECYCLE_DEVELOPMENT_ONLY);
  assert(watch->flash_bytes == 32U * 1024U * 1024U);
  assert(watch->psram_bytes == 8U * 1024U * 1024U);
  assert(watch->audio_input_present && watch->audio_output_present);
  assert(watch->full_duplex_audio_designed);
  assert(watch->display_present && !watch->status_indicator_present);
  assert(watch->physical_presence_gpio == 0);
  assert(!watch->live_runtime_allowed);
  assert(!watch->factory_qualification_required);
  assert(product_sku_capability_allowed(
      watch, PRODUCT_SKU_CAPABILITY_DEVICE_GET_STATUS, false));
  assert(!product_sku_capability_allowed(
      watch, PRODUCT_SKU_CAPABILITY_DEVICE_SET_INDICATOR, true));
  assert(product_sku_capability_allowed(
      watch, PRODUCT_SKU_CAPABILITY_DEVICE_SET_VOLUME, true));
}

static void test_hardware_observation_matrix(void) {
  const product_sku_profile_t *box3 =
      product_sku_profile_for_id(PRODUCT_SKU_ID_VOICE_AGENT_KIT_BOX3);
  product_sku_hardware_observation_t observation = observation_for(box3);
  assert(product_sku_validate_observation(box3, &observation) ==
         PRODUCT_SKU_VALIDATION_OK);
  assert(product_sku_validate_observation(NULL, &observation) ==
         PRODUCT_SKU_VALIDATION_INVALID_ARGUMENT);
  assert(product_sku_validate_observation(box3, NULL) ==
         PRODUCT_SKU_VALIDATION_INVALID_ARGUMENT);

  observation.chip = PRODUCT_SKU_CHIP_UNKNOWN;
  assert(product_sku_validate_observation(box3, &observation) ==
         PRODUCT_SKU_VALIDATION_WRONG_CHIP);
  observation = observation_for(box3);
  observation.chip_revision = 1000;
  assert(product_sku_validate_observation(box3, &observation) ==
         PRODUCT_SKU_VALIDATION_CHIP_REVISION_OUT_OF_RANGE);
  observation = observation_for(box3);
  observation.flash_bytes /= 2;
  assert(product_sku_validate_observation(box3, &observation) ==
         PRODUCT_SKU_VALIDATION_WRONG_FLASH_SIZE);
  observation = observation_for(box3);
  observation.psram_bytes /= 2;
  assert(product_sku_validate_observation(box3, &observation) ==
         PRODUCT_SKU_VALIDATION_WRONG_PSRAM_SIZE);
}

static void test_invalid_profile_combinations(void) {
  product_sku_profile_t profile =
      *product_sku_profile_for_id(PRODUCT_SKU_ID_VOICE_AGENT_KIT_BOX3);
  product_sku_hardware_observation_t observation = observation_for(&profile);

  profile.allowed_action_capabilities = UINT64_C(1) << 20;
  assert(!product_sku_profile_valid(&profile));
  assert(product_sku_validate_observation(&profile, &observation) ==
         PRODUCT_SKU_VALIDATION_INVALID_PROFILE);
  profile = *product_sku_profile_for_id(PRODUCT_SKU_ID_VOICE_AGENT_KIT_BOX3);
  profile.status_indicator_present = false;
  assert(!product_sku_profile_valid(&profile));
  profile = *product_sku_profile_for_id(PRODUCT_SKU_ID_VOICE_AGENT_KIT_BOX3);
  profile.status_indicator_gpio = profile.physical_presence_gpio;
  assert(!product_sku_profile_valid(&profile));
  profile = *product_sku_profile_for_id(PRODUCT_SKU_ID_VOICE_AGENT_KIT_BOX3);
  profile.allowed_action_capabilities = 0;
  assert(!product_sku_profile_valid(&profile));
  profile = *product_sku_profile_for_id(PRODUCT_SKU_ID_VOICE_AGENT_KIT_BOX3);
  profile.full_duplex_audio_designed = true;
  profile.audio_input_present = false;
  assert(!product_sku_profile_valid(&profile));
  profile = *product_sku_profile_for_id(PRODUCT_SKU_ID_VOICE_AGENT_KIT_BOX3);
  profile.factory_reset_hold_ms = profile.onboarding_hold_ms;
  assert(!product_sku_profile_valid(&profile));
  profile = *product_sku_profile_for_id(PRODUCT_SKU_ID_S3_N32R16_REFERENCE);
  profile.live_runtime_allowed = true;
  assert(!product_sku_profile_valid(&profile));
  profile = *product_sku_profile_for_id(PRODUCT_SKU_ID_VOICE_AGENT_KIT_BOX3);
  profile.identity_hmac_key_id = PRODUCT_SKU_NO_HMAC_KEY;
  assert(!product_sku_profile_valid(&profile));
}

static void test_factory_manifest_round_trip(void) {
  const product_sku_profile_t *box3 =
      product_sku_profile_for_id(PRODUCT_SKU_ID_VOICE_AGENT_KIT_BOX3);
  const uint8_t base_mac[6] = {0x02, 0, 0, 0x12, 0xab, 0xef};
  uint8_t blob[PRODUCT_SKU_FACTORY_MANIFEST_BYTES];
  uint8_t tag[PRODUCT_SKU_FACTORY_MANIFEST_TAG_BYTES];
  make_factory_manifest(blob, tag, base_mac, 1);

  uint8_t message[PRODUCT_SKU_FACTORY_AUTH_MESSAGE_BYTES];
  assert(
      product_sku_factory_manifest_auth_message(blob, sizeof(blob), message));
  assert(memcmp(message, "XIAOZHI-PRODUCT-SKU-MANIFEST-V1", 31) == 0);
  assert(message[31] == 0);
  assert(memcmp(message + 32, blob,
                PRODUCT_SKU_FACTORY_MANIFEST_AUTHENTICATED_BYTES) == 0);

  product_sku_factory_manifest_t manifest;
  assert(product_sku_factory_manifest_validate(box3, blob, sizeof(blob),
                                               base_mac, 1, tag, &manifest) ==
         PRODUCT_SKU_FACTORY_VALIDATION_OK);
  assert(manifest.sku_id == PRODUCT_SKU_ID_VOICE_AGENT_KIT_BOX3);
  assert(manifest.product_hardware_revision == 1);
  assert(manifest.chip_revision == 1);
  assert(manifest.factory_record_version == 7);
  assert(memcmp(manifest.base_mac, base_mac, 6) == 0);

  const product_sku_profile_t *reference =
      product_sku_profile_for_id(PRODUCT_SKU_ID_S3_N32R16_REFERENCE);
  assert(product_sku_factory_manifest_validate(reference, blob, sizeof(blob),
                                               base_mac, 1, tag, NULL) ==
         PRODUCT_SKU_FACTORY_VALIDATION_NOT_REQUIRED);
}

static void test_factory_manifest_fail_closed_matrix(void) {
  const product_sku_profile_t *box3 =
      product_sku_profile_for_id(PRODUCT_SKU_ID_VOICE_AGENT_KIT_BOX3);
  const uint8_t base_mac[6] = {0x02, 0, 0, 0x12, 0xab, 0xef};
  uint8_t blob[PRODUCT_SKU_FACTORY_MANIFEST_BYTES];
  uint8_t tag[PRODUCT_SKU_FACTORY_MANIFEST_TAG_BYTES];

  make_factory_manifest(blob, tag, base_mac, 1);
  blob[PRODUCT_SKU_FACTORY_MANIFEST_AUTHENTICATED_BYTES] ^= 1;
  assert(product_sku_factory_manifest_validate(box3, blob, sizeof(blob),
                                               base_mac, 1, tag, NULL) ==
         PRODUCT_SKU_FACTORY_VALIDATION_AUTHENTICATION_FAILED);

  make_factory_manifest(blob, tag, base_mac, 1);
  blob[5] = PRODUCT_SKU_ID_S3_N32R16_REFERENCE;
  assert(product_sku_factory_manifest_validate(box3, blob, sizeof(blob),
                                               base_mac, 1, tag, NULL) ==
         PRODUCT_SKU_FACTORY_VALIDATION_WRONG_SKU);

  make_factory_manifest(blob, tag, base_mac, 1);
  write_le16(blob + 6, 2);
  assert(product_sku_factory_manifest_validate(box3, blob, sizeof(blob),
                                               base_mac, 1, tag, NULL) ==
         PRODUCT_SKU_FACTORY_VALIDATION_WRONG_HARDWARE_REVISION);

  make_factory_manifest(blob, tag, base_mac, 1);
  assert(product_sku_factory_manifest_validate(box3, blob, sizeof(blob),
                                               base_mac, 2, tag, NULL) ==
         PRODUCT_SKU_FACTORY_VALIDATION_WRONG_CHIP_REVISION);

  make_factory_manifest(blob, tag, base_mac, 1);
  const uint8_t wrong_mac[6] = {0x02, 0, 0, 0x12, 0xab, 0xee};
  assert(product_sku_factory_manifest_validate(box3, blob, sizeof(blob),
                                               wrong_mac, 1, tag, NULL) ==
         PRODUCT_SKU_FACTORY_VALIDATION_WRONG_BASE_MAC);

  make_factory_manifest(blob, tag, base_mac, 1);
  write_le32(blob + 18, 0);
  assert(product_sku_factory_manifest_validate(box3, blob, sizeof(blob),
                                               base_mac, 1, tag, NULL) ==
         PRODUCT_SKU_FACTORY_VALIDATION_INVALID_RECORD_VERSION);

  make_factory_manifest(blob, tag, base_mac, 1);
  memset(blob + 22, 0, PRODUCT_SKU_FACTORY_MANIFEST_ID_BYTES);
  assert(product_sku_factory_manifest_validate(box3, blob, sizeof(blob),
                                               base_mac, 1, tag, NULL) ==
         PRODUCT_SKU_FACTORY_VALIDATION_INVALID_MANIFEST_ID);

  make_factory_manifest(blob, tag, base_mac, 1);
  blob[10] = 1;
  assert(product_sku_factory_manifest_validate(box3, blob, sizeof(blob),
                                               base_mac, 1, tag, NULL) ==
         PRODUCT_SKU_FACTORY_VALIDATION_MANIFEST_FORMAT_INVALID);
  uint8_t message[PRODUCT_SKU_FACTORY_AUTH_MESSAGE_BYTES];
  assert(!product_sku_factory_manifest_auth_message(blob, sizeof(blob) - 1,
                                                    message));
  for (size_t index = 0; index < sizeof(message); ++index) {
    assert(message[index] == 0);
  }
}

static void test_capability_policy(void) {
  const product_sku_profile_t *box3 =
      product_sku_profile_for_id(PRODUCT_SKU_ID_VOICE_AGENT_KIT_BOX3);
  assert(product_sku_capability_allowed(
      box3, PRODUCT_SKU_CAPABILITY_DEVICE_GET_STATUS, false));
  assert(!product_sku_capability_allowed(
      box3, PRODUCT_SKU_CAPABILITY_DEVICE_GET_STATUS, true));
  assert(product_sku_capability_allowed(
      box3, PRODUCT_SKU_CAPABILITY_DEVICE_SET_INDICATOR, true));
  assert(!product_sku_capability_allowed(
      box3, PRODUCT_SKU_CAPABILITY_DEVICE_SET_INDICATOR, false));
  assert(product_sku_capability_allowed(
      box3, PRODUCT_SKU_CAPABILITY_DEVICE_SET_VOLUME, true));
  assert(!product_sku_capability_allowed(box3, 0, false));
  assert(!product_sku_capability_allowed(box3, UINT64_C(1) << 10, false));
  assert(!product_sku_capability_allowed(
      box3, PRODUCT_SKU_CAPABILITY_DEVICE_GET_STATUS | (UINT64_C(1) << 1),
      false));
}

static void test_result_names(void) {
  assert(strcmp(product_sku_validation_result_name(
                    PRODUCT_SKU_VALIDATION_WRONG_FLASH_SIZE),
                "wrong_flash_size") == 0);
  assert(strcmp(product_sku_validation_result_name(
                    (product_sku_validation_result_t)99),
                "unknown") == 0);
  assert(strcmp(product_sku_factory_validation_result_name(
                    PRODUCT_SKU_FACTORY_VALIDATION_WRONG_BASE_MAC),
                "wrong_base_mac") == 0);
}

int main(void) {
  test_frozen_profiles();
  test_hardware_observation_matrix();
  test_invalid_profile_combinations();
  test_factory_manifest_round_trip();
  test_factory_manifest_fail_closed_matrix();
  test_capability_policy();
  test_result_names();
  puts("product_sku_core: all tests passed");
  return 0;
}
