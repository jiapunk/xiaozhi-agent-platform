#include "agent_device_identity.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#include "agent_device_proof_core.h"
#include "agent_device_time_core.h"
#include "esp_efuse.h"
#include "esp_hmac.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "product_storage.h"

enum {
    DEFAULT_MAXIMUM_TIME_AGE_SECONDS = 24 * 60 * 60,
    DEFAULT_BACKWARD_TIME_TOLERANCE_SECONDS = 5,
    TIME_LOCK_TIMEOUT_MS = 100,
    PROOF_MESSAGE_MAX = 512,
    IDENTIFIER_MAX = 64,
    PROOF_TIME_TOLERANCE_SECONDS = 2,
    ONBOARDING_DERIVATION_MESSAGE_MAX = 128,
};

static const char ONBOARDING_AP_KEY_DOMAIN[] =
    "xiaozhi-onboarding-ap-key-v1\n";

struct agent_device_identity {
    hmac_key_id_t hmac_key_id;
    char device_id[IDENTIFIER_MAX + 1];
    agent_device_time_core_t time;
    SemaphoreHandle_t time_lock;
    atomic_bool destroying;
};

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

static bool monotonic_ms(uint64_t *milliseconds)
{
    if (!milliseconds) {
        return false;
    }
    const int64_t microseconds = esp_timer_get_time();
    if (microseconds < 0) {
        return false;
    }
    *milliseconds = (uint64_t)microseconds / 1000;
    return true;
}

static bool take_time_lock(agent_device_identity_handle_t identity)
{
    return identity && identity->time_lock &&
           xSemaphoreTake(identity->time_lock,
                          pdMS_TO_TICKS(TIME_LOCK_TIMEOUT_MS)) == pdTRUE;
}

esp_err_t agent_device_identity_create(
    const agent_device_identity_config_t *config,
    agent_device_identity_handle_t *out_identity)
{
    if (!out_identity) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_identity = NULL;
    if (!config || config->hmac_key_id > (uint8_t)HMAC_KEY5 ||
        !product_storage_identity_hmac_key_allowed(config->hmac_key_id) ||
        !agent_device_proof_safe_identifier(config->device_id)) {
        return ESP_ERR_INVALID_ARG;
    }
    const uint32_t maximum_age = config->maximum_time_age_seconds
                                     ? config->maximum_time_age_seconds
                                     : DEFAULT_MAXIMUM_TIME_AGE_SECONDS;
    const uint32_t backward_tolerance =
        config->backward_time_tolerance_seconds
            ? config->backward_time_tolerance_seconds
            : DEFAULT_BACKWARD_TIME_TOLERANCE_SECONDS;
    agent_device_time_core_t time;
    if (!agent_device_time_core_init(&time, maximum_age,
                                     backward_tolerance)) {
        return ESP_ERR_INVALID_ARG;
    }
    const hmac_key_id_t key_id = (hmac_key_id_t)config->hmac_key_id;
    if (!efuse_policy_valid(key_id)) {
        return ESP_ERR_INVALID_STATE;
    }

    agent_device_identity_handle_t identity = heap_caps_calloc(
        1, sizeof(*identity), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!identity) {
        return ESP_ERR_NO_MEM;
    }
    identity->time_lock = xSemaphoreCreateMutex();
    if (!identity->time_lock) {
        heap_caps_free(identity);
        return ESP_ERR_NO_MEM;
    }
    identity->hmac_key_id = key_id;
    memcpy(identity->device_id, config->device_id,
           strlen(config->device_id) + 1);
    identity->time = time;
    atomic_init(&identity->destroying, false);
    *out_identity = identity;
    return ESP_OK;
}

static esp_err_t sign_scoped_proof(
    agent_device_identity_handle_t identity,
    const uint8_t *message,
    size_t message_size,
    uint8_t signature[32],
    agent_device_proof_scope_t scope)
{
    if (signature) {
        memset(signature, 0, 32);
    }
    if (!identity || !message || message_size == 0 ||
        message_size > PROOF_MESSAGE_MAX || !signature) {
        return ESP_ERR_INVALID_ARG;
    }
    int64_t proof_time = 0;
    int64_t current_time = 0;
    if (atomic_load_explicit(&identity->destroying,
                             memory_order_acquire) ||
        !agent_device_proof_validate_scoped(
            message, message_size, identity->device_id, scope,
            &proof_time) ||
        agent_device_identity_get_unix_time(identity, &current_time) !=
            ESP_OK ||
        !agent_device_proof_time_is_current(
            proof_time, current_time, PROOF_TIME_TOLERANCE_SECONDS) ||
        !efuse_policy_valid(identity->hmac_key_id)) {
        return ESP_ERR_INVALID_STATE;
    }
    const esp_err_t result = esp_hmac_calculate(
        identity->hmac_key_id, message, message_size, signature);
    if (result != ESP_OK) {
        memset(signature, 0, 32);
    }
    return result;
}

esp_err_t agent_device_identity_sign_proof(
    void *ctx,
    const uint8_t *message,
    size_t message_size,
    uint8_t signature[32])
{
    return sign_scoped_proof(ctx, message, message_size, signature,
                             AGENT_DEVICE_PROOF_SCOPE_SESSION);
}

esp_err_t agent_device_identity_sign_agent_token_proof(
    void *ctx,
    const uint8_t *message,
    size_t message_size,
    uint8_t signature[32])
{
    return sign_scoped_proof(ctx, message, message_size, signature,
                             AGENT_DEVICE_PROOF_SCOPE_AGENT_TOKEN);
}

esp_err_t agent_device_identity_sign_ota_offer_proof(
    void *ctx,
    const uint8_t *message,
    size_t message_size,
    uint8_t signature[32])
{
    return sign_scoped_proof(ctx, message, message_size, signature,
                             AGENT_DEVICE_PROOF_SCOPE_OTA_OFFER);
}

esp_err_t agent_device_identity_sign_device_claim_proof(
    void *ctx,
    const uint8_t *message,
    size_t message_size,
    uint8_t signature[32])
{
    return sign_scoped_proof(ctx, message, message_size, signature,
                             AGENT_DEVICE_PROOF_SCOPE_DEVICE_CLAIM);
}

esp_err_t agent_device_identity_sign_action_consent_challenge_proof(
    void *ctx,
    const uint8_t *message,
    size_t message_size,
    uint8_t signature[32])
{
    return sign_scoped_proof(
        ctx, message, message_size, signature,
        AGENT_DEVICE_PROOF_SCOPE_ACTION_CONSENT_CHALLENGE);
}

esp_err_t agent_device_identity_sign_action_consent_result_proof(
    void *ctx,
    const uint8_t *message,
    size_t message_size,
    uint8_t signature[32])
{
    return sign_scoped_proof(
        ctx, message, message_size, signature,
        AGENT_DEVICE_PROOF_SCOPE_ACTION_CONSENT_RESULT);
}

esp_err_t agent_device_identity_derive_onboarding_ap_key(
    void *ctx,
    const char *service_name,
    uint8_t output[32])
{
    agent_device_identity_handle_t identity = ctx;
    if (!identity || !output ||
        !agent_device_proof_safe_identifier(service_name)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (atomic_load_explicit(&identity->destroying,
                             memory_order_acquire) ||
        !efuse_policy_valid(identity->hmac_key_id)) {
        return ESP_ERR_INVALID_STATE;
    }
    uint8_t message[ONBOARDING_DERIVATION_MESSAGE_MAX] = {0};
    const int length = snprintf(
        (char *)message, sizeof(message), "%s%s",
        ONBOARDING_AP_KEY_DOMAIN, service_name);
    if (length <= 0 || (size_t)length >= sizeof(message)) {
        memset(message, 0, sizeof(message));
        return ESP_ERR_INVALID_SIZE;
    }
    const esp_err_t error = esp_hmac_calculate(
        identity->hmac_key_id, message, (size_t)length, output);
    memset(message, 0, sizeof(message));
    return error;
}

esp_err_t agent_device_identity_accept_authenticated_time(
    agent_device_identity_handle_t identity,
    int64_t unix_seconds)
{
    uint64_t now_ms = 0;
    if (!identity) {
        return ESP_ERR_INVALID_ARG;
    }
    if (atomic_load_explicit(&identity->destroying,
                             memory_order_acquire) ||
        !monotonic_ms(&now_ms)) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!take_time_lock(identity)) {
        return ESP_ERR_TIMEOUT;
    }
    const bool accepted = agent_device_time_core_accept(
        &identity->time, unix_seconds, now_ms);
    xSemaphoreGive(identity->time_lock);
    return accepted ? ESP_OK : ESP_ERR_INVALID_STATE;
}

esp_err_t agent_device_identity_accept_authenticated_time_callback(
    void *ctx,
    int64_t unix_seconds)
{
    return agent_device_identity_accept_authenticated_time(
        ctx, unix_seconds);
}

esp_err_t agent_device_identity_get_unix_time(
    void *ctx,
    int64_t *unix_seconds)
{
    agent_device_identity_handle_t identity = ctx;
    uint64_t now_ms = 0;
    if (!identity || !unix_seconds) {
        return ESP_ERR_INVALID_ARG;
    }
    *unix_seconds = 0;
    if (atomic_load_explicit(&identity->destroying,
                             memory_order_acquire) ||
        !monotonic_ms(&now_ms)) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!take_time_lock(identity)) {
        return ESP_ERR_TIMEOUT;
    }
    const bool available = agent_device_time_core_now(
        &identity->time, now_ms, unix_seconds);
    xSemaphoreGive(identity->time_lock);
    if (!available) {
        *unix_seconds = 0;
        return ESP_ERR_INVALID_STATE;
    }
    return ESP_OK;
}

esp_err_t agent_device_identity_get_status(
    agent_device_identity_handle_t identity,
    agent_device_identity_status_t *status)
{
    uint64_t now_ms = 0;
    if (!identity || !status) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(status, 0, sizeof(*status));
    if (atomic_load_explicit(&identity->destroying,
                             memory_order_acquire) ||
        !monotonic_ms(&now_ms)) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!take_time_lock(identity)) {
        return ESP_ERR_TIMEOUT;
    }
    agent_device_time_status_t time_status;
    const bool available = agent_device_time_core_status(
        &identity->time, now_ms, &time_status);
    xSemaphoreGive(identity->time_lock);
    if (!available) {
        return ESP_ERR_INVALID_STATE;
    }
    status->hmac_key_id = (uint8_t)identity->hmac_key_id;
    status->efuse_policy_valid =
        efuse_policy_valid(identity->hmac_key_id);
    status->time_synchronized = time_status.synchronized;
    status->time_age_seconds = time_status.age_seconds;
    return ESP_OK;
}

esp_err_t agent_device_identity_destroy(
    agent_device_identity_handle_t identity)
{
    if (!identity) {
        return ESP_OK;
    }
    bool expected = false;
    if (!atomic_compare_exchange_strong_explicit(
            &identity->destroying, &expected, true,
            memory_order_acq_rel, memory_order_acquire)) {
        return ESP_ERR_INVALID_STATE;
    }
    vSemaphoreDelete(identity->time_lock);
    identity->time_lock = NULL;
    memset(identity, 0, sizeof(*identity));
    heap_caps_free(identity);
    return ESP_OK;
}
