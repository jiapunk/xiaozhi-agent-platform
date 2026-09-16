#include "product_ota.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#include "esp_app_desc.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_https_ota.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "mbedtls/pk.h"
#include "product_ota_core.h"
#include "psa/crypto.h"
#include "sdkconfig.h"

enum {
    DEFAULT_NETWORK_TIMEOUT_MS = 15000,
    BEARER_TOKEN_MAX = 1024,
    AUTHORIZATION_HEADER_MAX = BEARER_TOKEN_MAX + 8,
    PUBLIC_KEY_PEM_MAX = 2048,
};

typedef struct {
    const product_ota_config_t *config;
    const product_ota_manifest_t *manifest;
    psa_hash_operation_t sha256;
    bool hash_failed;
    size_t received;
    char authorization[AUTHORIZATION_HEADER_MAX];
} download_context_t;

static const char *TAG = "product_ota";
static atomic_bool install_in_progress = false;

static void secure_zero(void *memory, size_t size)
{
    volatile uint8_t *bytes = memory;
    while (bytes && size > 0) {
        *bytes++ = 0;
        --size;
    }
}

static const char *compiled_board(void)
{
#if CONFIG_PRODUCT_BOARD_ESP_BOX_3
    return "esp32s3-box3";
#else
    return "esp32s3-n32r16";
#endif
}

uint32_t product_ota_required_health_checks(void)
{
    uint32_t required = 0;
#if CONFIG_PRODUCT_OTA_REQUIRE_STORAGE_HEALTH
    required |= PRODUCT_OTA_HEALTH_STORAGE;
#endif
#if CONFIG_PRODUCT_OTA_REQUIRE_NETWORK_HEALTH
    required |= PRODUCT_OTA_HEALTH_NETWORK;
#endif
#if CONFIG_PRODUCT_OTA_REQUIRE_CONTROL_PLANE_HEALTH
    required |= PRODUCT_OTA_HEALTH_CONTROL_PLANE;
#endif
#if CONFIG_PRODUCT_OTA_REQUIRE_AGENT_HEALTH
    required |= PRODUCT_OTA_HEALTH_AGENT;
#endif
#if CONFIG_PRODUCT_OTA_REQUIRE_AUDIO_HEALTH
    required |= PRODUCT_OTA_HEALTH_AUDIO;
#endif
    return required;
}

static bool token_valid(const char *token)
{
    if (!token) {
        return false;
    }
    const size_t size = strnlen(token, BEARER_TOKEN_MAX + 1);
    if (size == 0 || size > BEARER_TOKEN_MAX) {
        return false;
    }
    for (size_t index = 0; index < size; ++index) {
        const unsigned char byte = (unsigned char)token[index];
        if (byte <= 0x20 || byte >= 0x7f) {
            return false;
        }
    }
    return true;
}

static bool config_valid(const product_ota_config_t *config)
{
    if (!config || !config->allowed_image_authority ||
        !config->get_authenticated_time || config->signing_key_count == 0 ||
        config->signing_key_count > PRODUCT_OTA_MAX_SIGNING_KEYS) {
        return false;
    }
    char probe[PRODUCT_OTA_AUTHORITY_MAX + 16];
    const int probe_size = snprintf(probe, sizeof(probe), "https://%s/x",
                                    config->allowed_image_authority);
    if (probe_size <= 0 || (size_t)probe_size >= sizeof(probe) ||
        !product_ota_url_has_authority(probe,
                                       config->allowed_image_authority)) {
        return false;
    }
    for (size_t index = 0; index < config->signing_key_count; ++index) {
        const product_ota_signing_key_t *key = &config->signing_keys[index];
        if (!key->key_id || !key->public_key_pem || !key->key_id[0] ||
            strnlen(key->key_id, 65) > 64 ||
            strnlen(key->public_key_pem, PUBLIC_KEY_PEM_MAX + 1) >
                PUBLIC_KEY_PEM_MAX) {
            return false;
        }
        for (size_t prior = 0; prior < index; ++prior) {
            if (strcmp(key->key_id,
                       config->signing_keys[prior].key_id) == 0) {
                return false;
            }
        }
    }
    return true;
}

static const product_ota_signing_key_t *find_signing_key(
    const product_ota_config_t *config,
    const char *key_id)
{
    for (size_t index = 0; index < config->signing_key_count; ++index) {
        if (strcmp(config->signing_keys[index].key_id, key_id) == 0) {
            return &config->signing_keys[index];
        }
    }
    return NULL;
}

static bool verify_manifest_signature(
    const product_ota_manifest_t *manifest,
    const product_ota_signing_key_t *key)
{
    char canonical[PRODUCT_OTA_CANONICAL_MAX_BYTES];
    size_t canonical_size = 0;
    uint8_t digest[32];
    size_t digest_size = 0;
    mbedtls_pk_context public_key;
    mbedtls_pk_init(&public_key);
    bool valid = false;
    if (!product_ota_manifest_canonicalize(
            manifest, canonical, sizeof(canonical), &canonical_size) ||
        psa_hash_compute(PSA_ALG_SHA_256,
                         (const unsigned char *)canonical, canonical_size,
                         digest, sizeof(digest), &digest_size) != PSA_SUCCESS ||
        digest_size != sizeof(digest)) {
        goto cleanup;
    }
    const size_t pem_size = strlen(key->public_key_pem) + 1;
    if (mbedtls_pk_parse_public_key(
            &public_key, (const unsigned char *)key->public_key_pem,
            pem_size) != 0 ||
        !mbedtls_pk_can_do_psa(&public_key,
                               PSA_ALG_ECDSA(PSA_ALG_SHA_256),
                               PSA_KEY_USAGE_VERIFY_HASH) ||
        mbedtls_pk_get_bitlen(&public_key) != 256) {
        goto cleanup;
    }
    valid = mbedtls_pk_verify(&public_key, MBEDTLS_MD_SHA256,
                              digest, sizeof(digest),
                              manifest->signature,
                              manifest->signature_size) == 0;

cleanup:
    mbedtls_pk_free(&public_key);
    secure_zero(canonical, sizeof(canonical));
    secure_zero(digest, sizeof(digest));
    return valid;
}

static esp_err_t verify_manifest(
    const product_ota_config_t *config,
    const char *manifest_json,
    size_t manifest_size,
    product_ota_manifest_t *manifest)
{
    if (!config_valid(config) || !manifest ||
        !product_ota_manifest_parse(manifest_json, manifest_size, manifest)) {
        return ESP_ERR_INVALID_ARG;
    }
    const product_ota_signing_key_t *key =
        find_signing_key(config, manifest->signing_key_id);
    if (!key || !verify_manifest_signature(manifest, key)) {
        return ESP_ERR_INVALID_CRC;
    }
    int64_t current_time = 0;
    esp_err_t error = config->get_authenticated_time(config->time_ctx,
                                                       &current_time);
    if (error != ESP_OK) {
        return error;
    }
    const esp_app_desc_t *running = esp_app_get_description();
    const esp_partition_t *update = esp_ota_get_next_update_partition(NULL);
    if (!running || !update) {
        return ESP_ERR_NOT_FOUND;
    }
    const product_ota_policy_t policy = {
        .project = running->project_name,
        .board = compiled_board(),
        .channel = CONFIG_PRODUCT_OTA_CHANNEL,
        .allowed_image_authority = config->allowed_image_authority,
        .current_release_sequence = CONFIG_PRODUCT_OTA_RELEASE_SEQUENCE,
        .current_secure_version = running->secure_version,
        .authenticated_time = current_time,
        .maximum_image_size = update->size,
    };
    if (!product_ota_manifest_validate_policy(manifest, &policy)) {
        return ESP_ERR_INVALID_VERSION;
    }
    return ESP_OK;
}

static void emit_event(const download_context_t *context,
                       product_ota_event_t event,
                       esp_err_t error)
{
    if (context && context->config && context->config->event) {
        context->config->event(context->config->event_ctx, event,
                               context->received,
                               context->manifest->image_size, error);
    }
}

static esp_err_t http_event(esp_http_client_event_t *event)
{
    download_context_t *context = event ? event->user_data : NULL;
    if (!context || event->event_id != HTTP_EVENT_ON_DATA ||
        event->data_len <= 0 || !event->data || context->hash_failed) {
        return ESP_OK;
    }
    const size_t data_size = (size_t)event->data_len;
    if (context->received > context->manifest->image_size ||
        data_size > context->manifest->image_size - context->received ||
        psa_hash_update(&context->sha256,
                        (const unsigned char *)event->data,
                        data_size) != PSA_SUCCESS) {
        context->hash_failed = true;
        return ESP_OK;
    }
    context->received += data_size;
    return ESP_OK;
}

static esp_err_t http_initialized(esp_http_client_handle_t client)
{
    void *user_data = NULL;
    if (!client || esp_http_client_get_user_data(client, &user_data) != ESP_OK ||
        !user_data) {
        return ESP_ERR_INVALID_ARG;
    }
    download_context_t *context = user_data;
    if (esp_http_client_set_header(client, "Authorization",
                                   context->authorization) != ESP_OK ||
        esp_http_client_set_header(client, "Accept",
                                   "application/octet-stream") != ESP_OK ||
        esp_http_client_set_header(client, "Cache-Control", "no-store") !=
            ESP_OK) {
        return ESP_FAIL;
    }
    return ESP_OK;
}

static bool image_description_matches(const product_ota_manifest_t *manifest,
                                      const esp_app_desc_t *description)
{
    if (!manifest || !description ||
        strnlen(description->project_name, sizeof(description->project_name)) >=
            sizeof(description->project_name) ||
        strnlen(description->version, sizeof(description->version)) >=
            sizeof(description->version)) {
        return false;
    }
    return strcmp(description->project_name, manifest->project) == 0 &&
           strcmp(description->version, manifest->version) == 0 &&
           description->secure_version == manifest->secure_version;
}

static bool constant_time_equal(const uint8_t *left,
                                const uint8_t *right,
                                size_t size)
{
    uint8_t difference = 0;
    for (size_t index = 0; index < size; ++index) {
        difference |= left[index] ^ right[index];
    }
    return difference == 0;
}

esp_err_t product_ota_check_manifest(
    const product_ota_config_t *config,
    const char *manifest_json,
    size_t manifest_size,
    product_ota_release_summary_t *summary)
{
    if (!summary) {
        return ESP_ERR_INVALID_ARG;
    }
    product_ota_manifest_t manifest = {0};
    const esp_err_t error = verify_manifest(config, manifest_json,
                                            manifest_size, &manifest);
    if (error != ESP_OK) {
        secure_zero(&manifest, sizeof(manifest));
        return error;
    }
    product_ota_release_summary_t result = {0};
    memcpy(result.release_id, manifest.release_id,
           strlen(manifest.release_id) + 1);
    memcpy(result.version, manifest.version, strlen(manifest.version) + 1);
    result.release_sequence = manifest.release_sequence;
    result.secure_version = manifest.secure_version;
    result.image_size = manifest.image_size;
    memcpy(result.image_sha256, manifest.image_sha256,
           sizeof(result.image_sha256));
    result.not_before = manifest.not_before;
    result.expires_at = manifest.expires_at;
    *summary = result;
    secure_zero(&manifest, sizeof(manifest));
    return ESP_OK;
}

esp_err_t product_ota_install(const product_ota_config_t *config,
                              const char *manifest_json,
                              size_t manifest_size,
                              const char *bearer_token)
{
    if (!token_valid(bearer_token)) {
        return ESP_ERR_INVALID_ARG;
    }
    bool expected = false;
    if (!atomic_compare_exchange_strong(&install_in_progress, &expected, true)) {
        return ESP_ERR_INVALID_STATE;
    }

    product_ota_manifest_t manifest = {0};
    download_context_t context = {
        .config = config,
        .manifest = &manifest,
    };
    esp_https_ota_handle_t ota = NULL;
    bool ota_finished = false;
    esp_err_t error = verify_manifest(config, manifest_json, manifest_size,
                                      &manifest);
    if (error != ESP_OK) {
        goto cleanup;
    }
    const esp_partition_t *running_partition = esp_ota_get_running_partition();
    esp_ota_img_states_t running_state = ESP_OTA_IMG_UNDEFINED;
    if (!running_partition ||
        esp_ota_get_state_partition(running_partition, &running_state) !=
            ESP_OK ||
        running_state == ESP_OTA_IMG_PENDING_VERIFY) {
        error = ESP_ERR_OTA_ROLLBACK_INVALID_STATE;
        goto cleanup;
    }
    const esp_partition_t *update_partition =
        esp_ota_get_next_update_partition(NULL);
    if (!update_partition || manifest.image_size > update_partition->size) {
        error = ESP_ERR_INVALID_SIZE;
        goto cleanup;
    }
    const int authorization_size = snprintf(
        context.authorization, sizeof(context.authorization), "Bearer %s",
        bearer_token);
    if (authorization_size <= 0 ||
        (size_t)authorization_size >= sizeof(context.authorization)) {
        error = ESP_ERR_INVALID_SIZE;
        goto cleanup;
    }
    context.sha256 = psa_hash_operation_init();
    if (psa_hash_setup(&context.sha256, PSA_ALG_SHA_256) != PSA_SUCCESS) {
        error = ESP_FAIL;
        goto cleanup;
    }
    const esp_http_client_config_t http_config = {
        .url = manifest.image_url,
        .cert_pem = config->server_cert_pem,
        .user_agent = "xiaozhi-agent-product-ota/1",
        .method = HTTP_METHOD_GET,
        .timeout_ms = config->network_timeout_ms > 0
                          ? (int)config->network_timeout_ms
                          : DEFAULT_NETWORK_TIMEOUT_MS,
        .disable_auto_redirect = true,
        .max_authorization_retries = -1,
        .event_handler = http_event,
        .user_data = &context,
        .skip_cert_common_name_check = false,
        .crt_bundle_attach = config->server_cert_pem
                                 ? NULL
                                 : esp_crt_bundle_attach,
    };
    const esp_https_ota_config_t ota_config = {
        .http_config = &http_config,
        .http_client_init_cb = http_initialized,
        .bulk_flash_erase = false,
        .buffer_caps = 0,
        .ota_resumption = false,
        .partition = {
            .staging = update_partition,
            .final = update_partition,
            .finalize_with_copy = false,
        },
    };
    emit_event(&context, PRODUCT_OTA_EVENT_MANIFEST_ACCEPTED, ESP_OK);
    error = esp_https_ota_begin(&ota_config, &ota);
    if (error != ESP_OK) {
        goto cleanup;
    }
    if (esp_https_ota_get_status_code(ota) != 200 ||
        esp_https_ota_get_image_size(ota) != (int)manifest.image_size) {
        error = ESP_ERR_INVALID_SIZE;
        goto cleanup;
    }
    esp_app_desc_t new_description = {0};
    error = esp_https_ota_get_img_desc(ota, &new_description);
    if (error != ESP_OK || !image_description_matches(&manifest,
                                                       &new_description)) {
        if (error == ESP_OK) {
            error = ESP_ERR_INVALID_VERSION;
        }
        goto cleanup;
    }
    emit_event(&context, PRODUCT_OTA_EVENT_DOWNLOAD_STARTED, ESP_OK);
    do {
        error = esp_https_ota_perform(ota);
        if (context.hash_failed) {
            error = ESP_ERR_INVALID_SIZE;
            break;
        }
        emit_event(&context, PRODUCT_OTA_EVENT_DOWNLOAD_PROGRESS, ESP_OK);
    } while (error == ESP_ERR_HTTPS_OTA_IN_PROGRESS);
    if (error != ESP_OK ||
        !esp_https_ota_is_complete_data_received(ota) ||
        context.received != manifest.image_size) {
        if (error == ESP_OK) {
            error = ESP_ERR_INVALID_SIZE;
        }
        goto cleanup;
    }
    uint8_t downloaded_sha256[32];
    size_t downloaded_sha256_size = 0;
    if (psa_hash_finish(&context.sha256, downloaded_sha256,
                        sizeof(downloaded_sha256),
                        &downloaded_sha256_size) != PSA_SUCCESS ||
        downloaded_sha256_size != sizeof(downloaded_sha256)) {
        error = ESP_FAIL;
        secure_zero(downloaded_sha256, sizeof(downloaded_sha256));
        goto cleanup;
    }
    if (!constant_time_equal(downloaded_sha256, manifest.image_sha256,
                             sizeof(downloaded_sha256))) {
        error = ESP_ERR_INVALID_CRC;
        secure_zero(downloaded_sha256, sizeof(downloaded_sha256));
        goto cleanup;
    }
    secure_zero(downloaded_sha256, sizeof(downloaded_sha256));
    emit_event(&context, PRODUCT_OTA_EVENT_IMAGE_VERIFIED, ESP_OK);
    error = esp_https_ota_finish(ota);
    ota_finished = true;
    ota = NULL;
    if (error == ESP_OK) {
        emit_event(&context, PRODUCT_OTA_EVENT_READY_TO_REBOOT, ESP_OK);
    }

cleanup:
    if (ota && !ota_finished) {
        (void)esp_https_ota_abort(ota);
    }
    (void)psa_hash_abort(&context.sha256);
    if (error != ESP_OK) {
        emit_event(&context, PRODUCT_OTA_EVENT_FAILED, error);
        ESP_LOGE(TAG, "OTA failed closed: %s", esp_err_to_name(error));
    }
    secure_zero(context.authorization, sizeof(context.authorization));
    secure_zero(&manifest, sizeof(manifest));
    atomic_store(&install_in_progress, false);
    return error;
}

esp_err_t product_ota_get_boot_status(product_ota_boot_status_t *status)
{
    if (!status) {
        return ESP_ERR_INVALID_ARG;
    }
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (!running) {
        return ESP_ERR_NOT_FOUND;
    }
    esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
    const esp_err_t error = esp_ota_get_state_partition(running, &state);
    if (error != ESP_OK) {
        return error;
    }
    *status = (product_ota_boot_status_t){
        .pending_verification = state == ESP_OTA_IMG_PENDING_VERIFY,
        .required_health_checks = product_ota_required_health_checks(),
        .running_partition_subtype = (uint32_t)running->subtype,
    };
    return ESP_OK;
}

esp_err_t product_ota_confirm_running_image(uint32_t passed_health_checks)
{
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
    if (!running || esp_ota_get_state_partition(running, &state) != ESP_OK ||
        state != ESP_OTA_IMG_PENDING_VERIFY) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!product_ota_health_satisfied(
            passed_health_checks, product_ota_required_health_checks())) {
        return ESP_ERR_INVALID_STATE;
    }
    return esp_ota_mark_app_valid_cancel_rollback();
}

esp_err_t product_ota_reject_running_image_and_reboot(void)
{
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
    if (!running || esp_ota_get_state_partition(running, &state) != ESP_OK ||
        state != ESP_OTA_IMG_PENDING_VERIFY) {
        return ESP_ERR_INVALID_STATE;
    }
    return esp_ota_mark_app_invalid_rollback_and_reboot();
}
