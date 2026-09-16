#include "product_provisioning.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "network_provisioning/network_config.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "psa/crypto.h"
#include "product_provisioning_material_core.h"
#include "product_storage.h"
#include "protocomm.h"
#include "protocomm_httpd.h"
#include "protocomm_security.h"
#include "protocomm_security2.h"

enum {
    SIGNAL_TASK_READY = BIT0,
    SIGNAL_TASK_STOPPED = BIT1,
    COMMAND_QUEUE_LENGTH = 12,
    DEFAULT_WINDOW_MS = 5 * 60 * 1000,
    DEFAULT_AUTHENTICATION_FAILURE_LIMIT = 5,
    DEFAULT_COMMIT_DELAY_MS = 500,
    DEFAULT_SUCCESS_GRACE_MS = 5000,
    DEFAULT_TASK_STACK_SIZE = 7168,
    DEFAULT_TASK_PRIORITY = 4,
    MINIMUM_TASK_STACK_SIZE = 5120,
    MAXIMUM_TASK_STACK_SIZE = 16384,
    CREATE_TIMEOUT_MS = 5000,
    WORKER_POLL_MS = 50,
    DEVICE_ID_MAX = 64,
    DEVICE_CLAIM_RAW_BYTES = 32,
    DEVICE_CLAIM_ENCODED_BYTES = 43,
    DEVICE_CLAIM_RESPONSE_MAX = 192,
};

static const char *FACTORY_PARTITION = "nvs_factory";
static const char *FACTORY_NAMESPACE = "prod_prov";
static const char *FACTORY_MATERIAL_KEY = "sec2";
static const uint8_t MATERIAL_AUTH_DOMAIN[] =
    "xiaozhi-onboarding-material-v1\n";

typedef enum {
    COMMAND_OPEN = 0,
    COMMAND_CLOSE,
    COMMAND_APPLY,
    COMMAND_AUTH_FAILURE,
    COMMAND_ONLINE_OBSERVED,
    COMMAND_CLAIM_DISCLOSED,
    COMMAND_STOP,
} command_type_t;

typedef struct {
    command_type_t type;
} command_t;

struct product_provisioning {
    product_wifi_handle_t wifi;
    product_provisioning_physical_presence_fn physical_presence;
    void *physical_presence_ctx;
    product_provisioning_derive_ap_key_fn derive_ap_key;
    void *derive_ap_key_ctx;
    product_provisioning_publish_claim_fn publish_claim;
    void *publish_claim_ctx;
    product_provisioning_event_fn event;
    void *event_ctx;
    uint32_t task_stack_size;
    uint32_t task_priority;

    product_provisioning_core_t core;
    product_provisioning_material_t material;
    product_wifi_softap_config_t softap;
    char pending_ssid[33];
    char pending_password[64];
    bool pending_valid;
    char device_id[DEVICE_ID_MAX + 1];
    char claim[DEVICE_CLAIM_ENCODED_BYTES + 1];
    bool claim_valid;
    bool claim_disclosed;
    bool claim_session_bound;
    uint32_t claim_session_id;
    SemaphoreHandle_t pending_lock;
    QueueHandle_t commands;
    EventGroupHandle_t signals;
    TaskHandle_t worker;
    product_claim_recovery_core_t claim_recovery;

    protocomm_t *protocomm;
    bool transport_active;
    esp_event_handler_instance_t security_event_instance;
    network_prov_config_handlers_t config_handlers;

    atomic_bool stopping;
    atomic_bool window_open;
    atomic_bool transport_active_public;
    atomic_int state;
    atomic_int last_error;
    atomic_uint windows_opened;
    atomic_uint authentication_failures;
    atomic_uint candidates_submitted;
    atomic_uint candidates_accepted;
    atomic_uint candidates_rejected;
    atomic_uint lockouts;
    atomic_uint claims_disclosed;
    atomic_uint claim_publish_attempts;
    atomic_uint claims_bound;
    atomic_uint claim_publish_failures;
    atomic_uint claim_recovery_attempts;
    atomic_uint claims_recovered;
    atomic_uint claim_recovery_rejections;
    atomic_uint rejection_baseline;
};

static void secure_zero(void *memory, size_t size)
{
    volatile uint8_t *bytes = memory;
    while (bytes && size > 0) {
        *bytes++ = 0;
        --size;
    }
}

static uint64_t monotonic_ms(void)
{
    const int64_t microseconds = esp_timer_get_time();
    return microseconds > 0 ? (uint64_t)microseconds / 1000 : 0;
}

static void publish_event(product_provisioning_handle_t provisioning,
                          product_provisioning_event_type_t type,
                          esp_err_t error)
{
    if (!provisioning->event) {
        return;
    }
    const product_provisioning_event_t event = {
        .type = type,
        .state = provisioning->core.state,
        .error = error,
    };
    provisioning->event(provisioning->event_ctx, &event);
}

static void sync_state(product_provisioning_handle_t provisioning,
                       product_provisioning_state_t old_state)
{
    atomic_store_explicit(&provisioning->state,
                          (int)provisioning->core.state,
                          memory_order_release);
    const bool open =
        provisioning->core.state != PRODUCT_PROVISIONING_STATE_CLOSED &&
        provisioning->core.state != PRODUCT_PROVISIONING_STATE_LOCKED_OUT &&
        provisioning->core.state != PRODUCT_PROVISIONING_STATE_ERROR;
    atomic_store_explicit(&provisioning->window_open, open,
                          memory_order_release);
    if (old_state != provisioning->core.state) {
        publish_event(provisioning,
                      PRODUCT_PROVISIONING_EVENT_STATE_CHANGED, ESP_OK);
    }
}

static bool credentials_valid(const char *ssid, const char *password)
{
    if (!ssid || !password) {
        return false;
    }
    const size_t ssid_size = strnlen(ssid, 33);
    const size_t password_size = strnlen(password, 64);
    if (ssid_size == 0 || ssid_size > 32 || password_size < 8 ||
        password_size > 63) {
        return false;
    }
    for (size_t index = 0; index < ssid_size; ++index) {
        const unsigned char c = (unsigned char)ssid[index];
        if (c < 0x20 || c == 0x7f) {
            return false;
        }
    }
    for (size_t index = 0; index < password_size; ++index) {
        const unsigned char c = (unsigned char)password[index];
        if (c < 0x20 || c > 0x7e) {
            return false;
        }
    }
    return true;
}

static bool safe_identifier(const char *value)
{
    if (!value || !value[0]) {
        return false;
    }
    const size_t size = strnlen(value, DEVICE_ID_MAX + 1);
    if (size == 0 || size > DEVICE_ID_MAX) {
        return false;
    }
    for (size_t index = 0; index < size; ++index) {
        const unsigned char c = (unsigned char)value[index];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == ':' || c == '-' ||
            c == '_' || c == '.') {
            continue;
        }
        return false;
    }
    return true;
}

static bool base64url_encode(const uint8_t *input,
                             size_t input_size,
                             char *output,
                             size_t output_size)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const size_t required = (input_size / 3) * 4 +
                            (input_size % 3 == 0
                                 ? 0
                                 : input_size % 3 + 1);
    if (!input || !output || required + 1 > output_size) {
        return false;
    }
    size_t source = 0;
    size_t target = 0;
    while (source + 3 <= input_size) {
        const uint32_t value = ((uint32_t)input[source] << 16) |
                               ((uint32_t)input[source + 1] << 8) |
                               input[source + 2];
        output[target++] = alphabet[(value >> 18) & 0x3f];
        output[target++] = alphabet[(value >> 12) & 0x3f];
        output[target++] = alphabet[(value >> 6) & 0x3f];
        output[target++] = alphabet[value & 0x3f];
        source += 3;
    }
    const size_t remaining = input_size - source;
    if (remaining == 1) {
        const uint32_t value = (uint32_t)input[source] << 16;
        output[target++] = alphabet[(value >> 18) & 0x3f];
        output[target++] = alphabet[(value >> 12) & 0x3f];
    } else if (remaining == 2) {
        const uint32_t value = ((uint32_t)input[source] << 16) |
                               ((uint32_t)input[source + 1] << 8);
        output[target++] = alphabet[(value >> 18) & 0x3f];
        output[target++] = alphabet[(value >> 12) & 0x3f];
        output[target++] = alphabet[(value >> 6) & 0x3f];
    }
    output[target] = '\0';
    return target == required;
}

static bool take_pending_lock(product_provisioning_handle_t provisioning)
{
    return provisioning && provisioning->pending_lock &&
           xSemaphoreTake(provisioning->pending_lock,
                          pdMS_TO_TICKS(100)) == pdTRUE;
}

static void clear_pending_locked(product_provisioning_handle_t provisioning)
{
    secure_zero(provisioning->pending_ssid,
                sizeof(provisioning->pending_ssid));
    secure_zero(provisioning->pending_password,
                sizeof(provisioning->pending_password));
    provisioning->pending_valid = false;
}

static void clear_claim_locked(product_provisioning_handle_t provisioning)
{
    secure_zero(provisioning->claim, sizeof(provisioning->claim));
    provisioning->claim_valid = false;
    provisioning->claim_disclosed = false;
    provisioning->claim_session_bound = false;
    provisioning->claim_session_id = 0;
}

static void clear_claim(product_provisioning_handle_t provisioning)
{
    if (take_pending_lock(provisioning)) {
        clear_claim_locked(provisioning);
        xSemaphoreGive(provisioning->pending_lock);
    }
}

static esp_err_t generate_claim(product_provisioning_handle_t provisioning)
{
    uint8_t raw[DEVICE_CLAIM_RAW_BYTES] = {0};
    if (!take_pending_lock(provisioning)) {
        return ESP_ERR_TIMEOUT;
    }
    clear_claim_locked(provisioning);
    esp_fill_random(raw, sizeof(raw));
    const bool encoded = base64url_encode(
        raw, sizeof(raw), provisioning->claim,
        sizeof(provisioning->claim));
    secure_zero(raw, sizeof(raw));
    if (encoded) {
        provisioning->claim_valid = true;
    }
    xSemaphoreGive(provisioning->pending_lock);
    return encoded ? ESP_OK : ESP_ERR_INVALID_SIZE;
}

static esp_err_t enqueue(product_provisioning_handle_t provisioning,
                         command_type_t type)
{
    if (!provisioning ||
        atomic_load_explicit(&provisioning->stopping,
                             memory_order_acquire)) {
        return ESP_ERR_INVALID_STATE;
    }
    const command_t command = {.type = type};
    return xQueueSend(provisioning->commands, &command, 0) == pdTRUE
               ? ESP_OK
               : ESP_ERR_TIMEOUT;
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

static esp_err_t load_material(product_provisioning_handle_t provisioning,
                               const uint8_t derived_key[32])
{
    if (!derived_key) {
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t error = product_storage_require_ready();
    if (error != ESP_OK) {
        return error;
    }
    nvs_handle_t nvs = 0;
    error = nvs_open_from_partition(FACTORY_PARTITION, FACTORY_NAMESPACE,
                                    NVS_READONLY, &nvs);
    if (error != ESP_OK) {
        return error;
    }
    uint8_t blob[PRODUCT_PROVISIONING_MATERIAL_BLOB_SIZE] = {0};
    size_t blob_size = sizeof(blob);
    error = nvs_get_blob(nvs, FACTORY_MATERIAL_KEY, blob, &blob_size);
    nvs_close(nvs);
    uint8_t expected_tag[PRODUCT_PROVISIONING_MATERIAL_AUTH_TAG_SIZE] = {0};
    uint8_t authenticated[
        sizeof(MATERIAL_AUTH_DOMAIN) - 1 +
        PRODUCT_PROVISIONING_MATERIAL_AUTHENTICATED_SIZE] = {0};
    if (error == ESP_OK &&
        blob_size == PRODUCT_PROVISIONING_MATERIAL_BLOB_SIZE) {
        memcpy(authenticated, MATERIAL_AUTH_DOMAIN,
               sizeof(MATERIAL_AUTH_DOMAIN) - 1);
        memcpy(authenticated + sizeof(MATERIAL_AUTH_DOMAIN) - 1, blob,
               PRODUCT_PROVISIONING_MATERIAL_AUTHENTICATED_SIZE);
        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
        psa_key_id_t key_id = 0;
        size_t tag_size = 0;
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
        psa_set_key_algorithm(&attributes,
                              PSA_ALG_HMAC(PSA_ALG_SHA_256));
        psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
        psa_set_key_bits(&attributes, 256);
        psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
        psa_status_t status = psa_crypto_init();
        if (status == PSA_SUCCESS) {
            status = psa_import_key(&attributes, derived_key, 32, &key_id);
        }
        psa_reset_key_attributes(&attributes);
        if (status == PSA_SUCCESS) {
            status = psa_mac_compute(
                key_id, PSA_ALG_HMAC(PSA_ALG_SHA_256), authenticated,
                sizeof(authenticated), expected_tag, sizeof(expected_tag),
                &tag_size);
        }
        if (key_id != 0) {
            (void)psa_destroy_key(key_id);
        }
        if (status != PSA_SUCCESS || tag_size != sizeof(expected_tag) ||
            !constant_time_equal(
                expected_tag,
                blob + PRODUCT_PROVISIONING_MATERIAL_AUTHENTICATED_SIZE,
                sizeof(expected_tag))) {
            error = ESP_ERR_INVALID_CRC;
        }
    }
    if (error == ESP_OK &&
        !product_provisioning_material_decode(
            blob, blob_size, &provisioning->material)) {
        error = ESP_ERR_INVALID_CRC;
    }
    secure_zero(authenticated, sizeof(authenticated));
    secure_zero(expected_tag, sizeof(expected_tag));
    secure_zero(blob, sizeof(blob));
    return error;
}

static esp_err_t prepare_softap(product_provisioning_handle_t provisioning,
                                uint8_t derived_key[32])
{
    if (!derived_key) {
        return ESP_ERR_INVALID_ARG;
    }
    uint8_t mac[6] = {0};
    esp_err_t error = esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);
    if (error != ESP_OK ||
        !product_provisioning_format_service_name(mac,
                                                   provisioning->softap.ssid)) {
        secure_zero(mac, sizeof(mac));
        return error == ESP_OK ? ESP_FAIL : error;
    }
    secure_zero(mac, sizeof(mac));
    error = provisioning->derive_ap_key(
        provisioning->derive_ap_key_ctx, provisioning->softap.ssid,
        derived_key);
    if (error == ESP_OK &&
        !product_provisioning_format_ap_secret(
            derived_key, provisioning->softap.password)) {
        error = ESP_FAIL;
    }
    provisioning->softap.channel = 1;
    return error;
}

static bool is_auth_failure_reason(uint16_t reason)
{
    return reason == WIFI_REASON_AUTH_EXPIRE ||
           reason == WIFI_REASON_ASSOC_NOT_AUTHED ||
           reason == WIFI_REASON_AUTH_FAIL ||
           reason == WIFI_REASON_HANDSHAKE_TIMEOUT ||
           reason == WIFI_REASON_NO_AP_FOUND_W_COMPATIBLE_SECURITY ||
           reason == WIFI_REASON_NO_AP_FOUND_IN_AUTHMODE_THRESHOLD;
}

static esp_err_t wifi_get_status_handler(
    network_prov_config_get_wifi_data_t *response,
    network_prov_ctx_t **ctx)
{
    if (!response || !ctx || !*ctx) {
        return ESP_ERR_INVALID_ARG;
    }
    product_provisioning_handle_t provisioning =
        (product_provisioning_handle_t)*ctx;
    product_wifi_stats_t stats;
    if (product_wifi_get_stats(provisioning->wifi, &stats) != ESP_OK) {
        return ESP_FAIL;
    }
    memset(response, 0, sizeof(*response));
    if (stats.network_available &&
        stats.state == PRODUCT_WIFI_STATE_ONLINE) {
        response->wifi_state = NETWORK_PROV_WIFI_STA_CONNECTED;
        esp_netif_t *station =
            esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        esp_netif_ip_info_t ip = {0};
        wifi_ap_record_t ap = {0};
        if (!station || esp_netif_get_ip_info(station, &ip) != ESP_OK ||
            esp_wifi_sta_get_ap_info(&ap) != ESP_OK) {
            return ESP_FAIL;
        }
        (void)esp_ip4addr_ntoa(&ip.ip, response->conn_info.ip_addr,
                               sizeof(response->conn_info.ip_addr));
        memcpy(response->conn_info.bssid, ap.bssid,
               sizeof(response->conn_info.bssid));
        memcpy(response->conn_info.ssid, ap.ssid,
               sizeof(response->conn_info.ssid) - 1);
        response->conn_info.channel = ap.primary;
        response->conn_info.auth_mode = (uint8_t)ap.authmode;
        (void)enqueue(provisioning, COMMAND_ONLINE_OBSERVED);
    } else if (stats.candidate_rejections >
               atomic_load_explicit(&provisioning->rejection_baseline,
                                    memory_order_acquire)) {
        response->wifi_state = NETWORK_PROV_WIFI_STA_DISCONNECTED;
        response->fail_reason =
            is_auth_failure_reason(stats.last_disconnect_reason)
                ? NETWORK_PROV_WIFI_STA_AUTH_ERROR
                : NETWORK_PROV_WIFI_STA_AP_NOT_FOUND;
    } else {
        response->wifi_state = NETWORK_PROV_WIFI_STA_CONNECTING;
        response->connecting_info.attempts_remaining = 1;
    }
    return ESP_OK;
}

static esp_err_t wifi_set_config_handler(
    const network_prov_config_set_wifi_data_t *request,
    network_prov_ctx_t **ctx)
{
    if (!request || !ctx || !*ctx ||
        !credentials_valid(request->ssid, request->password)) {
        return ESP_ERR_INVALID_ARG;
    }
    product_provisioning_handle_t provisioning =
        (product_provisioning_handle_t)*ctx;
    if (!take_pending_lock(provisioning)) {
        return ESP_ERR_TIMEOUT;
    }
    clear_pending_locked(provisioning);
    memcpy(provisioning->pending_ssid, request->ssid,
           strlen(request->ssid) + 1);
    memcpy(provisioning->pending_password, request->password,
           strlen(request->password) + 1);
    provisioning->pending_valid = true;
    product_wifi_stats_t stats;
    if (product_wifi_get_stats(provisioning->wifi, &stats) == ESP_OK) {
        atomic_store_explicit(&provisioning->rejection_baseline,
                              stats.candidate_rejections,
                              memory_order_release);
    }
    xSemaphoreGive(provisioning->pending_lock);
    return ESP_OK;
}

static esp_err_t wifi_apply_config_handler(network_prov_ctx_t **ctx)
{
    if (!ctx || !*ctx) {
        return ESP_ERR_INVALID_ARG;
    }
    product_provisioning_handle_t provisioning =
        (product_provisioning_handle_t)*ctx;
    if (!take_pending_lock(provisioning)) {
        return ESP_ERR_TIMEOUT;
    }
    const bool pending_valid = provisioning->pending_valid;
    const bool claim_disclosed = provisioning->claim_disclosed;
    xSemaphoreGive(provisioning->pending_lock);
    return pending_valid && claim_disclosed
               ? enqueue(provisioning, COMMAND_APPLY)
               : ESP_ERR_INVALID_STATE;
}

static esp_err_t device_claim_handler(
    uint32_t session_id,
    const uint8_t *inbuf,
    ssize_t inlen,
    uint8_t **outbuf,
    ssize_t *outlen,
    void *priv_data)
{
    (void)inbuf;
    product_provisioning_handle_t provisioning = priv_data;
    if (outbuf) {
        *outbuf = NULL;
    }
    if (outlen) {
        *outlen = 0;
    }
    if (!provisioning || inlen != 0 || !outbuf || !outlen ||
        !take_pending_lock(provisioning)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!provisioning->claim_valid ||
        (provisioning->claim_session_bound &&
         provisioning->claim_session_id != session_id)) {
        xSemaphoreGive(provisioning->pending_lock);
        return ESP_ERR_INVALID_STATE;
    }
    char response[DEVICE_CLAIM_RESPONSE_MAX] = {0};
    const int length = snprintf(
        response, sizeof(response),
        "{\"version\":1,\"device_id\":\"%s\",\"claim\":\"%s\"}",
        provisioning->device_id, provisioning->claim);
    if (length <= 0 || (size_t)length >= sizeof(response)) {
        xSemaphoreGive(provisioning->pending_lock);
        secure_zero(response, sizeof(response));
        return ESP_ERR_INVALID_SIZE;
    }
    uint8_t *output = malloc((size_t)length);
    if (!output) {
        xSemaphoreGive(provisioning->pending_lock);
        secure_zero(response, sizeof(response));
        return ESP_ERR_NO_MEM;
    }
    memcpy(output, response, (size_t)length);
    secure_zero(response, sizeof(response));
    const bool first_disclosure = !provisioning->claim_disclosed;
    provisioning->claim_disclosed = true;
    provisioning->claim_session_bound = true;
    provisioning->claim_session_id = session_id;
    xSemaphoreGive(provisioning->pending_lock);
    *outbuf = output;
    *outlen = (ssize_t)length;
    if (first_disclosure) {
        atomic_fetch_add_explicit(&provisioning->claims_disclosed, 1,
                                  memory_order_relaxed);
        (void)enqueue(provisioning, COMMAND_CLAIM_DISCLOSED);
    }
    return ESP_OK;
}

static void security_event_handler(void *arg,
                                   esp_event_base_t event_base,
                                   int32_t event_id,
                                   void *event_data)
{
    (void)event_data;
    product_provisioning_handle_t provisioning = arg;
    if (event_base == PROTOCOMM_SECURITY_SESSION_EVENT &&
        (event_id == PROTOCOMM_SECURITY_SESSION_CREDENTIALS_MISMATCH ||
         event_id ==
             PROTOCOMM_SECURITY_SESSION_INVALID_SECURITY_PARAMS)) {
        (void)enqueue(provisioning, COMMAND_AUTH_FAILURE);
    }
}

static void stop_transport(product_provisioning_handle_t provisioning)
{
    if (provisioning->security_event_instance) {
        (void)esp_event_handler_instance_unregister(
            PROTOCOMM_SECURITY_SESSION_EVENT, ESP_EVENT_ANY_ID,
            provisioning->security_event_instance);
        provisioning->security_event_instance = NULL;
    }
    if (provisioning->protocomm) {
        if (provisioning->transport_active) {
            (void)protocomm_httpd_stop(provisioning->protocomm);
        }
        protocomm_delete(provisioning->protocomm);
        provisioning->protocomm = NULL;
    }
    provisioning->transport_active = false;
    atomic_store_explicit(&provisioning->transport_active_public, false,
                          memory_order_release);
}

static esp_err_t start_transport(product_provisioning_handle_t provisioning)
{
    if (provisioning->protocomm || provisioning->transport_active) {
        return ESP_ERR_INVALID_STATE;
    }
    provisioning->protocomm = protocomm_new();
    if (!provisioning->protocomm) {
        return ESP_ERR_NO_MEM;
    }
    protocomm_httpd_config_t http = {
        .ext_handle_provided = false,
        .data.config = {
            .port = 80,
            .stack_size = 6144,
            .task_priority = tskIDLE_PRIORITY + 5,
        },
    };
    esp_err_t error =
        protocomm_httpd_start(provisioning->protocomm, &http);
    if (error != ESP_OK) {
        stop_transport(provisioning);
        return error;
    }
    provisioning->transport_active = true;

    const protocomm_security2_params_t security = {
        .salt = (const char *)provisioning->material.salt,
        .salt_len = provisioning->material.salt_size,
        .verifier = (const char *)provisioning->material.verifier,
        .verifier_len = sizeof(provisioning->material.verifier),
    };
    error = protocomm_set_security(
        provisioning->protocomm, "prov-session", &protocomm_security2,
        &security);
    int security_version = 2;
    uint8_t patch_version = 0;
    if (error == ESP_OK) {
        error = protocomm_get_sec_version(provisioning->protocomm,
                                          &security_version,
                                          &patch_version);
    }
    char version[160];
    if (error == ESP_OK) {
        const int length = snprintf(
            version, sizeof(version),
            "{\"prov\":{\"ver\":\"v1\",\"sec_ver\":%d,"
            "\"sec_patch_ver\":%u,"
            "\"cap\":[\"wifi_prov\",\"xz_claim_v1\"]}}",
            security_version, patch_version);
        if (length <= 0 || (size_t)length >= sizeof(version)) {
            error = ESP_FAIL;
        }
    }
    if (error == ESP_OK) {
        error = protocomm_set_version(provisioning->protocomm,
                                      "proto-ver", version);
    }
    provisioning->config_handlers = (network_prov_config_handlers_t){
        .wifi_get_status_handler = wifi_get_status_handler,
        .wifi_set_config_handler = wifi_set_config_handler,
        .wifi_apply_config_handler = wifi_apply_config_handler,
        .ctx = (network_prov_ctx_t *)provisioning,
    };
    if (error == ESP_OK) {
        error = protocomm_add_endpoint(
            provisioning->protocomm, "xz-claim", device_claim_handler,
            provisioning);
    }
    if (error == ESP_OK) {
        error = protocomm_add_endpoint(
            provisioning->protocomm, "prov-config",
            network_prov_config_data_handler,
            &provisioning->config_handlers);
    }
    if (error == ESP_OK) {
        error = esp_event_handler_instance_register(
            PROTOCOMM_SECURITY_SESSION_EVENT, ESP_EVENT_ANY_ID,
            security_event_handler, provisioning,
            &provisioning->security_event_instance);
    }
    if (error != ESP_OK) {
        stop_transport(provisioning);
        return error;
    }
    atomic_store_explicit(&provisioning->transport_active_public, true,
                          memory_order_release);
    return ESP_OK;
}

static esp_err_t submit_candidate(
    product_provisioning_handle_t provisioning)
{
    if (!take_pending_lock(provisioning)) {
        return ESP_ERR_TIMEOUT;
    }
    if (!provisioning->pending_valid || !provisioning->claim_valid ||
        !provisioning->claim_disclosed) {
        xSemaphoreGive(provisioning->pending_lock);
        return ESP_ERR_INVALID_STATE;
    }
    const esp_err_t error = product_wifi_submit_claimed_credentials(
        provisioning->wifi, provisioning->pending_ssid,
        provisioning->pending_password, provisioning->claim);
    if (error == ESP_OK) {
        clear_pending_locked(provisioning);
        atomic_fetch_add_explicit(&provisioning->candidates_submitted, 1,
                                  memory_order_relaxed);
    }
    xSemaphoreGive(provisioning->pending_lock);
    return error;
}

static esp_err_t publish_claim(product_provisioning_handle_t provisioning)
{
    char claim[DEVICE_CLAIM_ENCODED_BYTES + 1] = {0};
    bool available = false;
    if (take_pending_lock(provisioning)) {
        available = provisioning->claim_valid &&
                    provisioning->claim_disclosed;
        if (available) {
            memcpy(claim, provisioning->claim, sizeof(claim));
        }
        xSemaphoreGive(provisioning->pending_lock);
    }
    atomic_fetch_add_explicit(&provisioning->claim_publish_attempts, 1,
                              memory_order_relaxed);
    product_provisioning_claim_outcome_t outcome =
        PRODUCT_PROVISIONING_CLAIM_RETRY;
    esp_err_t result = available
                           ? provisioning->publish_claim(
                                 provisioning->publish_claim_ctx,
                                 claim, &outcome)
                           : ESP_ERR_INVALID_STATE;
    if (result == ESP_OK && outcome != PRODUCT_PROVISIONING_CLAIM_BOUND) {
        result = ESP_ERR_INVALID_RESPONSE;
    }
    if (result == ESP_OK) {
        result = product_wifi_complete_device_claim(
            provisioning->wifi, claim);
    } else if (outcome == PRODUCT_PROVISIONING_CLAIM_REJECTED) {
        const esp_err_t abandon = product_wifi_abandon_device_claim(
            provisioning->wifi, claim);
        if (abandon == ESP_OK) {
            atomic_fetch_add_explicit(
                &provisioning->claim_recovery_rejections, 1,
                memory_order_relaxed);
            publish_event(
                provisioning,
                PRODUCT_PROVISIONING_EVENT_CLAIM_RECOVERY_REQUIRED,
                result);
        } else {
            result = abandon;
        }
    }
    secure_zero(claim, sizeof(claim));
    product_provisioning_core_claim_result(
        &provisioning->core, monotonic_ms(), result == ESP_OK);
    if (result == ESP_OK) {
        atomic_store_explicit(&provisioning->last_error, ESP_OK,
                              memory_order_release);
        atomic_fetch_add_explicit(&provisioning->claims_bound, 1,
                                  memory_order_relaxed);
        publish_event(provisioning, PRODUCT_PROVISIONING_EVENT_CLAIM_BOUND,
                      ESP_OK);
    } else {
        atomic_store_explicit(&provisioning->last_error, result,
                              memory_order_release);
        atomic_fetch_add_explicit(&provisioning->claim_publish_failures, 1,
                                  memory_order_relaxed);
    }
    return outcome == PRODUCT_PROVISIONING_CLAIM_REJECTED
               ? (result == ESP_OK ? ESP_ERR_INVALID_RESPONSE : result)
               : ESP_OK;
}

static void recover_pending_claim(
    product_provisioning_handle_t provisioning,
    uint64_t now_ms)
{
    char claim[PRODUCT_WIFI_DEVICE_CLAIM_MAX + 1] = {0};
    const esp_err_t load = product_wifi_get_pending_device_claim(
        provisioning->wifi, claim);
    if (load == ESP_ERR_NOT_FOUND) {
        product_claim_recovery_core_record(
            &provisioning->claim_recovery, now_ms,
            PRODUCT_CLAIM_RECOVERY_RECOVERED);
        return;
    }
    if (load != ESP_OK) {
        product_claim_recovery_core_record(
            &provisioning->claim_recovery, now_ms,
            PRODUCT_CLAIM_RECOVERY_RETRY);
        secure_zero(claim, sizeof(claim));
        return;
    }

    atomic_fetch_add_explicit(&provisioning->claim_recovery_attempts, 1,
                              memory_order_relaxed);
    product_provisioning_claim_outcome_t outcome =
        PRODUCT_PROVISIONING_CLAIM_RETRY;
    product_claim_recovery_result_t recovery_result =
        PRODUCT_CLAIM_RECOVERY_RETRY;
    esp_err_t result = provisioning->publish_claim(
        provisioning->publish_claim_ctx, claim, &outcome);
    if (result == ESP_OK && outcome == PRODUCT_PROVISIONING_CLAIM_BOUND) {
        result = product_wifi_complete_device_claim(
            provisioning->wifi, claim);
        if (result == ESP_OK) {
            atomic_fetch_add_explicit(&provisioning->claims_recovered, 1,
                                      memory_order_relaxed);
            atomic_store_explicit(&provisioning->last_error, ESP_OK,
                                  memory_order_release);
            publish_event(provisioning,
                          PRODUCT_PROVISIONING_EVENT_CLAIM_RECOVERED,
                          ESP_OK);
            recovery_result = PRODUCT_CLAIM_RECOVERY_RECOVERED;
        }
    } else if (outcome == PRODUCT_PROVISIONING_CLAIM_REJECTED) {
        const esp_err_t rejection = result == ESP_OK
                                        ? ESP_ERR_INVALID_RESPONSE
                                        : result;
        result = product_wifi_abandon_device_claim(
            provisioning->wifi, claim);
        if (result == ESP_OK) {
            atomic_fetch_add_explicit(
                &provisioning->claim_recovery_rejections, 1,
                memory_order_relaxed);
            atomic_store_explicit(&provisioning->last_error, rejection,
                                  memory_order_release);
            publish_event(
                provisioning,
                PRODUCT_PROVISIONING_EVENT_CLAIM_RECOVERY_REQUIRED,
                rejection);
            recovery_result = PRODUCT_CLAIM_RECOVERY_REJECTED;
        }
    } else if (result == ESP_OK) {
        result = ESP_ERR_INVALID_RESPONSE;
    }

    secure_zero(claim, sizeof(claim));
    product_claim_recovery_core_record(
        &provisioning->claim_recovery, now_ms, recovery_result);
}

static void record_error(product_provisioning_handle_t provisioning,
                         esp_err_t error)
{
    atomic_store_explicit(&provisioning->last_error, error,
                          memory_order_release);
    publish_event(provisioning, PRODUCT_PROVISIONING_EVENT_ERROR, error);
}

static esp_err_t execute_actions(
    product_provisioning_handle_t provisioning,
    product_provisioning_action_t actions)
{
    esp_err_t error = ESP_OK;
    if ((actions & PRODUCT_PROVISIONING_ACTION_STOP_TRANSPORT) != 0) {
        stop_transport(provisioning);
        clear_claim(provisioning);
    }
    if ((actions & PRODUCT_PROVISIONING_ACTION_BEGIN_ONBOARDING) != 0) {
        error = product_wifi_begin_onboarding(provisioning->wifi);
    }
    if (error == ESP_OK &&
        (actions & PRODUCT_PROVISIONING_ACTION_START_SOFTAP) != 0) {
        error = product_wifi_start_onboarding_softap(
            provisioning->wifi, &provisioning->softap);
    }
    if (error == ESP_OK &&
        (actions & PRODUCT_PROVISIONING_ACTION_START_TRANSPORT) != 0) {
        error = start_transport(provisioning);
        if (error == ESP_OK) {
            publish_event(provisioning,
                          PRODUCT_PROVISIONING_EVENT_WINDOW_OPENED,
                          ESP_OK);
        }
    }
    if (error == ESP_OK &&
        (actions & PRODUCT_PROVISIONING_ACTION_SUBMIT_CANDIDATE) != 0) {
        error = submit_candidate(provisioning);
    }
    if (error == ESP_OK &&
        (actions & PRODUCT_PROVISIONING_ACTION_PUBLISH_CLAIM) != 0) {
        /* Transient network/control-plane failures remain inside the window. */
        error = publish_claim(provisioning);
    }
    if ((actions & PRODUCT_PROVISIONING_ACTION_FINISH_ONBOARDING) != 0) {
        const esp_err_t finish =
            product_wifi_finish_onboarding(provisioning->wifi);
        if (error == ESP_OK && finish != ESP_OK &&
            finish != ESP_ERR_INVALID_STATE) {
            error = finish;
        }
        publish_event(provisioning,
                      PRODUCT_PROVISIONING_EVENT_WINDOW_CLOSED,
                      error);
    }
    return error;
}

static void fail_session(product_provisioning_handle_t provisioning,
                         esp_err_t error)
{
    const product_provisioning_state_t old_state = provisioning->core.state;
    const product_provisioning_action_t actions =
        product_provisioning_core_fail(&provisioning->core);
    (void)execute_actions(provisioning, actions);
    sync_state(provisioning, old_state);
    record_error(provisioning, error);
}

static void worker_task(void *arg)
{
    product_provisioning_handle_t provisioning = arg;
    xEventGroupSetBits(provisioning->signals, SIGNAL_TASK_READY);
    uint32_t last_candidate_rejections = 0;
    uint32_t last_credential_updates = 0;
    bool running = true;
    while (running) {
        command_t command = {0};
        const bool received =
            xQueueReceive(provisioning->commands, &command,
                          pdMS_TO_TICKS(WORKER_POLL_MS)) == pdTRUE;
        product_provisioning_action_t actions =
            PRODUCT_PROVISIONING_ACTION_NONE;
        const product_provisioning_state_t old_state =
            provisioning->core.state;
        if (received) {
            switch (command.type) {
            case COMMAND_OPEN: {
                uint8_t derived_key[32] = {0};
                esp_err_t error = generate_claim(provisioning);
                if (error == ESP_OK) {
                    error = prepare_softap(provisioning, derived_key);
                }
                if (error == ESP_OK) {
                    error = load_material(provisioning, derived_key);
                }
                secure_zero(derived_key, sizeof(derived_key));
                if (error != ESP_OK) {
                    fail_session(provisioning, error);
                    continue;
                }
                product_wifi_stats_t stats;
                error = product_wifi_get_stats(provisioning->wifi, &stats);
                if (error != ESP_OK) {
                    fail_session(provisioning, error);
                    continue;
                }
                last_candidate_rejections = stats.candidate_rejections;
                last_credential_updates = stats.credential_updates;
                actions = product_provisioning_core_open(
                    &provisioning->core, monotonic_ms());
                atomic_fetch_add_explicit(&provisioning->windows_opened, 1,
                                          memory_order_relaxed);
                break;
            }
            case COMMAND_CLOSE:
                actions = product_provisioning_core_close(
                    &provisioning->core);
                break;
            case COMMAND_APPLY: {
                product_wifi_stats_t stats;
                if (product_wifi_get_stats(provisioning->wifi, &stats) !=
                    ESP_OK) {
                    fail_session(provisioning, ESP_FAIL);
                    continue;
                }
                actions = product_provisioning_core_apply(
                    &provisioning->core, monotonic_ms(),
                    stats.candidate_rejections);
                break;
            }
            case COMMAND_AUTH_FAILURE:
                actions = product_provisioning_core_auth_failure(
                    &provisioning->core);
                atomic_fetch_add_explicit(
                    &provisioning->authentication_failures, 1,
                    memory_order_relaxed);
                if (provisioning->core.state ==
                    PRODUCT_PROVISIONING_STATE_LOCKED_OUT) {
                    atomic_fetch_add_explicit(&provisioning->lockouts, 1,
                                              memory_order_relaxed);
                    publish_event(provisioning,
                                  PRODUCT_PROVISIONING_EVENT_LOCKED_OUT,
                                  ESP_ERR_INVALID_STATE);
                }
                break;
            case COMMAND_ONLINE_OBSERVED:
                actions = product_provisioning_core_online_observed(
                    &provisioning->core, monotonic_ms());
                break;
            case COMMAND_CLAIM_DISCLOSED:
                publish_event(provisioning,
                              PRODUCT_PROVISIONING_EVENT_CLAIM_DISCLOSED,
                              ESP_OK);
                break;
            case COMMAND_STOP:
                actions = product_provisioning_core_close(
                    &provisioning->core);
                running = false;
                break;
            default:
                fail_session(provisioning, ESP_ERR_INVALID_ARG);
                continue;
            }
        }

        product_wifi_stats_t wifi_stats;
        if (product_wifi_get_stats(provisioning->wifi, &wifi_stats) ==
            ESP_OK) {
            const product_provisioning_action_t poll_actions =
                product_provisioning_core_poll(
                    &provisioning->core, monotonic_ms(),
                    wifi_stats.onboarding_active,
                    wifi_stats.onboarding_softap_active,
                    wifi_stats.network_available &&
                        wifi_stats.state == PRODUCT_WIFI_STATE_ONLINE,
                    wifi_stats.candidate_rejections);
            actions |= poll_actions;
            const bool session_active =
                provisioning->core.state !=
                    PRODUCT_PROVISIONING_STATE_CLOSED &&
                provisioning->core.state !=
                    PRODUCT_PROVISIONING_STATE_LOCKED_OUT &&
                provisioning->core.state !=
                    PRODUCT_PROVISIONING_STATE_ERROR;
            if (session_active &&
                wifi_stats.candidate_rejections >
                last_candidate_rejections) {
                atomic_fetch_add_explicit(
                    &provisioning->candidates_rejected,
                    wifi_stats.candidate_rejections -
                        last_candidate_rejections,
                    memory_order_relaxed);
                publish_event(provisioning,
                              PRODUCT_PROVISIONING_EVENT_CANDIDATE_REJECTED,
                              ESP_OK);
                last_candidate_rejections =
                    wifi_stats.candidate_rejections;
            }
            if (session_active &&
                wifi_stats.credential_updates > last_credential_updates) {
                atomic_fetch_add_explicit(
                    &provisioning->candidates_accepted,
                    wifi_stats.credential_updates - last_credential_updates,
                    memory_order_relaxed);
                publish_event(provisioning,
                              PRODUCT_PROVISIONING_EVENT_CANDIDATE_ACCEPTED,
                              ESP_OK);
                last_credential_updates = wifi_stats.credential_updates;
            }
            const bool recovery_ready =
                product_claim_recovery_core_should_attempt(
                    &provisioning->claim_recovery, monotonic_ms(),
                    !session_active,
                    wifi_stats.network_available &&
                        wifi_stats.state == PRODUCT_WIFI_STATE_ONLINE,
                    wifi_stats.device_claim_pending);
            if (recovery_ready) {
                recover_pending_claim(provisioning, monotonic_ms());
            }
        }
        if (actions != PRODUCT_PROVISIONING_ACTION_NONE) {
            const esp_err_t error = execute_actions(provisioning, actions);
            if (error != ESP_OK) {
                fail_session(provisioning, error);
                continue;
            }
        }
        sync_state(provisioning, old_state);
    }

    stop_transport(provisioning);
    if (take_pending_lock(provisioning)) {
        clear_pending_locked(provisioning);
        clear_claim_locked(provisioning);
        xSemaphoreGive(provisioning->pending_lock);
    }
    secure_zero(&provisioning->material, sizeof(provisioning->material));
    secure_zero(&provisioning->softap, sizeof(provisioning->softap));
    provisioning->worker = NULL;
    xEventGroupSetBits(provisioning->signals, SIGNAL_TASK_STOPPED);
    vTaskDelete(NULL);
}

esp_err_t product_provisioning_create(
    const product_provisioning_config_t *config,
    product_provisioning_handle_t *out_provisioning)
{
    if (!config || !out_provisioning || *out_provisioning || !config->wifi ||
        !config->physical_presence || !config->derive_ap_key ||
        !safe_identifier(config->device_id) || !config->publish_claim) {
        return ESP_ERR_INVALID_ARG;
    }
    const uint32_t window_ms =
        config->window_ms ? config->window_ms : DEFAULT_WINDOW_MS;
    const uint32_t authentication_failure_limit =
        config->authentication_failure_limit
            ? config->authentication_failure_limit
            : DEFAULT_AUTHENTICATION_FAILURE_LIMIT;
    const uint32_t commit_delay_ms =
        config->commit_delay_ms ? config->commit_delay_ms
                                : DEFAULT_COMMIT_DELAY_MS;
    const uint32_t success_grace_ms =
        config->success_grace_ms ? config->success_grace_ms
                                 : DEFAULT_SUCCESS_GRACE_MS;
    const uint32_t task_stack_size =
        config->task_stack_size ? config->task_stack_size
                                : DEFAULT_TASK_STACK_SIZE;
    const uint32_t task_priority =
        config->task_priority ? config->task_priority
                              : DEFAULT_TASK_PRIORITY;
    const product_provisioning_core_config_t core_config = {
        .window_ms = window_ms,
        .commit_delay_ms = commit_delay_ms,
        .success_grace_ms = success_grace_ms,
        .authentication_failure_limit = authentication_failure_limit,
        .claim_required = true,
    };
    if (task_stack_size < MINIMUM_TASK_STACK_SIZE ||
        task_stack_size > MAXIMUM_TASK_STACK_SIZE || task_priority == 0 ||
        task_priority >= configMAX_PRIORITIES) {
        return ESP_ERR_INVALID_ARG;
    }
    product_provisioning_handle_t provisioning =
        calloc(1, sizeof(*provisioning));
    if (!provisioning) {
        return ESP_ERR_NO_MEM;
    }
    if (!product_provisioning_core_init(&provisioning->core,
                                        &core_config)) {
        free(provisioning);
        return ESP_ERR_INVALID_ARG;
    }
    provisioning->wifi = config->wifi;
    provisioning->physical_presence = config->physical_presence;
    provisioning->physical_presence_ctx = config->physical_presence_ctx;
    provisioning->derive_ap_key = config->derive_ap_key;
    provisioning->derive_ap_key_ctx = config->derive_ap_key_ctx;
    provisioning->publish_claim = config->publish_claim;
    provisioning->publish_claim_ctx = config->publish_claim_ctx;
    memcpy(provisioning->device_id, config->device_id,
           strlen(config->device_id) + 1);
    provisioning->event = config->event;
    provisioning->event_ctx = config->event_ctx;
    provisioning->task_stack_size = task_stack_size;
    provisioning->task_priority = task_priority;
    atomic_init(&provisioning->stopping, false);
    atomic_init(&provisioning->window_open, false);
    atomic_init(&provisioning->transport_active_public, false);
    atomic_init(&provisioning->state, PRODUCT_PROVISIONING_STATE_CLOSED);
    atomic_init(&provisioning->last_error, ESP_OK);
    atomic_init(&provisioning->windows_opened, 0);
    atomic_init(&provisioning->authentication_failures, 0);
    atomic_init(&provisioning->candidates_submitted, 0);
    atomic_init(&provisioning->candidates_accepted, 0);
    atomic_init(&provisioning->candidates_rejected, 0);
    atomic_init(&provisioning->lockouts, 0);
    atomic_init(&provisioning->claims_disclosed, 0);
    atomic_init(&provisioning->claim_publish_attempts, 0);
    atomic_init(&provisioning->claims_bound, 0);
    atomic_init(&provisioning->claim_publish_failures, 0);
    atomic_init(&provisioning->claim_recovery_attempts, 0);
    atomic_init(&provisioning->claims_recovered, 0);
    atomic_init(&provisioning->claim_recovery_rejections, 0);
    product_claim_recovery_core_init(&provisioning->claim_recovery);
    atomic_init(&provisioning->rejection_baseline, 0);
    provisioning->pending_lock = xSemaphoreCreateMutex();
    provisioning->commands =
        xQueueCreate(COMMAND_QUEUE_LENGTH, sizeof(command_t));
    provisioning->signals = xEventGroupCreate();
    if (!provisioning->pending_lock || !provisioning->commands ||
        !provisioning->signals) {
        if (provisioning->pending_lock) {
            vSemaphoreDelete(provisioning->pending_lock);
        }
        if (provisioning->commands) {
            vQueueDelete(provisioning->commands);
        }
        if (provisioning->signals) {
            vEventGroupDelete(provisioning->signals);
        }
        secure_zero(provisioning, sizeof(*provisioning));
        free(provisioning);
        return ESP_ERR_NO_MEM;
    }
    if (xTaskCreate(worker_task, "product_prov", task_stack_size,
                    provisioning, task_priority,
                    &provisioning->worker) != pdPASS) {
        vSemaphoreDelete(provisioning->pending_lock);
        vQueueDelete(provisioning->commands);
        vEventGroupDelete(provisioning->signals);
        secure_zero(provisioning, sizeof(*provisioning));
        free(provisioning);
        return ESP_ERR_NO_MEM;
    }
    const EventBits_t ready = xEventGroupWaitBits(
        provisioning->signals, SIGNAL_TASK_READY, pdFALSE, pdTRUE,
        pdMS_TO_TICKS(CREATE_TIMEOUT_MS));
    if ((ready & SIGNAL_TASK_READY) == 0) {
        atomic_store_explicit(&provisioning->stopping, true,
                              memory_order_release);
        const command_t stop = {.type = COMMAND_STOP};
        (void)xQueueSend(provisioning->commands, &stop, 0);
        const EventBits_t stopped = xEventGroupWaitBits(
            provisioning->signals, SIGNAL_TASK_STOPPED, pdFALSE, pdTRUE,
            pdMS_TO_TICKS(CREATE_TIMEOUT_MS));
        if ((stopped & SIGNAL_TASK_STOPPED) == 0 &&
            provisioning->worker) {
            vTaskDelete(provisioning->worker);
        }
        vSemaphoreDelete(provisioning->pending_lock);
        vQueueDelete(provisioning->commands);
        vEventGroupDelete(provisioning->signals);
        secure_zero(provisioning, sizeof(*provisioning));
        free(provisioning);
        return ESP_ERR_TIMEOUT;
    }
    *out_provisioning = provisioning;
    return ESP_OK;
}

esp_err_t product_provisioning_open(product_provisioning_handle_t provisioning)
{
    if (!provisioning) {
        return ESP_ERR_INVALID_ARG;
    }
    const esp_err_t presence = provisioning->physical_presence(
        provisioning->physical_presence_ctx);
    if (presence != ESP_OK) {
        return presence;
    }
    bool expected = false;
    if (!atomic_compare_exchange_strong_explicit(
            &provisioning->window_open, &expected, true,
            memory_order_acq_rel, memory_order_acquire)) {
        return ESP_ERR_INVALID_STATE;
    }
    const esp_err_t error = enqueue(provisioning, COMMAND_OPEN);
    if (error != ESP_OK) {
        atomic_store_explicit(&provisioning->window_open, false,
                              memory_order_release);
    }
    return error;
}

esp_err_t product_provisioning_close(product_provisioning_handle_t provisioning)
{
    if (!provisioning) {
        return ESP_ERR_INVALID_ARG;
    }
    return enqueue(provisioning, COMMAND_CLOSE);
}

esp_err_t product_provisioning_get_stats(
    product_provisioning_handle_t provisioning,
    product_provisioning_stats_t *stats)
{
    if (!provisioning || !stats) {
        return ESP_ERR_INVALID_ARG;
    }
    *stats = (product_provisioning_stats_t){
        .state = (product_provisioning_state_t)atomic_load_explicit(
            &provisioning->state, memory_order_acquire),
        .window_open = atomic_load_explicit(&provisioning->window_open,
                                            memory_order_acquire),
        .transport_active = atomic_load_explicit(
            &provisioning->transport_active_public, memory_order_acquire),
        .windows_opened = atomic_load_explicit(
            &provisioning->windows_opened, memory_order_relaxed),
        .authentication_failures = atomic_load_explicit(
            &provisioning->authentication_failures,
            memory_order_relaxed),
        .candidates_submitted = atomic_load_explicit(
            &provisioning->candidates_submitted, memory_order_relaxed),
        .candidates_accepted = atomic_load_explicit(
            &provisioning->candidates_accepted, memory_order_relaxed),
        .candidates_rejected = atomic_load_explicit(
            &provisioning->candidates_rejected, memory_order_relaxed),
        .lockouts = atomic_load_explicit(&provisioning->lockouts,
                                         memory_order_relaxed),
        .claims_disclosed = atomic_load_explicit(
            &provisioning->claims_disclosed, memory_order_relaxed),
        .claim_publish_attempts = atomic_load_explicit(
            &provisioning->claim_publish_attempts, memory_order_relaxed),
        .claims_bound = atomic_load_explicit(
            &provisioning->claims_bound, memory_order_relaxed),
        .claim_publish_failures = atomic_load_explicit(
            &provisioning->claim_publish_failures,
            memory_order_relaxed),
        .claim_recovery_attempts = atomic_load_explicit(
            &provisioning->claim_recovery_attempts,
            memory_order_relaxed),
        .claims_recovered = atomic_load_explicit(
            &provisioning->claims_recovered, memory_order_relaxed),
        .claim_recovery_rejections = atomic_load_explicit(
            &provisioning->claim_recovery_rejections,
            memory_order_relaxed),
        .last_error = (esp_err_t)atomic_load_explicit(
            &provisioning->last_error, memory_order_acquire),
    };
    return ESP_OK;
}

esp_err_t product_provisioning_destroy(
    product_provisioning_handle_t provisioning,
    uint32_t timeout_ms)
{
    if (!provisioning || timeout_ms == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    const bool already_stopping = atomic_exchange_explicit(
        &provisioning->stopping, true, memory_order_acq_rel);
    if (!already_stopping) {
        const command_t stop = {.type = COMMAND_STOP};
        if (xQueueSend(provisioning->commands, &stop,
                       pdMS_TO_TICKS(timeout_ms < 100 ? timeout_ms : 100)) !=
            pdTRUE) {
            atomic_store_explicit(&provisioning->stopping, false,
                                  memory_order_release);
            return ESP_ERR_TIMEOUT;
        }
    }
    const EventBits_t stopped = xEventGroupWaitBits(
        provisioning->signals, SIGNAL_TASK_STOPPED, pdFALSE, pdTRUE,
        pdMS_TO_TICKS(timeout_ms));
    if ((stopped & SIGNAL_TASK_STOPPED) == 0) {
        return ESP_ERR_TIMEOUT;
    }
    vSemaphoreDelete(provisioning->pending_lock);
    vQueueDelete(provisioning->commands);
    vEventGroupDelete(provisioning->signals);
    secure_zero(provisioning, sizeof(*provisioning));
    free(provisioning);
    return ESP_OK;
}
