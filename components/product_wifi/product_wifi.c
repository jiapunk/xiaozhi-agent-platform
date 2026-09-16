#include "product_wifi.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "esp_event.h"
#include "esp_netif.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "product_storage.h"
#include "product_wifi_credential_set_core.h"
#include "product_wifi_credentials_core.h"
#include "product_wifi_state_core.h"
#include "sdkconfig.h"

enum {
    SIGNAL_TASK_READY = BIT0,
    SIGNAL_TASK_STOPPED = BIT1,
    COMMAND_QUEUE_LENGTH = 16,
    DEFAULT_MINIMUM_BACKOFF_MS = 2000,
    DEFAULT_MAXIMUM_BACKOFF_MS = 5 * 60 * 1000,
    DEFAULT_AUTHENTICATION_FAILURE_LIMIT = 3,
    DEFAULT_TASK_STACK_SIZE = 6144,
    DEFAULT_TASK_PRIORITY = 4,
    MINIMUM_TASK_STACK_SIZE = 4096,
    MAXIMUM_TASK_STACK_SIZE = 16384,
    WORKER_WAIT_CEILING_MS = 1000,
    CREATE_TIMEOUT_MS = 5000,
};

static const char *NVS_PARTITION = "nvs";
static const char *NVS_NAMESPACE = "prod_wifi";
static const char *NVS_STATE_KEY = "network_state";
static const char *NVS_SAVED_NETWORKS_KEY = "saved_networks";
static const char *NVS_LEGACY_CREDENTIAL_KEY = "credential";

_Static_assert((int)PRODUCT_WIFI_DEVICE_CLAIM_MAX ==
                   (int)PRODUCT_WIFI_DEVICE_CLAIM_SIZE,
               "claim size contract mismatch");
_Static_assert((int)PRODUCT_WIFI_SAVED_NETWORK_LIMIT ==
                   (int)PRODUCT_WIFI_CREDENTIAL_SET_LIMIT,
               "saved network limit contract mismatch");

typedef enum {
    COMMAND_START = 0,
    COMMAND_BEGIN_ONBOARDING,
    COMMAND_START_ONBOARDING_SOFTAP,
    COMMAND_SUBMIT_CREDENTIALS,
    COMMAND_CLEAR_CREDENTIALS,
    COMMAND_FINISH_ONBOARDING,
    COMMAND_STA_STARTED,
    COMMAND_DISCONNECTED,
    COMMAND_GOT_IP,
    COMMAND_LOST_IP,
    COMMAND_RECOVER_STATION,
    COMMAND_STOP,
} command_type_t;

typedef struct credential_submission {
    product_wifi_credentials_t credentials;
    char device_claim[PRODUCT_WIFI_DEVICE_CLAIM_MAX + 1];
    bool claim_pending;
} credential_submission_t;

typedef struct softap_submission {
    product_wifi_softap_config_t config;
} softap_submission_t;

typedef struct {
    command_type_t type;
    uint16_t disconnect_reason;
    credential_submission_t *submission;
    softap_submission_t *softap;
} command_t;

struct product_wifi {
    char hostname[PRODUCT_WIFI_HOSTNAME_MAX + 1];
    product_wifi_event_fn event;
    void *event_ctx;
    uint32_t task_stack_size;
    uint32_t task_priority;

    product_wifi_core_t core;
    product_wifi_credentials_t credentials;
    product_wifi_credential_set_t saved_networks;
    product_wifi_credentials_t candidate_credentials;
    char candidate_device_claim[PRODUCT_WIFI_DEVICE_CLAIM_MAX + 1];
    bool candidate_valid;
    bool candidate_claim_pending;
    char pending_device_claim[PRODUCT_WIFI_DEVICE_CLAIM_MAX + 1];
    bool device_claim_pending;
    SemaphoreHandle_t storage_lock;
    QueueHandle_t commands;
    EventGroupHandle_t signals;
    TaskHandle_t worker;
    esp_netif_t *station_netif;
    esp_netif_t *softap_netif;
    esp_event_handler_instance_t wifi_event_instance;
    esp_event_handler_instance_t ip_event_instance;
    bool wifi_initialized;
    bool driver_started;
    bool ignore_disconnect_once;
    bool station_recovering;
    bool selected_network_dirty;

    atomic_bool started;
    atomic_bool stopping;
    atomic_bool network_available;
    atomic_bool has_credentials;
    atomic_bool onboarding_active;
    atomic_bool onboarding_softap_active;
    atomic_uint saved_network_count;
    atomic_bool overflow_pending;
    atomic_int state;
    atomic_int last_error;
    atomic_uint reconnects;
    atomic_uint station_recoveries;
    atomic_uint authentication_failures;
    atomic_uint queue_overflows;
    atomic_uint onboarding_entries;
    atomic_uint credential_updates;
    atomic_uint candidate_rejections;
    atomic_bool device_claim_pending_public;
    atomic_uint device_claims_committed;
    atomic_uint device_claims_completed;
    atomic_uint device_claims_abandoned;
    atomic_uint last_disconnect_reason;
};

static void secure_zero(void *memory, size_t size)
{
    volatile unsigned char *bytes = memory;
    while (bytes && size > 0) {
        *bytes++ = 0;
        --size;
    }
}

static uint64_t monotonic_ms(void)
{
    return (uint64_t)esp_timer_get_time() / 1000;
}

static bool safe_hostname(const char *hostname)
{
    if (!hostname) {
        return false;
    }
    const size_t size = strnlen(hostname, PRODUCT_WIFI_HOSTNAME_MAX + 1);
    if (size == 0 || size > PRODUCT_WIFI_HOSTNAME_MAX ||
        hostname[0] == '-' || hostname[size - 1] == '-') {
        return false;
    }
    for (size_t index = 0; index < size; ++index) {
        const unsigned char c = (unsigned char)hostname[index];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-') {
            continue;
        }
        return false;
    }
    return true;
}

static bool safe_softap_config(const product_wifi_softap_config_t *config)
{
    if (!config) {
        return false;
    }
    const size_t ssid_size =
        strnlen(config->ssid, PRODUCT_WIFI_SOFTAP_SSID_MAX + 1);
    const size_t password_size =
        strnlen(config->password, PRODUCT_WIFI_SOFTAP_PASSWORD_MAX + 1);
    if (ssid_size == 0 || ssid_size > PRODUCT_WIFI_SOFTAP_SSID_MAX ||
        password_size < PRODUCT_WIFI_SOFTAP_PASSWORD_MIN ||
        password_size > PRODUCT_WIFI_SOFTAP_PASSWORD_MAX ||
        config->channel > 13) {
        return false;
    }
    for (size_t index = 0; index < ssid_size; ++index) {
        const unsigned char c = (unsigned char)config->ssid[index];
        if (c < 0x20 || c > 0x7e) {
            return false;
        }
    }
    for (size_t index = 0; index < password_size; ++index) {
        const unsigned char c = (unsigned char)config->password[index];
        if (c < 0x20 || c > 0x7e) {
            return false;
        }
    }
    return true;
}

static void sync_public_state(product_wifi_handle_t wifi)
{
    atomic_store_explicit(&wifi->state, (int)wifi->core.state,
                          memory_order_release);
    atomic_store_explicit(&wifi->network_available,
                          wifi->core.network_available,
                          memory_order_release);
    atomic_store_explicit(&wifi->has_credentials,
                          wifi->core.has_credentials,
                          memory_order_release);
    atomic_store_explicit(&wifi->onboarding_active,
                          wifi->core.onboarding_active,
                          memory_order_release);
}

static void publish_event(product_wifi_handle_t wifi,
                          product_wifi_event_type_t type,
                          esp_err_t error,
                          uint16_t disconnect_reason,
                          bool onboarding_required)
{
    if (!wifi->event) {
        return;
    }
    const uint64_t now_ms = monotonic_ms();
    const uint32_t retry_in_ms =
        wifi->core.state == PRODUCT_WIFI_STATE_BACKOFF &&
                wifi->core.retry_at_ms > now_ms
            ? (uint32_t)(wifi->core.retry_at_ms - now_ms)
            : 0;
    const product_wifi_event_t event = {
        .type = type,
        .state = wifi->core.state,
        .network_available = wifi->core.network_available,
        .onboarding_required = onboarding_required,
        .retry_in_ms = retry_in_ms,
        .disconnect_reason = disconnect_reason,
        .error = error,
    };
    wifi->event(wifi->event_ctx, &event);
}

static void publish_transition(product_wifi_handle_t wifi,
                               product_wifi_state_t old_state,
                               product_wifi_action_t actions,
                               esp_err_t error,
                               uint16_t disconnect_reason)
{
    sync_public_state(wifi);
    if (old_state != wifi->core.state) {
        publish_event(wifi, PRODUCT_WIFI_EVENT_STATE_CHANGED, error,
                      disconnect_reason, false);
    }
    if ((actions & (PRODUCT_WIFI_ACTION_NETWORK_UP |
                    PRODUCT_WIFI_ACTION_NETWORK_DOWN)) != 0) {
        publish_event(wifi, PRODUCT_WIFI_EVENT_NETWORK_CHANGED, error,
                      disconnect_reason, false);
    }
    if ((actions & PRODUCT_WIFI_ACTION_REQUIRE_ONBOARDING) != 0) {
        publish_event(wifi, PRODUCT_WIFI_EVENT_ONBOARDING_REQUIRED, error,
                      disconnect_reason, true);
    }
}

static void publish_error(product_wifi_handle_t wifi, esp_err_t error)
{
    atomic_store_explicit(&wifi->last_error, error, memory_order_release);
    publish_event(wifi, PRODUCT_WIFI_EVENT_ERROR, error, 0, false);
}

static esp_err_t enqueue(product_wifi_handle_t wifi,
                         const command_t *command,
                         TickType_t wait)
{
    if (!wifi || !command ||
        atomic_load_explicit(&wifi->stopping, memory_order_acquire)) {
        return ESP_ERR_INVALID_STATE;
    }
    return xQueueSend(wifi->commands, command, wait) == pdTRUE
               ? ESP_OK
               : ESP_ERR_TIMEOUT;
}

static void enqueue_driver_event(product_wifi_handle_t wifi,
                                 command_type_t type,
                                 uint16_t disconnect_reason)
{
    if (!wifi || atomic_load_explicit(&wifi->stopping,
                                      memory_order_acquire)) {
        return;
    }
    const command_t command = {
        .type = type,
        .disconnect_reason = disconnect_reason,
        .submission = NULL,
    };
    if (xQueueSend(wifi->commands, &command, 0) != pdTRUE) {
        atomic_fetch_add_explicit(&wifi->queue_overflows, 1,
                                  memory_order_relaxed);
        atomic_store_explicit(&wifi->overflow_pending, true,
                              memory_order_release);
    }
}

static void wifi_event_handler(void *arg,
                               esp_event_base_t event_base,
                               int32_t event_id,
                               void *event_data)
{
    product_wifi_handle_t wifi = arg;
    if (event_base != WIFI_EVENT) {
        return;
    }
    if (event_id == WIFI_EVENT_STA_START) {
        enqueue_driver_event(wifi, COMMAND_STA_STARTED, 0);
    } else if (event_id == WIFI_EVENT_STA_DISCONNECTED && event_data) {
        const wifi_event_sta_disconnected_t *event = event_data;
        enqueue_driver_event(wifi, COMMAND_DISCONNECTED, event->reason);
    }
}

static void ip_event_handler(void *arg,
                             esp_event_base_t event_base,
                             int32_t event_id,
                             void *event_data)
{
    (void)event_data;
    product_wifi_handle_t wifi = arg;
    if (event_base != IP_EVENT) {
        return;
    }
    if (event_id == IP_EVENT_STA_GOT_IP) {
        enqueue_driver_event(wifi, COMMAND_GOT_IP, 0);
    } else if (event_id == IP_EVENT_STA_LOST_IP) {
        enqueue_driver_event(wifi, COMMAND_LOST_IP, 0);
    }
}

static esp_err_t encode_and_set_state(
    nvs_handle_t nvs,
    const product_wifi_credentials_t *credentials,
    const char *device_claim)
{
    product_wifi_persisted_state_t state = {0};
    uint8_t blob[PRODUCT_WIFI_STATE_BLOB_SIZE] = {0};
    state.credentials = *credentials;
    if (device_claim) {
        memcpy(state.device_claim, device_claim,
               PRODUCT_WIFI_DEVICE_CLAIM_MAX + 1);
        state.claim_pending = true;
    }
    const bool encoded = product_wifi_state_encode(&state, blob);
    secure_zero(&state, sizeof(state));
    if (!encoded) {
        secure_zero(blob, sizeof(blob));
        return ESP_ERR_INVALID_ARG;
    }
    const esp_err_t error = nvs_set_blob(nvs, NVS_STATE_KEY, blob,
                                         sizeof(blob));
    secure_zero(blob, sizeof(blob));
    return error;
}

static esp_err_t encode_and_set_saved_networks(
    nvs_handle_t nvs,
    const product_wifi_credential_set_t *saved_networks)
{
    uint8_t blob[PRODUCT_WIFI_CREDENTIAL_SET_BLOB_SIZE] = {0};
    if (!product_wifi_credential_set_encode(saved_networks, blob)) {
        secure_zero(blob, sizeof(blob));
        return ESP_ERR_INVALID_ARG;
    }
    const esp_err_t error = nvs_set_blob(
        nvs, NVS_SAVED_NETWORKS_KEY, blob, sizeof(blob));
    secure_zero(blob, sizeof(blob));
    return error;
}

static bool credentials_equal(
    const product_wifi_credentials_t *left,
    const product_wifi_credentials_t *right)
{
    return left && right && strcmp(left->ssid, right->ssid) == 0 &&
           strcmp(left->password, right->password) == 0;
}

static esp_err_t load_network_state(product_wifi_handle_t wifi,
                                    bool *has_credentials)
{
    if (!wifi || !has_credentials) {
        return ESP_ERR_INVALID_ARG;
    }
    *has_credentials = false;
    nvs_handle_t nvs = 0;
    esp_err_t error = nvs_open_from_partition(
        NVS_PARTITION, NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (error == ESP_ERR_NVS_NOT_FOUND) {
        return ESP_OK;
    }
    if (error != ESP_OK) {
        return error;
    }

    bool migrate_state = false;
    uint8_t state_blob[PRODUCT_WIFI_STATE_BLOB_SIZE] = {0};
    size_t state_blob_size = sizeof(state_blob);
    error = nvs_get_blob(nvs, NVS_STATE_KEY, state_blob,
                         &state_blob_size);
    if (error == ESP_OK) {
        product_wifi_persisted_state_t state = {0};
        if (!product_wifi_state_decode(state_blob, state_blob_size,
                                       &state)) {
            secure_zero(&state, sizeof(state));
            secure_zero(state_blob, sizeof(state_blob));
            nvs_close(nvs);
            return ESP_ERR_INVALID_CRC;
        }
        wifi->credentials = state.credentials;
        wifi->device_claim_pending = state.claim_pending;
        if (state.claim_pending) {
            memcpy(wifi->pending_device_claim, state.device_claim,
                   sizeof(wifi->pending_device_claim));
        }
        secure_zero(&state, sizeof(state));
    } else if (error == ESP_ERR_NVS_NOT_FOUND) {
        uint8_t legacy[PRODUCT_WIFI_CREDENTIAL_BLOB_SIZE] = {0};
        size_t legacy_size = sizeof(legacy);
        error = nvs_get_blob(nvs, NVS_LEGACY_CREDENTIAL_KEY, legacy,
                             &legacy_size);
        if (error == ESP_ERR_NVS_NOT_FOUND) {
            secure_zero(legacy, sizeof(legacy));
            secure_zero(state_blob, sizeof(state_blob));
            nvs_close(nvs);
            return ESP_OK;
        }
        if (error != ESP_OK || !product_wifi_credentials_decode(
                                   legacy, legacy_size,
                                   &wifi->credentials)) {
            secure_zero(legacy, sizeof(legacy));
            secure_zero(state_blob, sizeof(state_blob));
            nvs_close(nvs);
            return error == ESP_OK ? ESP_ERR_INVALID_CRC : error;
        }
        secure_zero(legacy, sizeof(legacy));
        migrate_state = true;
    } else {
        secure_zero(state_blob, sizeof(state_blob));
        nvs_close(nvs);
        return error;
    }
    secure_zero(state_blob, sizeof(state_blob));

    product_wifi_credential_set_t saved = {0};
    uint8_t saved_blob[PRODUCT_WIFI_CREDENTIAL_SET_BLOB_SIZE] = {0};
    size_t saved_blob_size = sizeof(saved_blob);
    const esp_err_t saved_error = nvs_get_blob(
        nvs, NVS_SAVED_NETWORKS_KEY, saved_blob, &saved_blob_size);
    bool repair_saved = saved_error == ESP_ERR_NVS_NOT_FOUND ||
                        saved_error == ESP_ERR_NVS_INVALID_LENGTH;
    if (saved_error == ESP_OK && !product_wifi_credential_set_decode(
                                     saved_blob, saved_blob_size, &saved)) {
        repair_saved = true;
    } else if (saved_error != ESP_OK && !repair_saved) {
        secure_zero(&saved, sizeof(saved));
        secure_zero(saved_blob, sizeof(saved_blob));
        nvs_close(nvs);
        return saved_error;
    }
    secure_zero(saved_blob, sizeof(saved_blob));
    const bool active_matches = !repair_saved && saved.count > 0 &&
                                saved.active_index < saved.count &&
                                credentials_equal(
                                    &saved.entries[saved.active_index],
                                    &wifi->credentials);
    if (!active_matches) {
        if (repair_saved) {
            secure_zero(&saved, sizeof(saved));
        }
        if (!product_wifi_credential_set_upsert(&saved,
                                                &wifi->credentials)) {
            secure_zero(&saved, sizeof(saved));
            nvs_close(nvs);
            return ESP_ERR_INVALID_STATE;
        }
        repair_saved = true;
    }

    if (migrate_state) {
        error = encode_and_set_state(nvs, &wifi->credentials, NULL);
    }
    if (error == ESP_OK && (repair_saved || migrate_state)) {
        error = encode_and_set_saved_networks(nvs, &saved);
    }
    if (error == ESP_OK && migrate_state) {
        const esp_err_t erase = nvs_erase_key(
            nvs, NVS_LEGACY_CREDENTIAL_KEY);
        if (erase != ESP_OK && erase != ESP_ERR_NVS_NOT_FOUND) {
            error = erase;
        }
    }
    if (error == ESP_OK && (repair_saved || migrate_state)) {
        error = nvs_commit(nvs);
    }
    nvs_close(nvs);
    if (error != ESP_OK) {
        secure_zero(&saved, sizeof(saved));
        return error;
    }
    wifi->saved_networks = saved;
    atomic_store_explicit(&wifi->saved_network_count, saved.count,
                          memory_order_release);
    secure_zero(&saved, sizeof(saved));
    *has_credentials = true;
    return ESP_OK;
}

static esp_err_t persist_network_state(
    const product_wifi_credentials_t *credentials,
    const char *device_claim,
    const product_wifi_credential_set_t *saved_networks)
{
    nvs_handle_t nvs = 0;
    esp_err_t error = nvs_open_from_partition(
        NVS_PARTITION, NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (error == ESP_OK) {
        error = encode_and_set_state(nvs, credentials, device_claim);
    }
    if (error == ESP_OK) {
        error = encode_and_set_saved_networks(nvs, saved_networks);
    }
    if (error == ESP_OK) {
        const esp_err_t erase = nvs_erase_key(
            nvs, NVS_LEGACY_CREDENTIAL_KEY);
        if (erase != ESP_OK && erase != ESP_ERR_NVS_NOT_FOUND) {
            error = erase;
        }
    }
    if (error == ESP_OK) {
        error = nvs_commit(nvs);
    }
    if (nvs != 0) {
        nvs_close(nvs);
    }
    return error;
}

static esp_err_t erase_network_state(void)
{
    nvs_handle_t nvs = 0;
    esp_err_t error = nvs_open_from_partition(
        NVS_PARTITION, NVS_NAMESPACE, NVS_READWRITE, &nvs);
    if (error != ESP_OK) {
        return error;
    }
    error = nvs_erase_key(nvs, NVS_STATE_KEY);
    if (error == ESP_ERR_NVS_NOT_FOUND) {
        error = ESP_OK;
    }
    const esp_err_t legacy = nvs_erase_key(
        nvs, NVS_LEGACY_CREDENTIAL_KEY);
    if (error == ESP_OK && legacy != ESP_OK &&
        legacy != ESP_ERR_NVS_NOT_FOUND) {
        error = legacy;
    }
    const esp_err_t saved = nvs_erase_key(nvs, NVS_SAVED_NETWORKS_KEY);
    if (error == ESP_OK && saved != ESP_OK &&
        saved != ESP_ERR_NVS_NOT_FOUND) {
        error = saved;
    }
    if (error == ESP_OK) {
        error = nvs_commit(nvs);
    }
    nvs_close(nvs);
    return error;
}

static esp_err_t initialize_driver(product_wifi_handle_t wifi)
{
    esp_err_t error = esp_netif_init();
    if (error != ESP_OK && error != ESP_ERR_INVALID_STATE) {
        return error;
    }
    error = esp_event_loop_create_default();
    if (error != ESP_OK && error != ESP_ERR_INVALID_STATE) {
        return error;
    }

    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    init.nvs_enable = false;
    error = esp_wifi_init(&init);
    if (error != ESP_OK) {
        return error;
    }
    wifi->wifi_initialized = true;
    error = esp_wifi_set_storage(WIFI_STORAGE_RAM);
    if (error != ESP_OK) {
        return error;
    }
    wifi->station_netif = esp_netif_create_default_wifi_sta();
    if (!wifi->station_netif) {
        return ESP_ERR_NO_MEM;
    }
    error = esp_netif_set_hostname(wifi->station_netif, wifi->hostname);
    if (error != ESP_OK) {
        return error;
    }
    error = esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_handler, wifi,
        &wifi->wifi_event_instance);
    if (error != ESP_OK) {
        return error;
    }
    error = esp_event_handler_instance_register(
        IP_EVENT, ESP_EVENT_ANY_ID, ip_event_handler, wifi,
        &wifi->ip_event_instance);
    if (error != ESP_OK) {
        return error;
    }
    return esp_wifi_set_mode(WIFI_MODE_STA);
}

static esp_err_t apply_station_config_for(
    const product_wifi_credentials_t *credentials)
{
    if (!credentials ||
        !product_wifi_credentials_valid(credentials->ssid,
                                        credentials->password)) {
        return ESP_ERR_INVALID_STATE;
    }
    wifi_config_t config = {0};
    const size_t ssid_size = strlen(credentials->ssid);
    const size_t password_size = strlen(credentials->password);
    memcpy(config.sta.ssid, credentials->ssid, ssid_size);
    memcpy(config.sta.password, credentials->password, password_size);
    config.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
    config.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;
    config.sta.threshold.rssi = -127;
    config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    config.sta.pmf_cfg.capable = true;
    config.sta.pmf_cfg.required = false;
    config.sta.failure_retry_cnt = 2;
    config.sta.listen_interval = 10;
    return esp_wifi_set_config(WIFI_IF_STA, &config);
}

static esp_err_t start_station(product_wifi_handle_t wifi)
{
    esp_err_t error = esp_wifi_set_mode(WIFI_MODE_STA);
    if (error != ESP_OK) {
        return error;
    }
    error = apply_station_config_for(&wifi->credentials);
    if (error != ESP_OK) {
        return error;
    }
    if (!wifi->driver_started) {
        error = esp_wifi_start();
        if (error != ESP_OK) {
            return error;
        }
        wifi->driver_started = true;
        error = esp_wifi_set_ps(WIFI_PS_MIN_MODEM);
    }
    return error;
}

static void destroy_softap_netif(product_wifi_handle_t wifi)
{
    if (wifi->softap_netif) {
        esp_netif_destroy_default_wifi(wifi->softap_netif);
        wifi->softap_netif = NULL;
    }
    atomic_store_explicit(&wifi->onboarding_softap_active, false,
                          memory_order_release);
}

static esp_err_t start_onboarding_softap(
    product_wifi_handle_t wifi,
    const product_wifi_softap_config_t *softap)
{
    if (!wifi || !safe_softap_config(softap) ||
        !wifi->core.onboarding_active || wifi->driver_started ||
        wifi->softap_netif) {
        return ESP_ERR_INVALID_STATE;
    }
    wifi->softap_netif = esp_netif_create_default_wifi_ap();
    if (!wifi->softap_netif) {
        return ESP_ERR_NO_MEM;
    }
    wifi_config_t config = {0};
    const size_t ssid_size = strlen(softap->ssid);
    const size_t password_size = strlen(softap->password);
    memcpy(config.ap.ssid, softap->ssid, ssid_size);
    config.ap.ssid_len = (uint8_t)ssid_size;
    memcpy(config.ap.password, softap->password, password_size);
    config.ap.channel = softap->channel ? softap->channel : 1;
    config.ap.authmode = WIFI_AUTH_WPA2_PSK;
    config.ap.max_connection = 1;
    config.ap.beacon_interval = 100;
    config.ap.pairwise_cipher = WIFI_CIPHER_TYPE_CCMP;
    config.ap.pmf_cfg.capable = true;
    config.ap.pmf_cfg.required = false;

    /* APSTA keeps the password-protected setup AP online while allowing the
     * portal to scan every station channel for a user-selectable SSID. */
    esp_err_t error = esp_wifi_set_mode(WIFI_MODE_APSTA);
    if (error == ESP_OK) {
        error = esp_wifi_set_config(WIFI_IF_AP, &config);
    }
    if (error == ESP_OK) {
        error = esp_wifi_start();
    }
    if (error != ESP_OK) {
        (void)esp_wifi_stop();
        destroy_softap_netif(wifi);
        (void)esp_wifi_set_mode(WIFI_MODE_STA);
        return error;
    }
    wifi->driver_started = true;
    atomic_store_explicit(&wifi->onboarding_softap_active, true,
                          memory_order_release);
    publish_event(wifi, PRODUCT_WIFI_EVENT_ONBOARDING_TRANSPORT_CHANGED,
                  ESP_OK, 0, false);
    return ESP_OK;
}

static esp_err_t start_candidate(product_wifi_handle_t wifi)
{
    if (!wifi || !wifi->candidate_valid || !wifi->driver_started ||
        !atomic_load_explicit(&wifi->onboarding_softap_active,
                              memory_order_acquire)) {
        return ESP_ERR_INVALID_STATE;
    }
    esp_err_t error = esp_wifi_set_mode(WIFI_MODE_APSTA);
    if (error == ESP_OK) {
        error = apply_station_config_for(&wifi->candidate_credentials);
    }
    if (error == ESP_OK) {
        error = esp_wifi_connect();
    }
    return error;
}

static void reject_candidate(product_wifi_handle_t wifi)
{
    if (!wifi) {
        return;
    }
    (void)esp_wifi_disconnect();
    (void)esp_wifi_set_mode(WIFI_MODE_APSTA);
    secure_zero(&wifi->candidate_credentials,
                sizeof(wifi->candidate_credentials));
    secure_zero(wifi->candidate_device_claim,
                sizeof(wifi->candidate_device_claim));
    wifi->candidate_valid = false;
    wifi->candidate_claim_pending = false;
    atomic_fetch_add_explicit(&wifi->candidate_rejections, 1,
                              memory_order_relaxed);
    publish_event(wifi, PRODUCT_WIFI_EVENT_CREDENTIALS_REJECTED,
                  ESP_OK,
                  (uint16_t)atomic_load_explicit(
                      &wifi->last_disconnect_reason, memory_order_relaxed),
                  false);
}

static void stop_station(product_wifi_handle_t wifi)
{
    if (!wifi->driver_started) {
        return;
    }
    wifi->driver_started = false;
    (void)esp_wifi_disconnect();
    (void)esp_wifi_stop();
}

static esp_err_t restart_station(product_wifi_handle_t wifi)
{
    if (!wifi || wifi->core.onboarding_active || !wifi->core.has_credentials) {
        return ESP_ERR_INVALID_STATE;
    }
    wifi->station_recovering = true;
    if (wifi->driver_started) {
        wifi->driver_started = false;
        const esp_err_t stop_error = esp_wifi_stop();
        if (stop_error != ESP_OK) {
            wifi->station_recovering = false;
            return stop_error;
        }
    }
    const esp_err_t start_error = start_station(wifi);
    if (start_error != ESP_OK) {
        wifi->station_recovering = false;
    }
    return start_error;
}

static void cleanup_driver(product_wifi_handle_t wifi)
{
    if (wifi->wifi_event_instance) {
        (void)esp_event_handler_instance_unregister(
            WIFI_EVENT, ESP_EVENT_ANY_ID, wifi->wifi_event_instance);
        wifi->wifi_event_instance = NULL;
    }
    if (wifi->ip_event_instance) {
        (void)esp_event_handler_instance_unregister(
            IP_EVENT, ESP_EVENT_ANY_ID, wifi->ip_event_instance);
        wifi->ip_event_instance = NULL;
    }
    stop_station(wifi);
    destroy_softap_netif(wifi);
    if (wifi->station_netif) {
        esp_netif_destroy_default_wifi(wifi->station_netif);
        wifi->station_netif = NULL;
    }
    if (wifi->wifi_initialized) {
        (void)esp_wifi_deinit();
        wifi->wifi_initialized = false;
    }
    secure_zero(&wifi->candidate_credentials,
                sizeof(wifi->candidate_credentials));
    secure_zero(wifi->candidate_device_claim,
                sizeof(wifi->candidate_device_claim));
    wifi->candidate_valid = false;
    wifi->candidate_claim_pending = false;
}

static bool select_next_saved_network(product_wifi_handle_t wifi)
{
    if (!wifi || wifi->core.onboarding_active || wifi->candidate_valid ||
        wifi->saved_networks.count < 2) {
        return false;
    }
    product_wifi_credential_set_t previous = wifi->saved_networks;
    product_wifi_credentials_t next = {0};
    if (!product_wifi_credential_set_select_next(&wifi->saved_networks,
                                                  &next)) {
        secure_zero(&next, sizeof(next));
        return false;
    }
    const esp_err_t error = apply_station_config_for(&next);
    if (error != ESP_OK) {
        wifi->saved_networks = previous;
        secure_zero(&previous, sizeof(previous));
        secure_zero(&next, sizeof(next));
        publish_error(wifi, error);
        return false;
    }
    secure_zero(&previous, sizeof(previous));
    secure_zero(&wifi->credentials, sizeof(wifi->credentials));
    wifi->credentials = next;
    secure_zero(&next, sizeof(next));
    wifi->selected_network_dirty = true;
    publish_event(wifi, PRODUCT_WIFI_EVENT_NETWORK_CHANGED,
                  ESP_OK, 0, false);
    return true;
}

static bool authentication_failure(uint16_t reason)
{
    return reason == WIFI_REASON_AUTH_EXPIRE ||
           reason == WIFI_REASON_ASSOC_NOT_AUTHED ||
           reason == WIFI_REASON_AUTH_FAIL ||
           reason == WIFI_REASON_HANDSHAKE_TIMEOUT ||
           reason == WIFI_REASON_NO_AP_FOUND_W_COMPATIBLE_SECURITY ||
           reason == WIFI_REASON_NO_AP_FOUND_IN_AUTHMODE_THRESHOLD;
}

static void transition_fatal(product_wifi_handle_t wifi, esp_err_t error)
{
    const product_wifi_state_t old_state = wifi->core.state;
    const product_wifi_action_t actions = product_wifi_core_fatal(&wifi->core);
    atomic_store_explicit(&wifi->last_error, error, memory_order_release);
    publish_transition(wifi, old_state, actions, error, 0);
    stop_station(wifi);
    if (atomic_load_explicit(&wifi->onboarding_softap_active,
                             memory_order_acquire)) {
        destroy_softap_netif(wifi);
        publish_event(wifi,
                      PRODUCT_WIFI_EVENT_ONBOARDING_TRANSPORT_CHANGED,
                      error, 0, false);
    }
    publish_error(wifi, error);
}

static esp_err_t execute_actions(product_wifi_handle_t wifi,
                                 product_wifi_action_t actions)
{
    if ((actions & PRODUCT_WIFI_ACTION_RESTART_STATION) != 0) {
        return restart_station(wifi);
    }
    if ((actions & PRODUCT_WIFI_ACTION_STOP_STATION) != 0) {
        stop_station(wifi);
    }
    if ((actions & PRODUCT_WIFI_ACTION_START_STATION) != 0) {
        return start_station(wifi);
    }
    if ((actions & PRODUCT_WIFI_ACTION_START_CANDIDATE) != 0) {
        return start_candidate(wifi);
    }
    if ((actions & PRODUCT_WIFI_ACTION_REJECT_CANDIDATE) != 0) {
        reject_candidate(wifi);
    }
    if ((actions & PRODUCT_WIFI_ACTION_CONNECT) != 0) {
        if (wifi->core.consecutive_failures > 0) {
            atomic_fetch_add_explicit(&wifi->reconnects, 1,
                                      memory_order_relaxed);
        }
        return esp_wifi_connect();
    }
    return ESP_OK;
}

static void apply_actions(product_wifi_handle_t wifi,
                          product_wifi_state_t old_state,
                          product_wifi_action_t actions,
                          esp_err_t error,
                          uint16_t disconnect_reason)
{
    publish_transition(wifi, old_state, actions, error,
                       disconnect_reason);
    const esp_err_t action_error = execute_actions(wifi, actions);
    if (action_error != ESP_OK) {
        transition_fatal(wifi, action_error);
    }
}

static void handle_start(product_wifi_handle_t wifi)
{
    esp_err_t error = product_storage_require_ready();
    if (error != ESP_OK) {
        /* Storage has one product owner and is never implicitly repaired. */
        transition_fatal(wifi, error);
        return;
    }
    bool has_credentials = false;
    if (xSemaphoreTake(wifi->storage_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        transition_fatal(wifi, ESP_ERR_TIMEOUT);
        return;
    }
    error = load_network_state(wifi, &has_credentials);
    atomic_store_explicit(&wifi->device_claim_pending_public,
                          wifi->device_claim_pending,
                          memory_order_release);
    xSemaphoreGive(wifi->storage_lock);
    if (error != ESP_OK) {
        secure_zero(&wifi->credentials, sizeof(wifi->credentials));
        secure_zero(&wifi->saved_networks, sizeof(wifi->saved_networks));
        atomic_store_explicit(&wifi->saved_network_count, 0,
                              memory_order_release);
        publish_error(wifi, error);
        has_credentials = false;
    }
    error = initialize_driver(wifi);
    if (error != ESP_OK) {
        transition_fatal(wifi, error);
        return;
    }
    const product_wifi_state_t old_state = wifi->core.state;
    const product_wifi_action_t actions =
        product_wifi_core_start(&wifi->core, has_credentials);
    apply_actions(wifi, old_state, actions, ESP_OK, 0);
}

static void handle_begin_onboarding(product_wifi_handle_t wifi)
{
    const product_wifi_state_t old_state = wifi->core.state;
    const product_wifi_action_t actions =
        product_wifi_core_begin_onboarding(&wifi->core);
    if (wifi->core.state == PRODUCT_WIFI_STATE_ONBOARDING &&
        old_state != PRODUCT_WIFI_STATE_ONBOARDING) {
        atomic_fetch_add_explicit(&wifi->onboarding_entries, 1,
                                  memory_order_relaxed);
    }
    apply_actions(wifi, old_state, actions, ESP_OK, 0);
}

static void handle_start_onboarding_softap(
    product_wifi_handle_t wifi,
    softap_submission_t *submission)
{
    if (!submission) {
        publish_error(wifi, ESP_ERR_INVALID_ARG);
        return;
    }
    const esp_err_t error =
        start_onboarding_softap(wifi, &submission->config);
    secure_zero(submission, sizeof(*submission));
    free(submission);
    if (error != ESP_OK) {
        publish_error(wifi, error);
    }
}

static void handle_submission(product_wifi_handle_t wifi,
                              credential_submission_t *submission)
{
    if (!submission) {
        publish_error(wifi, ESP_ERR_INVALID_ARG);
        return;
    }
    if (wifi->core.state != PRODUCT_WIFI_STATE_ONBOARDING) {
        secure_zero(submission, sizeof(*submission));
        free(submission);
        publish_error(wifi, ESP_ERR_INVALID_STATE);
        return;
    }
    if (!atomic_load_explicit(&wifi->onboarding_softap_active,
                              memory_order_acquire)) {
        secure_zero(submission, sizeof(*submission));
        free(submission);
        publish_error(wifi, ESP_ERR_INVALID_STATE);
        return;
    }
    secure_zero(&wifi->candidate_credentials,
                sizeof(wifi->candidate_credentials));
    secure_zero(wifi->candidate_device_claim,
                sizeof(wifi->candidate_device_claim));
    wifi->candidate_credentials = submission->credentials;
    wifi->candidate_valid = true;
    wifi->candidate_claim_pending = submission->claim_pending;
    if (submission->claim_pending) {
        memcpy(wifi->candidate_device_claim, submission->device_claim,
               sizeof(wifi->candidate_device_claim));
    }
    secure_zero(submission, sizeof(*submission));
    free(submission);
    const product_wifi_state_t old_state = wifi->core.state;
    const product_wifi_action_t actions =
        product_wifi_core_candidate_submitted(&wifi->core);
    if ((actions & PRODUCT_WIFI_ACTION_START_CANDIDATE) == 0) {
        reject_candidate(wifi);
        publish_error(wifi, ESP_ERR_INVALID_STATE);
        return;
    }
    apply_actions(wifi, old_state, actions, ESP_OK, 0);
}

static void handle_clear_credentials(product_wifi_handle_t wifi)
{
    if (wifi->core.state != PRODUCT_WIFI_STATE_ONBOARDING) {
        publish_error(wifi, ESP_ERR_INVALID_STATE);
        return;
    }
    if (xSemaphoreTake(wifi->storage_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        publish_error(wifi, ESP_ERR_TIMEOUT);
        return;
    }
    const esp_err_t error = erase_network_state();
    if (error != ESP_OK) {
        xSemaphoreGive(wifi->storage_lock);
        publish_error(wifi, error);
        return;
    }
    secure_zero(&wifi->credentials, sizeof(wifi->credentials));
    secure_zero(&wifi->saved_networks, sizeof(wifi->saved_networks));
    atomic_store_explicit(&wifi->saved_network_count, 0,
                          memory_order_release);
    secure_zero(&wifi->candidate_credentials,
                sizeof(wifi->candidate_credentials));
    secure_zero(wifi->candidate_device_claim,
                sizeof(wifi->candidate_device_claim));
    wifi->candidate_valid = false;
    wifi->candidate_claim_pending = false;
    wifi->selected_network_dirty = false;
    secure_zero(wifi->pending_device_claim,
                sizeof(wifi->pending_device_claim));
    wifi->device_claim_pending = false;
    atomic_store_explicit(&wifi->device_claim_pending_public, false,
                          memory_order_release);
    xSemaphoreGive(wifi->storage_lock);
    const product_wifi_state_t old_state = wifi->core.state;
    const product_wifi_action_t actions =
        product_wifi_core_credentials_cleared(&wifi->core);
    publish_event(wifi, PRODUCT_WIFI_EVENT_CREDENTIALS_CLEARED,
                  ESP_OK, 0, false);
    apply_actions(wifi, old_state, actions, ESP_OK, 0);
}

static void handle_finish_onboarding(product_wifi_handle_t wifi)
{
    const product_wifi_state_t old_state = wifi->core.state;
    const bool keep_station =
        old_state == PRODUCT_WIFI_STATE_ONLINE &&
        wifi->core.network_available && wifi->core.has_credentials;
    const product_wifi_action_t actions =
        product_wifi_core_finish_onboarding(&wifi->core);
    if (atomic_load_explicit(&wifi->onboarding_softap_active,
                             memory_order_acquire)) {
        if (keep_station) {
            (void)esp_wifi_set_mode(WIFI_MODE_STA);
        } else {
            stop_station(wifi);
            (void)esp_wifi_set_mode(WIFI_MODE_STA);
        }
        destroy_softap_netif(wifi);
        publish_event(wifi,
                      PRODUCT_WIFI_EVENT_ONBOARDING_TRANSPORT_CHANGED,
                      ESP_OK, 0, false);
    }
    secure_zero(&wifi->candidate_credentials,
                sizeof(wifi->candidate_credentials));
    secure_zero(wifi->candidate_device_claim,
                sizeof(wifi->candidate_device_claim));
    wifi->candidate_valid = false;
    wifi->candidate_claim_pending = false;
    apply_actions(wifi, old_state, actions, ESP_OK, 0);
}

static void handle_sta_started(product_wifi_handle_t wifi)
{
    wifi->station_recovering = false;
    const product_wifi_state_t old_state = wifi->core.state;
    const product_wifi_action_t actions =
        product_wifi_core_station_started(&wifi->core);
    apply_actions(wifi, old_state, actions, ESP_OK, 0);
}

static void handle_disconnect(product_wifi_handle_t wifi, uint16_t reason)
{
    atomic_store_explicit(&wifi->last_disconnect_reason, reason,
                          memory_order_release);
    if (wifi->ignore_disconnect_once) {
        wifi->ignore_disconnect_once = false;
        return;
    }
    if (wifi->station_recovering) {
        return;
    }
    const bool auth_failure = authentication_failure(reason);
    if (auth_failure) {
        atomic_fetch_add_explicit(&wifi->authentication_failures, 1,
                                  memory_order_relaxed);
    }
    const bool rotated = select_next_saved_network(wifi);
    const product_wifi_state_t old_state = wifi->core.state;
    const product_wifi_action_t actions = product_wifi_core_disconnected(
        &wifi->core, auth_failure && !rotated, monotonic_ms(), esp_random());
    apply_actions(wifi, old_state, actions, ESP_OK, reason);
}

static void handle_got_ip(product_wifi_handle_t wifi)
{
    if (wifi->candidate_valid && wifi->core.candidate_credentials) {
        if (xSemaphoreTake(wifi->storage_lock, pdMS_TO_TICKS(1000)) !=
            pdTRUE) {
            transition_fatal(wifi, ESP_ERR_TIMEOUT);
            return;
        }
        const char *claim = wifi->candidate_claim_pending
                                ? wifi->candidate_device_claim
                                : NULL;
        product_wifi_credential_set_t updated = wifi->saved_networks;
        if (!product_wifi_credential_set_upsert(
                &updated, &wifi->candidate_credentials)) {
            secure_zero(&updated, sizeof(updated));
            xSemaphoreGive(wifi->storage_lock);
            transition_fatal(wifi, ESP_ERR_INVALID_STATE);
            return;
        }
        const esp_err_t persist_error = persist_network_state(
            &wifi->candidate_credentials, claim, &updated);
        if (persist_error != ESP_OK) {
            secure_zero(&updated, sizeof(updated));
            xSemaphoreGive(wifi->storage_lock);
            transition_fatal(wifi, persist_error);
            return;
        }
        secure_zero(&wifi->saved_networks,
                    sizeof(wifi->saved_networks));
        wifi->saved_networks = updated;
        secure_zero(&updated, sizeof(updated));
        atomic_store_explicit(&wifi->saved_network_count,
                              wifi->saved_networks.count,
                              memory_order_release);
        secure_zero(&wifi->credentials, sizeof(wifi->credentials));
        wifi->credentials = wifi->candidate_credentials;
        secure_zero(&wifi->candidate_credentials,
                    sizeof(wifi->candidate_credentials));
        secure_zero(wifi->pending_device_claim,
                    sizeof(wifi->pending_device_claim));
        if (wifi->candidate_claim_pending) {
            memcpy(wifi->pending_device_claim,
                   wifi->candidate_device_claim,
                   sizeof(wifi->pending_device_claim));
        }
        wifi->device_claim_pending = wifi->candidate_claim_pending;
        atomic_store_explicit(&wifi->device_claim_pending_public,
                              wifi->device_claim_pending,
                              memory_order_release);
        secure_zero(wifi->candidate_device_claim,
                    sizeof(wifi->candidate_device_claim));
        wifi->candidate_valid = false;
        wifi->candidate_claim_pending = false;
        wifi->selected_network_dirty = false;
        xSemaphoreGive(wifi->storage_lock);
        atomic_fetch_add_explicit(&wifi->credential_updates, 1,
                                  memory_order_relaxed);
        if (wifi->device_claim_pending) {
            atomic_fetch_add_explicit(&wifi->device_claims_committed, 1,
                                      memory_order_relaxed);
        }
        publish_event(wifi, PRODUCT_WIFI_EVENT_CREDENTIALS_ACCEPTED,
                      ESP_OK, 0, false);
    } else if (wifi->selected_network_dirty) {
        if (xSemaphoreTake(wifi->storage_lock, pdMS_TO_TICKS(1000)) !=
            pdTRUE) {
            transition_fatal(wifi, ESP_ERR_TIMEOUT);
            return;
        }
        product_wifi_credential_set_t updated = wifi->saved_networks;
        if (!product_wifi_credential_set_upsert(&updated,
                                                &wifi->credentials)) {
            secure_zero(&updated, sizeof(updated));
            xSemaphoreGive(wifi->storage_lock);
            transition_fatal(wifi, ESP_ERR_INVALID_STATE);
            return;
        }
        const char *claim = wifi->device_claim_pending
                                ? wifi->pending_device_claim
                                : NULL;
        const esp_err_t persist_error = persist_network_state(
            &wifi->credentials, claim, &updated);
        if (persist_error != ESP_OK) {
            secure_zero(&updated, sizeof(updated));
            xSemaphoreGive(wifi->storage_lock);
            transition_fatal(wifi, persist_error);
            return;
        }
        secure_zero(&wifi->saved_networks,
                    sizeof(wifi->saved_networks));
        wifi->saved_networks = updated;
        secure_zero(&updated, sizeof(updated));
        wifi->selected_network_dirty = false;
        atomic_store_explicit(&wifi->saved_network_count,
                              wifi->saved_networks.count,
                              memory_order_release);
        xSemaphoreGive(wifi->storage_lock);
    }
    const product_wifi_state_t old_state = wifi->core.state;
    const product_wifi_action_t actions =
        product_wifi_core_got_ip(&wifi->core);
    apply_actions(wifi, old_state, actions, ESP_OK, 0);
}

static void handle_lost_ip(product_wifi_handle_t wifi)
{
    if (wifi->core.state != PRODUCT_WIFI_STATE_ONLINE) {
        return;
    }
    const product_wifi_state_t old_state = wifi->core.state;
    const product_wifi_action_t actions = product_wifi_core_disconnected(
        &wifi->core, false, monotonic_ms(), esp_random());
    wifi->ignore_disconnect_once = true;
    apply_actions(wifi, old_state, actions, ESP_OK, 0);
    if (esp_wifi_disconnect() != ESP_OK) {
        wifi->ignore_disconnect_once = false;
    }
}

static void handle_poll(product_wifi_handle_t wifi)
{
    const product_wifi_state_t old_state = wifi->core.state;
    const product_wifi_action_t actions =
        product_wifi_core_poll(&wifi->core, monotonic_ms());
    apply_actions(wifi, old_state, actions, ESP_OK, 0);
}

static void handle_recover_station(product_wifi_handle_t wifi)
{
    const product_wifi_state_t old_state = wifi->core.state;
    const product_wifi_action_t actions =
        product_wifi_core_recover_station(&wifi->core);
    if ((actions & PRODUCT_WIFI_ACTION_RESTART_STATION) == 0) {
        publish_error(wifi, ESP_ERR_INVALID_STATE);
        return;
    }
    atomic_fetch_add_explicit(&wifi->station_recoveries, 1,
                              memory_order_relaxed);
    apply_actions(wifi, old_state, actions, ESP_OK, 0);
}

static void worker_task(void *arg)
{
    product_wifi_handle_t wifi = arg;
    xEventGroupSetBits(wifi->signals, SIGNAL_TASK_READY);

    bool running = true;
    while (running) {
        if (atomic_exchange_explicit(&wifi->overflow_pending, false,
                                     memory_order_acq_rel)) {
            transition_fatal(wifi, ESP_ERR_INVALID_STATE);
        }
        const uint32_t wait_ms = product_wifi_core_wait_ms(
            &wifi->core, monotonic_ms(), WORKER_WAIT_CEILING_MS);
        command_t command = {0};
        if (xQueueReceive(wifi->commands, &command,
                          pdMS_TO_TICKS(wait_ms)) != pdTRUE) {
            handle_poll(wifi);
            continue;
        }
        switch (command.type) {
        case COMMAND_START:
            handle_start(wifi);
            break;
        case COMMAND_BEGIN_ONBOARDING:
            handle_begin_onboarding(wifi);
            break;
        case COMMAND_START_ONBOARDING_SOFTAP:
            handle_start_onboarding_softap(wifi, command.softap);
            command.softap = NULL;
            break;
        case COMMAND_SUBMIT_CREDENTIALS:
            handle_submission(wifi, command.submission);
            command.submission = NULL;
            break;
        case COMMAND_CLEAR_CREDENTIALS:
            handle_clear_credentials(wifi);
            break;
        case COMMAND_FINISH_ONBOARDING:
            handle_finish_onboarding(wifi);
            break;
        case COMMAND_STA_STARTED:
            handle_sta_started(wifi);
            break;
        case COMMAND_DISCONNECTED:
            handle_disconnect(wifi, command.disconnect_reason);
            break;
        case COMMAND_GOT_IP:
            handle_got_ip(wifi);
            break;
        case COMMAND_LOST_IP:
            handle_lost_ip(wifi);
            break;
        case COMMAND_RECOVER_STATION:
            handle_recover_station(wifi);
            break;
        case COMMAND_STOP: {
            const product_wifi_state_t old_state = wifi->core.state;
            const product_wifi_action_t actions =
                product_wifi_core_stop(&wifi->core);
            publish_transition(wifi, old_state, actions, ESP_OK, 0);
            running = false;
            break;
        }
        default:
            transition_fatal(wifi, ESP_ERR_INVALID_ARG);
            break;
        }
    }

    cleanup_driver(wifi);
    secure_zero(&wifi->credentials, sizeof(wifi->credentials));
    secure_zero(&wifi->saved_networks, sizeof(wifi->saved_networks));
    command_t pending = {0};
    while (xQueueReceive(wifi->commands, &pending, 0) == pdTRUE) {
        if (pending.submission) {
            secure_zero(pending.submission, sizeof(*pending.submission));
            free(pending.submission);
        }
        if (pending.softap) {
            secure_zero(pending.softap, sizeof(*pending.softap));
            free(pending.softap);
        }
    }
    wifi->worker = NULL;
    xEventGroupSetBits(wifi->signals, SIGNAL_TASK_STOPPED);
    vTaskDelete(NULL);
}

esp_err_t product_wifi_create(const product_wifi_config_t *config,
                              product_wifi_handle_t *out_wifi)
{
    if (!config || !out_wifi || *out_wifi ||
        !safe_hostname(config->hostname)) {
        return ESP_ERR_INVALID_ARG;
    }
    const uint32_t minimum_backoff_ms = config->minimum_backoff_ms
                                            ? config->minimum_backoff_ms
                                            : DEFAULT_MINIMUM_BACKOFF_MS;
    const uint32_t maximum_backoff_ms = config->maximum_backoff_ms
                                            ? config->maximum_backoff_ms
                                            : DEFAULT_MAXIMUM_BACKOFF_MS;
    const uint32_t authentication_failure_limit =
        config->authentication_failure_limit
            ? config->authentication_failure_limit
            : DEFAULT_AUTHENTICATION_FAILURE_LIMIT;
    const uint32_t task_stack_size = config->task_stack_size
                                         ? config->task_stack_size
                                         : DEFAULT_TASK_STACK_SIZE;
    const uint32_t task_priority = config->task_priority
                                       ? config->task_priority
                                       : DEFAULT_TASK_PRIORITY;
    const product_wifi_core_config_t core_config = {
        .minimum_backoff_ms = minimum_backoff_ms,
        .maximum_backoff_ms = maximum_backoff_ms,
        .authentication_failure_limit = authentication_failure_limit,
    };
    if (task_stack_size < MINIMUM_TASK_STACK_SIZE ||
        task_stack_size > MAXIMUM_TASK_STACK_SIZE || task_priority == 0 ||
        task_priority >= configMAX_PRIORITIES) {
        return ESP_ERR_INVALID_ARG;
    }

    product_wifi_handle_t wifi = calloc(1, sizeof(*wifi));
    if (!wifi) {
        return ESP_ERR_NO_MEM;
    }
    if (!product_wifi_core_init(&wifi->core, &core_config)) {
        free(wifi);
        return ESP_ERR_INVALID_ARG;
    }
    memcpy(wifi->hostname, config->hostname,
           strlen(config->hostname) + 1);
    wifi->event = config->event;
    wifi->event_ctx = config->event_ctx;
    wifi->task_stack_size = task_stack_size;
    wifi->task_priority = task_priority;
    atomic_init(&wifi->started, false);
    atomic_init(&wifi->stopping, false);
    atomic_init(&wifi->network_available, false);
    atomic_init(&wifi->has_credentials, false);
    atomic_init(&wifi->onboarding_active, false);
    atomic_init(&wifi->onboarding_softap_active, false);
    atomic_init(&wifi->saved_network_count, 0);
    atomic_init(&wifi->overflow_pending, false);
    atomic_init(&wifi->state, PRODUCT_WIFI_STATE_STOPPED);
    atomic_init(&wifi->last_error, ESP_OK);
    atomic_init(&wifi->reconnects, 0);
    atomic_init(&wifi->station_recoveries, 0);
    atomic_init(&wifi->authentication_failures, 0);
    atomic_init(&wifi->queue_overflows, 0);
    atomic_init(&wifi->onboarding_entries, 0);
    atomic_init(&wifi->credential_updates, 0);
    atomic_init(&wifi->candidate_rejections, 0);
    atomic_init(&wifi->device_claim_pending_public, false);
    atomic_init(&wifi->device_claims_committed, 0);
    atomic_init(&wifi->device_claims_completed, 0);
    atomic_init(&wifi->device_claims_abandoned, 0);
    atomic_init(&wifi->last_disconnect_reason, 0);

    wifi->commands = xQueueCreate(COMMAND_QUEUE_LENGTH, sizeof(command_t));
    wifi->signals = xEventGroupCreate();
    wifi->storage_lock = xSemaphoreCreateMutex();
    if (!wifi->commands || !wifi->signals || !wifi->storage_lock) {
        if (wifi->commands) {
            vQueueDelete(wifi->commands);
        }
        if (wifi->signals) {
            vEventGroupDelete(wifi->signals);
        }
        if (wifi->storage_lock) {
            vSemaphoreDelete(wifi->storage_lock);
        }
        secure_zero(wifi, sizeof(*wifi));
        free(wifi);
        return ESP_ERR_NO_MEM;
    }
    if (xTaskCreate(worker_task, "product_wifi", task_stack_size, wifi,
                    task_priority, &wifi->worker) != pdPASS) {
        vQueueDelete(wifi->commands);
        vEventGroupDelete(wifi->signals);
        vSemaphoreDelete(wifi->storage_lock);
        secure_zero(wifi, sizeof(*wifi));
        free(wifi);
        return ESP_ERR_NO_MEM;
    }
    const EventBits_t ready = xEventGroupWaitBits(
        wifi->signals, SIGNAL_TASK_READY, pdFALSE, pdTRUE,
        pdMS_TO_TICKS(CREATE_TIMEOUT_MS));
    if ((ready & SIGNAL_TASK_READY) == 0) {
        atomic_store_explicit(&wifi->stopping, true, memory_order_release);
        const command_t stop = {.type = COMMAND_STOP};
        (void)xQueueSend(wifi->commands, &stop, 0);
        const EventBits_t stopped = xEventGroupWaitBits(
            wifi->signals, SIGNAL_TASK_STOPPED, pdFALSE, pdTRUE,
            pdMS_TO_TICKS(CREATE_TIMEOUT_MS));
        if ((stopped & SIGNAL_TASK_STOPPED) == 0 && wifi->worker) {
            vTaskDelete(wifi->worker);
            wifi->worker = NULL;
        }
        vQueueDelete(wifi->commands);
        vEventGroupDelete(wifi->signals);
        vSemaphoreDelete(wifi->storage_lock);
        secure_zero(wifi, sizeof(*wifi));
        free(wifi);
        return ESP_ERR_TIMEOUT;
    }
    *out_wifi = wifi;
    return ESP_OK;
}

esp_err_t product_wifi_start(product_wifi_handle_t wifi)
{
    if (!wifi) {
        return ESP_ERR_INVALID_ARG;
    }
    bool expected = false;
    if (!atomic_compare_exchange_strong_explicit(
            &wifi->started, &expected, true, memory_order_acq_rel,
            memory_order_acquire)) {
        return ESP_ERR_INVALID_STATE;
    }
    const command_t command = {.type = COMMAND_START};
    const esp_err_t error = enqueue(wifi, &command, 0);
    if (error != ESP_OK) {
        atomic_store_explicit(&wifi->started, false, memory_order_release);
    }
    return error;
}

esp_err_t product_wifi_begin_onboarding(product_wifi_handle_t wifi)
{
    if (!wifi) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!atomic_load_explicit(&wifi->started, memory_order_acquire)) {
        return ESP_ERR_INVALID_STATE;
    }
    const product_wifi_state_t state = (product_wifi_state_t)
        atomic_load_explicit(&wifi->state, memory_order_acquire);
    if (state == PRODUCT_WIFI_STATE_STOPPED ||
        state == PRODUCT_WIFI_STATE_FATAL) {
        return ESP_ERR_INVALID_STATE;
    }
    const command_t command = {.type = COMMAND_BEGIN_ONBOARDING};
    return enqueue(wifi, &command, 0);
}

esp_err_t product_wifi_start_onboarding_softap(
    product_wifi_handle_t wifi,
    const product_wifi_softap_config_t *config)
{
    if (!wifi || !safe_softap_config(config)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!atomic_load_explicit(&wifi->started, memory_order_acquire) ||
        !atomic_load_explicit(&wifi->onboarding_active,
                              memory_order_acquire) ||
        atomic_load_explicit(&wifi->onboarding_softap_active,
                             memory_order_acquire)) {
        return ESP_ERR_INVALID_STATE;
    }
    softap_submission_t *submission = calloc(1, sizeof(*submission));
    if (!submission) {
        return ESP_ERR_NO_MEM;
    }
    submission->config = *config;
    const command_t command = {
        .type = COMMAND_START_ONBOARDING_SOFTAP,
        .softap = submission,
    };
    const esp_err_t error = enqueue(wifi, &command, 0);
    if (error != ESP_OK) {
        secure_zero(submission, sizeof(*submission));
        free(submission);
    }
    return error;
}

static bool usable_scan_ssid(const uint8_t *ssid)
{
    if (!ssid) {
        return false;
    }
    const size_t length = strnlen((const char *)ssid,
                                  PRODUCT_WIFI_NETWORK_SSID_MAX + 1);
    if (length == 0 || length > PRODUCT_WIFI_NETWORK_SSID_MAX) {
        return false;
    }
    for (size_t index = 0; index < length; ++index) {
        if (ssid[index] < 0x20 || ssid[index] == 0x7f) {
            return false;
        }
    }
    return true;
}

esp_err_t product_wifi_scan_networks(
    product_wifi_handle_t wifi,
    product_wifi_scan_result_t *results,
    size_t result_capacity,
    size_t *result_count)
{
    if (!wifi || !results || !result_count || result_capacity == 0 ||
        result_capacity > PRODUCT_WIFI_SCAN_RESULT_LIMIT) {
        return ESP_ERR_INVALID_ARG;
    }
    *result_count = 0;
    const product_wifi_state_t state = (product_wifi_state_t)
        atomic_load_explicit(&wifi->state, memory_order_acquire);
    if (state != PRODUCT_WIFI_STATE_ONBOARDING ||
        !atomic_load_explicit(&wifi->onboarding_softap_active,
                              memory_order_acquire) ||
        atomic_load_explicit(&wifi->stopping, memory_order_acquire)) {
        return ESP_ERR_INVALID_STATE;
    }

    const wifi_scan_config_t scan = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = false,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time = {
            .active = {
                .min = 40,
                .max = 120,
            },
        },
    };
    esp_err_t error = esp_wifi_scan_start(&scan, true);
    if (error != ESP_OK) {
        return error;
    }

    wifi_ap_record_t records[PRODUCT_WIFI_SCAN_RESULT_LIMIT] = {0};
    uint16_t record_count = (uint16_t)result_capacity;
    error = esp_wifi_scan_get_ap_records(&record_count, records);
    if (error != ESP_OK) {
        return error;
    }
    for (uint16_t index = 0;
         index < record_count && *result_count < result_capacity; ++index) {
        if (!usable_scan_ssid(records[index].ssid)) {
            continue;
        }
        bool duplicate = false;
        for (size_t existing = 0; existing < *result_count; ++existing) {
            if (strcmp(results[existing].ssid,
                       (const char *)records[index].ssid) == 0) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) {
            continue;
        }
        product_wifi_scan_result_t *result = &results[*result_count];
        snprintf(result->ssid, sizeof(result->ssid), "%s",
                 (const char *)records[index].ssid);
        result->rssi = records[index].rssi;
        result->secured = records[index].authmode != WIFI_AUTH_OPEN;
        ++*result_count;
    }
    return ESP_OK;
}

static esp_err_t submit_credentials(product_wifi_handle_t wifi,
                                    const char *ssid,
                                    const char *password,
                                    const char *device_claim)
{
    if (!wifi || !ssid || !password) {
        return ESP_ERR_INVALID_ARG;
    }
    if ((product_wifi_state_t)atomic_load_explicit(
            &wifi->state, memory_order_acquire) !=
        PRODUCT_WIFI_STATE_ONBOARDING) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!product_wifi_credentials_valid(ssid, password)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (device_claim &&
        !product_wifi_device_claim_is_canonical(device_claim)) {
        return ESP_ERR_INVALID_ARG;
    }
    credential_submission_t *submission = calloc(1, sizeof(*submission));
    if (!submission) {
        return ESP_ERR_NO_MEM;
    }
    memcpy(submission->credentials.ssid, ssid, strlen(ssid) + 1);
    memcpy(submission->credentials.password, password,
           strlen(password) + 1);
    if (device_claim) {
        memcpy(submission->device_claim, device_claim,
               PRODUCT_WIFI_DEVICE_CLAIM_MAX + 1);
        submission->claim_pending = true;
    }
    const command_t command = {
        .type = COMMAND_SUBMIT_CREDENTIALS,
        .submission = submission,
    };
    const esp_err_t error = enqueue(wifi, &command, 0);
    if (error != ESP_OK) {
        secure_zero(submission, sizeof(*submission));
        free(submission);
    }
    return error;
}

esp_err_t product_wifi_submit_credentials(product_wifi_handle_t wifi,
                                          const char *ssid,
                                          const char *password)
{
    return submit_credentials(wifi, ssid, password, NULL);
}

esp_err_t product_wifi_submit_claimed_credentials(
    product_wifi_handle_t wifi,
    const char *ssid,
    const char *password,
    const char *device_claim)
{
    if (!device_claim) {
        return ESP_ERR_INVALID_ARG;
    }
    return submit_credentials(wifi, ssid, password, device_claim);
}

esp_err_t product_wifi_get_pending_device_claim(
    product_wifi_handle_t wifi,
    char output[PRODUCT_WIFI_DEVICE_CLAIM_MAX + 1])
{
    if (!wifi || !output ||
        atomic_load_explicit(&wifi->stopping, memory_order_acquire)) {
        return ESP_ERR_INVALID_ARG;
    }
    secure_zero(output, PRODUCT_WIFI_DEVICE_CLAIM_MAX + 1);
    if (!atomic_load_explicit(&wifi->started, memory_order_acquire)) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!atomic_load_explicit(&wifi->device_claim_pending_public,
                              memory_order_acquire)) {
        return ESP_ERR_NOT_FOUND;
    }
    if (xSemaphoreTake(wifi->storage_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    esp_err_t result = ESP_ERR_NOT_FOUND;
    if (wifi->device_claim_pending) {
        memcpy(output, wifi->pending_device_claim,
               PRODUCT_WIFI_DEVICE_CLAIM_MAX + 1);
        result = ESP_OK;
    }
    xSemaphoreGive(wifi->storage_lock);
    return result;
}

static esp_err_t resolve_device_claim(product_wifi_handle_t wifi,
                                      const char *device_claim,
                                      bool abandoned)
{
    if (!wifi ||
        !product_wifi_device_claim_is_canonical(device_claim) ||
        atomic_load_explicit(&wifi->stopping, memory_order_acquire)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!atomic_load_explicit(&wifi->started, memory_order_acquire)) {
        return ESP_ERR_INVALID_STATE;
    }
    if (xSemaphoreTake(wifi->storage_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    esp_err_t result = ESP_OK;
    if (!wifi->device_claim_pending) {
        result = ESP_ERR_NOT_FOUND;
    } else if (strcmp(wifi->pending_device_claim, device_claim) != 0) {
        result = ESP_ERR_INVALID_STATE;
    } else {
        result = persist_network_state(&wifi->credentials, NULL,
                                       &wifi->saved_networks);
        if (result == ESP_OK) {
            secure_zero(wifi->pending_device_claim,
                        sizeof(wifi->pending_device_claim));
            wifi->device_claim_pending = false;
            atomic_store_explicit(&wifi->device_claim_pending_public, false,
                                  memory_order_release);
            atomic_fetch_add_explicit(
                abandoned ? &wifi->device_claims_abandoned
                          : &wifi->device_claims_completed,
                1, memory_order_relaxed);
        }
    }
    xSemaphoreGive(wifi->storage_lock);
    return result;
}

esp_err_t product_wifi_complete_device_claim(
    product_wifi_handle_t wifi,
    const char *device_claim)
{
    return resolve_device_claim(wifi, device_claim, false);
}

esp_err_t product_wifi_abandon_device_claim(
    product_wifi_handle_t wifi,
    const char *device_claim)
{
    return resolve_device_claim(wifi, device_claim, true);
}

esp_err_t product_wifi_clear_credentials(product_wifi_handle_t wifi)
{
    if (!wifi) {
        return ESP_ERR_INVALID_ARG;
    }
    if ((product_wifi_state_t)atomic_load_explicit(
            &wifi->state, memory_order_acquire) !=
        PRODUCT_WIFI_STATE_ONBOARDING) {
        return ESP_ERR_INVALID_STATE;
    }
    const command_t command = {.type = COMMAND_CLEAR_CREDENTIALS};
    return enqueue(wifi, &command, 0);
}

esp_err_t product_wifi_finish_onboarding(product_wifi_handle_t wifi)
{
    if (!wifi) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!atomic_load_explicit(&wifi->onboarding_active,
                              memory_order_acquire)) {
        return ESP_ERR_INVALID_STATE;
    }
    const command_t command = {.type = COMMAND_FINISH_ONBOARDING};
    return enqueue(wifi, &command, 0);
}

esp_err_t product_wifi_get_stats(product_wifi_handle_t wifi,
                                 product_wifi_stats_t *stats)
{
    if (!wifi || !stats ||
        atomic_load_explicit(&wifi->stopping, memory_order_acquire)) {
        return ESP_ERR_INVALID_ARG;
    }
    *stats = (product_wifi_stats_t){
        .state = (product_wifi_state_t)atomic_load_explicit(
            &wifi->state, memory_order_acquire),
        .started = atomic_load_explicit(&wifi->started,
                                        memory_order_acquire),
        .network_available = atomic_load_explicit(
            &wifi->network_available, memory_order_acquire),
        .has_credentials = atomic_load_explicit(
            &wifi->has_credentials, memory_order_acquire),
        .onboarding_active = atomic_load_explicit(
            &wifi->onboarding_active, memory_order_acquire),
        .onboarding_softap_active = atomic_load_explicit(
            &wifi->onboarding_softap_active, memory_order_acquire),
        .saved_networks = (uint8_t)atomic_load_explicit(
            &wifi->saved_network_count, memory_order_acquire),
        .reconnects = atomic_load_explicit(&wifi->reconnects,
                                           memory_order_relaxed),
        .station_recoveries = atomic_load_explicit(
            &wifi->station_recoveries, memory_order_relaxed),
        .authentication_failures = atomic_load_explicit(
            &wifi->authentication_failures, memory_order_relaxed),
        .queue_overflows = atomic_load_explicit(
            &wifi->queue_overflows, memory_order_relaxed),
        .onboarding_entries = atomic_load_explicit(
            &wifi->onboarding_entries, memory_order_relaxed),
        .credential_updates = atomic_load_explicit(
            &wifi->credential_updates, memory_order_relaxed),
        .candidate_rejections = atomic_load_explicit(
            &wifi->candidate_rejections, memory_order_relaxed),
        .device_claim_pending = atomic_load_explicit(
            &wifi->device_claim_pending_public, memory_order_acquire),
        .device_claims_committed = atomic_load_explicit(
            &wifi->device_claims_committed, memory_order_relaxed),
        .device_claims_completed = atomic_load_explicit(
            &wifi->device_claims_completed, memory_order_relaxed),
        .device_claims_abandoned = atomic_load_explicit(
            &wifi->device_claims_abandoned, memory_order_relaxed),
        .last_disconnect_reason = (uint16_t)atomic_load_explicit(
            &wifi->last_disconnect_reason, memory_order_relaxed),
        .last_error = (esp_err_t)atomic_load_explicit(
            &wifi->last_error, memory_order_acquire),
    };
    return ESP_OK;
}

esp_err_t product_wifi_recover_station(product_wifi_handle_t wifi)
{
    if (!wifi || !atomic_load_explicit(&wifi->started,
                                       memory_order_acquire)) {
        return ESP_ERR_INVALID_ARG;
    }
    const product_wifi_state_t state = (product_wifi_state_t)
        atomic_load_explicit(&wifi->state, memory_order_acquire);
    if (atomic_load_explicit(&wifi->onboarding_active,
                             memory_order_acquire) ||
        !atomic_load_explicit(&wifi->has_credentials,
                              memory_order_acquire) ||
        (state != PRODUCT_WIFI_STATE_CONNECTING &&
         state != PRODUCT_WIFI_STATE_BACKOFF)) {
        return ESP_ERR_INVALID_STATE;
    }
    const command_t command = {.type = COMMAND_RECOVER_STATION};
    return enqueue(wifi, &command, 0);
}

esp_err_t product_wifi_stop(product_wifi_handle_t wifi, uint32_t timeout_ms)
{
    if (!wifi || timeout_ms == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    const bool already_stopping = atomic_exchange_explicit(
        &wifi->stopping, true, memory_order_acq_rel);
    if (!already_stopping) {
        const command_t command = {.type = COMMAND_STOP};
        if (xQueueSend(wifi->commands, &command,
                       pdMS_TO_TICKS(timeout_ms < 100 ? timeout_ms : 100)) !=
            pdTRUE) {
            atomic_store_explicit(&wifi->stopping, false,
                                  memory_order_release);
            return ESP_ERR_TIMEOUT;
        }
    }
    const EventBits_t stopped = xEventGroupWaitBits(
        wifi->signals, SIGNAL_TASK_STOPPED, pdFALSE, pdTRUE,
        pdMS_TO_TICKS(timeout_ms));
    if ((stopped & SIGNAL_TASK_STOPPED) == 0) {
        /* Retain stopping=true: callers may only retry stop. */
        return ESP_ERR_TIMEOUT;
    }
    vQueueDelete(wifi->commands);
    vEventGroupDelete(wifi->signals);
    vSemaphoreDelete(wifi->storage_lock);
    secure_zero(wifi, sizeof(*wifi));
    free(wifi);
    return ESP_OK;
}
