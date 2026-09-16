#include "product_ota_client.h"

#include <inttypes.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "esp_crt_bundle.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"
#include "esp_random.h"
#include "product_ota_client_protocol.h"
#include "sdkconfig.h"

enum {
    IDENTIFIER_MAX = 64,
    SERVER_CERT_PEM_MAX = 16384,
    DEFAULT_NETWORK_TIMEOUT_MS = 10000,
};

static const int64_t MINIMUM_UNIX_TIME = INT64_C(1609459200);
static const int64_t MAXIMUM_UNIX_TIME = INT64_C(4102444800);

typedef struct {
    char offer_endpoint[PRODUCT_OTA_CLIENT_ENDPOINT_MAX];
    char device_id[IDENTIFIER_MAX + 1];
    char client_id[IDENTIFIER_MAX + 1];
} owned_strings_t;

struct product_ota_client {
    owned_strings_t *strings;
    char *server_cert_pem;
    char *response;
    size_t response_size;
    bool response_overflow;
    bool response_is_json;
    product_ota_client_sign_proof_fn sign_ota_proof;
    void *sign_ctx;
    product_ota_client_get_time_fn get_authenticated_time;
    void *time_ctx;
    esp_http_client_handle_t http;
    atomic_bool busy;
};

static void secure_zero(void *memory, size_t size)
{
    volatile unsigned char *bytes = memory;
    while (bytes && size > 0) {
        *bytes++ = 0;
        --size;
    }
}

static void *allocate_prefer_psram(size_t size)
{
    void *memory = heap_caps_calloc(1, size,
                                    MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!memory) {
        memory = heap_caps_calloc(1, size,
                                  MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    }
    return memory;
}

static bool copy_string(char *output, size_t output_size, const char *input)
{
    if (!output || output_size == 0 || !input || !input[0]) {
        return false;
    }
    const size_t size = strnlen(input, output_size);
    if (size == output_size) {
        return false;
    }
    memcpy(output, input, size + 1);
    return true;
}

static const char *compiled_board(void)
{
#if CONFIG_PRODUCT_BOARD_ESP_BOX_3
    return "esp32s3-box3";
#else
    return "esp32s3-n32r16";
#endif
}

static bool json_content_type(const char *value)
{
    static const char expected[] = "application/json";
    if (!value || strncasecmp(value, expected, sizeof(expected) - 1) != 0) {
        return false;
    }
    const char suffix = value[sizeof(expected) - 1];
    return suffix == '\0' || suffix == ';';
}

static esp_err_t http_event(esp_http_client_event_t *event)
{
    product_ota_client_handle_t client = event ? event->user_data : NULL;
    if (!client) {
        return ESP_OK;
    }
    if (event->event_id == HTTP_EVENT_ON_HEADER && event->header_key &&
        event->header_value &&
        strcasecmp(event->header_key, "Content-Type") == 0) {
        client->response_is_json = json_content_type(event->header_value);
        return ESP_OK;
    }
    if (event->event_id != HTTP_EVENT_ON_DATA || event->data_len <= 0 ||
        !event->data) {
        return ESP_OK;
    }
    const size_t size = (size_t)event->data_len;
    if (client->response_size > PRODUCT_OTA_CLIENT_RESPONSE_MAX ||
        size > PRODUCT_OTA_CLIENT_RESPONSE_MAX - client->response_size) {
        client->response_overflow = true;
        return ESP_OK;
    }
    memcpy(client->response + client->response_size, event->data, size);
    client->response_size += size;
    return ESP_OK;
}

static void reset_response(product_ota_client_handle_t client)
{
    secure_zero(client->response, PRODUCT_OTA_CLIENT_RESPONSE_MAX + 1);
    client->response_size = 0;
    client->response_overflow = false;
    client->response_is_json = false;
}

static void clear_headers(esp_http_client_handle_t http)
{
    if (!http) {
        return;
    }
    static const char *const names[] = {
        "X-Device-Timestamp", "X-Device-Nonce", "X-Device-Signature",
        "X-OTA-Board", "X-OTA-Channel", "X-OTA-Release-Sequence",
        "X-OTA-Version",
    };
    for (size_t index = 0; index < sizeof(names) / sizeof(names[0]); ++index) {
        (void)esp_http_client_delete_header(http, names[index]);
    }
}

static esp_err_t set_header(esp_http_client_handle_t http,
                            const char *name,
                            const char *value)
{
    return esp_http_client_set_header(http, name, value) == ESP_OK
               ? ESP_OK
               : ESP_FAIL;
}

static void release_storage(product_ota_client_handle_t client)
{
    if (!client) {
        return;
    }
    if (client->http) {
        clear_headers(client->http);
        (void)esp_http_client_cleanup(client->http);
        client->http = NULL;
    }
    if (client->response) {
        secure_zero(client->response, PRODUCT_OTA_CLIENT_RESPONSE_MAX + 1);
        heap_caps_free(client->response);
    }
    if (client->server_cert_pem) {
        secure_zero(client->server_cert_pem, strlen(client->server_cert_pem));
        heap_caps_free(client->server_cert_pem);
    }
    if (client->strings) {
        secure_zero(client->strings, sizeof(*client->strings));
        heap_caps_free(client->strings);
    }
    secure_zero(client, sizeof(*client));
    heap_caps_free(client);
}

esp_err_t product_ota_client_create(
    const product_ota_client_config_t *config,
    product_ota_client_handle_t *out_client)
{
    if (!out_client) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_client = NULL;
    if (!config || !config->sign_ota_proof ||
        !config->get_authenticated_time ||
        !product_ota_client_endpoint_valid(config->offer_endpoint) ||
        !product_ota_client_safe_identifier(config->device_id, 64) ||
        !product_ota_client_safe_identifier(config->client_id, 64) ||
        ((!config->server_cert_pem || !config->server_cert_pem[0]) ==
         !config->use_crt_bundle) ||
        (config->network_timeout_ms != 0 &&
         (config->network_timeout_ms < 1000 ||
          config->network_timeout_ms > 30000))) {
        return ESP_ERR_INVALID_ARG;
    }
    product_ota_client_handle_t client = heap_caps_calloc(
        1, sizeof(*client), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!client) {
        return ESP_ERR_NO_MEM;
    }
    client->strings = allocate_prefer_psram(sizeof(*client->strings));
    client->response = allocate_prefer_psram(
        PRODUCT_OTA_CLIENT_RESPONSE_MAX + 1);
    if (!client->strings || !client->response) {
        release_storage(client);
        return ESP_ERR_NO_MEM;
    }
    if (!copy_string(client->strings->offer_endpoint,
                     sizeof(client->strings->offer_endpoint),
                     config->offer_endpoint) ||
        !copy_string(client->strings->device_id,
                     sizeof(client->strings->device_id), config->device_id) ||
        !copy_string(client->strings->client_id,
                     sizeof(client->strings->client_id), config->client_id)) {
        release_storage(client);
        return ESP_ERR_INVALID_SIZE;
    }
    if (config->server_cert_pem && config->server_cert_pem[0]) {
        const size_t size = strnlen(config->server_cert_pem,
                                    SERVER_CERT_PEM_MAX + 1);
        if (size > SERVER_CERT_PEM_MAX) {
            release_storage(client);
            return ESP_ERR_INVALID_SIZE;
        }
        client->server_cert_pem = allocate_prefer_psram(size + 1);
        if (!client->server_cert_pem) {
            release_storage(client);
            return ESP_ERR_NO_MEM;
        }
        memcpy(client->server_cert_pem, config->server_cert_pem, size + 1);
    }
    client->sign_ota_proof = config->sign_ota_proof;
    client->sign_ctx = config->sign_ctx;
    client->get_authenticated_time = config->get_authenticated_time;
    client->time_ctx = config->time_ctx;
    atomic_init(&client->busy, false);
    const esp_http_client_config_t http_config = {
        .url = client->strings->offer_endpoint,
        .cert_pem = client->server_cert_pem,
        .method = HTTP_METHOD_POST,
        .timeout_ms = (int)(config->network_timeout_ms
                                ? config->network_timeout_ms
                                : DEFAULT_NETWORK_TIMEOUT_MS),
        .disable_auto_redirect = true,
        .max_authorization_retries = -1,
        .event_handler = http_event,
        .user_data = client,
        .crt_bundle_attach = config->use_crt_bundle
                                 ? esp_crt_bundle_attach
                                 : NULL,
        .tls_version = ESP_HTTP_CLIENT_TLS_VER_TLS_1_2,
        .buffer_size = 2048,
        .buffer_size_tx = 1024,
    };
    client->http = esp_http_client_init(&http_config);
    if (!client->http) {
        release_storage(client);
        return ESP_ERR_NO_MEM;
    }
    *out_client = client;
    return ESP_OK;
}

void product_ota_client_clear_offer(product_ota_offer_t *offer)
{
    if (!offer) {
        return;
    }
    char *manifest = offer->manifest;
    const size_t manifest_capacity = offer->manifest_capacity;
    char *token = offer->download_token;
    const size_t token_capacity = offer->download_token_capacity;
    secure_zero(manifest,
                manifest_capacity < PRODUCT_OTA_CLIENT_MANIFEST_MAX + 1
                    ? manifest_capacity
                    : PRODUCT_OTA_CLIENT_MANIFEST_MAX + 1);
    secure_zero(token,
                token_capacity < PRODUCT_OTA_CLIENT_TOKEN_MAX + 1
                    ? token_capacity
                    : PRODUCT_OTA_CLIENT_TOKEN_MAX + 1);
    secure_zero(offer, sizeof(*offer));
    offer->manifest = manifest;
    offer->manifest_capacity = manifest_capacity;
    offer->download_token = token;
    offer->download_token_capacity = token_capacity;
}

esp_err_t product_ota_client_fetch_offer(
    product_ota_client_handle_t client,
    const product_ota_config_t *ota_config,
    product_ota_offer_t *offer)
{
    if (!client || !ota_config || !offer || !offer->manifest ||
        offer->manifest_capacity < PRODUCT_OTA_CLIENT_MANIFEST_MAX + 1 ||
        !offer->download_token ||
        offer->download_token_capacity < PRODUCT_OTA_CLIENT_TOKEN_MAX + 1) {
        return ESP_ERR_INVALID_ARG;
    }
    bool expected = false;
    if (!atomic_compare_exchange_strong_explicit(
            &client->busy, &expected, true,
            memory_order_acq_rel, memory_order_acquire)) {
        return ESP_ERR_INVALID_STATE;
    }
    product_ota_client_clear_offer(offer);

    uint8_t nonce_raw[PRODUCT_OTA_CLIENT_NONCE_BYTES] = {0};
    uint8_t signature_raw[PRODUCT_OTA_CLIENT_SIGNATURE_BYTES] = {0};
    char timestamp[24] = {0};
    char nonce[32] = {0};
    char signature[48] = {0};
    char sequence[16] = {0};
    char canonical[PRODUCT_OTA_CLIENT_CANONICAL_MAX] = {0};
    int64_t unix_seconds = 0;
    esp_err_t result = client->get_authenticated_time(
        client->time_ctx, &unix_seconds);
    if (result != ESP_OK || unix_seconds < MINIMUM_UNIX_TIME ||
        unix_seconds > MAXIMUM_UNIX_TIME) {
        result = ESP_ERR_INVALID_STATE;
        goto cleanup;
    }
    const int timestamp_size = snprintf(timestamp, sizeof(timestamp),
                                        "%" PRId64, unix_seconds);
    const int sequence_size = snprintf(sequence, sizeof(sequence), "%d",
                                       CONFIG_PRODUCT_OTA_RELEASE_SEQUENCE);
    esp_fill_random(nonce_raw, sizeof(nonce_raw));
    if (timestamp_size <= 0 || (size_t)timestamp_size >= sizeof(timestamp) ||
        sequence_size <= 0 || (size_t)sequence_size >= sizeof(sequence) ||
        !product_ota_client_base64url_encode(
            nonce_raw, sizeof(nonce_raw), nonce, sizeof(nonce)) ||
        !product_ota_client_build_canonical(
            client->strings->device_id, client->strings->client_id,
            timestamp, nonce, compiled_board(), CONFIG_PRODUCT_OTA_CHANNEL,
            CONFIG_PRODUCT_OTA_RELEASE_SEQUENCE, CONFIG_APP_PROJECT_VER,
            canonical, sizeof(canonical))) {
        result = ESP_ERR_INVALID_SIZE;
        goto cleanup;
    }
    result = client->sign_ota_proof(
        client->sign_ctx, (const uint8_t *)canonical,
        strlen(canonical), signature_raw);
    if (result != ESP_OK ||
        !product_ota_client_base64url_encode(
            signature_raw, sizeof(signature_raw), signature,
            sizeof(signature))) {
        if (result == ESP_OK) {
            result = ESP_ERR_INVALID_SIZE;
        }
        goto cleanup;
    }
    clear_headers(client->http);
    if (set_header(client->http, "Device-Id", client->strings->device_id) !=
            ESP_OK ||
        set_header(client->http, "Client-Id", client->strings->client_id) !=
            ESP_OK ||
        set_header(client->http, "X-Device-Timestamp", timestamp) != ESP_OK ||
        set_header(client->http, "X-Device-Nonce", nonce) != ESP_OK ||
        set_header(client->http, "X-Device-Signature", signature) != ESP_OK ||
        set_header(client->http, "X-OTA-Board", compiled_board()) != ESP_OK ||
        set_header(client->http, "X-OTA-Channel", CONFIG_PRODUCT_OTA_CHANNEL) !=
            ESP_OK ||
        set_header(client->http, "X-OTA-Release-Sequence", sequence) != ESP_OK ||
        set_header(client->http, "X-OTA-Version", CONFIG_APP_PROJECT_VER) !=
            ESP_OK ||
        set_header(client->http, "Accept", "application/json") != ESP_OK ||
        set_header(client->http, "Content-Length", "0") != ESP_OK ||
        set_header(client->http, "Cache-Control", "no-store") != ESP_OK) {
        result = ESP_FAIL;
        goto cleanup;
    }
    reset_response(client);
    result = esp_http_client_perform(client->http);
    if (result != ESP_OK || client->response_overflow ||
        !client->response_is_json ||
        esp_http_client_get_status_code(client->http) != 200 ||
        client->response_size == 0) {
        if (result == ESP_OK) {
            result = ESP_ERR_INVALID_RESPONSE;
        }
        goto cleanup;
    }
    product_ota_client_offer_status_t parsed_status = 0;
    if (!product_ota_client_parse_offer(
            client->response, client->response_size,
            client->strings->device_id, &parsed_status,
            offer->manifest, offer->manifest_capacity,
            &offer->manifest_size, offer->download_token,
            offer->download_token_capacity, &offer->token_ttl_seconds,
            &offer->retry_after_seconds)) {
        result = ESP_ERR_INVALID_RESPONSE;
        goto cleanup;
    }
    switch (parsed_status) {
    case PRODUCT_OTA_CLIENT_OFFER_AVAILABLE:
        offer->status = PRODUCT_OTA_FLEET_AVAILABLE;
        break;
    case PRODUCT_OTA_CLIENT_OFFER_UP_TO_DATE:
        offer->status = PRODUCT_OTA_FLEET_UP_TO_DATE;
        break;
    case PRODUCT_OTA_CLIENT_OFFER_DEFERRED:
        offer->status = PRODUCT_OTA_FLEET_DEFERRED;
        break;
    default:
        result = ESP_ERR_INVALID_RESPONSE;
        goto cleanup;
    }
    if (offer->status == PRODUCT_OTA_FLEET_AVAILABLE) {
        result = product_ota_check_manifest(
            ota_config, offer->manifest, offer->manifest_size,
            &offer->release);
        if (result != ESP_OK) {
            goto cleanup;
        }
    }

cleanup:
    clear_headers(client->http);
    if (result != ESP_OK) {
        product_ota_client_clear_offer(offer);
    }
    secure_zero(nonce_raw, sizeof(nonce_raw));
    secure_zero(signature_raw, sizeof(signature_raw));
    secure_zero(timestamp, sizeof(timestamp));
    secure_zero(nonce, sizeof(nonce));
    secure_zero(signature, sizeof(signature));
    secure_zero(sequence, sizeof(sequence));
    secure_zero(canonical, sizeof(canonical));
    reset_response(client);
    atomic_store_explicit(&client->busy, false, memory_order_release);
    return result;
}

esp_err_t product_ota_client_destroy(product_ota_client_handle_t client)
{
    if (!client) {
        return ESP_OK;
    }
    if (atomic_load_explicit(&client->busy, memory_order_acquire)) {
        return ESP_ERR_INVALID_STATE;
    }
    release_storage(client);
    return ESP_OK;
}
