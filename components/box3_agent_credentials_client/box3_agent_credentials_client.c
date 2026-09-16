#include "box3_agent_credentials_client.h"

#include <inttypes.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#include "box3_agent_credentials_protocol.h"
#include "esp_crt_bundle.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"
#include "esp_random.h"

enum {
    IDENTIFIER_MAX = 64,
    SERVER_CERT_PEM_MAX = 16384,
    DEFAULT_NETWORK_TIMEOUT_MS = 10000,
};

static const int64_t MINIMUM_UNIX_TIME = INT64_C(1609459200); /* 2021-01-01 */
static const int64_t MAXIMUM_UNIX_TIME = INT64_C(4102444800); /* 2100-01-01 */

typedef struct {
    char endpoint[BOX3_AGENT_CREDENTIALS_URI_MAX];
    char device_id[IDENTIFIER_MAX + 1];
    char client_id[IDENTIFIER_MAX + 1];
} owned_strings_t;

struct box3_agent_credentials_client {
    owned_strings_t *strings;
    char *server_cert_pem;
    char *response;
    size_t response_size;
    bool response_overflow;

    box3_agent_sign_proof_fn sign_proof;
    void *sign_ctx;
    box3_agent_get_unix_time_fn get_unix_time;
    void *time_ctx;
    box3_agent_refresh_agent_token_fn refresh_agent_token;
    void *agent_ctx;

    esp_http_client_handle_t http;
    atomic_bool refreshing;
};

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

static void secure_zero(void *memory, size_t size)
{
    volatile unsigned char *bytes = memory;
    while (bytes && size > 0) {
        *bytes++ = 0;
        --size;
    }
}

static bool copy_string(char *output,
                        size_t output_size,
                        const char *input)
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

static esp_err_t http_event(esp_http_client_event_t *event)
{
    box3_agent_credentials_client_handle_t client =
        event ? event->user_data : NULL;
    if (!client || event->event_id != HTTP_EVENT_ON_DATA ||
        event->data_len <= 0) {
        return ESP_OK;
    }
    const size_t data_size = (size_t)event->data_len;
    if (client->response_size + data_size >
        BOX3_AGENT_CREDENTIALS_RESPONSE_MAX) {
        client->response_overflow = true;
        return ESP_OK;
    }
    memcpy(client->response + client->response_size,
           event->data, data_size);
    client->response_size += data_size;
    return ESP_OK;
}

static void clear_proof_headers(
    box3_agent_credentials_client_handle_t client)
{
    (void)esp_http_client_delete_header(client->http,
                                        "X-Device-Timestamp");
    (void)esp_http_client_delete_header(client->http,
                                        "X-Device-Nonce");
    (void)esp_http_client_delete_header(client->http,
                                        "X-Device-Signature");
}

static esp_err_t set_proof_headers(
    box3_agent_credentials_client_handle_t client,
    const char *timestamp,
    const char *nonce,
    const char *signature)
{
    if (esp_http_client_set_header(client->http, "Device-Id",
                                   client->strings->device_id) != ESP_OK ||
        esp_http_client_set_header(client->http, "Client-Id",
                                   client->strings->client_id) != ESP_OK ||
        esp_http_client_set_header(client->http, "X-Device-Timestamp",
                                   timestamp) != ESP_OK ||
        esp_http_client_set_header(client->http, "X-Device-Nonce",
                                   nonce) != ESP_OK ||
        esp_http_client_set_header(client->http, "X-Device-Signature",
                                   signature) != ESP_OK ||
        esp_http_client_set_header(client->http, "Accept",
                                   "application/json") != ESP_OK ||
        esp_http_client_set_header(client->http, "Content-Length", "0") !=
            ESP_OK ||
        esp_http_client_set_header(client->http, "Cache-Control",
                                   "no-store") != ESP_OK) {
        clear_proof_headers(client);
        return ESP_FAIL;
    }
    return ESP_OK;
}

static esp_err_t fetch_voice_credentials(
    box3_agent_credentials_client_handle_t client,
    box3_agent_voice_credentials_t *voice)
{
    int64_t unix_seconds = 0;
    uint8_t nonce_raw[BOX3_AGENT_CREDENTIALS_NONCE_BYTES];
    uint8_t signature_raw[BOX3_AGENT_CREDENTIALS_SIGNATURE_BYTES];
    char timestamp[24];
    char nonce[32];
    char signature[48];
    char canonical[BOX3_AGENT_CREDENTIALS_CANONICAL_MAX];
    esp_err_t result = client->get_unix_time(client->time_ctx,
                                              &unix_seconds);
    if (result != ESP_OK || unix_seconds < MINIMUM_UNIX_TIME ||
        unix_seconds > MAXIMUM_UNIX_TIME) {
        result = ESP_ERR_INVALID_STATE;
        goto cleanup;
    }
    const int timestamp_size = snprintf(
        timestamp, sizeof(timestamp), "%" PRId64, unix_seconds);
    if (timestamp_size <= 0 ||
        (size_t)timestamp_size >= sizeof(timestamp)) {
        result = ESP_ERR_INVALID_SIZE;
        goto cleanup;
    }

    esp_fill_random(nonce_raw, sizeof(nonce_raw));
    if (!box3_agent_credentials_base64url(
            nonce_raw, sizeof(nonce_raw), nonce, sizeof(nonce)) ||
        !box3_agent_credentials_build_canonical(
            client->strings->device_id, client->strings->client_id,
            timestamp, nonce, canonical, sizeof(canonical))) {
        result = ESP_ERR_INVALID_SIZE;
        goto cleanup;
    }
    result = client->sign_proof(
        client->sign_ctx, (const uint8_t *)canonical,
        strlen(canonical), signature_raw);
    if (result != ESP_OK ||
        !box3_agent_credentials_base64url(
            signature_raw, sizeof(signature_raw),
            signature, sizeof(signature))) {
        if (result == ESP_OK) {
            result = ESP_ERR_INVALID_SIZE;
        }
        goto cleanup;
    }
    result = set_proof_headers(client, timestamp, nonce, signature);
    if (result != ESP_OK) {
        goto cleanup;
    }

    secure_zero(client->response,
                BOX3_AGENT_CREDENTIALS_RESPONSE_MAX + 1);
    client->response_size = 0;
    client->response_overflow = false;
    result = esp_http_client_perform(client->http);
    const int status_code =
        esp_http_client_get_status_code(client->http);
    clear_proof_headers(client);
    if (result == ESP_OK && status_code == 402) {
        result = ESP_ERR_NOT_ALLOWED;
        goto cleanup;
    }
    if (result != ESP_OK || client->response_overflow ||
        status_code != 200 ||
        client->response_size == 0 ||
        !box3_agent_credentials_parse_voice_response(
            client->response, client->response_size,
            client->strings->device_id, voice)) {
        if (result == ESP_OK) {
            result = ESP_ERR_INVALID_RESPONSE;
        }
        goto cleanup;
    }
    result = ESP_OK;

cleanup:
    secure_zero(nonce_raw, sizeof(nonce_raw));
    secure_zero(signature_raw, sizeof(signature_raw));
    secure_zero(timestamp, sizeof(timestamp));
    secure_zero(nonce, sizeof(nonce));
    secure_zero(signature, sizeof(signature));
    secure_zero(canonical, sizeof(canonical));
    secure_zero(client->response,
                BOX3_AGENT_CREDENTIALS_RESPONSE_MAX + 1);
    client->response_size = 0;
    client->response_overflow = false;
    return result;
}

static void release_storage(
    box3_agent_credentials_client_handle_t client)
{
    if (!client) {
        return;
    }
    if (client->http) {
        clear_proof_headers(client);
        (void)esp_http_client_cleanup(client->http);
        client->http = NULL;
    }
    if (client->response) {
        secure_zero(client->response,
                    BOX3_AGENT_CREDENTIALS_RESPONSE_MAX + 1);
        heap_caps_free(client->response);
        client->response = NULL;
    }
    heap_caps_free(client->server_cert_pem);
    client->server_cert_pem = NULL;
    if (client->strings) {
        secure_zero(client->strings, sizeof(*client->strings));
        heap_caps_free(client->strings);
        client->strings = NULL;
    }
    secure_zero(client, sizeof(*client));
    heap_caps_free(client);
}

esp_err_t box3_agent_credentials_client_create(
    const box3_agent_credentials_client_config_t *config,
    box3_agent_credentials_client_handle_t *out_client)
{
    if (!out_client) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_client = NULL;
    if (!config || !config->sign_proof || !config->get_unix_time ||
        !config->refresh_agent_token ||
        !box3_agent_credentials_validate_endpoint(
            config->session_endpoint) ||
        !box3_agent_credentials_safe_identifier(config->device_id) ||
        !box3_agent_credentials_safe_identifier(config->client_id) ||
        ((!config->server_cert_pem || !config->server_cert_pem[0]) ==
         !config->use_crt_bundle) ||
        (config->network_timeout_ms != 0 &&
         (config->network_timeout_ms < 1000 ||
          config->network_timeout_ms > 30000))) {
        return ESP_ERR_INVALID_ARG;
    }

    box3_agent_credentials_client_handle_t client = heap_caps_calloc(
        1, sizeof(*client), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!client) {
        return ESP_ERR_NO_MEM;
    }
    client->strings = allocate_prefer_psram(sizeof(*client->strings));
    client->response = allocate_prefer_psram(
        BOX3_AGENT_CREDENTIALS_RESPONSE_MAX + 1);
    if (!client->strings || !client->response) {
        release_storage(client);
        return ESP_ERR_NO_MEM;
    }
    if (!copy_string(client->strings->endpoint,
                     sizeof(client->strings->endpoint),
                     config->session_endpoint) ||
        !copy_string(client->strings->device_id,
                     sizeof(client->strings->device_id),
                     config->device_id) ||
        !copy_string(client->strings->client_id,
                     sizeof(client->strings->client_id),
                     config->client_id)) {
        release_storage(client);
        return ESP_ERR_INVALID_SIZE;
    }
    if (config->server_cert_pem && config->server_cert_pem[0]) {
        const size_t cert_size = strnlen(
            config->server_cert_pem, SERVER_CERT_PEM_MAX + 1);
        if (cert_size > SERVER_CERT_PEM_MAX) {
            release_storage(client);
            return ESP_ERR_INVALID_SIZE;
        }
        client->server_cert_pem = allocate_prefer_psram(cert_size + 1);
        if (!client->server_cert_pem) {
            release_storage(client);
            return ESP_ERR_NO_MEM;
        }
        memcpy(client->server_cert_pem,
               config->server_cert_pem, cert_size + 1);
    }

    client->sign_proof = config->sign_proof;
    client->sign_ctx = config->sign_ctx;
    client->get_unix_time = config->get_unix_time;
    client->time_ctx = config->time_ctx;
    client->refresh_agent_token = config->refresh_agent_token;
    client->agent_ctx = config->agent_ctx;
    atomic_init(&client->refreshing, false);

    const esp_http_client_config_t http_config = {
        .url = client->strings->endpoint,
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
        .buffer_size = 1024,
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

esp_err_t box3_agent_credentials_client_refresh(
    void *ctx,
    box3_agent_credentials_t *credentials)
{
    box3_agent_credentials_client_handle_t client = ctx;
    bool expected = false;
    if (!client || !credentials) {
        return ESP_ERR_INVALID_ARG;
    }
    secure_zero(credentials, sizeof(*credentials));
    if (!atomic_compare_exchange_strong_explicit(
            &client->refreshing, &expected, true,
            memory_order_acq_rel, memory_order_acquire)) {
        return ESP_ERR_INVALID_STATE;
    }

    box3_agent_voice_credentials_t voice = {0};
    esp_err_t result = fetch_voice_credentials(client, &voice);
    if (result == ESP_OK) {
        if (!copy_string(credentials->voice_uri,
                         sizeof(credentials->voice_uri), voice.uri) ||
            !copy_string(credentials->voice_bearer_token,
                         sizeof(credentials->voice_bearer_token),
                         voice.bearer_token)) {
            result = ESP_ERR_INVALID_SIZE;
        } else {
            credentials->voice_ttl_seconds = voice.ttl_seconds;
            memcpy(credentials->binding_id, voice.binding_id,
                   sizeof(credentials->binding_id));
            credentials->binding_revision = voice.binding_revision;
        }
    }
    if (result == ESP_OK) {
        result = client->refresh_agent_token(
            client->agent_ctx, credentials->agent_bearer_token,
            sizeof(credentials->agent_bearer_token),
            &credentials->agent_ttl_seconds,
            credentials->binding_id, sizeof(credentials->binding_id),
            &credentials->binding_revision);
        if (result == ESP_OK &&
            (!box3_agent_credentials_validate_agent_token(
                 credentials->agent_bearer_token,
                 sizeof(credentials->agent_bearer_token),
                 credentials->agent_ttl_seconds) ||
             !box3_agent_credentials_tokens_are_separate(
                 credentials->voice_bearer_token,
                 sizeof(credentials->voice_bearer_token),
                 credentials->agent_bearer_token,
                 sizeof(credentials->agent_bearer_token)) ||
             strcmp(credentials->binding_id, voice.binding_id) != 0 ||
             credentials->binding_revision != voice.binding_revision)) {
            result = ESP_ERR_INVALID_RESPONSE;
        }
    }
    secure_zero(&voice, sizeof(voice));
    if (result != ESP_OK) {
        secure_zero(credentials, sizeof(*credentials));
    }
    atomic_store_explicit(&client->refreshing, false,
                          memory_order_release);
    return result;
}

esp_err_t box3_agent_credentials_client_destroy(
    box3_agent_credentials_client_handle_t client)
{
    if (!client) {
        return ESP_OK;
    }
    if (atomic_load_explicit(&client->refreshing,
                             memory_order_acquire)) {
        return ESP_ERR_INVALID_STATE;
    }
    release_storage(client);
    return ESP_OK;
}
