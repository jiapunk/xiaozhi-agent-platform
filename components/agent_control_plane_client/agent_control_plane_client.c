#include "agent_control_plane_client.h"

#include <inttypes.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "agent_control_plane_protocol.h"
#include "esp_crt_bundle.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"
#include "esp_random.h"
#include "mbedtls/md.h"

enum {
    IDENTIFIER_MAX = 64,
    SERVER_CERT_PEM_MAX = 16384,
    DEFAULT_NETWORK_TIMEOUT_MS = 10000,
};

static const int64_t MINIMUM_UNIX_TIME = INT64_C(1609459200);
static const int64_t MAXIMUM_UNIX_TIME = INT64_C(4102444800);

typedef struct {
    char time_endpoint[AGENT_CONTROL_PLANE_URI_MAX];
    char agent_token_endpoint[AGENT_CONTROL_PLANE_URI_MAX];
    char device_claim_endpoint[AGENT_CONTROL_PLANE_URI_MAX];
    char action_challenge_endpoint[AGENT_CONTROL_PLANE_URI_MAX];
    char action_result_endpoint[AGENT_CONTROL_PLANE_URI_MAX];
    char device_id[IDENTIFIER_MAX + 1];
    char client_id[IDENTIFIER_MAX + 1];
} owned_strings_t;

struct agent_control_plane_client {
    owned_strings_t *strings;
    char *server_cert_pem;
    char *response;
    size_t response_size;
    bool response_overflow;
    bool response_is_json;

    agent_control_plane_sign_proof_fn sign_agent_proof;
    agent_control_plane_sign_proof_fn sign_device_claim_proof;
    agent_control_plane_sign_proof_fn sign_action_challenge_proof;
    agent_control_plane_sign_proof_fn sign_action_result_proof;
    void *sign_ctx;
    agent_control_plane_get_unix_time_fn get_unix_time;
    void *time_ctx;
    agent_control_plane_accept_time_fn accept_authenticated_time;
    void *accept_time_ctx;

    esp_http_client_handle_t time_http;
    esp_http_client_handle_t agent_http;
    esp_http_client_handle_t claim_http;
    esp_http_client_handle_t action_challenge_http;
    esp_http_client_handle_t action_result_http;
    uint32_t network_timeout_ms;
    atomic_bool busy;
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

static bool copy_string(char *output, size_t output_size,
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

static bool json_content_type(const char *value)
{
    static const char expected[] = "application/json";
    if (!value || strncasecmp(value, expected,
                              sizeof(expected) - 1) != 0) {
        return false;
    }
    const char suffix = value[sizeof(expected) - 1];
    return suffix == '\0' || suffix == ';';
}

static esp_err_t http_event(esp_http_client_event_t *event)
{
    agent_control_plane_client_handle_t client =
        event ? event->user_data : NULL;
    if (!client) {
        return ESP_OK;
    }
    if (event->event_id == HTTP_EVENT_ON_HEADER && event->header_key &&
        event->header_value &&
        strcasecmp(event->header_key, "Content-Type") == 0) {
        client->response_is_json = json_content_type(event->header_value);
        return ESP_OK;
    }
    if (event->event_id != HTTP_EVENT_ON_DATA || event->data_len <= 0) {
        return ESP_OK;
    }
    const size_t data_size = (size_t)event->data_len;
    if (client->response_size + data_size >
        AGENT_CONTROL_PLANE_RESPONSE_MAX) {
        client->response_overflow = true;
        return ESP_OK;
    }
    memcpy(client->response + client->response_size,
           event->data, data_size);
    client->response_size += data_size;
    return ESP_OK;
}

static void reset_response(agent_control_plane_client_handle_t client)
{
    secure_zero(client->response,
                AGENT_CONTROL_PLANE_RESPONSE_MAX + 1);
    client->response_size = 0;
    client->response_overflow = false;
    client->response_is_json = false;
}

static void clear_dynamic_headers(esp_http_client_handle_t http)
{
    if (!http) {
        return;
    }
    (void)esp_http_client_delete_header(http, "X-Device-Timestamp");
    (void)esp_http_client_delete_header(http, "X-Device-Nonce");
    (void)esp_http_client_delete_header(http, "X-Device-Signature");
    (void)esp_http_client_delete_header(http, "X-Device-Claim");
    (void)esp_http_client_delete_header(
        http, "X-Action-Consent-Body-SHA256");
}

static void clear_action_headers(esp_http_client_handle_t http)
{
    if (!http) {
        return;
    }
    clear_dynamic_headers(http);
    (void)esp_http_client_delete_header(http, "Content-Type");
    (void)esp_http_client_delete_header(http, "Content-Length");
    (void)esp_http_client_delete_header(http,
                                        "X-Xiaozhi-Action-Consent");
    (void)esp_http_client_set_post_field(http, NULL, 0);
}

static esp_err_t set_common_headers(
    agent_control_plane_client_handle_t client,
    esp_http_client_handle_t http,
    const char *nonce)
{
    if (esp_http_client_set_header(http, "Device-Id",
                                   client->strings->device_id) != ESP_OK ||
        esp_http_client_set_header(http, "Client-Id",
                                   client->strings->client_id) != ESP_OK ||
        esp_http_client_set_header(http, "X-Device-Nonce", nonce) != ESP_OK ||
        esp_http_client_set_header(http, "Accept", "application/json") !=
            ESP_OK ||
        esp_http_client_set_header(http, "Content-Length", "0") != ESP_OK ||
        esp_http_client_set_header(http, "Cache-Control", "no-store") !=
            ESP_OK) {
        clear_dynamic_headers(http);
        return ESP_FAIL;
    }
    return ESP_OK;
}

static esp_err_t perform_json(
    agent_control_plane_client_handle_t client,
    esp_http_client_handle_t http)
{
    reset_response(client);
    esp_err_t result = esp_http_client_perform(http);
    if (result != ESP_OK || client->response_overflow ||
        !client->response_is_json ||
        esp_http_client_get_status_code(http) != 200 ||
        client->response_size == 0) {
        return result == ESP_OK ? ESP_ERR_INVALID_RESPONSE : result;
    }
    return ESP_OK;
}

static esp_err_t make_nonce(uint8_t raw[AGENT_CONTROL_PLANE_NONCE_BYTES],
                            char encoded[32])
{
    esp_fill_random(raw, AGENT_CONTROL_PLANE_NONCE_BYTES);
    return agent_control_plane_base64url(
               raw, AGENT_CONTROL_PLANE_NONCE_BYTES, encoded, 32)
               ? ESP_OK
               : ESP_ERR_INVALID_SIZE;
}

esp_err_t agent_control_plane_client_sync_time(
    agent_control_plane_client_handle_t client)
{
    uint8_t nonce_raw[AGENT_CONTROL_PLANE_NONCE_BYTES] = {0};
    char nonce[32] = {0};
    int64_t unix_seconds = 0;
    bool expected = false;
    if (!client) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!atomic_compare_exchange_strong_explicit(
            &client->busy, &expected, true,
            memory_order_acq_rel, memory_order_acquire)) {
        return ESP_ERR_INVALID_STATE;
    }
    esp_err_t result = make_nonce(nonce_raw, nonce);
    if (result == ESP_OK) {
        result = set_common_headers(client, client->time_http, nonce);
    }
    if (result == ESP_OK) {
        result = perform_json(client, client->time_http);
    }
    clear_dynamic_headers(client->time_http);
    if (result == ESP_OK &&
        !agent_control_plane_parse_time_response(
            client->response, client->response_size,
            client->strings->device_id, client->strings->client_id,
            nonce, &unix_seconds)) {
        result = ESP_ERR_INVALID_RESPONSE;
    }
    if (result == ESP_OK) {
        result = client->accept_authenticated_time(
            client->accept_time_ctx, unix_seconds);
    }
    secure_zero(nonce_raw, sizeof(nonce_raw));
    secure_zero(nonce, sizeof(nonce));
    reset_response(client);
    atomic_store_explicit(&client->busy, false, memory_order_release);
    return result;
}

esp_err_t agent_control_plane_client_get_or_sync_unix_time(
    void *ctx,
    int64_t *unix_seconds)
{
    agent_control_plane_client_handle_t client = ctx;
    if (!client || !unix_seconds) {
        return ESP_ERR_INVALID_ARG;
    }
    *unix_seconds = 0;
    esp_err_t result = client->get_unix_time(
        client->time_ctx, unix_seconds);
    if (result == ESP_OK) {
        return ESP_OK;
    }
    result = agent_control_plane_client_sync_time(client);
    if (result != ESP_OK) {
        *unix_seconds = 0;
        return result;
    }
    result = client->get_unix_time(client->time_ctx, unix_seconds);
    if (result != ESP_OK) {
        *unix_seconds = 0;
    }
    return result;
}

esp_err_t agent_control_plane_client_refresh_agent_token(
    void *ctx,
    char *token,
    size_t token_size,
    uint32_t *ttl_seconds,
    char *binding_id,
    size_t binding_id_size,
    uint64_t *binding_revision)
{
    agent_control_plane_client_handle_t client = ctx;
    uint8_t nonce_raw[AGENT_CONTROL_PLANE_NONCE_BYTES] = {0};
    uint8_t signature_raw[AGENT_CONTROL_PLANE_SIGNATURE_BYTES] = {0};
    char timestamp[24] = {0};
    char nonce[32] = {0};
    char signature[48] = {0};
    char canonical[AGENT_CONTROL_PLANE_CANONICAL_MAX] = {0};
    int64_t unix_seconds = 0;
    bool expected = false;
    if (!client || !token || token_size == 0 || !ttl_seconds ||
        !binding_id || binding_id_size < 23 || !binding_revision) {
        return ESP_ERR_INVALID_ARG;
    }
    secure_zero(token, token_size);
    *ttl_seconds = 0;
    secure_zero(binding_id, binding_id_size);
    *binding_revision = 0;
    if (!atomic_compare_exchange_strong_explicit(
            &client->busy, &expected, true,
            memory_order_acq_rel, memory_order_acquire)) {
        return ESP_ERR_INVALID_STATE;
    }

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
    result = make_nonce(nonce_raw, nonce);
    if (result != ESP_OK ||
        !agent_control_plane_build_agent_canonical(
            client->strings->device_id, client->strings->client_id,
            timestamp, nonce, canonical, sizeof(canonical))) {
        result = ESP_ERR_INVALID_SIZE;
        goto cleanup;
    }
    result = client->sign_agent_proof(
        client->sign_ctx, (const uint8_t *)canonical,
        strlen(canonical), signature_raw);
    if (result != ESP_OK ||
        !agent_control_plane_base64url(
            signature_raw, sizeof(signature_raw), signature,
            sizeof(signature))) {
        if (result == ESP_OK) {
            result = ESP_ERR_INVALID_SIZE;
        }
        goto cleanup;
    }
    result = set_common_headers(client, client->agent_http, nonce);
    if (result != ESP_OK ||
        esp_http_client_set_header(client->agent_http,
                                   "X-Device-Timestamp",
                                   timestamp) != ESP_OK ||
        esp_http_client_set_header(client->agent_http,
                                   "X-Device-Signature",
                                   signature) != ESP_OK) {
        result = ESP_FAIL;
        goto cleanup;
    }
    result = perform_json(client, client->agent_http);
    if (result == ESP_ERR_INVALID_RESPONSE &&
        esp_http_client_get_status_code(client->agent_http) == 402) {
        result = ESP_ERR_NOT_ALLOWED;
    }
    clear_dynamic_headers(client->agent_http);
    if (result == ESP_OK &&
        !agent_control_plane_parse_agent_token_response(
            client->response, client->response_size,
            client->strings->device_id, token, token_size,
            ttl_seconds, binding_id, binding_id_size,
            binding_revision)) {
        result = ESP_ERR_INVALID_RESPONSE;
    }

cleanup:
    clear_dynamic_headers(client->agent_http);
    if (result != ESP_OK) {
        secure_zero(token, token_size);
        *ttl_seconds = 0;
        secure_zero(binding_id, binding_id_size);
        *binding_revision = 0;
    }
    secure_zero(nonce_raw, sizeof(nonce_raw));
    secure_zero(signature_raw, sizeof(signature_raw));
    secure_zero(timestamp, sizeof(timestamp));
    secure_zero(nonce, sizeof(nonce));
    secure_zero(signature, sizeof(signature));
    secure_zero(canonical, sizeof(canonical));
    reset_response(client);
    atomic_store_explicit(&client->busy, false, memory_order_release);
    return result;
}

esp_err_t agent_control_plane_client_confirm_device_claim_ex(
    void *ctx,
    const char *claim,
    agent_control_plane_device_claim_outcome_t *outcome)
{
    agent_control_plane_client_handle_t client = ctx;
    uint8_t nonce_raw[AGENT_CONTROL_PLANE_NONCE_BYTES] = {0};
    uint8_t signature_raw[AGENT_CONTROL_PLANE_SIGNATURE_BYTES] = {0};
    char timestamp[24] = {0};
    char nonce[32] = {0};
    char signature[48] = {0};
    char canonical[AGENT_CONTROL_PLANE_CANONICAL_MAX] = {0};
    int64_t unix_seconds = 0;
    bool expected = false;
    if (!outcome) {
        return ESP_ERR_INVALID_ARG;
    }
    *outcome = AGENT_CONTROL_PLANE_DEVICE_CLAIM_RETRY;
    if (!client ||
        !agent_control_plane_device_claim_is_canonical(claim)) {
        *outcome = AGENT_CONTROL_PLANE_DEVICE_CLAIM_REJECTED;
        return ESP_ERR_INVALID_ARG;
    }

    /* A refresh may use this client's busy gate, so do it before claiming it. */
    esp_err_t result = agent_control_plane_client_get_or_sync_unix_time(
        client, &unix_seconds);
    if (result != ESP_OK || unix_seconds < MINIMUM_UNIX_TIME ||
        unix_seconds > MAXIMUM_UNIX_TIME) {
        return result == ESP_OK ? ESP_ERR_INVALID_STATE : result;
    }
    if (!atomic_compare_exchange_strong_explicit(
            &client->busy, &expected, true,
            memory_order_acq_rel, memory_order_acquire)) {
        return ESP_ERR_INVALID_STATE;
    }

    const int timestamp_size = snprintf(
        timestamp, sizeof(timestamp), "%" PRId64, unix_seconds);
    if (timestamp_size <= 0 ||
        (size_t)timestamp_size >= sizeof(timestamp)) {
        result = ESP_ERR_INVALID_SIZE;
        goto cleanup;
    }
    result = make_nonce(nonce_raw, nonce);
    if (result != ESP_OK ||
        !agent_control_plane_build_device_claim_canonical(
            client->strings->device_id, client->strings->client_id,
            timestamp, nonce, claim, canonical, sizeof(canonical))) {
        result = ESP_ERR_INVALID_SIZE;
        goto cleanup;
    }
    result = client->sign_device_claim_proof(
        client->sign_ctx, (const uint8_t *)canonical,
        strlen(canonical), signature_raw);
    if (result != ESP_OK ||
        !agent_control_plane_base64url(
            signature_raw, sizeof(signature_raw), signature,
            sizeof(signature))) {
        if (result == ESP_OK) {
            result = ESP_ERR_INVALID_SIZE;
        }
        goto cleanup;
    }
    result = set_common_headers(client, client->claim_http, nonce);
    if (result != ESP_OK ||
        esp_http_client_set_header(client->claim_http,
                                   "X-Device-Timestamp",
                                   timestamp) != ESP_OK ||
        esp_http_client_set_header(client->claim_http,
                                   "X-Device-Signature",
                                   signature) != ESP_OK ||
        esp_http_client_set_header(client->claim_http,
                                   "X-Device-Claim", claim) != ESP_OK) {
        result = ESP_FAIL;
        goto cleanup;
    }
    result = perform_json(client, client->claim_http);
    const int status_code =
        esp_http_client_get_status_code(client->claim_http);
    clear_dynamic_headers(client->claim_http);
    if (result == ESP_OK &&
        !agent_control_plane_parse_device_claim_response(
            client->response, client->response_size,
            client->strings->device_id)) {
        result = ESP_ERR_INVALID_RESPONSE;
    }
    if (result == ESP_OK) {
        *outcome = AGENT_CONTROL_PLANE_DEVICE_CLAIM_BOUND;
    } else if (result == ESP_ERR_INVALID_RESPONSE &&
               agent_control_plane_device_claim_http_is_terminal(
                   status_code)) {
        *outcome = AGENT_CONTROL_PLANE_DEVICE_CLAIM_REJECTED;
    }

cleanup:
    clear_dynamic_headers(client->claim_http);
    secure_zero(nonce_raw, sizeof(nonce_raw));
    secure_zero(signature_raw, sizeof(signature_raw));
    secure_zero(timestamp, sizeof(timestamp));
    secure_zero(nonce, sizeof(nonce));
    secure_zero(signature, sizeof(signature));
    secure_zero(canonical, sizeof(canonical));
    reset_response(client);
    atomic_store_explicit(&client->busy, false, memory_order_release);
    return result;
}

esp_err_t agent_control_plane_client_confirm_device_claim(
    void *ctx,
    const char *claim)
{
    agent_control_plane_device_claim_outcome_t outcome =
        AGENT_CONTROL_PLANE_DEVICE_CLAIM_RETRY;
    return agent_control_plane_client_confirm_device_claim_ex(
        ctx, claim, &outcome);
}

static bool action_body_sha256(const char *body,
                               size_t body_size,
                               char output[65])
{
    static const char hex[] = "0123456789abcdef";
    uint8_t digest[32] = {0};
    const mbedtls_md_info_t *info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!body || body_size == 0 ||
        body_size > AGENT_CONTROL_PLANE_ACTION_BODY_MAX || !output ||
        !info || mbedtls_md(info, (const unsigned char *)body,
                            body_size, digest) != 0) {
        secure_zero(digest, sizeof(digest));
        return false;
    }
    for (size_t index = 0; index < sizeof(digest); ++index) {
        output[index * 2] = hex[digest[index] >> 4];
        output[index * 2 + 1] = hex[digest[index] & 0x0f];
    }
    output[64] = '\0';
    secure_zero(digest, sizeof(digest));
    return true;
}

static esp_err_t perform_action_consent_request(
    agent_control_plane_client_handle_t client,
    esp_http_client_handle_t http,
    agent_control_plane_action_proof_scope_t scope,
    agent_control_plane_sign_proof_fn signer,
    int64_t unix_seconds,
    const char *body,
    size_t body_size,
    uint32_t request_timeout_ms,
    int *status_code)
{
    uint8_t nonce_raw[AGENT_CONTROL_PLANE_NONCE_BYTES] = {0};
    uint8_t signature_raw[AGENT_CONTROL_PLANE_SIGNATURE_BYTES] = {0};
    char timestamp[24] = {0};
    char nonce[32] = {0};
    char signature[48] = {0};
    char body_sha256[65] = {0};
    char content_length[16] = {0};
    char canonical[AGENT_CONTROL_PLANE_CANONICAL_MAX] = {0};
    if (status_code) {
        *status_code = 0;
    }
    if (!client || !http || !signer || !body || body_size == 0 ||
        body_size > AGENT_CONTROL_PLANE_ACTION_BODY_MAX || !status_code ||
        unix_seconds < MINIMUM_UNIX_TIME || unix_seconds > MAXIMUM_UNIX_TIME ||
        (request_timeout_ms != 0 &&
         (request_timeout_ms < 100 || request_timeout_ms > 30000))) {
        return ESP_ERR_INVALID_ARG;
    }
    const int timestamp_size = snprintf(
        timestamp, sizeof(timestamp), "%" PRId64, unix_seconds);
    const int length_size = snprintf(
        content_length, sizeof(content_length), "%zu", body_size);
    esp_err_t result = ESP_OK;
    if (timestamp_size <= 0 ||
        (size_t)timestamp_size >= sizeof(timestamp) || length_size <= 0 ||
        (size_t)length_size >= sizeof(content_length) ||
        !action_body_sha256(body, body_size, body_sha256)) {
        result = ESP_ERR_INVALID_SIZE;
        goto cleanup;
    }
    result = make_nonce(nonce_raw, nonce);
    if (result != ESP_OK ||
        !agent_control_plane_build_action_canonical(
            scope, client->strings->device_id,
            client->strings->client_id, timestamp, nonce, body_sha256,
            canonical, sizeof(canonical))) {
        result = ESP_ERR_INVALID_SIZE;
        goto cleanup;
    }
    result = signer(client->sign_ctx, (const uint8_t *)canonical,
                    strlen(canonical), signature_raw);
    if (result != ESP_OK ||
        !agent_control_plane_base64url(
            signature_raw, sizeof(signature_raw), signature,
            sizeof(signature))) {
        if (result == ESP_OK) {
            result = ESP_ERR_INVALID_SIZE;
        }
        goto cleanup;
    }
    const uint32_t effective_timeout = request_timeout_ms
                                           ? request_timeout_ms
                                           : client->network_timeout_ms;
    if (esp_http_client_set_timeout_ms(http, (int)effective_timeout) != ESP_OK ||
        esp_http_client_set_header(http, "Device-Id",
                                   client->strings->device_id) != ESP_OK ||
        esp_http_client_set_header(http, "Client-Id",
                                   client->strings->client_id) != ESP_OK ||
        esp_http_client_set_header(http, "X-Device-Timestamp",
                                   timestamp) != ESP_OK ||
        esp_http_client_set_header(http, "X-Device-Nonce", nonce) != ESP_OK ||
        esp_http_client_set_header(http, "X-Device-Signature",
                                   signature) != ESP_OK ||
        esp_http_client_set_header(http, "X-Action-Consent-Body-SHA256",
                                   body_sha256) != ESP_OK ||
        esp_http_client_set_header(http, "X-Xiaozhi-Action-Consent",
                                   "xz-action-consent-v1") != ESP_OK ||
        esp_http_client_set_header(http, "Content-Type",
                                   "application/json") != ESP_OK ||
        esp_http_client_set_header(http, "Accept",
                                   "application/json") != ESP_OK ||
        esp_http_client_set_header(http, "Cache-Control", "no-store") !=
            ESP_OK ||
        esp_http_client_set_header(http, "Content-Length",
                                   content_length) != ESP_OK ||
        esp_http_client_set_post_field(http, body, (int)body_size) != ESP_OK) {
        result = ESP_FAIL;
        goto cleanup;
    }
    reset_response(client);
    result = esp_http_client_perform(http);
    *status_code = esp_http_client_get_status_code(http);
    if (result == ESP_OK &&
        (client->response_overflow || !client->response_is_json ||
         client->response_size == 0)) {
        result = ESP_ERR_INVALID_RESPONSE;
    }

cleanup:
    clear_action_headers(http);
    if (client && http && client->network_timeout_ms != 0) {
        (void)esp_http_client_set_timeout_ms(
            http, (int)client->network_timeout_ms);
    }
    secure_zero(nonce_raw, sizeof(nonce_raw));
    secure_zero(signature_raw, sizeof(signature_raw));
    secure_zero(timestamp, sizeof(timestamp));
    secure_zero(nonce, sizeof(nonce));
    secure_zero(signature, sizeof(signature));
    secure_zero(body_sha256, sizeof(body_sha256));
    secure_zero(content_length, sizeof(content_length));
    secure_zero(canonical, sizeof(canonical));
    return result;
}

static esp_err_t register_action_consent_at(
    agent_control_plane_client_handle_t client,
    const char *session_id,
    uint32_t request_id,
    bool indicator_on,
    int64_t unix_seconds,
    int64_t expires_at_unix,
    uint32_t request_timeout_ms,
    agent_control_plane_action_consent_t *consent)
{
    uint8_t challenge_raw[AGENT_CONTROL_PLANE_NONCE_BYTES] = {0};
    char challenge_id[32] = {0};
    char body[AGENT_CONTROL_PLANE_ACTION_BODY_MAX + 1] = {0};
    uint64_t owner_revision = 0;
    int status_code = 0;
    bool expected = false;
    if (consent) {
        secure_zero(consent, sizeof(*consent));
    }
    if (!client || !consent ||
        !agent_control_plane_safe_identifier(session_id) || request_id == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t result = ESP_OK;
    if (unix_seconds < MINIMUM_UNIX_TIME || unix_seconds > MAXIMUM_UNIX_TIME ||
        expires_at_unix <= unix_seconds ||
        expires_at_unix - unix_seconds > 30) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!atomic_compare_exchange_strong_explicit(
            &client->busy, &expected, true,
            memory_order_acq_rel, memory_order_acquire)) {
        return ESP_ERR_INVALID_STATE;
    }
    result = make_nonce(challenge_raw, challenge_id);
    if (result != ESP_OK ||
        !agent_control_plane_build_action_challenge_body(
            challenge_id, session_id, request_id, indicator_on,
            expires_at_unix, body, sizeof(body))) {
        result = ESP_ERR_INVALID_SIZE;
        goto cleanup;
    }
    result = perform_action_consent_request(
        client, client->action_challenge_http,
        AGENT_CONTROL_PLANE_ACTION_PROOF_CHALLENGE,
        client->sign_action_challenge_proof, unix_seconds,
        body, strlen(body), request_timeout_ms, &status_code);
    if (result != ESP_OK || status_code != 201 ||
        client->response_size >
            AGENT_CONTROL_PLANE_ACTION_APP_JSON_BYTES - 1 ||
        !agent_control_plane_parse_action_challenge_response(
            client->response, client->response_size, challenge_id,
            client->strings->device_id, session_id, request_id,
            indicator_on, expires_at_unix, &owner_revision)) {
        if (result == ESP_OK) {
            result = ESP_ERR_INVALID_RESPONSE;
        }
        goto cleanup;
    }
    if (!copy_string(consent->challenge_id,
                     sizeof(consent->challenge_id), challenge_id) ||
        !copy_string(consent->session_id, sizeof(consent->session_id),
                     session_id)) {
        result = ESP_ERR_INVALID_SIZE;
        goto cleanup;
    }
    memcpy(consent->app_challenge_json, client->response,
           client->response_size);
    consent->app_challenge_json[client->response_size] = '\0';
    consent->app_challenge_json_size = client->response_size;
    consent->request_id = request_id;
    consent->indicator_on = indicator_on;
    consent->expires_at_unix = expires_at_unix;
    consent->owner_revision = owner_revision;

cleanup:
    if (result != ESP_OK) {
        secure_zero(consent, sizeof(*consent));
    }
    secure_zero(challenge_raw, sizeof(challenge_raw));
    secure_zero(challenge_id, sizeof(challenge_id));
    secure_zero(body, sizeof(body));
    reset_response(client);
    atomic_store_explicit(&client->busy, false, memory_order_release);
    return result;
}

esp_err_t agent_control_plane_client_register_action_consent(
    agent_control_plane_client_handle_t client,
    const char *session_id,
    uint32_t request_id,
    bool indicator_on,
    int64_t expires_at_unix,
    agent_control_plane_action_consent_t *consent)
{
    if (consent) {
        secure_zero(consent, sizeof(*consent));
    }
    int64_t unix_seconds = 0;
    if (!client || !consent) {
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t result = agent_control_plane_client_get_or_sync_unix_time(
        client, &unix_seconds);
    if (result != ESP_OK) {
        return result;
    }
    return register_action_consent_at(
        client, session_id, request_id, indicator_on, unix_seconds,
        expires_at_unix, 0, consent);
}

esp_err_t agent_control_plane_client_register_action_consent_bounded(
    agent_control_plane_client_handle_t client,
    const char *session_id,
    uint32_t request_id,
    bool indicator_on,
    uint32_t lifetime_seconds,
    uint32_t request_timeout_ms,
    agent_control_plane_action_consent_t *consent)
{
    if (consent) {
        secure_zero(consent, sizeof(*consent));
    }
    if (!client || !consent || lifetime_seconds == 0 ||
        lifetime_seconds > 30 || request_timeout_ms < 100 ||
        request_timeout_ms > 30000) {
        return ESP_ERR_INVALID_ARG;
    }
    int64_t unix_seconds = 0;
    esp_err_t result = client->get_unix_time(
        client->time_ctx, &unix_seconds);
    if (result != ESP_OK || unix_seconds < MINIMUM_UNIX_TIME ||
        unix_seconds > MAXIMUM_UNIX_TIME - (int64_t)lifetime_seconds) {
        return result == ESP_OK ? ESP_ERR_INVALID_STATE : result;
    }
    return register_action_consent_at(
        client, session_id, request_id, indicator_on, unix_seconds,
        unix_seconds + (int64_t)lifetime_seconds, request_timeout_ms,
        consent);
}

static esp_err_t poll_action_consent_at(
    agent_control_plane_client_handle_t client,
    const agent_control_plane_action_consent_t *consent,
    int64_t unix_seconds,
    uint32_t request_timeout_ms,
    agent_control_plane_action_decision_t *decision)
{
    char body[AGENT_CONTROL_PLANE_ACTION_BODY_MAX + 1] = {0};
    int status_code = 0;
    bool expected = false;
    if (decision) {
        *decision = AGENT_CONTROL_PLANE_ACTION_PENDING;
    }
    if (!client || !consent || !decision ||
        !agent_control_plane_build_action_result_body(
            consent->challenge_id, consent->owner_revision,
            consent->session_id, consent->request_id,
            consent->indicator_on, body, sizeof(body))) {
        secure_zero(body, sizeof(body));
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t result = ESP_OK;
    if (unix_seconds < MINIMUM_UNIX_TIME || unix_seconds > MAXIMUM_UNIX_TIME ||
        unix_seconds >= consent->expires_at_unix) {
        secure_zero(body, sizeof(body));
        return ESP_ERR_INVALID_STATE;
    }
    if (!atomic_compare_exchange_strong_explicit(
            &client->busy, &expected, true,
            memory_order_acq_rel, memory_order_acquire)) {
        secure_zero(body, sizeof(body));
        return ESP_ERR_INVALID_STATE;
    }
    result = perform_action_consent_request(
        client, client->action_result_http,
        AGENT_CONTROL_PLANE_ACTION_PROOF_RESULT,
        client->sign_action_result_proof, unix_seconds,
        body, strlen(body), request_timeout_ms, &status_code);
    agent_control_plane_action_protocol_decision_t parsed =
        AGENT_CONTROL_PLANE_ACTION_PROTOCOL_PENDING;
    if (result != ESP_OK ||
        !agent_control_plane_parse_action_result_response(
            client->response, client->response_size, status_code,
            consent->challenge_id, &parsed)) {
        if (result == ESP_OK) {
            result = ESP_ERR_INVALID_RESPONSE;
        }
        goto cleanup;
    }
    if (parsed == AGENT_CONTROL_PLANE_ACTION_PROTOCOL_APPROVE) {
        *decision = AGENT_CONTROL_PLANE_ACTION_APPROVED;
    } else if (parsed == AGENT_CONTROL_PLANE_ACTION_PROTOCOL_DENY) {
        *decision = AGENT_CONTROL_PLANE_ACTION_DENIED;
    }

cleanup:
    secure_zero(body, sizeof(body));
    reset_response(client);
    atomic_store_explicit(&client->busy, false, memory_order_release);
    return result;
}

esp_err_t agent_control_plane_client_poll_action_consent(
    agent_control_plane_client_handle_t client,
    const agent_control_plane_action_consent_t *consent,
    agent_control_plane_action_decision_t *decision)
{
    if (decision) {
        *decision = AGENT_CONTROL_PLANE_ACTION_PENDING;
    }
    int64_t unix_seconds = 0;
    if (!client || !decision) {
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t result = agent_control_plane_client_get_or_sync_unix_time(
        client, &unix_seconds);
    if (result != ESP_OK) {
        return result;
    }
    return poll_action_consent_at(
        client, consent, unix_seconds, 0, decision);
}

esp_err_t agent_control_plane_client_poll_action_consent_bounded(
    agent_control_plane_client_handle_t client,
    const agent_control_plane_action_consent_t *consent,
    uint32_t request_timeout_ms,
    agent_control_plane_action_decision_t *decision)
{
    if (decision) {
        *decision = AGENT_CONTROL_PLANE_ACTION_PENDING;
    }
    if (!client || !decision || request_timeout_ms < 100 ||
        request_timeout_ms > 30000) {
        return ESP_ERR_INVALID_ARG;
    }
    int64_t unix_seconds = 0;
    esp_err_t result = client->get_unix_time(
        client->time_ctx, &unix_seconds);
    if (result != ESP_OK) {
        return result;
    }
    return poll_action_consent_at(
        client, consent, unix_seconds, request_timeout_ms, decision);
}

static void release_storage(agent_control_plane_client_handle_t client)
{
    if (!client) {
        return;
    }
    if (client->time_http) {
        clear_dynamic_headers(client->time_http);
        (void)esp_http_client_cleanup(client->time_http);
        client->time_http = NULL;
    }
    if (client->agent_http) {
        clear_dynamic_headers(client->agent_http);
        (void)esp_http_client_cleanup(client->agent_http);
        client->agent_http = NULL;
    }
    if (client->claim_http) {
        clear_dynamic_headers(client->claim_http);
        (void)esp_http_client_cleanup(client->claim_http);
        client->claim_http = NULL;
    }
    if (client->action_challenge_http) {
        clear_action_headers(client->action_challenge_http);
        (void)esp_http_client_cleanup(client->action_challenge_http);
        client->action_challenge_http = NULL;
    }
    if (client->action_result_http) {
        clear_action_headers(client->action_result_http);
        (void)esp_http_client_cleanup(client->action_result_http);
        client->action_result_http = NULL;
    }
    if (client->response) {
        secure_zero(client->response,
                    AGENT_CONTROL_PLANE_RESPONSE_MAX + 1);
        heap_caps_free(client->response);
        client->response = NULL;
    }
    if (client->server_cert_pem) {
        secure_zero(client->server_cert_pem,
                    strlen(client->server_cert_pem));
        heap_caps_free(client->server_cert_pem);
        client->server_cert_pem = NULL;
    }
    if (client->strings) {
        secure_zero(client->strings, sizeof(*client->strings));
        heap_caps_free(client->strings);
        client->strings = NULL;
    }
    secure_zero(client, sizeof(*client));
    heap_caps_free(client);
}

esp_err_t agent_control_plane_client_create(
    const agent_control_plane_client_config_t *config,
    agent_control_plane_client_handle_t *out_client)
{
    if (!out_client) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_client = NULL;
    if (!config || !config->sign_agent_proof ||
        !config->sign_device_claim_proof ||
        !config->sign_action_challenge_proof ||
        !config->sign_action_result_proof ||
        !config->get_unix_time || !config->accept_authenticated_time ||
        !agent_control_plane_validate_endpoints(
            config->time_endpoint, config->agent_token_endpoint,
            config->device_claim_endpoint,
            config->action_challenge_endpoint,
            config->action_result_endpoint) ||
        !agent_control_plane_safe_identifier(config->device_id) ||
        !agent_control_plane_safe_identifier(config->client_id) ||
        ((!config->server_cert_pem || !config->server_cert_pem[0]) ==
         !config->use_crt_bundle) ||
        (config->network_timeout_ms != 0 &&
         (config->network_timeout_ms < 1000 ||
          config->network_timeout_ms > 30000))) {
        return ESP_ERR_INVALID_ARG;
    }

    agent_control_plane_client_handle_t client = heap_caps_calloc(
        1, sizeof(*client), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!client) {
        return ESP_ERR_NO_MEM;
    }
    client->strings = allocate_prefer_psram(sizeof(*client->strings));
    client->response = allocate_prefer_psram(
        AGENT_CONTROL_PLANE_RESPONSE_MAX + 1);
    if (!client->strings || !client->response) {
        release_storage(client);
        return ESP_ERR_NO_MEM;
    }
    if (!copy_string(client->strings->time_endpoint,
                     sizeof(client->strings->time_endpoint),
                     config->time_endpoint) ||
        !copy_string(client->strings->agent_token_endpoint,
                     sizeof(client->strings->agent_token_endpoint),
                     config->agent_token_endpoint) ||
        !copy_string(client->strings->device_claim_endpoint,
                     sizeof(client->strings->device_claim_endpoint),
                     config->device_claim_endpoint) ||
        !copy_string(client->strings->action_challenge_endpoint,
                     sizeof(client->strings->action_challenge_endpoint),
                     config->action_challenge_endpoint) ||
        !copy_string(client->strings->action_result_endpoint,
                     sizeof(client->strings->action_result_endpoint),
                     config->action_result_endpoint) ||
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
    client->sign_agent_proof = config->sign_agent_proof;
    client->sign_device_claim_proof =
        config->sign_device_claim_proof;
    client->sign_action_challenge_proof =
        config->sign_action_challenge_proof;
    client->sign_action_result_proof =
        config->sign_action_result_proof;
    client->sign_ctx = config->sign_ctx;
    client->get_unix_time = config->get_unix_time;
    client->time_ctx = config->time_ctx;
    client->accept_authenticated_time =
        config->accept_authenticated_time;
    client->accept_time_ctx = config->accept_time_ctx;
    client->network_timeout_ms = config->network_timeout_ms
                                     ? config->network_timeout_ms
                                     : DEFAULT_NETWORK_TIMEOUT_MS;
    atomic_init(&client->busy, false);

    const int timeout_ms = (int)client->network_timeout_ms;
    esp_http_client_config_t http_config = {
        .url = client->strings->time_endpoint,
        .cert_pem = client->server_cert_pem,
        .method = HTTP_METHOD_POST,
        .timeout_ms = timeout_ms,
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
    client->time_http = esp_http_client_init(&http_config);
    http_config.url = client->strings->agent_token_endpoint;
    client->agent_http = esp_http_client_init(&http_config);
    http_config.url = client->strings->device_claim_endpoint;
    client->claim_http = esp_http_client_init(&http_config);
    http_config.url = client->strings->action_challenge_endpoint;
    client->action_challenge_http = esp_http_client_init(&http_config);
    http_config.url = client->strings->action_result_endpoint;
    client->action_result_http = esp_http_client_init(&http_config);
    if (!client->time_http || !client->agent_http ||
        !client->claim_http || !client->action_challenge_http ||
        !client->action_result_http) {
        release_storage(client);
        return ESP_ERR_NO_MEM;
    }
    *out_client = client;
    return ESP_OK;
}

esp_err_t agent_control_plane_client_destroy(
    agent_control_plane_client_handle_t client)
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
