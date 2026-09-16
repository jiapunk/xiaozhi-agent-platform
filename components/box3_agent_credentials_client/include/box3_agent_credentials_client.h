#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "box3_agent_supervisor.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct box3_agent_credentials_client *
    box3_agent_credentials_client_handle_t;

/*
 * Returns the HMAC-SHA256 of the supplied canonical proof without exposing the
 * long-lived per-device bootstrap secret to this component. Production
 * implementations may use eFuse HMAC, a secure element, or another protected
 * key service.
 */
typedef esp_err_t (*box3_agent_sign_proof_fn)(
    void *ctx,
    const uint8_t *message,
    size_t message_size,
    uint8_t signature[32]);

/* Returns trusted Unix seconds only after secure time synchronization. */
typedef esp_err_t (*box3_agent_get_unix_time_fn)(
    void *ctx,
    int64_t *unix_seconds);

/*
 * Obtains a separate, scoped Agent/LLM-proxy token. It must not return the
 * voice token or a model-provider master key.
 */
typedef esp_err_t (*box3_agent_refresh_agent_token_fn)(
    void *ctx,
    char *token,
    size_t token_size,
    uint32_t *ttl_seconds,
    char *binding_id,
    size_t binding_id_size,
    uint64_t *binding_revision);

typedef struct {
    const char *session_endpoint; /* Exact HTTPS /v1/session URL. */
    const char *device_id;
    const char *client_id;

    /* Exactly one server verification source must be selected. */
    const char *server_cert_pem;
    bool use_crt_bundle;
    /* Zero selects 10 seconds; valid configured range is 1..30 seconds. */
    uint32_t network_timeout_ms;

    box3_agent_sign_proof_fn sign_proof;
    void *sign_ctx;
    box3_agent_get_unix_time_fn get_unix_time;
    void *time_ctx;
    box3_agent_refresh_agent_token_fn refresh_agent_token;
    void *agent_ctx;
} box3_agent_credentials_client_config_t;

esp_err_t box3_agent_credentials_client_create(
    const box3_agent_credentials_client_config_t *config,
    box3_agent_credentials_client_handle_t *out_client);

/* Signature-compatible with box3_agent_refresh_credentials_fn. */
esp_err_t box3_agent_credentials_client_refresh(
    void *ctx,
    box3_agent_credentials_t *credentials);

/*
 * Call only after the supervisor is stopped and no refresh is in flight. The
 * lifecycle owner must serialize destroy against every client API call.
 */
esp_err_t box3_agent_credentials_client_destroy(
    box3_agent_credentials_client_handle_t client);

#ifdef __cplusplus
}
#endif
