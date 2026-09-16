#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct agent_control_plane_client *
    agent_control_plane_client_handle_t;

typedef enum {
    AGENT_CONTROL_PLANE_DEVICE_CLAIM_RETRY = 0,
    AGENT_CONTROL_PLANE_DEVICE_CLAIM_BOUND,
    AGENT_CONTROL_PLANE_DEVICE_CLAIM_REJECTED,
} agent_control_plane_device_claim_outcome_t;

enum {
    AGENT_CONTROL_PLANE_ACTION_CHALLENGE_ID_BYTES = 23,
    AGENT_CONTROL_PLANE_ACTION_SESSION_ID_BYTES = 65,
    AGENT_CONTROL_PLANE_ACTION_APP_JSON_BYTES = 513,
};

typedef enum {
    AGENT_CONTROL_PLANE_ACTION_PENDING = 0,
    AGENT_CONTROL_PLANE_ACTION_APPROVED,
    AGENT_CONTROL_PLANE_ACTION_DENIED,
} agent_control_plane_action_decision_t;

typedef struct {
    char challenge_id[AGENT_CONTROL_PLANE_ACTION_CHALLENGE_ID_BYTES];
    char session_id[AGENT_CONTROL_PLANE_ACTION_SESSION_ID_BYTES];
    uint32_t request_id;
    bool indicator_on;
    int64_t expires_at_unix;
    uint64_t owner_revision;
    /* Exact canonical challenge for an authenticated device-to-App relay. */
    char app_challenge_json[AGENT_CONTROL_PLANE_ACTION_APP_JSON_BYTES];
    size_t app_challenge_json_size;
} agent_control_plane_action_consent_t;

typedef esp_err_t (*agent_control_plane_sign_proof_fn)(
    void *ctx,
    const uint8_t *message,
    size_t message_size,
    uint8_t signature[32]);

typedef esp_err_t (*agent_control_plane_get_unix_time_fn)(
    void *ctx,
    int64_t *unix_seconds);

typedef esp_err_t (*agent_control_plane_accept_time_fn)(
    void *ctx,
    int64_t unix_seconds);

typedef struct {
    /* All endpoints must be HTTPS on the exact same authority. */
    const char *time_endpoint;        /* Exact /v1/time path. */
    const char *agent_token_endpoint; /* Exact /v1/agent-token path. */
    const char *device_claim_endpoint; /* Exact /v1/device-claim/device. */
    const char *action_challenge_endpoint;
    const char *action_result_endpoint;
    const char *device_id;
    const char *client_id;

    /* Exactly one server verification source must be selected. */
    const char *server_cert_pem;
    bool use_crt_bundle;
    /* Zero selects 10 seconds; valid configured range is 1..30 seconds. */
    uint32_t network_timeout_ms;

    /* Must accept only the Agent-token proof domain, not arbitrary bytes. */
    agent_control_plane_sign_proof_fn sign_agent_proof;
    /* Must accept only the device-claim proof domain. */
    agent_control_plane_sign_proof_fn sign_device_claim_proof;
    /* Each callback accepts only its exact body-digest proof domain. */
    agent_control_plane_sign_proof_fn sign_action_challenge_proof;
    agent_control_plane_sign_proof_fn sign_action_result_proof;
    void *sign_ctx;
    agent_control_plane_get_unix_time_fn get_unix_time;
    void *time_ctx;
    agent_control_plane_accept_time_fn accept_authenticated_time;
    void *accept_time_ctx;
} agent_control_plane_client_config_t;

esp_err_t agent_control_plane_client_create(
    const agent_control_plane_client_config_t *config,
    agent_control_plane_client_handle_t *out_client);

/* Call after Wi-Fi is usable and before requesting either credential. */
esp_err_t agent_control_plane_client_sync_time(
    agent_control_plane_client_handle_t client);

/*
 * Signature-compatible with box3_agent_get_unix_time_fn. Returns guarded time
 * immediately when fresh; otherwise performs one authenticated time refresh
 * and retries the product clock callback.
 */
esp_err_t agent_control_plane_client_get_or_sync_unix_time(
    void *ctx,
    int64_t *unix_seconds);

/* Signature-compatible with box3_agent_refresh_agent_token_fn. */
esp_err_t agent_control_plane_client_refresh_agent_token(
    void *ctx,
    char *token,
    size_t token_size,
    uint32_t *ttl_seconds,
    char *binding_id,
    size_t binding_id_size,
    uint64_t *binding_revision);

/*
 * Confirms the one-time 32-byte Base64URL ownership claim after network join.
 * Success means the control plane atomically returned status "bound".
 */
esp_err_t agent_control_plane_client_confirm_device_claim(
    void *ctx,
    const char *claim);

/*
 * Adds recovery semantics: transport, 408, 429, 5xx, and malformed 200
 * responses remain RETRY; authenticated 3xx/other 4xx responses are terminal
 * REJECTED; only an exact canonical 200 response is BOUND.
 */
esp_err_t agent_control_plane_client_confirm_device_claim_ex(
    void *ctx,
    const char *claim,
    agent_control_plane_device_claim_outcome_t *outcome);

/*
 * Called only after the Agent tool input has parsed to the typed exact action.
 * Generates a 128-bit challenge and returns the server-enriched canonical App
 * challenge. This function does not deliver it to the App and never accepts
 * prompt/voice text.
 */
esp_err_t agent_control_plane_client_register_action_consent(
    agent_control_plane_client_handle_t client,
    const char *session_id,
    uint32_t request_id,
    bool indicator_on,
    int64_t expires_at_unix,
    agent_control_plane_action_consent_t *consent);

/*
 * Runtime-owned bounded variant. It uses only the already guarded local clock
 * (no network time refresh), creates a lifetime of 1..30 seconds, and caps the
 * challenge HTTP request to request_timeout_ms. A stale clock fails closed.
 */
esp_err_t agent_control_plane_client_register_action_consent_bounded(
    agent_control_plane_client_handle_t client,
    const char *session_id,
    uint32_t request_id,
    bool indicator_on,
    uint32_t lifetime_seconds,
    uint32_t request_timeout_ms,
    agent_control_plane_action_consent_t *consent);

/*
 * Fetches the stored App decision for the exact registered action. ESP_OK with
 * PENDING is retryable within the challenge lifetime. Any error is fail-closed
 * and must never be interpreted as approval.
 */
esp_err_t agent_control_plane_client_poll_action_consent(
    agent_control_plane_client_handle_t client,
    const agent_control_plane_action_consent_t *consent,
    agent_control_plane_action_decision_t *decision);

/* Uses only guarded local time and caps this result request to the given wait. */
esp_err_t agent_control_plane_client_poll_action_consent_bounded(
    agent_control_plane_client_handle_t client,
    const agent_control_plane_action_consent_t *consent,
    uint32_t request_timeout_ms,
    agent_control_plane_action_decision_t *decision);

/* The lifecycle owner must serialize destroy against every network API. */
esp_err_t agent_control_plane_client_destroy(
    agent_control_plane_client_handle_t client);

#ifdef __cplusplus
}
#endif
