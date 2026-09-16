#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct agent_device_identity *agent_device_identity_handle_t;

typedef struct {
    /* Must exactly match the control-plane registry identity. */
    const char *device_id;

    /* eFuse HMAC key index 0..5; its purpose must already be HMAC_UP. */
    uint8_t hmac_key_id;

    /* Zero selects 24 hours; valid configured range is 60 s..7 days. */
    uint32_t maximum_time_age_seconds;

    /* Zero selects 5 s; nonzero configured range is 1..300 s. */
    uint32_t backward_time_tolerance_seconds;
} agent_device_identity_config_t;

typedef struct {
    uint8_t hmac_key_id;
    bool efuse_policy_valid;
    bool time_synchronized;
    uint64_t time_age_seconds;
} agent_device_identity_status_t;

/*
 * This function never programs eFuse. The selected key must have been injected
 * by an authorized factory station with HMAC_UP purpose and read/write/purpose
 * protection already enabled.
 */
esp_err_t agent_device_identity_create(
    const agent_device_identity_config_t *config,
    agent_device_identity_handle_t *out_identity);

/* Signature-compatible with box3_agent_sign_proof_fn. */
esp_err_t agent_device_identity_sign_proof(
    void *ctx,
    const uint8_t *message,
    size_t message_size,
    uint8_t signature[32]);

/* Agent-token proof scope; never accepts a session proof or arbitrary bytes. */
esp_err_t agent_device_identity_sign_agent_token_proof(
    void *ctx,
    const uint8_t *message,
    size_t message_size,
    uint8_t signature[32]);

/* OTA-offer proof scope; binds board/channel/sequence/version state. */
esp_err_t agent_device_identity_sign_ota_offer_proof(
    void *ctx,
    const uint8_t *message,
    size_t message_size,
    uint8_t signature[32]);

/* Ownership-claim proof scope; binds the one-time 32-byte claim value. */
esp_err_t agent_device_identity_sign_device_claim_proof(
    void *ctx,
    const uint8_t *message,
    size_t message_size,
    uint8_t signature[32]);

/* Exact action-consent challenge body-digest proof scope. */
esp_err_t agent_device_identity_sign_action_consent_challenge_proof(
    void *ctx,
    const uint8_t *message,
    size_t message_size,
    uint8_t signature[32]);

/* Exact action-consent decision-result body-digest proof scope. */
esp_err_t agent_device_identity_sign_action_consent_result_proof(
    void *ctx,
    const uint8_t *message,
    size_t message_size,
    uint8_t signature[32]);

/*
 * Derives only the domain-separated onboarding SoftAP key. This intentionally
 * does not expose a general-purpose HMAC oracle to the provisioning component.
 */
esp_err_t agent_device_identity_derive_onboarding_ap_key(
    void *ctx,
    const char *service_name,
    uint8_t output[32]);

/*
 * Accept only a value obtained from a product-authenticated time source. Raw
 * unauthenticated SNTP is an availability bootstrap, not proof of authenticity.
 */
esp_err_t agent_device_identity_accept_authenticated_time(
    agent_device_identity_handle_t identity,
    int64_t unix_seconds);

/* Callback-compatible form for the product authenticated-time client. */
esp_err_t agent_device_identity_accept_authenticated_time_callback(
    void *ctx,
    int64_t unix_seconds);

/* Signature-compatible with box3_agent_get_unix_time_fn. */
esp_err_t agent_device_identity_get_unix_time(
    void *ctx,
    int64_t *unix_seconds);

esp_err_t agent_device_identity_get_status(
    agent_device_identity_handle_t identity,
    agent_device_identity_status_t *status);

/* The lifecycle owner must serialize destroy against every API call. */
esp_err_t agent_device_identity_destroy(
    agent_device_identity_handle_t identity);

#ifdef __cplusplus
}
#endif
