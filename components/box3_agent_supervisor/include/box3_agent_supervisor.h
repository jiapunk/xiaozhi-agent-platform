#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "box3_agent_supervisor_core.h"
#include "box3_agent_voice.h"
#include "device_websocket_limits.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    BOX3_AGENT_SUPERVISOR_AGENT_TOKEN_MAX = 2048,
};

typedef struct box3_agent_supervisor *box3_agent_supervisor_handle_t;

typedef struct {
    char voice_uri[DEVICE_WEBSOCKET_URI_MAX];
    char voice_bearer_token[DEVICE_WEBSOCKET_TOKEN_MAX];
    char agent_bearer_token[BOX3_AGENT_SUPERVISOR_AGENT_TOKEN_MAX + 1];
    char binding_id[23];
    uint64_t binding_revision;
    uint32_t voice_ttl_seconds;
    uint32_t agent_ttl_seconds;
} box3_agent_credentials_t;

/*
 * Called only by the supervisor task. Implementations must use bounded
 * network timeouts, fill every field, and never log credential contents.
 */
typedef esp_err_t (*box3_agent_refresh_credentials_fn)(
    void *ctx,
    box3_agent_credentials_t *credentials);

typedef void (*box3_agent_supervisor_event_fn)(
    void *ctx,
    box3_agent_supervisor_state_t state,
    esp_err_t last_error);

typedef struct {
    /*
     * Static product template. websocket.uri, websocket.bearer_token, and
     * agent.api_key must be NULL; the supervisor supplies them per session.
     * The aggregate callback fields documented by box3_agent_voice must also
     * remain unset. All static strings and the server certificate are copied.
     * Callback contexts, device_ops.ctx, the Agent memory handle, and
     * credential_ctx stay caller-owned and must outlive the supervisor.
     */
    box3_agent_voice_config_t product;
    box3_agent_refresh_credentials_fn refresh_credentials;
    void *credential_ctx;
    box3_agent_supervisor_event_fn event;
    void *event_ctx;

    /* Zero selects 5 s / 60 s / 60 s / 5 s defaults. */
    uint32_t minimum_backoff_ms;
    uint32_t maximum_backoff_ms;
    uint32_t refresh_margin_seconds;
    uint32_t product_stop_timeout_ms;

    /* Zero selects 8192 bytes and priority 5. */
    uint32_t task_stack_size;
    uint32_t task_priority;
} box3_agent_supervisor_config_t;

typedef struct {
    box3_agent_supervisor_state_t state;
    bool started;
    bool network_available;
    bool has_session;
    bool ready;
    uint32_t credential_refreshes;
    uint32_t credential_failures;
    uint32_t session_starts;
    uint32_t session_failures;
    uint32_t disconnects;
    uint32_t cleanup_retries;
    uint32_t interrupt_rejections;
} box3_agent_supervisor_stats_t;

esp_err_t box3_agent_supervisor_create(
    const box3_agent_supervisor_config_t *config,
    box3_agent_supervisor_handle_t *out_supervisor);

esp_err_t box3_agent_supervisor_start(
    box3_agent_supervisor_handle_t supervisor);

/* May be called from the product Wi-Fi/IP event task. */
esp_err_t box3_agent_supervisor_set_network_available(
    box3_agent_supervisor_handle_t supervisor,
    bool available);

/* Wake a blocked supervisor after a reviewed account-entitlement change. */
esp_err_t box3_agent_supervisor_entitlement_changed(
    box3_agent_supervisor_handle_t supervisor);

/* Queues an interrupt onto the supervisor task; no product callback is invoked. */
esp_err_t box3_agent_supervisor_interrupt(
    box3_agent_supervisor_handle_t supervisor,
    agent_bridge_interrupt_reason_t reason);

esp_err_t box3_agent_supervisor_get_stats(
    box3_agent_supervisor_handle_t supervisor,
    box3_agent_supervisor_stats_t *stats);

/*
 * Must not be called from a product, credential, or supervisor callback.
 * Only the lifecycle owner may call stop; concurrent stop calls are forbidden.
 * ESP_OK consumes the handle. A timeout retains it for a later retry.
 */
esp_err_t box3_agent_supervisor_stop(
    box3_agent_supervisor_handle_t supervisor,
    uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif
