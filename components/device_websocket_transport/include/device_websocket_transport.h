#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "device_websocket_limits.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct device_websocket_transport *device_websocket_transport_handle_t;

typedef enum {
    DEVICE_WEBSOCKET_EVENT_CONNECTED = 0,
    DEVICE_WEBSOCKET_EVENT_TEXT,
    DEVICE_WEBSOCKET_EVENT_BINARY,
    DEVICE_WEBSOCKET_EVENT_DISCONNECTED,
    DEVICE_WEBSOCKET_EVENT_ERROR,
    DEVICE_WEBSOCKET_EVENT_AUDIO_DROPPED,
} device_websocket_event_type_t;

typedef enum {
    DEVICE_WEBSOCKET_ERROR_CLIENT = 0,
    DEVICE_WEBSOCKET_ERROR_TLS,
    DEVICE_WEBSOCKET_ERROR_HANDSHAKE,
    DEVICE_WEBSOCKET_ERROR_PROTOCOL,
    DEVICE_WEBSOCKET_ERROR_SEND,
} device_websocket_error_source_t;

typedef struct {
    device_websocket_event_type_t type;
    /* TEXT/BINARY bytes are valid only until the callback returns. */
    const uint8_t *data;
    size_t size;
    device_websocket_error_source_t error_source;
    esp_err_t esp_error;
    int tls_stack_error;
    int certificate_verify_flags;
    int handshake_status;
    int socket_errno;
} device_websocket_event_t;

typedef void (*device_websocket_event_fn)(
    void *ctx,
    const device_websocket_event_t *event);

typedef struct {
    const char *uri;
    /* Raw short-lived token; the component adds the "Bearer " prefix. */
    const char *bearer_token;
    const char *device_id;
    const char *client_id;
    int protocol_version;

    /* Exactly one verification source must be selected. */
    const char *server_cert_pem;
    bool use_crt_bundle;

    uint32_t network_timeout_ms;
    uint32_t send_timeout_ms;
    uint32_t ping_interval_seconds;
    uint32_t pong_timeout_seconds;

    device_websocket_event_fn event;
    void *event_ctx;
} device_websocket_transport_config_t;

typedef struct {
    uint32_t connections;
    uint32_t disconnections;
    uint32_t received_text_messages;
    uint32_t received_binary_messages;
    uint32_t malformed_messages;
    uint32_t sent_text_messages;
    uint32_t sent_binary_messages;
    uint32_t send_errors;
    uint32_t audio_drops;
    uint32_t control_rejections;
} device_websocket_transport_stats_t;

/*
 * Creates a WSS-only client with server verification. Config strings are
 * copied except server_cert_pem, which must remain valid until destroy.
 * Automatic reconnect is disabled so an expired token is never reused.
 */
esp_err_t device_websocket_transport_create(
    const device_websocket_transport_config_t *config,
    device_websocket_transport_handle_t *out_transport);

esp_err_t device_websocket_transport_start(
    device_websocket_transport_handle_t transport);

/* Must not be called from the event callback. */
esp_err_t device_websocket_transport_close(
    device_websocket_transport_handle_t transport,
    uint32_t timeout_ms);
/*
 * Returns ESP_ERR_TIMEOUT without freeing storage if the TX worker has not
 * stopped. The caller must retain the handle and retry; ESP_OK consumes it.
 * A NULL handle is accepted for cleanup convenience.
 */
esp_err_t device_websocket_transport_destroy(
    device_websocket_transport_handle_t transport);

bool device_websocket_transport_connected(
    device_websocket_transport_handle_t transport);

/*
 * These calls copy into bounded queues and return promptly. ESP_OK means
 * accepted for sending, not remote acknowledgement. Control overflow rejects
 * the newest item; audio overflow replaces the oldest queued audio frame.
 */
esp_err_t device_websocket_transport_send_text(
    device_websocket_transport_handle_t transport,
    const char *data,
    size_t size);
esp_err_t device_websocket_transport_send_binary(
    device_websocket_transport_handle_t transport,
    const uint8_t *data,
    size_t size);

esp_err_t device_websocket_transport_get_stats(
    device_websocket_transport_handle_t transport,
    device_websocket_transport_stats_t *stats);

#ifdef __cplusplus
}
#endif
