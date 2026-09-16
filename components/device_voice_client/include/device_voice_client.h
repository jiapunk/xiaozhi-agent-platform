#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "agent_bridge.h"
#include "device_websocket_transport.h"
#include "esp_err.h"
#include "voice_agent_controller.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct device_voice_client *device_voice_client_handle_t;

typedef enum {
    DEVICE_VOICE_CLIENT_EVENT_READY = 0,
    DEVICE_VOICE_CLIENT_EVENT_DISCONNECTED,
    DEVICE_VOICE_CLIENT_EVENT_PROTOCOL_ERROR,
    DEVICE_VOICE_CLIENT_EVENT_QUEUE_OVERFLOW,
    DEVICE_VOICE_CLIENT_EVENT_TRANSPORT_ERROR,
    DEVICE_VOICE_CLIENT_EVENT_SPEECH_BUDGET_EXCEEDED,
    DEVICE_VOICE_CLIENT_EVENT_SPEECH_BUDGET_UNAVAILABLE,
} device_voice_client_event_type_t;

typedef struct {
    device_voice_client_event_type_t type;
    agent_bridge_result_t result;
    device_websocket_error_source_t transport_error_source;
    esp_err_t transport_esp_error;
    int handshake_status;
} device_voice_client_event_t;

typedef struct {
    int (*submit_agent)(void *ctx,
                        uint32_t request_id,
                        const char *session_id,
                        const char *text);
    int (*cancel_agent)(void *ctx, uint32_t request_id);
    int (*receive_binary)(void *ctx,
                          const uint8_t *packet,
                          size_t packet_size);
    void (*playback_event)(void *ctx,
                           voice_agent_playback_event_t event,
                           uint32_t request_id);
    void (*capture_enabled)(void *ctx, bool enabled);
    void (*state_changed)(void *ctx,
                          agent_bridge_state_t from,
                          agent_bridge_state_t to,
                          uint32_t request_id);
    void (*event)(void *ctx, const device_voice_client_event_t *event);
} device_voice_client_ops_t;

typedef struct {
    device_websocket_transport_config_t websocket;
    device_voice_client_ops_t ops;
    void *ops_ctx;
    int uplink_sample_rate;
    int downlink_sample_rate;
    int frame_duration_ms;
    uint32_t hello_timeout_ms;
} device_voice_client_config_t;

typedef struct {
    uint32_t control_queue_rejections;
    uint32_t binary_queue_drops;
    uint32_t protocol_errors;
    uint32_t hello_timeouts;
    uint32_t speech_budget_exceeded;
    uint32_t speech_budget_unavailable;
    device_websocket_transport_stats_t transport;
} device_voice_client_stats_t;

/*
 * Owns one serialized worker, Device Agent runtime, and secure WebSocket
 * transport. Wi-Fi must already be connected and the token must already have
 * been provisioned. The embedded websocket event fields are replaced by this
 * component and should be left NULL by callers.
 */
/*
 * On an ordinary failure out_client is NULL. If fail-safe cleanup itself
 * times out, a retained handle is returned and must be passed to destroy().
 */
esp_err_t device_voice_client_create(
    const device_voice_client_config_t *config,
    device_voice_client_handle_t *out_client);
esp_err_t device_voice_client_start(device_voice_client_handle_t client);

/*
 * Must not be called from an operation or event callback. Returns a failure
 * without freeing storage if a worker is still active; retain and retry the
 * handle. ESP_OK consumes it. A NULL handle is accepted for cleanup.
 */
esp_err_t device_voice_client_destroy(device_voice_client_handle_t client);

/* Agent callbacks may call these from any task; text is copied. */
esp_err_t device_voice_client_on_agent_final(
    device_voice_client_handle_t client,
    uint32_t request_id,
    const char *text);
esp_err_t device_voice_client_on_agent_error(
    device_voice_client_handle_t client,
    uint32_t request_id);

/* Button/session events may call this from any task. */
esp_err_t device_voice_client_interrupt(
    device_voice_client_handle_t client,
    agent_bridge_interrupt_reason_t reason);

/*
 * Signature-compatible adapter for box3_voice_audio_config_t.send_binary when
 * that stream's ops_ctx is the client. With an aggregate product ops_ctx, use
 * a one-line forwarding callback instead.
 */
int device_voice_client_send_audio(void *ctx,
                                   const uint8_t *data,
                                   size_t size);

bool device_voice_client_ready(device_voice_client_handle_t client);
esp_err_t device_voice_client_get_stats(
    device_voice_client_handle_t client,
    device_voice_client_stats_t *stats);

#ifdef __cplusplus
}
#endif
