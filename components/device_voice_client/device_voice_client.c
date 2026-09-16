#include "device_voice_client.h"

#include <stdatomic.h>
#include <string.h>

#include "cJSON.h"
#include "device_voice_client_protocol.h"
#include "device_voice_runtime.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "xiaozhi_agent_adapter.h"

static const char *TAG = "device_voice_client";

enum {
    CLIENT_STOP_REQUESTED = BIT0,
    CLIENT_WORKER_STOPPED = BIT1,
    CLIENT_TRANSPORT_CONNECTED = BIT2,
    CLIENT_READY = BIT3,
    CLIENT_PENDING_CONNECTED = BIT4,
    CLIENT_PENDING_DISCONNECTED = BIT5,
    CLIENT_PENDING_INTERRUPT = BIT6,
    CLIENT_PENDING_FATAL = BIT7,
    CLIENT_EVENT_POOL_DEPTH = 8,
    CLIENT_WORKER_STOP_TIMEOUT_MS = 3000,
    CLIENT_AGENT_TEXT_MAX = 512,
};

typedef enum {
    INTERNAL_EVENT_TEXT = 0,
    INTERNAL_EVENT_BINARY,
    INTERNAL_EVENT_AGENT_FINAL,
    INTERNAL_EVENT_AGENT_ERROR,
    INTERNAL_EVENT_TRANSPORT_ERROR,
} internal_event_type_t;

typedef struct {
    internal_event_type_t type;
    uint32_t request_id;
    size_t size;
    device_websocket_error_source_t transport_error_source;
    esp_err_t transport_esp_error;
    int handshake_status;
    uint8_t data[DEVICE_WEBSOCKET_BINARY_MAX];
} internal_event_t;

struct device_voice_client {
    device_voice_client_ops_t ops;
    void *ops_ctx;
    int transport_version;
    int uplink_sample_rate;
    uint32_t hello_timeout_ms;

    device_websocket_transport_handle_t transport;
    device_voice_runtime_t runtime;
    char *tx_buffer;
    EventGroupHandle_t signals;
    QueueHandle_t free_events;
    QueueHandle_t events;
    internal_event_t *event_pool;
    TaskHandle_t worker;
    int64_t hello_deadline_us;

    atomic_int pending_interrupt_reason;
    atomic_bool destroying;
    atomic_uint control_queue_rejections;
    atomic_uint binary_queue_drops;
    atomic_uint protocol_errors;
    atomic_uint hello_timeouts;
    atomic_uint speech_budget_exceeded;
    atomic_uint speech_budget_unavailable;
};

static void emit_client_event(device_voice_client_handle_t client,
                              device_voice_client_event_type_t type,
                              agent_bridge_result_t result,
                              device_websocket_error_source_t error_source,
                              esp_err_t esp_error,
                              int handshake_status)
{
    if (!atomic_load_explicit(&client->destroying, memory_order_acquire) &&
        client->ops.event) {
        const device_voice_client_event_t event = {
            .type = type,
            .result = result,
            .transport_error_source = error_source,
            .transport_esp_error = esp_error,
            .handshake_status = handshake_status,
        };
        client->ops.event(client->ops_ctx, &event);
    }
}

static void set_capture(device_voice_client_handle_t client, bool enabled)
{
    if (client->ops.capture_enabled) {
        client->ops.capture_enabled(client->ops_ctx, enabled);
    }
}

static void return_event(device_voice_client_handle_t client,
                         internal_event_t *event)
{
    if (event && xQueueSend(client->free_events, &event, 0) != pdTRUE) {
        ESP_LOGE(TAG, "Event pool invariant violated");
    }
}

static void flush_events(device_voice_client_handle_t client)
{
    internal_event_t *event = NULL;
    while (xQueueReceive(client->events, &event, 0) == pdTRUE) {
        return_event(client, event);
    }
}

static esp_err_t enqueue_event(device_voice_client_handle_t client,
                               internal_event_type_t type,
                               uint32_t request_id,
                               const uint8_t *data,
                               size_t size,
                               const device_websocket_event_t *transport_error)
{
    internal_event_t *event = NULL;
    if (!client || size > DEVICE_WEBSOCKET_BINARY_MAX ||
        (!data && size > 0) ||
        (xEventGroupGetBits(client->signals) & CLIENT_STOP_REQUESTED) != 0) {
        return ESP_ERR_INVALID_STATE;
    }
    if (xQueueReceive(client->free_events, &event, 0) != pdTRUE) {
        if (type == INTERNAL_EVENT_BINARY) {
            atomic_fetch_add_explicit(&client->binary_queue_drops, 1,
                                      memory_order_relaxed);
        } else {
            atomic_fetch_add_explicit(&client->control_queue_rejections, 1,
                                      memory_order_relaxed);
        }
        return ESP_ERR_NO_MEM;
    }
    event->type = type;
    event->request_id = request_id;
    event->size = size;
    if (size > 0) {
        memcpy(event->data, data, size);
    }
    if (transport_error) {
        event->transport_error_source = transport_error->error_source;
        event->transport_esp_error = transport_error->esp_error;
        event->handshake_status = transport_error->handshake_status;
    } else {
        event->transport_error_source = DEVICE_WEBSOCKET_ERROR_CLIENT;
        event->transport_esp_error = ESP_OK;
        event->handshake_status = 0;
    }
    if (xQueueSend(client->events, &event, 0) != pdTRUE) {
        return_event(client, event);
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

static int runtime_submit_agent(void *ctx,
                                uint32_t request_id,
                                const char *session_id,
                                const char *text)
{
    device_voice_client_handle_t client = ctx;
    return client->ops.submit_agent(client->ops_ctx, request_id,
                                    session_id, text);
}

static int runtime_cancel_agent(void *ctx, uint32_t request_id)
{
    device_voice_client_handle_t client = ctx;
    return client->ops.cancel_agent(client->ops_ctx, request_id);
}

static int runtime_send_json(void *ctx, const char *json, size_t size)
{
    device_voice_client_handle_t client = ctx;
    return device_websocket_transport_send_text(
               client->transport, json, size) == ESP_OK
               ? 0
               : -1;
}

static int runtime_receive_binary(void *ctx,
                                  const uint8_t *packet,
                                  size_t size)
{
    device_voice_client_handle_t client = ctx;
    return client->ops.receive_binary(client->ops_ctx, packet, size);
}

static void runtime_playback_event(void *ctx,
                                   voice_agent_playback_event_t event,
                                   uint32_t request_id)
{
    device_voice_client_handle_t client = ctx;
    client->ops.playback_event(client->ops_ctx, event, request_id);
}

static void runtime_state_changed(void *ctx,
                                  agent_bridge_state_t from,
                                  agent_bridge_state_t to,
                                  uint32_t request_id)
{
    device_voice_client_handle_t client = ctx;
    if (client->ops.state_changed) {
        client->ops.state_changed(client->ops_ctx, from, to, request_id);
    }
}

static void handle_disconnected(device_voice_client_handle_t client)
{
    xEventGroupClearBits(client->signals,
                         CLIENT_TRANSPORT_CONNECTED | CLIENT_READY |
                             CLIENT_PENDING_CONNECTED |
                             CLIENT_PENDING_FATAL);
    client->hello_deadline_us = 0;
    set_capture(client, false);
    (void)device_voice_runtime_on_disconnected(&client->runtime);
    flush_events(client);
    emit_client_event(client, DEVICE_VOICE_CLIENT_EVENT_DISCONNECTED,
                      AGENT_BRIDGE_OK, DEVICE_WEBSOCKET_ERROR_CLIENT,
                      ESP_OK, 0);
}

static void fail_connection(device_voice_client_handle_t client,
                            agent_bridge_result_t result)
{
    atomic_fetch_add_explicit(&client->protocol_errors, 1,
                              memory_order_relaxed);
    set_capture(client, false);
    (void)device_voice_runtime_on_disconnected(&client->runtime);
    xEventGroupClearBits(client->signals,
                         CLIENT_READY | CLIENT_TRANSPORT_CONNECTED);
    client->hello_deadline_us = 0;
    emit_client_event(client, DEVICE_VOICE_CLIENT_EVENT_PROTOCOL_ERROR,
                      result, DEVICE_WEBSOCKET_ERROR_PROTOCOL,
                      ESP_ERR_INVALID_RESPONSE, 0);
    (void)device_websocket_transport_close(client->transport, 1000);
}

static void handle_connected(device_voice_client_handle_t client)
{
    size_t hello_size = 0;
    agent_bridge_result_t result;

    if (device_voice_runtime_ready(&client->runtime)) {
        set_capture(client, false);
        (void)device_voice_runtime_on_disconnected(&client->runtime);
    }
    result = device_voice_client_build_hello(
        client->transport_version, client->uplink_sample_rate,
        client->runtime.frame_duration_ms, client->tx_buffer,
        DEVICE_WEBSOCKET_CONTROL_MAX, &hello_size);
    if (result != AGENT_BRIDGE_OK ||
        device_websocket_transport_send_text(
            client->transport, client->tx_buffer, hello_size) != ESP_OK) {
        fail_connection(client, AGENT_BRIDGE_ERR_OPERATION);
        return;
    }
    xEventGroupSetBits(client->signals, CLIENT_TRANSPORT_CONNECTED);
    client->hello_deadline_us = esp_timer_get_time() +
                                (int64_t)client->hello_timeout_ms * 1000;
}

static void handle_text(device_voice_client_handle_t client,
                        const uint8_t *data,
                        size_t size)
{
    cJSON *root = device_voice_client_parse_json_strict(data, size);
    const cJSON *type;
    agent_bridge_result_t result;
    xiaozhi_agent_message_outcome_t outcome;

    if (!root || !cJSON_IsObject(root)) {
        cJSON_Delete(root);
        fail_connection(client, AGENT_BRIDGE_ERR_INVALID_ARG);
        return;
    }
    type = cJSON_GetObjectItemCaseSensitive(root, "type");
    if (!cJSON_IsString(type) || !type->valuestring) {
        cJSON_Delete(root);
        fail_connection(client, AGENT_BRIDGE_ERR_INVALID_ARG);
        return;
    }
    if (strcmp(type->valuestring, "hello") == 0) {
        if ((xEventGroupGetBits(client->signals) &
             CLIENT_TRANSPORT_CONNECTED) == 0 ||
            device_voice_runtime_ready(&client->runtime)) {
            cJSON_Delete(root);
            fail_connection(client, AGENT_BRIDGE_ERR_INVALID_STATE);
            return;
        }
        result = device_voice_runtime_accept_server_hello(&client->runtime,
                                                           root);
        cJSON_Delete(root);
        if (result != AGENT_BRIDGE_OK) {
            fail_connection(client, result);
            return;
        }
        client->hello_deadline_us = 0;
        xEventGroupSetBits(client->signals, CLIENT_READY);
        set_capture(client, true);
        emit_client_event(client, DEVICE_VOICE_CLIENT_EVENT_READY,
                          AGENT_BRIDGE_OK, DEVICE_WEBSOCKET_ERROR_CLIENT,
                          ESP_OK, 0);
        return;
    }

    result = device_voice_runtime_on_json(&client->runtime, root, &outcome);
    cJSON_Delete(root);
    if (result == AGENT_BRIDGE_ERR_STALE_EVENT) {
        atomic_fetch_add_explicit(&client->protocol_errors, 1,
                                  memory_order_relaxed);
        emit_client_event(client, DEVICE_VOICE_CLIENT_EVENT_PROTOCOL_ERROR,
                          result, DEVICE_WEBSOCKET_ERROR_PROTOCOL,
                          ESP_ERR_INVALID_RESPONSE, 0);
    } else if (result != AGENT_BRIDGE_OK) {
        fail_connection(client, result);
    } else if (outcome.service_error != XIAOZHI_AGENT_SERVICE_ERROR_NONE) {
        set_capture(client, false);
        if (outcome.service_error ==
            XIAOZHI_AGENT_SERVICE_ERROR_SPEECH_BUDGET_EXCEEDED) {
            atomic_fetch_add_explicit(&client->speech_budget_exceeded, 1,
                                      memory_order_relaxed);
            emit_client_event(
                client,
                DEVICE_VOICE_CLIENT_EVENT_SPEECH_BUDGET_EXCEEDED,
                AGENT_BRIDGE_OK, DEVICE_WEBSOCKET_ERROR_CLIENT, ESP_OK, 0);
        } else {
            atomic_fetch_add_explicit(&client->speech_budget_unavailable, 1,
                                      memory_order_relaxed);
            emit_client_event(
                client,
                DEVICE_VOICE_CLIENT_EVENT_SPEECH_BUDGET_UNAVAILABLE,
                AGENT_BRIDGE_OK, DEVICE_WEBSOCKET_ERROR_CLIENT, ESP_OK, 0);
        }
    }
}

static void handle_internal_event(device_voice_client_handle_t client,
                                  internal_event_t *event)
{
    agent_bridge_result_t result = AGENT_BRIDGE_OK;
    switch (event->type) {
    case INTERNAL_EVENT_TEXT:
        handle_text(client, event->data, event->size);
        break;
    case INTERNAL_EVENT_BINARY:
        result = device_voice_runtime_on_binary(&client->runtime,
                                                event->data, event->size);
        if (result != AGENT_BRIDGE_OK &&
            result != AGENT_BRIDGE_ERR_INVALID_STATE) {
            fail_connection(client, result);
        }
        break;
    case INTERNAL_EVENT_AGENT_FINAL:
        result = device_voice_runtime_on_agent_final(
            &client->runtime, event->request_id, (const char *)event->data);
        if (result != AGENT_BRIDGE_OK &&
            result != AGENT_BRIDGE_ERR_STALE_EVENT) {
            fail_connection(client, result);
        }
        break;
    case INTERNAL_EVENT_AGENT_ERROR:
        result = device_voice_runtime_on_agent_error(
            &client->runtime, event->request_id);
        if (result != AGENT_BRIDGE_OK &&
            result != AGENT_BRIDGE_ERR_STALE_EVENT) {
            fail_connection(client, result);
        }
        break;
    case INTERNAL_EVENT_TRANSPORT_ERROR:
        emit_client_event(client, DEVICE_VOICE_CLIENT_EVENT_TRANSPORT_ERROR,
                          AGENT_BRIDGE_ERR_OPERATION,
                          event->transport_error_source,
                          event->transport_esp_error,
                          event->handshake_status);
        break;
    }
}

static void check_hello_timeout(device_voice_client_handle_t client)
{
    if (client->hello_deadline_us > 0 &&
        esp_timer_get_time() >= client->hello_deadline_us) {
        client->hello_deadline_us = 0;
        atomic_fetch_add_explicit(&client->hello_timeouts, 1,
                                  memory_order_relaxed);
        fail_connection(client, AGENT_BRIDGE_ERR_OPERATION);
    }
}

static void worker_entry(void *argument)
{
    device_voice_client_handle_t client = argument;

    for (;;) {
        EventBits_t bits = xEventGroupGetBits(client->signals);
        if ((bits & CLIENT_STOP_REQUESTED) != 0) {
            break;
        }
        if ((bits & CLIENT_PENDING_DISCONNECTED) != 0) {
            xEventGroupClearBits(client->signals,
                                 CLIENT_PENDING_DISCONNECTED);
            handle_disconnected(client);
            continue;
        }
        if ((bits & CLIENT_PENDING_INTERRUPT) != 0) {
            xEventGroupClearBits(client->signals, CLIENT_PENDING_INTERRUPT);
            agent_bridge_interrupt_reason_t reason =
                (agent_bridge_interrupt_reason_t)atomic_load_explicit(
                    &client->pending_interrupt_reason, memory_order_acquire);
            (void)device_voice_runtime_interrupt(&client->runtime, reason);
            continue;
        }
        if ((bits & CLIENT_PENDING_FATAL) != 0) {
            xEventGroupClearBits(client->signals, CLIENT_PENDING_FATAL);
            emit_client_event(client, DEVICE_VOICE_CLIENT_EVENT_QUEUE_OVERFLOW,
                              AGENT_BRIDGE_ERR_OPERATION,
                              DEVICE_WEBSOCKET_ERROR_PROTOCOL,
                              ESP_ERR_NO_MEM, 0);
            fail_connection(client, AGENT_BRIDGE_ERR_OPERATION);
            continue;
        }
        if ((bits & CLIENT_PENDING_CONNECTED) != 0) {
            xEventGroupClearBits(client->signals, CLIENT_PENDING_CONNECTED);
            handle_connected(client);
            continue;
        }

        check_hello_timeout(client);

        internal_event_t *event = NULL;
        if (xQueueReceive(client->events, &event,
                          pdMS_TO_TICKS(10)) == pdTRUE) {
            handle_internal_event(client, event);
            return_event(client, event);
        }
    }

    set_capture(client, false);
    (void)device_voice_runtime_on_disconnected(&client->runtime);
    flush_events(client);
    xEventGroupClearBits(client->signals,
                         CLIENT_READY | CLIENT_TRANSPORT_CONNECTED);
    xEventGroupSetBits(client->signals, CLIENT_WORKER_STOPPED);
    client->worker = NULL;
    vTaskDelete(NULL);
}

static void transport_event(void *ctx,
                            const device_websocket_event_t *event)
{
    device_voice_client_handle_t client = ctx;
    if (!client || !event ||
        (xEventGroupGetBits(client->signals) & CLIENT_STOP_REQUESTED) != 0) {
        return;
    }
    switch (event->type) {
    case DEVICE_WEBSOCKET_EVENT_CONNECTED:
        xEventGroupSetBits(client->signals, CLIENT_PENDING_CONNECTED);
        break;
    case DEVICE_WEBSOCKET_EVENT_DISCONNECTED:
        xEventGroupSetBits(client->signals, CLIENT_PENDING_DISCONNECTED);
        break;
    case DEVICE_WEBSOCKET_EVENT_TEXT:
        if (enqueue_event(client, INTERNAL_EVENT_TEXT, 0,
                          event->data, event->size, NULL) != ESP_OK) {
            xEventGroupSetBits(client->signals, CLIENT_PENDING_FATAL);
        }
        break;
    case DEVICE_WEBSOCKET_EVENT_BINARY:
        (void)enqueue_event(client, INTERNAL_EVENT_BINARY, 0,
                            event->data, event->size, NULL);
        break;
    case DEVICE_WEBSOCKET_EVENT_ERROR:
        (void)enqueue_event(client, INTERNAL_EVENT_TRANSPORT_ERROR, 0,
                            NULL, 0, event);
        break;
    case DEVICE_WEBSOCKET_EVENT_AUDIO_DROPPED:
        break;
    }
}

static esp_err_t cleanup_unstarted(device_voice_client_handle_t client)
{
    if (!client) {
        return ESP_OK;
    }
    if (client->transport) {
        esp_err_t result =
            device_websocket_transport_destroy(client->transport);
        if (result != ESP_OK) {
            ESP_LOGE(TAG, "Transport cleanup incomplete; retaining resources");
            return result;
        }
        client->transport = NULL;
    }
    if (client->events) {
        vQueueDelete(client->events);
    }
    if (client->free_events) {
        vQueueDelete(client->free_events);
    }
    if (client->signals) {
        vEventGroupDelete(client->signals);
    }
    heap_caps_free(client->event_pool);
    heap_caps_free(client->tx_buffer);
    heap_caps_free(client);
    return ESP_OK;
}

static esp_err_t fail_create(device_voice_client_handle_t client,
                             device_voice_client_handle_t *out_client,
                             esp_err_t failure)
{
    esp_err_t cleanup_result = cleanup_unstarted(client);
    if (cleanup_result != ESP_OK) {
        *out_client = client;
        ESP_LOGE(TAG, "Startup cleanup incomplete; client retained");
    }
    return failure;
}

esp_err_t device_voice_client_create(
    const device_voice_client_config_t *config,
    device_voice_client_handle_t *out_client)
{
    device_voice_client_handle_t client;
    device_voice_runtime_config_t runtime_config;
    device_websocket_transport_config_t websocket_config;
    agent_bridge_result_t runtime_result;
    esp_err_t result;

    if (!out_client) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_client = NULL;
    if (!config || !config->ops.submit_agent ||
        !config->ops.cancel_agent || !config->ops.receive_binary ||
        !config->ops.playback_event || config->websocket.event ||
        config->uplink_sample_rate <= 0 ||
        config->uplink_sample_rate > 48000 ||
        config->downlink_sample_rate <= 0 ||
        config->downlink_sample_rate > 48000 ||
        config->frame_duration_ms < 20 ||
        config->frame_duration_ms > 120 ||
        config->hello_timeout_ms < 1000 ||
        config->hello_timeout_ms > 30000) {
        return ESP_ERR_INVALID_ARG;
    }
    client = heap_caps_calloc(1, sizeof(*client),
                              MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!client) {
        return ESP_ERR_NO_MEM;
    }
    client->ops = config->ops;
    client->ops_ctx = config->ops_ctx;
    client->transport_version = config->websocket.protocol_version;
    client->uplink_sample_rate = config->uplink_sample_rate;
    client->hello_timeout_ms = config->hello_timeout_ms;
    atomic_store_explicit(&client->pending_interrupt_reason,
                          AGENT_BRIDGE_INTERRUPT_USER_BARGE_IN,
                          memory_order_relaxed);
    client->tx_buffer = heap_caps_calloc(
        1, DEVICE_WEBSOCKET_CONTROL_MAX,
        MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    client->event_pool = heap_caps_calloc(
        CLIENT_EVENT_POOL_DEPTH, sizeof(internal_event_t),
        MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!client->event_pool) {
        client->event_pool = heap_caps_calloc(
            CLIENT_EVENT_POOL_DEPTH, sizeof(internal_event_t),
            MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    }
    client->signals = xEventGroupCreate();
    client->free_events = xQueueCreate(CLIENT_EVENT_POOL_DEPTH,
                                       sizeof(internal_event_t *));
    client->events = xQueueCreate(CLIENT_EVENT_POOL_DEPTH,
                                  sizeof(internal_event_t *));
    if (!client->tx_buffer || !client->event_pool || !client->signals ||
        !client->free_events || !client->events) {
        return fail_create(client, out_client, ESP_ERR_NO_MEM);
    }
    for (size_t index = 0; index < CLIENT_EVENT_POOL_DEPTH; ++index) {
        internal_event_t *event = &client->event_pool[index];
        if (xQueueSend(client->free_events, &event, 0) != pdTRUE) {
            return fail_create(client, out_client, ESP_FAIL);
        }
    }

    runtime_config = (device_voice_runtime_config_t){
        .ops = {
            .submit_agent = runtime_submit_agent,
            .cancel_agent = runtime_cancel_agent,
            .send_json = runtime_send_json,
            .receive_binary = runtime_receive_binary,
            .playback_event = runtime_playback_event,
            .state_changed = runtime_state_changed,
        },
        .ops_ctx = client,
        .tx_buffer = client->tx_buffer,
        .tx_buffer_size = DEVICE_WEBSOCKET_CONTROL_MAX,
        .downlink_sample_rate = config->downlink_sample_rate,
        .frame_duration_ms = config->frame_duration_ms,
    };
    runtime_result = device_voice_runtime_init(&client->runtime,
                                               &runtime_config);
    if (runtime_result != AGENT_BRIDGE_OK) {
        return fail_create(client, out_client, ESP_ERR_INVALID_ARG);
    }

    websocket_config = config->websocket;
    websocket_config.event = transport_event;
    websocket_config.event_ctx = client;
    result = device_websocket_transport_create(&websocket_config,
                                                &client->transport);
    if (result != ESP_OK) {
        return fail_create(client, out_client, result);
    }
    if (xTaskCreate(worker_entry, "device_voice", 8192, client, 7,
                    &client->worker) != pdPASS) {
        return fail_create(client, out_client, ESP_ERR_NO_MEM);
    }
    *out_client = client;
    return ESP_OK;
}

esp_err_t device_voice_client_start(device_voice_client_handle_t client)
{
    if (!client) {
        return ESP_ERR_INVALID_ARG;
    }
    return device_websocket_transport_start(client->transport);
}

esp_err_t device_voice_client_destroy(device_voice_client_handle_t client)
{
    esp_err_t result;

    if (!client) {
        return ESP_OK;
    }
    atomic_store_explicit(&client->destroying, true, memory_order_release);
    xEventGroupSetBits(client->signals, CLIENT_STOP_REQUESTED);
    if (client->worker) {
        EventBits_t bits = xEventGroupWaitBits(
            client->signals, CLIENT_WORKER_STOPPED, pdFALSE, pdTRUE,
            pdMS_TO_TICKS(CLIENT_WORKER_STOP_TIMEOUT_MS));
        if ((bits & CLIENT_WORKER_STOPPED) == 0) {
            ESP_LOGE(TAG, "Worker shutdown timed out; retaining resources");
            return ESP_ERR_TIMEOUT;
        }
    }
    result = device_websocket_transport_destroy(client->transport);
    if (result != ESP_OK) {
        return result;
    }
    client->transport = NULL;
    (void)cleanup_unstarted(client);
    return ESP_OK;
}

esp_err_t device_voice_client_on_agent_final(
    device_voice_client_handle_t client,
    uint32_t request_id,
    const char *text)
{
    size_t size;
    esp_err_t result;
    if (!client || request_id == 0 || !text || !text[0]) {
        return ESP_ERR_INVALID_ARG;
    }
    size = strlen(text);
    if (size > CLIENT_AGENT_TEXT_MAX) {
        return ESP_ERR_INVALID_SIZE;
    }
    result = enqueue_event(client, INTERNAL_EVENT_AGENT_FINAL, request_id,
                           (const uint8_t *)text, size + 1, NULL);
    if (result == ESP_ERR_NO_MEM) {
        xEventGroupSetBits(client->signals, CLIENT_PENDING_FATAL);
    }
    return result;
}

esp_err_t device_voice_client_on_agent_error(
    device_voice_client_handle_t client,
    uint32_t request_id)
{
    esp_err_t result;
    if (!client || request_id == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    result = enqueue_event(client, INTERNAL_EVENT_AGENT_ERROR, request_id,
                           NULL, 0, NULL);
    if (result == ESP_ERR_NO_MEM) {
        xEventGroupSetBits(client->signals, CLIENT_PENDING_FATAL);
    }
    return result;
}

esp_err_t device_voice_client_interrupt(
    device_voice_client_handle_t client,
    agent_bridge_interrupt_reason_t reason)
{
    if (!client || reason < AGENT_BRIDGE_INTERRUPT_USER_BARGE_IN ||
        reason > AGENT_BRIDGE_INTERRUPT_SESSION_CLOSED) {
        return ESP_ERR_INVALID_ARG;
    }
    atomic_store_explicit(&client->pending_interrupt_reason, reason,
                          memory_order_release);
    xEventGroupSetBits(client->signals, CLIENT_PENDING_INTERRUPT);
    return ESP_OK;
}

int device_voice_client_send_audio(void *ctx,
                                   const uint8_t *data,
                                   size_t size)
{
    device_voice_client_handle_t client = ctx;
    if (!client || !device_voice_client_ready(client)) {
        return -1;
    }
    return device_websocket_transport_send_binary(
               client->transport, data, size) == ESP_OK
               ? 0
               : -1;
}

bool device_voice_client_ready(device_voice_client_handle_t client)
{
    return client &&
           (xEventGroupGetBits(client->signals) & CLIENT_READY) != 0;
}

esp_err_t device_voice_client_get_stats(
    device_voice_client_handle_t client,
    device_voice_client_stats_t *stats)
{
    if (!client || !stats) {
        return ESP_ERR_INVALID_ARG;
    }
    *stats = (device_voice_client_stats_t){
        .control_queue_rejections = atomic_load_explicit(
            &client->control_queue_rejections, memory_order_relaxed),
        .binary_queue_drops = atomic_load_explicit(
            &client->binary_queue_drops, memory_order_relaxed),
        .protocol_errors = atomic_load_explicit(
            &client->protocol_errors, memory_order_relaxed),
        .hello_timeouts = atomic_load_explicit(
            &client->hello_timeouts, memory_order_relaxed),
        .speech_budget_exceeded = atomic_load_explicit(
            &client->speech_budget_exceeded, memory_order_relaxed),
        .speech_budget_unavailable = atomic_load_explicit(
            &client->speech_budget_unavailable, memory_order_relaxed),
    };
    return device_websocket_transport_get_stats(client->transport,
                                                 &stats->transport);
}
