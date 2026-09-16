#include "device_websocket_transport.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#include "device_websocket_transport_core.h"
#include "esp_crt_bundle.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_websocket_client.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/queue.h"
#include "freertos/task.h"

static const char *TAG = "device_ws";

enum {
    TRANSPORT_CONNECTED = BIT0,
    TRANSPORT_CLOSING = BIT1,
    TRANSPORT_STOP_TX = BIT2,
    TRANSPORT_TX_STOPPED = BIT3,
    TRANSPORT_TASK_STOP_TIMEOUT_MS = 3000,
};

typedef struct {
    size_t size;
    uint8_t data[DEVICE_WEBSOCKET_CONTROL_MAX];
} control_item_t;

typedef struct {
    size_t size;
    uint8_t data[DEVICE_WEBSOCKET_BINARY_MAX];
} binary_item_t;

typedef struct {
    atomic_uint connections;
    atomic_uint disconnections;
    atomic_uint received_text_messages;
    atomic_uint received_binary_messages;
    atomic_uint malformed_messages;
    atomic_uint sent_text_messages;
    atomic_uint sent_binary_messages;
    atomic_uint send_errors;
    atomic_uint audio_drops;
    atomic_uint control_rejections;
} atomic_stats_t;

struct device_websocket_transport {
    char uri[DEVICE_WEBSOCKET_URI_MAX];
    char token[DEVICE_WEBSOCKET_TOKEN_MAX];
    char authorization[DEVICE_WEBSOCKET_TOKEN_MAX + 8];
    char device_id[DEVICE_WEBSOCKET_IDENTIFIER_MAX + 1];
    char client_id[DEVICE_WEBSOCKET_IDENTIFIER_MAX + 1];
    char protocol_version[2];
    const char *server_cert_pem;
    bool use_crt_bundle;
    uint32_t send_timeout_ms;
    device_websocket_event_fn event;
    void *event_ctx;

    esp_websocket_client_handle_t client;
    EventGroupHandle_t events;
    QueueHandle_t free_control;
    QueueHandle_t control_queue;
    QueueHandle_t free_binary;
    QueueHandle_t binary_queue;
    TaskHandle_t tx_task;
    control_item_t *control_pool;
    binary_item_t *binary_pool;
    device_websocket_rx_t rx;
    atomic_bool started;
    atomic_bool destroying;
    atomic_stats_t stats;
};

static void *allocate_pool(size_t size)
{
    void *memory = heap_caps_calloc(1, size,
                                    MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!memory) {
        memory = heap_caps_calloc(1, size,
                                  MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    }
    return memory;
}

static bool copy_string(char *output, size_t capacity, const char *input)
{
    size_t length;
    if (!output || capacity == 0 || !input) {
        return false;
    }
    length = strlen(input);
    if (length >= capacity) {
        return false;
    }
    memcpy(output, input, length + 1);
    return true;
}

static void emit_event(device_websocket_transport_handle_t transport,
                       const device_websocket_event_t *event)
{
    if (!atomic_load_explicit(&transport->destroying,
                              memory_order_acquire) &&
        transport->event) {
        transport->event(transport->event_ctx, event);
    }
}

static void emit_simple_event(device_websocket_transport_handle_t transport,
                              device_websocket_event_type_t type)
{
    const device_websocket_event_t event = {
        .type = type,
    };
    emit_event(transport, &event);
}

static void emit_error(device_websocket_transport_handle_t transport,
                       device_websocket_error_source_t source,
                       esp_err_t esp_error,
                       int tls_stack_error,
                       int certificate_verify_flags,
                       int handshake_status,
                       int socket_errno)
{
    const device_websocket_event_t event = {
        .type = DEVICE_WEBSOCKET_EVENT_ERROR,
        .error_source = source,
        .esp_error = esp_error,
        .tls_stack_error = tls_stack_error,
        .certificate_verify_flags = certificate_verify_flags,
        .handshake_status = handshake_status,
        .socket_errno = socket_errno,
    };
    emit_event(transport, &event);
}

static bool connected_for_send(
    device_websocket_transport_handle_t transport)
{
    EventBits_t bits = xEventGroupGetBits(transport->events);
    return (bits & TRANSPORT_CONNECTED) != 0 &&
           (bits & (TRANSPORT_CLOSING | TRANSPORT_STOP_TX)) == 0;
}

static void return_control(device_websocket_transport_handle_t transport,
                           control_item_t *item)
{
    if (item && xQueueSend(transport->free_control, &item, 0) != pdTRUE) {
        ESP_LOGE(TAG, "Control pool invariant violated");
    }
}

static void return_binary(device_websocket_transport_handle_t transport,
                          binary_item_t *item)
{
    if (item && xQueueSend(transport->free_binary, &item, 0) != pdTRUE) {
        ESP_LOGE(TAG, "Binary pool invariant violated");
    }
}

static void flush_tx_queues(device_websocket_transport_handle_t transport)
{
    control_item_t *control = NULL;
    binary_item_t *binary = NULL;
    while (xQueueReceive(transport->control_queue, &control, 0) == pdTRUE) {
        return_control(transport, control);
    }
    while (xQueueReceive(transport->binary_queue, &binary, 0) == pdTRUE) {
        return_binary(transport, binary);
    }
}

static void tx_task_entry(void *argument)
{
    device_websocket_transport_handle_t transport = argument;

    for (;;) {
        if ((xEventGroupGetBits(transport->events) & TRANSPORT_STOP_TX) != 0) {
            break;
        }

        control_item_t *control = NULL;
        if (xQueueReceive(transport->control_queue, &control, 0) == pdTRUE) {
            int sent = -1;
            if (connected_for_send(transport)) {
                sent = esp_websocket_client_send_text(
                    transport->client, (const char *)control->data,
                    (int)control->size,
                    pdMS_TO_TICKS(transport->send_timeout_ms));
            }
            if (sent == (int)control->size) {
                atomic_fetch_add_explicit(&transport->stats.sent_text_messages,
                                          1, memory_order_relaxed);
            } else {
                atomic_fetch_add_explicit(&transport->stats.send_errors, 1,
                                          memory_order_relaxed);
                emit_error(transport, DEVICE_WEBSOCKET_ERROR_SEND,
                           ESP_FAIL, 0, 0, 0, 0);
            }
            return_control(transport, control);
            continue;
        }

        binary_item_t *binary = NULL;
        if (xQueueReceive(transport->binary_queue, &binary,
                          pdMS_TO_TICKS(10)) == pdTRUE) {
            int sent = -1;
            if (connected_for_send(transport)) {
                sent = esp_websocket_client_send_bin(
                    transport->client, (const char *)binary->data,
                    (int)binary->size,
                    pdMS_TO_TICKS(transport->send_timeout_ms));
            }
            if (sent == (int)binary->size) {
                atomic_fetch_add_explicit(&transport->stats.sent_binary_messages,
                                          1, memory_order_relaxed);
            } else {
                atomic_fetch_add_explicit(&transport->stats.send_errors, 1,
                                          memory_order_relaxed);
                emit_error(transport, DEVICE_WEBSOCKET_ERROR_SEND,
                           ESP_FAIL, 0, 0, 0, 0);
            }
            return_binary(transport, binary);
        }
    }

    flush_tx_queues(transport);
    xEventGroupSetBits(transport->events, TRANSPORT_TX_STOPPED);
    transport->tx_task = NULL;
    vTaskDelete(NULL);
}

static device_websocket_error_source_t map_error_source(
    const esp_websocket_error_codes_t *error)
{
    if (!error) {
        return DEVICE_WEBSOCKET_ERROR_CLIENT;
    }
    switch (error->error_type) {
    case WEBSOCKET_ERROR_TYPE_HANDSHAKE:
        return DEVICE_WEBSOCKET_ERROR_HANDSHAKE;
    case WEBSOCKET_ERROR_TYPE_TCP_TRANSPORT:
        return error->esp_tls_cert_verify_flags != 0
                   ? DEVICE_WEBSOCKET_ERROR_TLS
                   : DEVICE_WEBSOCKET_ERROR_CLIENT;
    default:
        return DEVICE_WEBSOCKET_ERROR_CLIENT;
    }
}

static void handle_data_event(device_websocket_transport_handle_t transport,
                              const esp_websocket_event_data_t *data)
{
    device_websocket_message_view_t message;
    device_websocket_core_result_t result;

    if (!data || data->data_len < 0 || data->payload_len < 0 ||
        data->payload_offset < 0) {
        result = DEVICE_WEBSOCKET_CORE_MALFORMED;
    } else {
        result = device_websocket_rx_feed(
            &transport->rx, data->op_code, (size_t)data->payload_len,
            (size_t)data->payload_offset, data->fin,
            (const uint8_t *)data->data_ptr, (size_t)data->data_len, &message);
    }
    if (result == DEVICE_WEBSOCKET_CORE_OK) {
        return;
    }
    if (result != DEVICE_WEBSOCKET_CORE_COMPLETE) {
        atomic_fetch_add_explicit(&transport->stats.malformed_messages, 1,
                                  memory_order_relaxed);
        emit_error(transport, DEVICE_WEBSOCKET_ERROR_PROTOCOL,
                   ESP_ERR_INVALID_RESPONSE, 0, 0, 0, 0);
        return;
    }

    device_websocket_event_t event = {
        .type = message.opcode == 1 ? DEVICE_WEBSOCKET_EVENT_TEXT
                                    : DEVICE_WEBSOCKET_EVENT_BINARY,
        .data = message.data,
        .size = message.size,
    };
    if (event.type == DEVICE_WEBSOCKET_EVENT_TEXT) {
        atomic_fetch_add_explicit(&transport->stats.received_text_messages, 1,
                                  memory_order_relaxed);
    } else {
        atomic_fetch_add_explicit(&transport->stats.received_binary_messages, 1,
                                  memory_order_relaxed);
    }
    emit_event(transport, &event);
}

static void websocket_event_handler(void *handler_args,
                                    esp_event_base_t event_base,
                                    int32_t event_id,
                                    void *event_data)
{
    (void)event_base;
    device_websocket_transport_handle_t transport = handler_args;
    esp_websocket_event_data_t *data = event_data;

    switch ((esp_websocket_event_id_t)event_id) {
    case WEBSOCKET_EVENT_CONNECTED: {
        device_websocket_rx_init(&transport->rx);
        if ((xEventGroupGetBits(transport->events) &
             (TRANSPORT_CLOSING | TRANSPORT_STOP_TX)) != 0) {
            break;
        }
        xEventGroupSetBits(transport->events, TRANSPORT_CONNECTED);
        atomic_fetch_add_explicit(&transport->stats.connections, 1,
                                  memory_order_relaxed);
        emit_simple_event(transport, DEVICE_WEBSOCKET_EVENT_CONNECTED);
        break;
    }
    case WEBSOCKET_EVENT_DATA:
        if (data && (data->op_code == 0 || data->op_code == 1 ||
                     data->op_code == 2)) {
            handle_data_event(transport, data);
        }
        break;
    case WEBSOCKET_EVENT_ERROR: {
        const esp_websocket_error_codes_t *error =
            data ? &data->error_handle : NULL;
        emit_error(transport, map_error_source(error),
                   error ? error->esp_tls_last_esp_err : ESP_FAIL,
                   error ? error->esp_tls_stack_err : 0,
                   error ? error->esp_tls_cert_verify_flags : 0,
                   error ? error->esp_ws_handshake_status_code : 0,
                   error ? error->esp_transport_sock_errno : 0);
        break;
    }
    case WEBSOCKET_EVENT_DISCONNECTED:
    case WEBSOCKET_EVENT_CLOSED: {
        EventBits_t previous = xEventGroupClearBits(
            transport->events, TRANSPORT_CONNECTED);
        device_websocket_rx_init(&transport->rx);
        flush_tx_queues(transport);
        if ((previous & TRANSPORT_CONNECTED) != 0) {
            atomic_fetch_add_explicit(&transport->stats.disconnections, 1,
                                      memory_order_relaxed);
            emit_simple_event(transport,
                              DEVICE_WEBSOCKET_EVENT_DISCONNECTED);
        }
        break;
    }
    case WEBSOCKET_EVENT_FINISH:
        atomic_store_explicit(&transport->started, false,
                              memory_order_release);
        break;
    default:
        break;
    }
}

static void cleanup_unstarted(device_websocket_transport_handle_t transport)
{
    if (!transport) {
        return;
    }
    if (transport->client) {
        (void)esp_websocket_unregister_events(
            transport->client, WEBSOCKET_EVENT_ANY, websocket_event_handler);
        (void)esp_websocket_client_destroy(transport->client);
    }
    if (transport->binary_queue) {
        vQueueDelete(transport->binary_queue);
    }
    if (transport->free_binary) {
        vQueueDelete(transport->free_binary);
    }
    if (transport->control_queue) {
        vQueueDelete(transport->control_queue);
    }
    if (transport->free_control) {
        vQueueDelete(transport->free_control);
    }
    if (transport->events) {
        vEventGroupDelete(transport->events);
    }
    heap_caps_free(transport->binary_pool);
    heap_caps_free(transport->control_pool);
    heap_caps_free(transport);
}

esp_err_t device_websocket_transport_create(
    const device_websocket_transport_config_t *config,
    device_websocket_transport_handle_t *out_transport)
{
    device_websocket_transport_handle_t transport;
    esp_websocket_client_config_t websocket_config = {0};
    esp_err_t result;

    if (!out_transport) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_transport = NULL;
    if (!config || !config->event ||
        device_websocket_validate_product_config(
            config->uri, config->bearer_token, config->device_id,
            config->client_id, config->protocol_version,
            config->server_cert_pem && config->server_cert_pem[0],
            config->use_crt_bundle) !=
            DEVICE_WEBSOCKET_CORE_OK ||
        config->network_timeout_ms < 1000 ||
        config->network_timeout_ms > 60000 ||
        config->send_timeout_ms < 50 || config->send_timeout_ms > 2000 ||
        config->ping_interval_seconds < 5 ||
        config->ping_interval_seconds > 120 ||
        config->pong_timeout_seconds < 5 ||
        config->pong_timeout_seconds > 120) {
        return ESP_ERR_INVALID_ARG;
    }
#if !CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
    if (config->use_crt_bundle) {
        return ESP_ERR_NOT_SUPPORTED;
    }
#endif
    transport = heap_caps_calloc(1, sizeof(*transport),
                                 MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!transport) {
        return ESP_ERR_NO_MEM;
    }
    if (!copy_string(transport->uri, sizeof(transport->uri), config->uri) ||
        !copy_string(transport->token, sizeof(transport->token),
                     config->bearer_token) ||
        !copy_string(transport->device_id, sizeof(transport->device_id),
                     config->device_id) ||
        !copy_string(transport->client_id, sizeof(transport->client_id),
                     config->client_id) ||
        snprintf(transport->authorization, sizeof(transport->authorization),
                 "Bearer %s", transport->token) <= 0 ||
        snprintf(transport->protocol_version,
                 sizeof(transport->protocol_version), "%d",
                 config->protocol_version) != 1) {
        cleanup_unstarted(transport);
        return ESP_ERR_INVALID_ARG;
    }
    transport->server_cert_pem = config->server_cert_pem;
    transport->use_crt_bundle = config->use_crt_bundle;
    transport->send_timeout_ms = config->send_timeout_ms;
    transport->event = config->event;
    transport->event_ctx = config->event_ctx;
    device_websocket_rx_init(&transport->rx);

    transport->events = xEventGroupCreate();
    transport->free_control = xQueueCreate(
        DEVICE_WEBSOCKET_TX_QUEUE_DEPTH, sizeof(control_item_t *));
    transport->control_queue = xQueueCreate(
        DEVICE_WEBSOCKET_TX_QUEUE_DEPTH, sizeof(control_item_t *));
    transport->free_binary = xQueueCreate(
        DEVICE_WEBSOCKET_TX_QUEUE_DEPTH, sizeof(binary_item_t *));
    transport->binary_queue = xQueueCreate(
        DEVICE_WEBSOCKET_TX_QUEUE_DEPTH, sizeof(binary_item_t *));
    transport->control_pool = allocate_pool(
        DEVICE_WEBSOCKET_TX_QUEUE_DEPTH * sizeof(control_item_t));
    transport->binary_pool = allocate_pool(
        DEVICE_WEBSOCKET_TX_QUEUE_DEPTH * sizeof(binary_item_t));
    if (!transport->events || !transport->free_control ||
        !transport->control_queue || !transport->free_binary ||
        !transport->binary_queue || !transport->control_pool ||
        !transport->binary_pool) {
        cleanup_unstarted(transport);
        return ESP_ERR_NO_MEM;
    }
    for (size_t index = 0; index < DEVICE_WEBSOCKET_TX_QUEUE_DEPTH; ++index) {
        control_item_t *control = &transport->control_pool[index];
        binary_item_t *binary = &transport->binary_pool[index];
        if (xQueueSend(transport->free_control, &control, 0) != pdTRUE ||
            xQueueSend(transport->free_binary, &binary, 0) != pdTRUE) {
            cleanup_unstarted(transport);
            return ESP_FAIL;
        }
    }

    websocket_config.uri = transport->uri;
    websocket_config.disable_auto_reconnect = true;
    websocket_config.user_context = transport;
    websocket_config.task_name = "device_ws_client";
    websocket_config.task_prio = 5;
    websocket_config.task_stack = 8192;
    websocket_config.buffer_size = DEVICE_WEBSOCKET_CONTROL_MAX;
    websocket_config.cert_pem = transport->server_cert_pem;
#if CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
    websocket_config.crt_bundle_attach =
        transport->use_crt_bundle ? esp_crt_bundle_attach : NULL;
#endif
    websocket_config.skip_cert_common_name_check = false;
    websocket_config.keep_alive_enable = true;
    websocket_config.keep_alive_idle = 15;
    websocket_config.keep_alive_interval = 5;
    websocket_config.keep_alive_count = 3;
    websocket_config.network_timeout_ms = (int)config->network_timeout_ms;
    websocket_config.ping_interval_sec = config->ping_interval_seconds;
    websocket_config.pingpong_timeout_sec =
        (int)config->pong_timeout_seconds;
    transport->client = esp_websocket_client_init(&websocket_config);
    if (!transport->client) {
        cleanup_unstarted(transport);
        return ESP_FAIL;
    }
    result = esp_websocket_client_append_header(
        transport->client, "Authorization", transport->authorization);
    if (result == ESP_OK) {
        result = esp_websocket_client_append_header(
            transport->client, "Protocol-Version",
            transport->protocol_version);
    }
    if (result == ESP_OK) {
        result = esp_websocket_client_append_header(
            transport->client, "Device-Id", transport->device_id);
    }
    if (result == ESP_OK) {
        result = esp_websocket_client_append_header(
            transport->client, "Client-Id", transport->client_id);
    }
    if (result == ESP_OK) {
        result = esp_websocket_register_events(
            transport->client, WEBSOCKET_EVENT_ANY,
            websocket_event_handler, transport);
    }
    if (result != ESP_OK ||
        xTaskCreate(tx_task_entry, "device_ws_tx", 6144, transport, 6,
                    &transport->tx_task) != pdPASS) {
        cleanup_unstarted(transport);
        return result != ESP_OK ? result : ESP_ERR_NO_MEM;
    }

    *out_transport = transport;
    return ESP_OK;
}

esp_err_t device_websocket_transport_start(
    device_websocket_transport_handle_t transport)
{
    bool expected = false;
    if (!transport) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!atomic_compare_exchange_strong_explicit(
            &transport->started, &expected, true,
            memory_order_acq_rel, memory_order_acquire)) {
        return ESP_ERR_INVALID_STATE;
    }
    xEventGroupClearBits(transport->events,
                         TRANSPORT_CLOSING | TRANSPORT_CONNECTED);
    esp_err_t result = esp_websocket_client_start(transport->client);
    if (result != ESP_OK) {
        atomic_store_explicit(&transport->started, false,
                              memory_order_release);
    }
    return result;
}

esp_err_t device_websocket_transport_close(
    device_websocket_transport_handle_t transport,
    uint32_t timeout_ms)
{
    if (!transport || timeout_ms == 0 || timeout_ms > 10000) {
        return ESP_ERR_INVALID_ARG;
    }
    xEventGroupSetBits(transport->events, TRANSPORT_CLOSING);
    flush_tx_queues(transport);
    if (!atomic_load_explicit(&transport->started, memory_order_acquire)) {
        xEventGroupClearBits(transport->events, TRANSPORT_CONNECTED);
        return ESP_OK;
    }
    return esp_websocket_client_close(transport->client,
                                      pdMS_TO_TICKS(timeout_ms));
}

esp_err_t device_websocket_transport_destroy(
    device_websocket_transport_handle_t transport)
{
    esp_err_t result;

    if (!transport) {
        return ESP_OK;
    }
    atomic_store_explicit(&transport->destroying, true, memory_order_release);
    xEventGroupSetBits(transport->events,
                       TRANSPORT_CLOSING | TRANSPORT_STOP_TX);
    xEventGroupClearBits(transport->events, TRANSPORT_CONNECTED);
    flush_tx_queues(transport);
    if (atomic_load_explicit(&transport->started, memory_order_acquire)) {
        (void)esp_websocket_client_stop(transport->client);
    }
    if (transport->tx_task) {
        EventBits_t bits = xEventGroupWaitBits(
            transport->events, TRANSPORT_TX_STOPPED,
            pdFALSE, pdTRUE,
            pdMS_TO_TICKS(TRANSPORT_TASK_STOP_TIMEOUT_MS));
        if ((bits & TRANSPORT_TX_STOPPED) == 0) {
            ESP_LOGE(TAG, "TX worker shutdown timed out; retaining resources");
            return ESP_ERR_TIMEOUT;
        }
    }
    (void)esp_websocket_unregister_events(
        transport->client, WEBSOCKET_EVENT_ANY, websocket_event_handler);
    result = esp_websocket_client_destroy(transport->client);
    if (result != ESP_OK) {
        ESP_LOGE(TAG, "WebSocket client destroy failed; retaining resources");
        return result;
    }
    transport->client = NULL;
    cleanup_unstarted(transport);
    return ESP_OK;
}

bool device_websocket_transport_connected(
    device_websocket_transport_handle_t transport)
{
    return transport && connected_for_send(transport);
}

esp_err_t device_websocket_transport_send_text(
    device_websocket_transport_handle_t transport,
    const char *data,
    size_t size)
{
    control_item_t *item = NULL;
    if (!transport || !data || size == 0 ||
        size > DEVICE_WEBSOCKET_CONTROL_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!connected_for_send(transport)) {
        return ESP_ERR_INVALID_STATE;
    }
    if (xQueueReceive(transport->free_control, &item, 0) != pdTRUE) {
        atomic_fetch_add_explicit(&transport->stats.control_rejections, 1,
                                  memory_order_relaxed);
        return ESP_ERR_NO_MEM;
    }
    item->size = size;
    memcpy(item->data, data, size);
    if (xQueueSend(transport->control_queue, &item, 0) != pdTRUE) {
        return_control(transport, item);
        atomic_fetch_add_explicit(&transport->stats.control_rejections, 1,
                                  memory_order_relaxed);
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

esp_err_t device_websocket_transport_send_binary(
    device_websocket_transport_handle_t transport,
    const uint8_t *data,
    size_t size)
{
    binary_item_t *item = NULL;
    bool dropped = false;
    if (!transport || !data || size == 0 ||
        size > DEVICE_WEBSOCKET_BINARY_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!connected_for_send(transport)) {
        return ESP_ERR_INVALID_STATE;
    }
    if (xQueueReceive(transport->free_binary, &item, 0) != pdTRUE) {
        if (xQueueReceive(transport->binary_queue, &item, 0) != pdTRUE) {
            atomic_fetch_add_explicit(&transport->stats.audio_drops, 1,
                                      memory_order_relaxed);
            emit_simple_event(transport,
                              DEVICE_WEBSOCKET_EVENT_AUDIO_DROPPED);
            return ESP_ERR_NO_MEM;
        }
        dropped = true;
    }
    item->size = size;
    memcpy(item->data, data, size);
    if (xQueueSend(transport->binary_queue, &item, 0) != pdTRUE) {
        return_binary(transport, item);
        atomic_fetch_add_explicit(&transport->stats.audio_drops, 1,
                                  memory_order_relaxed);
        emit_simple_event(transport, DEVICE_WEBSOCKET_EVENT_AUDIO_DROPPED);
        return ESP_ERR_NO_MEM;
    }
    if (dropped) {
        atomic_fetch_add_explicit(&transport->stats.audio_drops, 1,
                                  memory_order_relaxed);
        emit_simple_event(transport, DEVICE_WEBSOCKET_EVENT_AUDIO_DROPPED);
    }
    return ESP_OK;
}

esp_err_t device_websocket_transport_get_stats(
    device_websocket_transport_handle_t transport,
    device_websocket_transport_stats_t *stats)
{
    if (!transport || !stats) {
        return ESP_ERR_INVALID_ARG;
    }
    *stats = (device_websocket_transport_stats_t){
        .connections = atomic_load_explicit(&transport->stats.connections,
                                            memory_order_relaxed),
        .disconnections = atomic_load_explicit(
            &transport->stats.disconnections, memory_order_relaxed),
        .received_text_messages = atomic_load_explicit(
            &transport->stats.received_text_messages, memory_order_relaxed),
        .received_binary_messages = atomic_load_explicit(
            &transport->stats.received_binary_messages,
            memory_order_relaxed),
        .malformed_messages = atomic_load_explicit(
            &transport->stats.malformed_messages, memory_order_relaxed),
        .sent_text_messages = atomic_load_explicit(
            &transport->stats.sent_text_messages, memory_order_relaxed),
        .sent_binary_messages = atomic_load_explicit(
            &transport->stats.sent_binary_messages, memory_order_relaxed),
        .send_errors = atomic_load_explicit(&transport->stats.send_errors,
                                            memory_order_relaxed),
        .audio_drops = atomic_load_explicit(&transport->stats.audio_drops,
                                            memory_order_relaxed),
        .control_rejections = atomic_load_explicit(
            &transport->stats.control_rejections, memory_order_relaxed),
    };
    return ESP_OK;
}
