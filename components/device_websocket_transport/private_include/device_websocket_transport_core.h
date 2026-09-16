#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "device_websocket_limits.h"

typedef enum {
    DEVICE_WEBSOCKET_CORE_OK = 0,
    DEVICE_WEBSOCKET_CORE_COMPLETE,
    DEVICE_WEBSOCKET_CORE_INVALID_ARG,
    DEVICE_WEBSOCKET_CORE_INVALID_CONFIG,
    DEVICE_WEBSOCKET_CORE_MALFORMED,
    DEVICE_WEBSOCKET_CORE_TOO_LARGE,
} device_websocket_core_result_t;

typedef struct {
    uint8_t data[DEVICE_WEBSOCKET_BINARY_MAX];
    size_t expected_size;
    size_t received_size;
    uint8_t opcode;
    bool active;
} device_websocket_rx_t;

typedef struct {
    const uint8_t *data;
    size_t size;
    uint8_t opcode;
} device_websocket_message_view_t;

device_websocket_core_result_t device_websocket_validate_product_config(
    const char *uri,
    const char *token,
    const char *device_id,
    const char *client_id,
    int protocol_version,
    bool has_server_certificate,
    bool use_crt_bundle);

void device_websocket_rx_init(device_websocket_rx_t *rx);
device_websocket_core_result_t device_websocket_rx_feed(
    device_websocket_rx_t *rx,
    uint8_t opcode,
    size_t payload_size,
    size_t payload_offset,
    bool fin,
    const uint8_t *data,
    size_t data_size,
    device_websocket_message_view_t *message);
