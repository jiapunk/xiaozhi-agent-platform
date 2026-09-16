#include "device_websocket_transport_core.h"

#include <string.h>

enum {
    WS_OPCODE_CONTINUATION = 0,
    WS_OPCODE_TEXT = 1,
    WS_OPCODE_BINARY = 2,
};

static bool safe_identifier(const char *value)
{
    size_t length;
    if (!value || !value[0]) {
        return false;
    }
    length = strlen(value);
    if (length > DEVICE_WEBSOCKET_IDENTIFIER_MAX) {
        return false;
    }
    for (size_t index = 0; index < length; ++index) {
        const unsigned char c = (unsigned char)value[index];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == ':' || c == '-' || c == '_' ||
            c == '.') {
            continue;
        }
        return false;
    }
    return true;
}

static bool safe_uri(const char *uri)
{
    size_t length;
    if (!uri || strncmp(uri, "wss://", 6) != 0) {
        return false;
    }
    length = strlen(uri);
    if (length <= 6 || length >= DEVICE_WEBSOCKET_URI_MAX) {
        return false;
    }
    for (size_t index = 0; index < length; ++index) {
        const unsigned char c = (unsigned char)uri[index];
        if (c <= 0x20 || c == 0x7f) {
            return false;
        }
    }
    return true;
}

static bool safe_token(const char *token)
{
    size_t length;
    if (!token || !token[0]) {
        return false;
    }
    length = strlen(token);
    if (length >= DEVICE_WEBSOCKET_TOKEN_MAX) {
        return false;
    }
    for (size_t index = 0; index < length; ++index) {
        const unsigned char c = (unsigned char)token[index];
        if (c <= 0x20 || c >= 0x7f) {
            return false;
        }
    }
    return true;
}

device_websocket_core_result_t device_websocket_validate_product_config(
    const char *uri,
    const char *token,
    const char *device_id,
    const char *client_id,
    int protocol_version,
    bool has_server_certificate,
    bool use_crt_bundle)
{
    if (!safe_uri(uri) || !safe_token(token) ||
        !safe_identifier(device_id) || !safe_identifier(client_id) ||
        protocol_version < 1 || protocol_version > 3 ||
        has_server_certificate == use_crt_bundle) {
        return DEVICE_WEBSOCKET_CORE_INVALID_CONFIG;
    }
    return DEVICE_WEBSOCKET_CORE_OK;
}

void device_websocket_rx_init(device_websocket_rx_t *rx)
{
    if (rx) {
        memset(rx, 0, sizeof(*rx));
    }
}

static device_websocket_core_result_t fail_and_reset(
    device_websocket_rx_t *rx,
    device_websocket_core_result_t result)
{
    device_websocket_rx_init(rx);
    return result;
}

device_websocket_core_result_t device_websocket_rx_feed(
    device_websocket_rx_t *rx,
    uint8_t opcode,
    size_t payload_size,
    size_t payload_offset,
    bool fin,
    const uint8_t *data,
    size_t data_size,
    device_websocket_message_view_t *message)
{
    size_t maximum_size;

    if (message) {
        memset(message, 0, sizeof(*message));
    }
    if (!rx || !message || (!data && data_size > 0)) {
        return DEVICE_WEBSOCKET_CORE_INVALID_ARG;
    }

    if (payload_offset == 0) {
        if (opcode != WS_OPCODE_TEXT && opcode != WS_OPCODE_BINARY) {
            return fail_and_reset(rx, DEVICE_WEBSOCKET_CORE_MALFORMED);
        }
        maximum_size = opcode == WS_OPCODE_TEXT
                           ? DEVICE_WEBSOCKET_CONTROL_MAX
                           : DEVICE_WEBSOCKET_BINARY_MAX;
        if (payload_size == 0 || payload_size > maximum_size) {
            return fail_and_reset(rx, DEVICE_WEBSOCKET_CORE_TOO_LARGE);
        }
        rx->expected_size = payload_size;
        rx->received_size = 0;
        rx->opcode = opcode;
        rx->active = true;
    } else if (!rx->active ||
               (opcode != WS_OPCODE_CONTINUATION && opcode != rx->opcode) ||
               payload_size != rx->expected_size ||
               payload_offset != rx->received_size) {
        return fail_and_reset(rx, DEVICE_WEBSOCKET_CORE_MALFORMED);
    }

    if (!rx->active || data_size == 0 || payload_offset != rx->received_size ||
        data_size > rx->expected_size - rx->received_size) {
        return fail_and_reset(rx, DEVICE_WEBSOCKET_CORE_MALFORMED);
    }
    memcpy(rx->data + rx->received_size, data, data_size);
    rx->received_size += data_size;
    if (rx->received_size < rx->expected_size) {
        return DEVICE_WEBSOCKET_CORE_OK;
    }
    if (!fin) {
        return fail_and_reset(rx, DEVICE_WEBSOCKET_CORE_MALFORMED);
    }

    message->data = rx->data;
    message->size = rx->received_size;
    message->opcode = rx->opcode;
    rx->expected_size = 0;
    rx->received_size = 0;
    rx->opcode = 0;
    rx->active = false;
    return DEVICE_WEBSOCKET_CORE_COMPLETE;
}
