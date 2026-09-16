#include "device_websocket_transport_core.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                    \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,          \
                    #condition);                                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static int test_product_configuration_is_fail_closed(void)
{
    CHECK(device_websocket_validate_product_config(
              "wss://gateway.example/v1/device", "v1.payload.signature",
              "device-1", "client:one", 2, false, true) ==
          DEVICE_WEBSOCKET_CORE_OK);
    CHECK(device_websocket_validate_product_config(
              "wss://gateway.example/v1/device", "v1.payload.signature",
              "device-1", "client:one", 3, true, false) ==
          DEVICE_WEBSOCKET_CORE_OK);

    CHECK(device_websocket_validate_product_config(
              "ws://gateway.example/v1/device", "token", "device-1",
              "client-1", 2, false, true) ==
          DEVICE_WEBSOCKET_CORE_INVALID_CONFIG);
    CHECK(device_websocket_validate_product_config(
              "wss://gateway.example/v1/device", "token\r\ninjected: yes",
              "device-1", "client-1", 2, false, true) ==
          DEVICE_WEBSOCKET_CORE_INVALID_CONFIG);
    CHECK(device_websocket_validate_product_config(
              "wss://gateway.example/v1/device", "token", "device/../1",
              "client-1", 2, false, true) ==
          DEVICE_WEBSOCKET_CORE_INVALID_CONFIG);
    CHECK(device_websocket_validate_product_config(
              "wss://gateway.example/v1/device", "token", "device-1",
              "client 1", 2, false, true) ==
          DEVICE_WEBSOCKET_CORE_INVALID_CONFIG);
    CHECK(device_websocket_validate_product_config(
              "wss://gateway.example/v1/device", "token", "device-1",
              "client-1", 0, false, true) ==
          DEVICE_WEBSOCKET_CORE_INVALID_CONFIG);
    CHECK(device_websocket_validate_product_config(
              "wss://gateway.example/v1/device", "token", "device-1",
              "client-1", 2, false, false) ==
          DEVICE_WEBSOCKET_CORE_INVALID_CONFIG);
    CHECK(device_websocket_validate_product_config(
              "wss://gateway.example/v1/device", "token", "device-1",
              "client-1", 2, true, true) ==
          DEVICE_WEBSOCKET_CORE_INVALID_CONFIG);
    return 0;
}

static int test_complete_and_chunked_messages(void)
{
    device_websocket_rx_t rx;
    device_websocket_message_view_t message;
    const uint8_t json[] = "{\"type\":\"hello\"}";
    const uint8_t binary[] = {1, 2, 3, 4, 5, 6};

    device_websocket_rx_init(&rx);
    CHECK(device_websocket_rx_feed(
              &rx, 1, sizeof(json) - 1, 0, true, json, sizeof(json) - 1,
              &message) == DEVICE_WEBSOCKET_CORE_COMPLETE);
    CHECK(message.opcode == 1 && message.size == sizeof(json) - 1);
    CHECK(memcmp(message.data, json, message.size) == 0);

    CHECK(device_websocket_rx_feed(
              &rx, 2, sizeof(binary), 0, true, binary, 2, &message) ==
          DEVICE_WEBSOCKET_CORE_OK);
    CHECK(device_websocket_rx_feed(
              &rx, 0, sizeof(binary), 2, true, binary + 2, 3, &message) ==
          DEVICE_WEBSOCKET_CORE_OK);
    CHECK(device_websocket_rx_feed(
              &rx, 2, sizeof(binary), 5, true, binary + 5, 1, &message) ==
          DEVICE_WEBSOCKET_CORE_COMPLETE);
    CHECK(message.opcode == 2 && message.size == sizeof(binary));
    CHECK(memcmp(message.data, binary, sizeof(binary)) == 0);
    return 0;
}

static int test_malformed_fragments_reset_state(void)
{
    device_websocket_rx_t rx;
    device_websocket_message_view_t message;
    const uint8_t bytes[] = {1, 2, 3, 4};

    device_websocket_rx_init(&rx);
    CHECK(device_websocket_rx_feed(
              &rx, 2, sizeof(bytes), 0, true, bytes, 2, &message) ==
          DEVICE_WEBSOCKET_CORE_OK);
    CHECK(device_websocket_rx_feed(
              &rx, 0, sizeof(bytes), 3, true, bytes + 2, 2, &message) ==
          DEVICE_WEBSOCKET_CORE_MALFORMED);
    CHECK(!rx.active);

    CHECK(device_websocket_rx_feed(
              &rx, 0, sizeof(bytes), 1, true, bytes, 1, &message) ==
          DEVICE_WEBSOCKET_CORE_MALFORMED);
    CHECK(device_websocket_rx_feed(
              &rx, 2, sizeof(bytes), 0, false, bytes, sizeof(bytes),
              &message) == DEVICE_WEBSOCKET_CORE_MALFORMED);
    CHECK(device_websocket_rx_feed(
              &rx, 1, DEVICE_WEBSOCKET_CONTROL_MAX + 1, 0, true,
              bytes, sizeof(bytes), &message) ==
          DEVICE_WEBSOCKET_CORE_TOO_LARGE);
    CHECK(device_websocket_rx_feed(
              &rx, 2, 0, 0, true, bytes, 1, &message) ==
          DEVICE_WEBSOCKET_CORE_TOO_LARGE);
    return 0;
}

int main(void)
{
    CHECK(test_product_configuration_is_fail_closed() == 0);
    CHECK(test_complete_and_chunked_messages() == 0);
    CHECK(test_malformed_fragments_reset_state() == 0);
    puts("device_websocket_transport_core: all host tests passed");
    return 0;
}
