idf_component_register(
    SRCS
        "device_websocket_transport.c"
        "device_websocket_transport_core.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "private_include"
    REQUIRES esp_websocket_client freertos heap mbedtls
)
