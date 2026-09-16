idf_component_register(
    SRCS
        "device_voice_client.c"
        "device_voice_client_protocol.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "private_include"
    REQUIRES
        device_voice_runtime
        device_websocket_transport
        espressif__cjson
        esp_timer
        freertos
        heap
)
