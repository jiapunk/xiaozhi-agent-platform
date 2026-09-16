idf_component_register(
    SRCS
        "agent_control_plane_client.c"
        "agent_control_plane_protocol.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "private_include"
    REQUIRES
        esp_http_client
        esp_system
        heap
        mbedtls
        espressif__cjson
)
