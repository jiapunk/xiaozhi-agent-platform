idf_component_register(
    SRCS
        "box3_agent_credentials_client.c"
        "box3_agent_credentials_protocol.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "private_include"
    REQUIRES
        box3_agent_supervisor
        esp_http_client
        esp_system
        heap
        mbedtls
        espressif__cjson
)
