idf_component_register(
    SRCS "product_ota_client.c" "product_ota_client_protocol.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "private_include"
    REQUIRES
        esp_http_client esp_hw_support mbedtls product_ota espressif__cjson
)
