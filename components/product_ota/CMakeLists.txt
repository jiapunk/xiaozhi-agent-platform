idf_component_register(
    SRCS "product_ota.c" "product_ota_core.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "private_include"
    REQUIRES
        app_update esp_app_format esp_http_client esp_https_ota
        esp_partition mbedtls espressif__cjson
)
