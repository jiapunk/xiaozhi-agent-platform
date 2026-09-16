idf_component_register(
    SRCS
        "product_wifi.c"
        "product_wifi_core.c"
        "product_wifi_credential_set_core.c"
        "product_wifi_credentials_core.c"
        "product_wifi_state_core.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "private_include"
    REQUIRES
        esp_event esp_netif esp_timer esp_wifi freertos nvs_flash
        product_storage
)
