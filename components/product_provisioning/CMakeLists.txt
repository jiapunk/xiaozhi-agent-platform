idf_component_register(
    SRCS
        "product_provisioning.c"
        "product_provisioning_core.c"
        "product_provisioning_material_core.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "private_include"
    REQUIRES
        esp_event esp_netif esp_timer esp_wifi freertos nvs_flash
        product_storage product_wifi protocomm mbedtls
        espressif__network_provisioning
)
