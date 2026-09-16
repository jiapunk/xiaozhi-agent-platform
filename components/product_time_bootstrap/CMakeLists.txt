idf_component_register(
    SRCS
        "product_time_bootstrap.c"
        "product_time_bootstrap_core.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_netif esp_system esp_timer freertos heap lwip
)
