idf_component_register(
    SRCS
        "product_local_action.c"
        "product_local_action_core.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_driver_gpio esp_timer freertos heap
)
