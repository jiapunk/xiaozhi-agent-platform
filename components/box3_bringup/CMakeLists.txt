idf_component_register(
    SRCS "box3_bringup.c"
    INCLUDE_DIRS "include"
    REQUIRES box3_audio esp_claw_runtime product_status_indicator product_sku
             esp_driver_gpio freertos log
)
