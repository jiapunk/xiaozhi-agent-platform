idf_component_register(
    SRCS "product_status_indicator.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_driver_gpio heap product_sku
)
