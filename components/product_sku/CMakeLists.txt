idf_component_register(
    SRCS "product_sku.c" "product_sku_core.c"
    INCLUDE_DIRS "include"
    REQUIRES efuse esp_hw_support esp_security nvs_flash product_storage spi_flash esp_psram
)
