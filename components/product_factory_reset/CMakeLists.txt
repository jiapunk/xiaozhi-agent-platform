idf_component_register(
    SRCS
        "product_factory_reset.c"
        "product_factory_reset_core.c"
    INCLUDE_DIRS "include"
    REQUIRES nvs_flash product_storage
)
