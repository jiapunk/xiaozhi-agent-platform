idf_component_register(
    SRCS "product_storage.c" "product_storage_core.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "private_include"
    REQUIRES efuse nvs_flash nvs_sec_provider
)
