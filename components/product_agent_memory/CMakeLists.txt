idf_component_register(
    SRCS "product_agent_memory.c" "product_agent_memory_core.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "private_include"
    REQUIRES freertos nvs_flash product_storage
)
