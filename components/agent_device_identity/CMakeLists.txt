idf_component_register(
    SRCS
        "agent_device_identity.c"
        "agent_device_proof_core.c"
        "agent_device_time_core.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "private_include"
    REQUIRES
        efuse
        esp_security
        esp_timer
        freertos
        heap
        product_storage
)
