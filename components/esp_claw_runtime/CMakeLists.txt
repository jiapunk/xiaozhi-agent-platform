idf_component_register(
    SRCS "esp_claw_runtime.c" "esp_claw_capability_grant_core.c"
         "esp_claw_memory_grant_core.c"
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "private_include"
    REQUIRES claw_core claw_cap freertos product_agent_memory
)
