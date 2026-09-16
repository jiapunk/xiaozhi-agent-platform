idf_component_register(
    SRCS
        "box3_agent_supervisor.c"
        "box3_agent_supervisor_core.c"
        "box3_agent_supervisor_product_wifi.c"
    INCLUDE_DIRS "include"
    REQUIRES
        box3_agent_voice
        esp_timer
        esp_system
        freertos
        heap
        product_wifi
        product_agent_memory
)
