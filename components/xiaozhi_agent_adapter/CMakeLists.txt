idf_component_register(
    SRCS "xiaozhi_agent_adapter.c"
    INCLUDE_DIRS "include"
    REQUIRES voice_agent_controller espressif__cjson
)
