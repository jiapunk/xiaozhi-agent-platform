idf_component_register(
    SRCS "device_voice_runtime.c"
    INCLUDE_DIRS "include"
    REQUIRES
        voice_agent_controller
        xiaozhi_agent_adapter
        espressif__cjson
)
