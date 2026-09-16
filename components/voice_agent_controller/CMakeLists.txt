idf_component_register(
    SRCS "voice_agent_controller.c" "voice_agent_protocol.c"
    INCLUDE_DIRS "include"
    REQUIRES agent_bridge
)
