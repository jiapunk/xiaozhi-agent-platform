idf_component_register(
    SRCS "box3_agent_voice.c"
    INCLUDE_DIRS "include"
    REQUIRES
        box3_audio
        box3_voice_audio
        device_voice_client
        esp_claw_runtime
        freertos
        heap
)
