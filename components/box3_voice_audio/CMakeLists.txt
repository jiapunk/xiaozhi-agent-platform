idf_component_register(
    SRCS "box3_voice_audio.cc"
    INCLUDE_DIRS "include"
    REQUIRES
        box3_audio
        voice_agent_controller
        voice_audio_protocol
        voice_audio_session
        esp_timer
        freertos
        heap
        espressif__esp_audio_codec
        espressif__esp_audio_effects
)
