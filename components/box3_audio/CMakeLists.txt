idf_component_register(
    SRCS "box3_audio.cc"
    INCLUDE_DIRS "include"
    REQUIRES esp_driver_gpio esp_driver_i2c esp_driver_i2s espressif__esp_codec_dev
)
