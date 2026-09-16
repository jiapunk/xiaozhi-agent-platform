idf_component_register(
    SRCS "bread_s3cam_bringup.cc"
    INCLUDE_DIRS "include"
    REQUIRES esp_claw_runtime product_status_indicator product_sku product_wifi
             esp_driver_gpio esp_driver_i2s esp_driver_ledc esp_driver_spi esp_lcd
             esp_app_format esp_audio_codec esp_http_client esp_http_server
             esp_hw_support esp_system esp_timer esp_video
             esp_websocket_client espressif__cjson freertos heap log mbedtls
             nvs_flash spi_flash
)
