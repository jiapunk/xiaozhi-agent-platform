idf_component_register(
    SRCS "waveshare_watch_bringup.cc"
    INCLUDE_DIRS "include"
    REQUIRES esp_codec_dev esp_driver_i2s esp_timer freertos log
             product_sku waveshare__esp32_s3_touch_amoled_2_06
)

# The Waveshare BSP uses the LVGL simple include form.
target_compile_definitions(${COMPONENT_LIB} PRIVATE LV_LVGL_H_INCLUDE_SIMPLE)
