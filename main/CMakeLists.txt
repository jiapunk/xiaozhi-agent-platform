if(DEFINED ENV{PRODUCT_WAVESHARE_WATCH_DIAGNOSTIC} AND
   "$ENV{PRODUCT_WAVESHARE_WATCH_DIAGNOSTIC}" STREQUAL "1")
    set(PRODUCT_MAIN_SRCS "waveshare_watch_app_main.c")
    set(PRODUCT_MAIN_REQUIRES
        waveshare_watch_bringup product_sku
    )
elseif(DEFINED ENV{PRODUCT_BREAD_S3CAM_DIAGNOSTIC} AND
   "$ENV{PRODUCT_BREAD_S3CAM_DIAGNOSTIC}" STREQUAL "1")
    # Keep the reversible hardware diagnostic on the same IDF 5.5.1 camera
    # stack as the factory XiaoZhi image.  Pulling in the full cloud runtime
    # here needlessly widens the dependency closure and can select IDF 6-only
    # APIs even though the diagnostic never uses them.
    set(PRODUCT_MAIN_SRCS "bread_s3cam_app_main.c")
    set(PRODUCT_MAIN_REQUIRES
        bread_s3cam_bringup product_sku
    )
else()
    set(PRODUCT_MAIN_SRCS "app_main.c")
    set(PRODUCT_MAIN_REQUIRES
        agent_bridge agent_device_identity agent_control_plane_client
        voice_agent_controller xiaozhi_agent_adapter
        esp_claw_runtime esp_system heap box3_audio voice_audio_protocol
        voice_audio_session
        box3_voice_audio
        box3_agent_voice
        box3_agent_supervisor
        box3_agent_credentials_client
        box3_product_runtime
        device_voice_runtime
        device_websocket_transport
        device_voice_client
        product_wifi
        product_local_action
        product_provisioning
        product_storage
        product_factory_reset
        product_agent_memory
        product_agent_observability
        product_status_indicator
        box3_bringup
        bread_s3cam_bringup
        product_sku
        product_ota
        product_ota_client
    )
endif()

if(CONFIG_PRODUCT_WAVESHARE_WATCH_BRINGUP_ENABLE)
    if(NOT CONFIG_PRODUCT_BOARD_WAVESHARE_S3_TOUCH_AMOLED_206 OR
       NOT CONFIG_PRODUCT_SKU_WAVESHARE_S3_TOUCH_AMOLED_206_DEVKIT)
        message(FATAL_ERROR
            "Waveshare watch bring-up requires the exact board/SKU profile")
    endif()
    if(CONFIG_PRODUCT_LIVE_RUNTIME_ENABLE OR
       CONFIG_PRODUCT_PRODUCTION_SECURITY_PROFILE OR
       CONFIG_PRODUCT_STORAGE_REQUIRE_HMAC_NVS_ENCRYPTION OR
       CONFIG_SECURE_BOOT OR CONFIG_SECURE_FLASH_ENC_ENABLED)
        message(FATAL_ERROR
            "Development watch bring-up cannot use Live or production security profiles")
    endif()
endif()

if(CONFIG_PRODUCT_BOX3_BRINGUP_ENABLE)
    if(NOT CONFIG_PRODUCT_BOARD_ESP_BOX_3 OR
       NOT CONFIG_PRODUCT_SKU_VOICE_AGENT_KIT_BOX3)
        message(FATAL_ERROR
            "BOX-3 bring-up firmware requires the exact BOX-3 board/SKU profile")
    endif()
    if(CONFIG_PRODUCT_LIVE_RUNTIME_ENABLE OR
       CONFIG_PRODUCT_PRODUCTION_SECURITY_PROFILE OR
       CONFIG_PRODUCT_STORAGE_REQUIRE_HMAC_NVS_ENCRYPTION OR
       CONFIG_SECURE_BOOT OR CONFIG_SECURE_FLASH_ENC_ENABLED)
        message(FATAL_ERROR
            "Development BOX-3 bring-up firmware cannot be combined with Live or production security profiles")
    endif()
endif()

if(CONFIG_PRODUCT_BREAD_S3CAM_BRINGUP_ENABLE)
    if(NOT CONFIG_PRODUCT_BOARD_BREAD_COMPACT_WIFI_S3CAM OR
       NOT CONFIG_PRODUCT_SKU_BREAD_COMPACT_WIFI_S3CAM_DEVKIT)
        message(FATAL_ERROR
            "Bread S3CAM bring-up requires the exact board/SKU profile")
    endif()
    if(CONFIG_PRODUCT_LIVE_RUNTIME_ENABLE OR
       CONFIG_PRODUCT_PRODUCTION_SECURITY_PROFILE OR
       CONFIG_PRODUCT_STORAGE_REQUIRE_HMAC_NVS_ENCRYPTION OR
       CONFIG_SECURE_BOOT OR CONFIG_SECURE_FLASH_ENC_ENABLED)
        message(FATAL_ERROR
            "Development Bread S3CAM bring-up cannot use Live or production security profiles")
    endif()
endif()

if((CONFIG_PRODUCT_BOARD_ESP_BOX_3 AND
    NOT CONFIG_PRODUCT_SKU_VOICE_AGENT_KIT_BOX3) OR
   (CONFIG_PRODUCT_BOARD_S3_N32R16_REFERENCE AND
    NOT CONFIG_PRODUCT_SKU_S3_N32R16_REFERENCE) OR
   (CONFIG_PRODUCT_BOARD_BREAD_COMPACT_WIFI_S3CAM AND
    NOT CONFIG_PRODUCT_SKU_BREAD_COMPACT_WIFI_S3CAM_DEVKIT) OR
   (CONFIG_PRODUCT_BOARD_WAVESHARE_S3_TOUCH_AMOLED_206 AND
    NOT CONFIG_PRODUCT_SKU_WAVESHARE_S3_TOUCH_AMOLED_206_DEVKIT))
    message(FATAL_ERROR
        "The product board and product-owned SKU selections must match")
endif()

if(CONFIG_PRODUCT_SKU_WAVESHARE_S3_TOUCH_AMOLED_206_DEVKIT AND
   NOT CONFIG_PRODUCT_HARDWARE_REVISION EQUAL 1)
    message(FATAL_ERROR
        "WAVESHARE_S3_TOUCH_AMOLED_206_DEVKIT freezes hardware revision 1")
endif()

if(CONFIG_PRODUCT_SKU_BREAD_COMPACT_WIFI_S3CAM_DEVKIT AND
   NOT CONFIG_PRODUCT_HARDWARE_REVISION EQUAL 1)
    message(FATAL_ERROR
        "BREAD_COMPACT_WIFI_S3CAM_DEVKIT freezes hardware revision 1")
endif()

if(CONFIG_PRODUCT_SKU_VOICE_AGENT_KIT_BOX3 AND
   NOT CONFIG_PRODUCT_HARDWARE_REVISION EQUAL 1)
    message(FATAL_ERROR
        "VOICE_AGENT_KIT_BOX3 currently freezes product hardware revision 1")
endif()

if(CONFIG_PRODUCT_LIVE_RUNTIME_ENABLE)
    if(NOT CONFIG_PRODUCT_SKU_VOICE_AGENT_KIT_BOX3)
        message(FATAL_ERROR
            "The current Live runtime is qualified only for VOICE_AGENT_KIT_BOX3")
    endif()
    if(NOT CONFIG_PRODUCT_IDENTITY_HMAC_KEY_ID EQUAL 5)
        message(FATAL_ERROR
            "VOICE_AGENT_KIT_BOX3 factory identity manifest is bound to HMAC_UP key block 5")
    endif()
    if(CONFIG_LOG_MAXIMUM_LEVEL GREATER 3)
        message(FATAL_ERROR
            "Product Live runtime caps compiled log verbosity at INFO")
    endif()
    if(CONFIG_ESP_COREDUMP_ENABLE OR
       CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH OR
       CONFIG_ESP_COREDUMP_ENABLE_TO_UART)
        message(FATAL_ERROR
            "Product Live runtime forbids unreviewed core dumps containing Agent memory")
    endif()
    if(NOT CONFIG_CLAW_CORE_STAGE_VERBOSITY_SIMPLE OR
       CONFIG_CLAW_CORE_STAGE_VERBOSITY_VERBOSE)
        message(FATAL_ERROR
            "Product Live runtime forbids Agent reasoning/tool arguments in stage events")
    endif()
    if(CONFIG_PRODUCT_CONTROL_AUTHORITY STREQUAL "")
        message(FATAL_ERROR
            "PRODUCT_LIVE_RUNTIME_ENABLE requires PRODUCT_CONTROL_AUTHORITY")
    endif()
    if(CONFIG_PRODUCT_AGENT_PROXY_AUTHORITY STREQUAL "")
        message(FATAL_ERROR
            "PRODUCT_LIVE_RUNTIME_ENABLE requires PRODUCT_AGENT_PROXY_AUTHORITY")
    endif()
    if(CONFIG_PRODUCT_SNTP_SERVER_1 STREQUAL "")
        message(FATAL_ERROR
            "PRODUCT_LIVE_RUNTIME_ENABLE requires PRODUCT_SNTP_SERVER_1")
    endif()
    if(NOT CONFIG_MBEDTLS_CERTIFICATE_BUNDLE)
        message(FATAL_ERROR
            "The reference live runtime requires the ESP certificate bundle")
    endif()
    if(CONFIG_PRODUCT_ONBOARDING_BUTTON_DEBOUNCE_MS LESS
       CONFIG_PRODUCT_ONBOARDING_BUTTON_SAMPLE_PERIOD_MS)
        message(FATAL_ERROR
            "Onboarding button debounce must cover at least one sample period")
    endif()
    if(CONFIG_PRODUCT_FACTORY_RESET_PRESS_MS LESS_EQUAL
       CONFIG_PRODUCT_ONBOARDING_BUTTON_LONG_PRESS_MS)
        message(FATAL_ERROR
            "Factory-reset hold time must be greater than onboarding hold time")
    endif()
    if(NOT CONFIG_PRODUCT_ONBOARDING_BUTTON_GPIO EQUAL 0 OR
       CONFIG_PRODUCT_ONBOARDING_BUTTON_ACTIVE_HIGH)
        message(FATAL_ERROR
            "The pinned ESP32-S3-BOX-3 onboarding button is GPIO0 active-low; add a reviewed board profile before changing it")
    endif()
    if(CONFIG_PRODUCT_STORAGE_REQUIRE_HMAC_NVS_ENCRYPTION AND
       CONFIG_PRODUCT_IDENTITY_HMAC_KEY_ID EQUAL
       CONFIG_PRODUCT_STORAGE_NVS_HMAC_KEY_ID)
        message(FATAL_ERROR
            "Identity and NVS encryption must use different HMAC key slots")
    endif()
endif()

if(CONFIG_PRODUCT_PRODUCTION_SECURITY_PROFILE)
    if(CONFIG_PRODUCT_AGENT_INDICATOR_ACTION_ENABLE)
        message(FATAL_ERROR
            "Production security keeps device.set_indicator disabled until signed-App, live authorization/database, board UX, and market-release evidence pass")
    endif()
    if(NOT CONFIG_APP_REPRODUCIBLE_BUILD)
        message(FATAL_ERROR
            "The production-security profile requires reproducible firmware inputs")
    endif()
    if(NOT CONFIG_PRODUCT_BOARD_ESP_BOX_3 OR
       NOT CONFIG_PRODUCT_SKU_VOICE_AGENT_KIT_BOX3 OR
       NOT CONFIG_PRODUCT_HARDWARE_REVISION EQUAL 1 OR
       NOT CONFIG_PRODUCT_LIVE_RUNTIME_ENABLE OR
       NOT CONFIG_PRODUCT_STORAGE_REQUIRE_HMAC_NVS_ENCRYPTION)
        message(FATAL_ERROR
            "The production-security profile requires BOX-3 Live runtime and protected product storage")
    endif()
    if(NOT CONFIG_SECURE_BOOT OR
       NOT CONFIG_SECURE_BOOT_V2_ENABLED OR
       NOT CONFIG_SECURE_SIGNED_APPS_RSA_SCHEME)
        message(FATAL_ERROR
            "The production-security profile requires Secure Boot V2 RSA-3072")
    endif()
    if(CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES OR
       CONFIG_SECURE_BOOT_INSECURE OR
       CONFIG_SECURE_BOOT_ENABLE_AGGRESSIVE_KEY_REVOKE OR
       CONFIG_SECURE_BOOT_V2_ALLOW_EFUSE_RD_DIS OR
       CONFIG_SECURE_BOOT_FLASH_BOOTLOADER_DEFAULT)
        message(FATAL_ERROR
            "The production-security profile requires external signing and forbids insecure/automatic bootloader options")
    endif()
    if(NOT CONFIG_SECURE_FLASH_ENC_ENABLED OR
       NOT CONFIG_SECURE_FLASH_ENCRYPTION_KEY_SOURCE_EFUSES OR
       NOT CONFIG_SECURE_FLASH_ENCRYPTION_AES128 OR
       NOT CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE)
        message(FATAL_ERROR
            "The production-security profile requires eFuse-backed XTS-AES-128 flash encryption in release mode")
    endif()
    if(NOT CONFIG_SECURE_ENABLE_SECURE_ROM_DL_MODE OR
       CONFIG_SECURE_DISABLE_ROM_DL_MODE OR
       CONFIG_SECURE_INSECURE_ALLOW_DL_MODE)
        message(FATAL_ERROR
            "The production-security profile requires ESP32-S3 Secure Download mode")
    endif()
    if(NOT CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE OR
       NOT CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK OR
       CONFIG_BOOTLOADER_APP_SECURE_VERSION LESS 1 OR
       CONFIG_BOOTLOADER_EFUSE_SECURE_VERSION_EMULATE)
        message(FATAL_ERROR
            "The production-security profile requires real anti-rollback with secure version >= 1")
    endif()
    if(NOT CONFIG_PRODUCT_STORAGE_NVS_HMAC_KEY_ID EQUAL 4 OR
       NOT CONFIG_PRODUCT_IDENTITY_HMAC_KEY_ID EQUAL 5)
        message(FATAL_ERROR
            "The production-security eFuse map reserves key blocks 4 and 5 for storage and identity")
    endif()
    if(NOT CONFIG_PRODUCT_OTA_CHANNEL STREQUAL "production")
        message(FATAL_ERROR
            "The production-security profile requires the production OTA channel")
    endif()
    if(NOT CONFIG_PARTITION_TABLE_CUSTOM_FILENAME STREQUAL
       "partitions_16MB_box3_production.csv" OR
       NOT CONFIG_PARTITION_TABLE_OFFSET EQUAL 0x10000)
        message(FATAL_ERROR
            "The production-security profile requires the secure-boot partition layout at offset 0x10000")
    endif()
endif()

idf_component_register(
    SRCS ${PRODUCT_MAIN_SRCS}
    INCLUDE_DIRS "."
    REQUIRES ${PRODUCT_MAIN_REQUIRES}
)
