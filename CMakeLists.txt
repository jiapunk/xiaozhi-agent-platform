cmake_minimum_required(VERSION 3.16)

if(DEFINED ENV{ESP_CLAW_ROOT})
    set(ESP_CLAW_ROOT "$ENV{ESP_CLAW_ROOT}")
else()
    set(ESP_CLAW_ROOT "${CMAKE_CURRENT_LIST_DIR}/third_party/esp-claw")
endif()
if(NOT EXISTS "${ESP_CLAW_ROOT}/components/claw_modules/claw_core/CMakeLists.txt")
    message(FATAL_ERROR
        "ESP-Claw sources are missing. Run tools/sync_upstreams.sh before building.")
endif()

# ESP-Claw is a multi-component repository rather than one monolithic IDF
# component. Import only the Agent runtime dependency closure used by M0.
set(PRODUCT_CLAW_COMPONENT_DIRS
    "${ESP_CLAW_ROOT}/components/common/http_reuse"
    "${ESP_CLAW_ROOT}/components/claw_modules/claw_utils"
    "${ESP_CLAW_ROOT}/components/claw_modules/claw_core"
    "${ESP_CLAW_ROOT}/components/claw_modules/claw_cap"
    "${ESP_CLAW_ROOT}/components/claw_modules/claw_skill"
    "${ESP_CLAW_ROOT}/components/claw_modules/claw_event_router"
    "${ESP_CLAW_ROOT}/components/claw_modules/claw_manager"
)

if(PRODUCT_WAVESHARE_WATCH_DIAGNOSTIC)
    # Keep the first watch image small and reversible. The board BSP owns the
    # display, touch, I2C and duplex I2S paths while the product SKU layer
    # independently checks the observed ESP32-S3/Flash/PSRAM geometry.
    set(COMPONENT_DIRS
        "$ENV{IDF_PATH}/components"
        "${CMAKE_CURRENT_LIST_DIR}/main"
        "${CMAKE_CURRENT_LIST_DIR}/components/waveshare_watch_bringup"
        "${CMAKE_CURRENT_LIST_DIR}/components/product_storage"
        "${CMAKE_CURRENT_LIST_DIR}/components/product_sku"
    )
    set(COMPONENTS main)
elseif(PRODUCT_BREAD_S3CAM_DIAGNOSTIC)
    # IDF's component manager evaluates manifests for every discovered project
    # component. Enumerate the diagnostic closure so unrelated IDF 6-only
    # audio/cloud manifests cannot make the proven IDF 5.5.1 build unsolvable.
    set(COMPONENT_DIRS
        "$ENV{IDF_PATH}/components"
        "${CMAKE_CURRENT_LIST_DIR}/main"
        "${CMAKE_CURRENT_LIST_DIR}/components/bread_s3cam_bringup"
        "${CMAKE_CURRENT_LIST_DIR}/components/esp_claw_runtime"
        "${CMAKE_CURRENT_LIST_DIR}/components/product_agent_memory"
        "${CMAKE_CURRENT_LIST_DIR}/components/product_status_indicator"
        "${CMAKE_CURRENT_LIST_DIR}/components/product_storage"
        "${CMAKE_CURRENT_LIST_DIR}/components/product_wifi"
        "${CMAKE_CURRENT_LIST_DIR}/components/product_sku"
        ${PRODUCT_CLAW_COMPONENT_DIRS}
    )
    set(COMPONENTS main)
else()
    set(EXTRA_COMPONENT_DIRS
        "${CMAKE_CURRENT_LIST_DIR}/components"
        ${PRODUCT_CLAW_COMPONENT_DIRS}
    )
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
idf_build_set_property(MINIMAL_BUILD ON)
project(xiaozhi_agent_platform)
