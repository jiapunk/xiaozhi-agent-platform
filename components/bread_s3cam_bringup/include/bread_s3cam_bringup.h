#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Starts the development-only hardware/ESP-Claw diagnostic task. */
esp_err_t bread_s3cam_bringup_start(void);

#ifdef __cplusplus
}
#endif
