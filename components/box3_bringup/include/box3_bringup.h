#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Starts the development-only ESP32-S3-BOX-3 hardware/capability harness.
 * It never starts Wi-Fi, accepts remote commands, writes eFuse, or claims
 * production qualification.
 */
esp_err_t box3_bringup_start(void);

#ifdef __cplusplus
}
#endif
