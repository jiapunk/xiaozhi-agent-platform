#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Starts the reversible display, touch, microphone and speaker diagnostic. */
esp_err_t waveshare_watch_bringup_start(void);

#ifdef __cplusplus
}
#endif
