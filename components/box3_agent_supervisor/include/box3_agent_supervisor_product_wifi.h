#pragma once

#include "product_wifi.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Direct product_wifi_config_t.event adapter. event_ctx must be the BOX-3
 * supervisor handle and must outlive the product Wi-Fi manager.
 */
void box3_agent_supervisor_product_wifi_event(
    void *ctx,
    const product_wifi_event_t *event);

#ifdef __cplusplus
}
#endif
