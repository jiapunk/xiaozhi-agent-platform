#include "box3_agent_supervisor_product_wifi.h"

#include "box3_agent_supervisor.h"
#include "esp_log.h"

static const char *TAG = "agent_wifi_bind";

void box3_agent_supervisor_product_wifi_event(
    void *ctx,
    const product_wifi_event_t *event)
{
    if (!ctx || !event ||
        event->type != PRODUCT_WIFI_EVENT_NETWORK_CHANGED) {
        return;
    }
    const esp_err_t error = box3_agent_supervisor_set_network_available(
        (box3_agent_supervisor_handle_t)ctx, event->network_available);
    if (error != ESP_OK) {
        ESP_LOGW(TAG, "network availability handoff failed: %s",
                 esp_err_to_name(error));
    }
}
