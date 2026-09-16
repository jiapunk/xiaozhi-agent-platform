#pragma once

#include <stddef.h>

#include "agent_bridge.h"
#include "cJSON.h"
#include "device_websocket_limits.h"

agent_bridge_result_t device_voice_client_build_hello(
    int transport_version,
    int uplink_sample_rate,
    int frame_duration_ms,
    char *output,
    size_t output_capacity,
    size_t *output_size);

/* Caller owns the returned cJSON. Rejects trailing non-whitespace and NUL. */
cJSON *device_voice_client_parse_json_strict(const uint8_t *data,
                                             size_t size);
