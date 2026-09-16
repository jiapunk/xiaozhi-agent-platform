#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    bool synchronized;
    int64_t unix_at_sync;
    uint64_t monotonic_at_sync_ms;
    uint32_t maximum_age_seconds;
    uint32_t backward_tolerance_seconds;
} agent_device_time_core_t;

typedef struct {
    bool synchronized;
    uint64_t age_seconds;
} agent_device_time_status_t;

bool agent_device_time_core_init(
    agent_device_time_core_t *core,
    uint32_t maximum_age_seconds,
    uint32_t backward_tolerance_seconds);

/* The caller must authenticate the source before accepting this observation. */
bool agent_device_time_core_accept(
    agent_device_time_core_t *core,
    int64_t unix_seconds,
    uint64_t monotonic_ms);

bool agent_device_time_core_now(
    const agent_device_time_core_t *core,
    uint64_t monotonic_ms,
    int64_t *unix_seconds);

bool agent_device_time_core_status(
    const agent_device_time_core_t *core,
    uint64_t monotonic_ms,
    agent_device_time_status_t *status);
