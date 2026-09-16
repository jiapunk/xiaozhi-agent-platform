#pragma once

#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>

#include "esp_claw_runtime.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Monotonic, saturating, content-free counters. No request/session identifier,
 * argument, output, prompt, response, key, value, or provider body is retained.
 */
typedef struct {
    atomic_uint total;
    atomic_uint invalid_events;
    atomic_uint executed;
    atomic_uint denied_disabled;
    atomic_uint denied_context;
    atomic_uint denied_consent;
    atomic_uint invalid_input;
    atomic_uint execution_failed;
    atomic_uint device_reads;
    atomic_uint device_actions;
    atomic_uint memory_reads;
    atomic_uint memory_writes;
} product_agent_observability_t;

typedef struct {
    uint32_t total;
    uint32_t invalid_events;
    uint32_t executed;
    uint32_t denied_disabled;
    uint32_t denied_context;
    uint32_t denied_consent;
    uint32_t invalid_input;
    uint32_t execution_failed;
    uint32_t device_reads;
    uint32_t device_actions;
    uint32_t memory_reads;
    uint32_t memory_writes;
} product_agent_observability_stats_t;

bool product_agent_observability_init(
    product_agent_observability_t *observability);

/* Directly usable as esp_claw_capability_audit_fn; never blocks or logs. */
void product_agent_observability_record(
    void *ctx,
    const esp_claw_capability_audit_event_t *event);

bool product_agent_observability_snapshot(
    const product_agent_observability_t *observability,
    product_agent_observability_stats_t *stats);

#ifdef __cplusplus
}
#endif
