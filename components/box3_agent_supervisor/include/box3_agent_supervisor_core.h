#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    BOX3_AGENT_SUPERVISOR_WAIT_NETWORK = 0,
    BOX3_AGENT_SUPERVISOR_REFRESHING,
    BOX3_AGENT_SUPERVISOR_STARTING,
    BOX3_AGENT_SUPERVISOR_ONLINE,
    BOX3_AGENT_SUPERVISOR_BACKOFF,
    BOX3_AGENT_SUPERVISOR_ENTITLEMENT_BLOCKED,
    BOX3_AGENT_SUPERVISOR_STOPPING,
} box3_agent_supervisor_state_t;

typedef enum {
    BOX3_AGENT_SUPERVISOR_ACTION_NONE = 0,
    BOX3_AGENT_SUPERVISOR_ACTION_REFRESH,
    BOX3_AGENT_SUPERVISOR_ACTION_START,
    BOX3_AGENT_SUPERVISOR_ACTION_STOP,
} box3_agent_supervisor_action_t;

typedef struct {
    uint32_t minimum_backoff_ms;
    uint32_t maximum_backoff_ms;
    uint32_t refresh_margin_seconds;
} box3_agent_supervisor_core_config_t;

typedef struct {
    box3_agent_supervisor_state_t state;
    box3_agent_supervisor_state_t after_stop;
    uint32_t minimum_backoff_ms;
    uint32_t maximum_backoff_ms;
    uint32_t refresh_margin_seconds;
    uint32_t consecutive_failures;
    uint64_t refresh_at_ms;
    uint64_t retry_at_ms;
    bool network_available;
} box3_agent_supervisor_core_t;

bool box3_agent_supervisor_core_init(
    box3_agent_supervisor_core_t *core,
    const box3_agent_supervisor_core_config_t *config);

box3_agent_supervisor_action_t box3_agent_supervisor_core_set_network(
    box3_agent_supervisor_core_t *core,
    bool available,
    uint64_t now_ms);

box3_agent_supervisor_action_t box3_agent_supervisor_core_credentials_result(
    box3_agent_supervisor_core_t *core,
    bool success,
    uint32_t voice_ttl_seconds,
    uint32_t agent_ttl_seconds,
    uint64_t now_ms,
    uint32_t random_value);

box3_agent_supervisor_action_t box3_agent_supervisor_core_entitlement_denied(
    box3_agent_supervisor_core_t *core);

box3_agent_supervisor_action_t box3_agent_supervisor_core_entitlement_changed(
    box3_agent_supervisor_core_t *core);

box3_agent_supervisor_action_t box3_agent_supervisor_core_start_failed(
    box3_agent_supervisor_core_t *core,
    bool session_present,
    uint64_t now_ms,
    uint32_t random_value);

bool box3_agent_supervisor_core_ready(box3_agent_supervisor_core_t *core);

box3_agent_supervisor_action_t box3_agent_supervisor_core_disconnected(
    box3_agent_supervisor_core_t *core,
    uint64_t now_ms,
    uint32_t random_value);

box3_agent_supervisor_action_t box3_agent_supervisor_core_session_stopped(
    box3_agent_supervisor_core_t *core);

box3_agent_supervisor_action_t box3_agent_supervisor_core_poll(
    box3_agent_supervisor_core_t *core,
    uint64_t now_ms);

uint32_t box3_agent_supervisor_core_wait_ms(
    const box3_agent_supervisor_core_t *core,
    uint64_t now_ms,
    uint32_t ceiling_ms);

#ifdef __cplusplus
}
#endif
