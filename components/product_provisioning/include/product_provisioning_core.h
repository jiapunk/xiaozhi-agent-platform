#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PRODUCT_PROVISIONING_STATE_CLOSED = 0,
    PRODUCT_PROVISIONING_STATE_OPENING_WIFI,
    PRODUCT_PROVISIONING_STATE_STARTING_TRANSPORT,
    PRODUCT_PROVISIONING_STATE_SERVING,
    PRODUCT_PROVISIONING_STATE_VALIDATING,
    PRODUCT_PROVISIONING_STATE_SUCCESS_GRACE,
    PRODUCT_PROVISIONING_STATE_LOCKED_OUT,
    PRODUCT_PROVISIONING_STATE_ERROR,
} product_provisioning_state_t;

typedef enum {
    PRODUCT_PROVISIONING_ACTION_NONE = 0,
    PRODUCT_PROVISIONING_ACTION_BEGIN_ONBOARDING = 1U << 0,
    PRODUCT_PROVISIONING_ACTION_START_SOFTAP = 1U << 1,
    PRODUCT_PROVISIONING_ACTION_START_TRANSPORT = 1U << 2,
    PRODUCT_PROVISIONING_ACTION_STOP_TRANSPORT = 1U << 3,
    PRODUCT_PROVISIONING_ACTION_SUBMIT_CANDIDATE = 1U << 4,
    PRODUCT_PROVISIONING_ACTION_FINISH_ONBOARDING = 1U << 5,
    PRODUCT_PROVISIONING_ACTION_PUBLISH_CLAIM = 1U << 6,
} product_provisioning_action_t;

typedef struct {
    uint32_t window_ms;
    uint32_t commit_delay_ms;
    uint32_t success_grace_ms;
    uint32_t authentication_failure_limit;
    bool claim_required;
} product_provisioning_core_config_t;

typedef struct {
    product_provisioning_state_t state;
    uint32_t window_ms;
    uint32_t commit_delay_ms;
    uint32_t success_grace_ms;
    uint32_t authentication_failure_limit;
    uint32_t authentication_failures;
    uint32_t candidate_rejections_at_apply;
    uint64_t deadline_ms;
    uint64_t commit_at_ms;
    uint64_t success_at_ms;
    uint64_t claim_retry_at_ms;
    bool candidate_submitted;
    bool online_observed;
    bool claim_required;
    bool claim_published;
} product_provisioning_core_t;

typedef enum {
    PRODUCT_CLAIM_RECOVERY_RETRY = 0,
    PRODUCT_CLAIM_RECOVERY_RECOVERED,
    PRODUCT_CLAIM_RECOVERY_REJECTED,
} product_claim_recovery_result_t;

typedef struct {
    uint64_t retry_at_ms;
} product_claim_recovery_core_t;

void product_claim_recovery_core_init(
    product_claim_recovery_core_t *recovery);

bool product_claim_recovery_core_should_attempt(
    product_claim_recovery_core_t *recovery,
    uint64_t now_ms,
    bool session_inactive,
    bool wifi_online,
    bool claim_pending);

void product_claim_recovery_core_record(
    product_claim_recovery_core_t *recovery,
    uint64_t now_ms,
    product_claim_recovery_result_t result);

bool product_provisioning_core_init(
    product_provisioning_core_t *core,
    const product_provisioning_core_config_t *config);

product_provisioning_action_t product_provisioning_core_open(
    product_provisioning_core_t *core,
    uint64_t now_ms);

product_provisioning_action_t product_provisioning_core_apply(
    product_provisioning_core_t *core,
    uint64_t now_ms,
    uint32_t candidate_rejections);

product_provisioning_action_t product_provisioning_core_auth_failure(
    product_provisioning_core_t *core);

product_provisioning_action_t product_provisioning_core_poll(
    product_provisioning_core_t *core,
    uint64_t now_ms,
    bool wifi_onboarding,
    bool softap_active,
    bool wifi_online,
    uint32_t candidate_rejections);

product_provisioning_action_t product_provisioning_core_online_observed(
    product_provisioning_core_t *core,
    uint64_t now_ms);

void product_provisioning_core_claim_result(
    product_provisioning_core_t *core,
    uint64_t now_ms,
    bool published);

product_provisioning_action_t product_provisioning_core_close(
    product_provisioning_core_t *core);

product_provisioning_action_t product_provisioning_core_fail(
    product_provisioning_core_t *core);

#ifdef __cplusplus
}
#endif
