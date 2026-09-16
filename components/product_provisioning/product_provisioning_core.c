#include "product_provisioning_core.h"

#include <string.h>
#include <stdint.h>

enum {
    MINIMUM_WINDOW_MS = 60 * 1000,
    MAXIMUM_WINDOW_MS = 10 * 60 * 1000,
    MAXIMUM_COMMIT_DELAY_MS = 5000,
    MAXIMUM_SUCCESS_GRACE_MS = 30 * 1000,
    MAXIMUM_AUTHENTICATION_FAILURES = 20,
    CLAIM_RETRY_MS = 2000,
};

void product_claim_recovery_core_init(
    product_claim_recovery_core_t *recovery)
{
    if (recovery) {
        memset(recovery, 0, sizeof(*recovery));
    }
}

bool product_claim_recovery_core_should_attempt(
    product_claim_recovery_core_t *recovery,
    uint64_t now_ms,
    bool session_inactive,
    bool wifi_online,
    bool claim_pending)
{
    if (!recovery) {
        return false;
    }
    if (!claim_pending) {
        recovery->retry_at_ms = 0;
        return false;
    }
    return session_inactive && wifi_online &&
           now_ms >= recovery->retry_at_ms;
}

void product_claim_recovery_core_record(
    product_claim_recovery_core_t *recovery,
    uint64_t now_ms,
    product_claim_recovery_result_t result)
{
    if (!recovery) {
        return;
    }
    if (result == PRODUCT_CLAIM_RECOVERY_RECOVERED ||
        result == PRODUCT_CLAIM_RECOVERY_REJECTED) {
        recovery->retry_at_ms = 0;
        return;
    }
    recovery->retry_at_ms =
        now_ms > UINT64_MAX - CLAIM_RETRY_MS
            ? UINT64_MAX
            : now_ms + CLAIM_RETRY_MS;
}

static product_provisioning_action_t close_actions(
    product_provisioning_core_t *core,
    product_provisioning_state_t state)
{
    core->state = state;
    core->deadline_ms = 0;
    core->commit_at_ms = 0;
    core->success_at_ms = 0;
    core->claim_retry_at_ms = 0;
    core->candidate_submitted = false;
    core->online_observed = false;
    core->claim_published = false;
    return PRODUCT_PROVISIONING_ACTION_STOP_TRANSPORT |
           PRODUCT_PROVISIONING_ACTION_FINISH_ONBOARDING;
}

bool product_provisioning_core_init(
    product_provisioning_core_t *core,
    const product_provisioning_core_config_t *config)
{
    if (!core || !config || config->window_ms < MINIMUM_WINDOW_MS ||
        config->window_ms > MAXIMUM_WINDOW_MS ||
        config->commit_delay_ms == 0 ||
        config->commit_delay_ms > MAXIMUM_COMMIT_DELAY_MS ||
        config->success_grace_ms == 0 ||
        config->success_grace_ms > MAXIMUM_SUCCESS_GRACE_MS ||
        config->authentication_failure_limit == 0 ||
        config->authentication_failure_limit >
            MAXIMUM_AUTHENTICATION_FAILURES) {
        return false;
    }
    memset(core, 0, sizeof(*core));
    core->state = PRODUCT_PROVISIONING_STATE_CLOSED;
    core->window_ms = config->window_ms;
    core->commit_delay_ms = config->commit_delay_ms;
    core->success_grace_ms = config->success_grace_ms;
    core->authentication_failure_limit =
        config->authentication_failure_limit;
    core->claim_required = config->claim_required;
    return true;
}

product_provisioning_action_t product_provisioning_core_open(
    product_provisioning_core_t *core,
    uint64_t now_ms)
{
    if (!core || (core->state != PRODUCT_PROVISIONING_STATE_CLOSED &&
                  core->state != PRODUCT_PROVISIONING_STATE_LOCKED_OUT &&
                  core->state != PRODUCT_PROVISIONING_STATE_ERROR)) {
        return PRODUCT_PROVISIONING_ACTION_NONE;
    }
    core->state = PRODUCT_PROVISIONING_STATE_OPENING_WIFI;
    core->deadline_ms = now_ms + core->window_ms;
    core->authentication_failures = 0;
    core->candidate_submitted = false;
    core->online_observed = false;
    core->claim_published = false;
    core->claim_retry_at_ms = 0;
    return PRODUCT_PROVISIONING_ACTION_BEGIN_ONBOARDING;
}

product_provisioning_action_t product_provisioning_core_apply(
    product_provisioning_core_t *core,
    uint64_t now_ms,
    uint32_t candidate_rejections)
{
    if (!core || core->state != PRODUCT_PROVISIONING_STATE_SERVING) {
        return PRODUCT_PROVISIONING_ACTION_NONE;
    }
    core->state = PRODUCT_PROVISIONING_STATE_VALIDATING;
    core->candidate_rejections_at_apply = candidate_rejections;
    core->commit_at_ms = now_ms + core->commit_delay_ms;
    core->candidate_submitted = false;
    return PRODUCT_PROVISIONING_ACTION_NONE;
}

product_provisioning_action_t product_provisioning_core_auth_failure(
    product_provisioning_core_t *core)
{
    if (!core || core->state == PRODUCT_PROVISIONING_STATE_CLOSED ||
        core->state == PRODUCT_PROVISIONING_STATE_LOCKED_OUT ||
        core->state == PRODUCT_PROVISIONING_STATE_ERROR) {
        return PRODUCT_PROVISIONING_ACTION_NONE;
    }
    ++core->authentication_failures;
    if (core->authentication_failures >=
        core->authentication_failure_limit) {
        return close_actions(core, PRODUCT_PROVISIONING_STATE_LOCKED_OUT);
    }
    return PRODUCT_PROVISIONING_ACTION_NONE;
}

product_provisioning_action_t product_provisioning_core_poll(
    product_provisioning_core_t *core,
    uint64_t now_ms,
    bool wifi_onboarding,
    bool softap_active,
    bool wifi_online,
    uint32_t candidate_rejections)
{
    if (!core || core->state == PRODUCT_PROVISIONING_STATE_CLOSED ||
        core->state == PRODUCT_PROVISIONING_STATE_LOCKED_OUT ||
        core->state == PRODUCT_PROVISIONING_STATE_ERROR) {
        return PRODUCT_PROVISIONING_ACTION_NONE;
    }
    if (now_ms >= core->deadline_ms) {
        return close_actions(core, PRODUCT_PROVISIONING_STATE_CLOSED);
    }
    if (core->state == PRODUCT_PROVISIONING_STATE_OPENING_WIFI &&
        wifi_onboarding) {
        core->state = PRODUCT_PROVISIONING_STATE_STARTING_TRANSPORT;
        return PRODUCT_PROVISIONING_ACTION_START_SOFTAP;
    }
    if (core->state == PRODUCT_PROVISIONING_STATE_STARTING_TRANSPORT &&
        softap_active) {
        core->state = PRODUCT_PROVISIONING_STATE_SERVING;
        return PRODUCT_PROVISIONING_ACTION_START_TRANSPORT;
    }
    if (core->state == PRODUCT_PROVISIONING_STATE_VALIDATING) {
        if (!core->candidate_submitted && now_ms >= core->commit_at_ms) {
            core->candidate_submitted = true;
            return PRODUCT_PROVISIONING_ACTION_SUBMIT_CANDIDATE;
        }
        if (candidate_rejections > core->candidate_rejections_at_apply) {
            core->state = PRODUCT_PROVISIONING_STATE_SERVING;
            core->commit_at_ms = 0;
            core->candidate_submitted = false;
        } else if (wifi_online) {
            core->state = PRODUCT_PROVISIONING_STATE_SUCCESS_GRACE;
            if (core->claim_required) {
                core->claim_retry_at_ms = now_ms + CLAIM_RETRY_MS;
                return PRODUCT_PROVISIONING_ACTION_PUBLISH_CLAIM;
            }
            core->success_at_ms = now_ms + core->success_grace_ms;
        }
    }
    if (core->state == PRODUCT_PROVISIONING_STATE_SUCCESS_GRACE) {
        if (core->claim_required && !core->claim_published) {
            if (now_ms >= core->claim_retry_at_ms) {
                core->claim_retry_at_ms = now_ms + CLAIM_RETRY_MS;
                return PRODUCT_PROVISIONING_ACTION_PUBLISH_CLAIM;
            }
        } else if (now_ms >= core->success_at_ms) {
            return close_actions(core, PRODUCT_PROVISIONING_STATE_CLOSED);
        }
    }
    return PRODUCT_PROVISIONING_ACTION_NONE;
}

product_provisioning_action_t product_provisioning_core_online_observed(
    product_provisioning_core_t *core,
    uint64_t now_ms)
{
    if (!core || core->state !=
                     PRODUCT_PROVISIONING_STATE_SUCCESS_GRACE) {
        return PRODUCT_PROVISIONING_ACTION_NONE;
    }
    core->online_observed = true;
    if (!core->claim_required || core->claim_published) {
        core->success_at_ms = now_ms + 500;
    }
    return PRODUCT_PROVISIONING_ACTION_NONE;
}

void product_provisioning_core_claim_result(
    product_provisioning_core_t *core,
    uint64_t now_ms,
    bool published)
{
    if (!core || core->state != PRODUCT_PROVISIONING_STATE_SUCCESS_GRACE ||
        !core->claim_required || core->claim_published) {
        return;
    }
    if (published) {
        core->claim_published = true;
        core->claim_retry_at_ms = 0;
        core->success_at_ms = now_ms + 500;
    } else {
        core->claim_retry_at_ms = now_ms + CLAIM_RETRY_MS;
    }
}

product_provisioning_action_t product_provisioning_core_close(
    product_provisioning_core_t *core)
{
    if (!core || core->state == PRODUCT_PROVISIONING_STATE_CLOSED) {
        return PRODUCT_PROVISIONING_ACTION_NONE;
    }
    return close_actions(core, PRODUCT_PROVISIONING_STATE_CLOSED);
}

product_provisioning_action_t product_provisioning_core_fail(
    product_provisioning_core_t *core)
{
    if (!core) {
        return PRODUCT_PROVISIONING_ACTION_NONE;
    }
    return close_actions(core, PRODUCT_PROVISIONING_STATE_ERROR);
}
