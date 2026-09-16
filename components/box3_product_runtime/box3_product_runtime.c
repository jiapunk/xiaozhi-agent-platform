#include "box3_product_runtime.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "agent_control_plane_client.h"
#include "agent_device_identity.h"
#include "box3_agent_credentials_client.h"
#include "box3_product_runtime_core.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "product_factory_reset.h"
#include "product_storage.h"
#include "product_time_bootstrap.h"

static const char *TAG = "box3_product";

enum {
    STARTUP_CLEANUP_TIMEOUT_MS = 5000,
    SUPERVISOR_MINIMUM_STOP_TIMEOUT_MS = 100,
    FACTORY_RESET_RESTART_DELAY_MS = 100,
    FACTORY_RESET_RESTART_STACK_SIZE = 2048,
    FACTORY_RESET_RESTART_TASK_PRIORITY = 5,
    ACTION_CONSENT_DEFAULT_TIMEOUT_MS = 20000,
    ACTION_CONSENT_MINIMUM_TIMEOUT_MS = 1000,
    ACTION_CONSENT_MAXIMUM_TIMEOUT_MS = 28000,
    ACTION_CONSENT_DEFAULT_POLL_MS = 500,
    ACTION_CONSENT_MINIMUM_POLL_MS = 100,
    ACTION_CONSENT_MAXIMUM_POLL_MS = 2000,
    ACTION_CONSENT_MINIMUM_REQUEST_MS = 100,
    ACTION_CONSENT_MAXIMUM_REQUEST_MS = 2000,
    CONTROL_DEFAULT_NETWORK_TIMEOUT_MS = 10000,
};

struct box3_product_runtime {
    box3_product_runtime_core_t core;
    agent_device_identity_handle_t identity;
    agent_control_plane_client_handle_t control;
    box3_agent_credentials_client_handle_t credentials;
    box3_agent_supervisor_handle_t supervisor;
    product_time_bootstrap_handle_t time_bootstrap;
    product_wifi_handle_t wifi;
    product_provisioning_handle_t provisioning;
    product_local_action_handle_t local_action;
    box3_product_runtime_event_fn event;
    void *event_ctx;
    atomic_int state;
    atomic_bool stopping;
    atomic_bool network_available;
    atomic_bool onboarding_required;
    atomic_bool onboarding_open;
    atomic_bool approximate_time_available;
    atomic_bool physical_presence_grant;
    uint32_t control_network_timeout_ms;
    uint32_t action_consent_timeout_ms;
    uint32_t action_consent_poll_interval_ms;
    atomic_uint action_consent_cancel_epoch;
    atomic_uint action_consents_requested;
    atomic_uint action_consents_registered;
    atomic_uint action_consents_approved;
    atomic_uint action_consents_denied;
    atomic_uint action_consents_expired;
    atomic_uint action_consents_canceled;
    atomic_uint action_consents_failed;
};

static void secure_zero(void *memory, size_t size)
{
    volatile unsigned char *bytes = memory;
    while (bytes && size > 0) {
        *bytes++ = 0;
        --size;
    }
}

static void release_runtime(box3_product_runtime_handle_t runtime)
{
    if (!runtime) {
        return;
    }
    secure_zero(runtime, sizeof(*runtime));
    heap_caps_free(runtime);
}

static bool runtime_stopping(box3_product_runtime_handle_t runtime)
{
    return !runtime || atomic_load_explicit(
                           &runtime->stopping, memory_order_acquire);
}

static box3_product_runtime_state_t runtime_state(
    box3_product_runtime_handle_t runtime)
{
    return runtime
               ? (box3_product_runtime_state_t)atomic_load_explicit(
                     &runtime->state, memory_order_acquire)
               : BOX3_PRODUCT_RUNTIME_STOPPING;
}

static void publish_event(box3_product_runtime_handle_t runtime,
                          const box3_product_runtime_event_t *event)
{
    if (runtime && event && runtime->event && !runtime_stopping(runtime)) {
        runtime->event(runtime->event_ctx, event);
    }
}

static void set_state(box3_product_runtime_handle_t runtime,
                      box3_product_runtime_state_t state,
                      esp_err_t error)
{
    if (runtime_stopping(runtime)) {
        return;
    }
    const int old_state = atomic_exchange_explicit(
        &runtime->state, (int)state, memory_order_acq_rel);
    if (old_state != (int)state) {
        const box3_product_runtime_event_t event = {
            .type = BOX3_PRODUCT_RUNTIME_EVENT_STATE_CHANGED,
            .state = state,
            .error = error,
            .network_available = atomic_load_explicit(
                &runtime->network_available, memory_order_acquire),
            .onboarding_required = atomic_load_explicit(
                &runtime->onboarding_required, memory_order_acquire),
            .approximate_time_available = atomic_load_explicit(
                &runtime->approximate_time_available, memory_order_acquire),
        };
        publish_event(runtime, &event);
    }
}

static void publish_error(box3_product_runtime_handle_t runtime,
                          esp_err_t error)
{
    if (error == ESP_OK || runtime_stopping(runtime)) {
        return;
    }
    const box3_product_runtime_event_t event = {
        .type = BOX3_PRODUCT_RUNTIME_EVENT_ERROR,
        .state = runtime_state(runtime),
        .error = error,
        .network_available = atomic_load_explicit(
            &runtime->network_available, memory_order_acquire),
        .onboarding_required = atomic_load_explicit(
            &runtime->onboarding_required, memory_order_acquire),
        .approximate_time_available = atomic_load_explicit(
            &runtime->approximate_time_available, memory_order_acquire),
    };
    publish_event(runtime, &event);
}

static void time_bootstrap_event(
    void *ctx,
    const product_time_bootstrap_event_t *source)
{
    box3_product_runtime_handle_t runtime = ctx;
    if (runtime_stopping(runtime) || !source) {
        return;
    }
    atomic_store_explicit(&runtime->approximate_time_available,
                          source->approximate_time_available,
                          memory_order_release);
    const esp_err_t handoff =
        box3_agent_supervisor_set_network_available(
            runtime->supervisor,
            source->approximate_time_available);
    if (handoff != ESP_OK) {
        publish_error(runtime, handoff);
    }
    if (!source->approximate_time_available &&
        atomic_load_explicit(&runtime->network_available,
                             memory_order_acquire)) {
        set_state(runtime, BOX3_PRODUCT_RUNTIME_DEGRADED, source->error);
    }
    const box3_product_runtime_event_t event = {
        .type = BOX3_PRODUCT_RUNTIME_EVENT_TIME_BOOTSTRAP,
        .state = runtime_state(runtime),
        .error = source->error,
        .network_available = atomic_load_explicit(
            &runtime->network_available, memory_order_acquire),
        .onboarding_required = atomic_load_explicit(
            &runtime->onboarding_required, memory_order_acquire),
        .approximate_time_available =
            source->approximate_time_available,
    };
    publish_event(runtime, &event);
    if (source->error != ESP_OK) {
        publish_error(runtime, source->error);
    }
}

static void supervisor_event(void *ctx,
                             box3_agent_supervisor_state_t state,
                             esp_err_t last_error)
{
    box3_product_runtime_handle_t runtime = ctx;
    if (runtime_stopping(runtime)) {
        return;
    }
    const bool network = atomic_load_explicit(
        &runtime->network_available, memory_order_acquire);
    const bool onboarding = atomic_load_explicit(
        &runtime->onboarding_open, memory_order_acquire);
    const bool onboarding_required = atomic_load_explicit(
        &runtime->onboarding_required, memory_order_acquire);
    if (onboarding) {
        set_state(runtime, BOX3_PRODUCT_RUNTIME_ONBOARDING, last_error);
    } else if (!network || state == BOX3_AGENT_SUPERVISOR_WAIT_NETWORK) {
        set_state(runtime,
                  onboarding_required
                      ? BOX3_PRODUCT_RUNTIME_ONBOARDING_REQUIRED
                      : BOX3_PRODUCT_RUNTIME_WAIT_NETWORK,
                  last_error);
    } else if (state == BOX3_AGENT_SUPERVISOR_ONLINE) {
        set_state(runtime, BOX3_PRODUCT_RUNTIME_ONLINE, last_error);
    } else if (state == BOX3_AGENT_SUPERVISOR_ENTITLEMENT_BLOCKED) {
        set_state(runtime, BOX3_PRODUCT_RUNTIME_ENTITLEMENT_REQUIRED,
                  last_error);
    } else {
        set_state(runtime, BOX3_PRODUCT_RUNTIME_DEGRADED, last_error);
    }
    const box3_product_runtime_event_t event = {
        .type = BOX3_PRODUCT_RUNTIME_EVENT_SUPERVISOR,
        .state = runtime_state(runtime),
        .error = last_error,
        .network_available = network,
        .onboarding_required = onboarding_required,
        .approximate_time_available = atomic_load_explicit(
            &runtime->approximate_time_available, memory_order_acquire),
        .supervisor_state = state,
    };
    publish_event(runtime, &event);
}

static void wifi_event(void *ctx, const product_wifi_event_t *source)
{
    box3_product_runtime_handle_t runtime = ctx;
    if (runtime_stopping(runtime) || !source) {
        return;
    }
    if (source->type == PRODUCT_WIFI_EVENT_NETWORK_CHANGED) {
        atomic_store_explicit(&runtime->network_available,
                              source->network_available,
                              memory_order_release);
        esp_err_t handoff = product_time_bootstrap_set_network_available(
            runtime->time_bootstrap, source->network_available);
        if (!source->network_available) {
            atomic_store_explicit(&runtime->approximate_time_available,
                                  false, memory_order_release);
            const esp_err_t supervisor_handoff =
                box3_agent_supervisor_set_network_available(
                    runtime->supervisor, false);
            if (handoff == ESP_OK) {
                handoff = supervisor_handoff;
            }
        }
        if (handoff != ESP_OK) {
            publish_error(runtime, handoff);
        }
        if (!source->network_available) {
            const bool required = atomic_load_explicit(
                &runtime->onboarding_required, memory_order_acquire);
            set_state(runtime,
                      required ? BOX3_PRODUCT_RUNTIME_ONBOARDING_REQUIRED
                               : BOX3_PRODUCT_RUNTIME_WAIT_NETWORK,
                      source->error);
        }
    }
    if (source->type == PRODUCT_WIFI_EVENT_ONBOARDING_REQUIRED) {
        atomic_store_explicit(&runtime->onboarding_required,
                              source->onboarding_required,
                              memory_order_release);
        if (source->onboarding_required &&
            !atomic_load_explicit(&runtime->onboarding_open,
                                  memory_order_acquire)) {
            set_state(runtime, BOX3_PRODUCT_RUNTIME_ONBOARDING_REQUIRED,
                      source->error);
        }
    } else if (source->type == PRODUCT_WIFI_EVENT_CREDENTIALS_ACCEPTED) {
        atomic_store_explicit(&runtime->onboarding_required, false,
                              memory_order_release);
    }
    if (source->type == PRODUCT_WIFI_EVENT_ERROR) {
        publish_error(runtime, source->error);
    }
    const box3_product_runtime_event_t event = {
        .type = BOX3_PRODUCT_RUNTIME_EVENT_WIFI,
        .state = runtime_state(runtime),
        .error = source->error,
        .network_available = source->network_available,
        .onboarding_required = source->onboarding_required,
        .approximate_time_available = atomic_load_explicit(
            &runtime->approximate_time_available, memory_order_acquire),
        .wifi_event = source->type,
    };
    publish_event(runtime, &event);
}

static void provisioning_event(
    void *ctx,
    const product_provisioning_event_t *source)
{
    box3_product_runtime_handle_t runtime = ctx;
    if (runtime_stopping(runtime) || !source) {
        return;
    }
    if (source->type == PRODUCT_PROVISIONING_EVENT_WINDOW_OPENED) {
        atomic_store_explicit(&runtime->onboarding_open, true,
                              memory_order_release);
        set_state(runtime, BOX3_PRODUCT_RUNTIME_ONBOARDING, source->error);
    } else if (source->type ==
                   PRODUCT_PROVISIONING_EVENT_CANDIDATE_ACCEPTED) {
        atomic_store_explicit(&runtime->onboarding_required, false,
                              memory_order_release);
    } else if (source->type ==
                   PRODUCT_PROVISIONING_EVENT_CLAIM_RECOVERY_REQUIRED) {
        atomic_store_explicit(&runtime->onboarding_required, true,
                              memory_order_release);
        set_state(runtime, BOX3_PRODUCT_RUNTIME_ONBOARDING_REQUIRED,
                  source->error);
    } else if (source->type ==
                   PRODUCT_PROVISIONING_EVENT_CLAIM_RECOVERED) {
        atomic_store_explicit(&runtime->onboarding_required, false,
                              memory_order_release);
    } else if (source->type == PRODUCT_PROVISIONING_EVENT_WINDOW_CLOSED ||
               source->type == PRODUCT_PROVISIONING_EVENT_LOCKED_OUT) {
        atomic_store_explicit(&runtime->onboarding_open, false,
                              memory_order_release);
        const bool network = atomic_load_explicit(
            &runtime->network_available, memory_order_acquire);
        const bool required = atomic_load_explicit(
            &runtime->onboarding_required, memory_order_acquire);
        set_state(runtime,
                  required
                      ? BOX3_PRODUCT_RUNTIME_ONBOARDING_REQUIRED
                      : (network ? BOX3_PRODUCT_RUNTIME_DEGRADED
                                 : BOX3_PRODUCT_RUNTIME_WAIT_NETWORK),
                  source->error);
    }
    if (source->type == PRODUCT_PROVISIONING_EVENT_ERROR) {
        publish_error(runtime, source->error);
    }
    const box3_product_runtime_event_t event = {
        .type = BOX3_PRODUCT_RUNTIME_EVENT_PROVISIONING,
        .state = runtime_state(runtime),
        .error = source->error,
        .network_available = atomic_load_explicit(
            &runtime->network_available, memory_order_acquire),
        .onboarding_required = atomic_load_explicit(
            &runtime->onboarding_required, memory_order_acquire),
        .approximate_time_available = atomic_load_explicit(
            &runtime->approximate_time_available, memory_order_acquire),
        .provisioning_event = source->type,
    };
    publish_event(runtime, &event);
}

static esp_err_t publish_device_claim(
    void *ctx,
    const char *claim,
    product_provisioning_claim_outcome_t *outcome)
{
    if (!outcome) {
        return ESP_ERR_INVALID_ARG;
    }
    agent_control_plane_device_claim_outcome_t control_outcome =
        AGENT_CONTROL_PLANE_DEVICE_CLAIM_RETRY;
    const esp_err_t result =
        agent_control_plane_client_confirm_device_claim_ex(
            ctx, claim, &control_outcome);
    switch (control_outcome) {
    case AGENT_CONTROL_PLANE_DEVICE_CLAIM_BOUND:
        *outcome = PRODUCT_PROVISIONING_CLAIM_BOUND;
        break;
    case AGENT_CONTROL_PLANE_DEVICE_CLAIM_REJECTED:
        *outcome = PRODUCT_PROVISIONING_CLAIM_REJECTED;
        break;
    case AGENT_CONTROL_PLANE_DEVICE_CLAIM_RETRY:
    default:
        *outcome = PRODUCT_PROVISIONING_CLAIM_RETRY;
        break;
    }
    return result;
}

static esp_err_t consume_physical_presence(void *ctx)
{
    box3_product_runtime_handle_t runtime = ctx;
    if (runtime_stopping(runtime) ||
        !atomic_exchange_explicit(&runtime->physical_presence_grant, false,
                                  memory_order_acq_rel)) {
        return ESP_ERR_INVALID_STATE;
    }
    return ESP_OK;
}

static void factory_reset_restart_task(void *argument)
{
    (void)argument;
    vTaskDelay(pdMS_TO_TICKS(FACTORY_RESET_RESTART_DELAY_MS));
    esp_restart();
    vTaskDelete(NULL);
}

static esp_err_t trigger_from_local_action(
    void *ctx,
    product_local_action_kind_t action)
{
    box3_product_runtime_handle_t runtime = ctx;
    if (runtime_stopping(runtime)) {
        return ESP_ERR_INVALID_STATE;
    }
    if (action == PRODUCT_LOCAL_ACTION_ONBOARDING) {
        return box3_product_runtime_open_onboarding(runtime);
    }
    if (action != PRODUCT_LOCAL_ACTION_FACTORY_RESET) {
        return ESP_ERR_INVALID_ARG;
    }
    const esp_err_t error = product_factory_reset_prepare();
    if (error != ESP_OK) {
        return error;
    }
    ESP_LOGW(TAG,
             "factory reset intent committed; restarting into recovery");
    if (xTaskCreate(factory_reset_restart_task, "factory_reset",
                    FACTORY_RESET_RESTART_STACK_SIZE, NULL,
                    FACTORY_RESET_RESTART_TASK_PRIORITY, NULL) != pdPASS) {
        /* Intent is already durable. Immediate restart is the safe fallback. */
        esp_restart();
    }
    return ESP_OK;
}

static void local_action_event_callback(
    void *ctx,
    const product_local_action_event_t *source)
{
    box3_product_runtime_handle_t runtime = ctx;
    if (runtime_stopping(runtime) || !source) {
        return;
    }
    const box3_product_runtime_event_t event = {
        .type = BOX3_PRODUCT_RUNTIME_EVENT_LOCAL_ACTION,
        .state = runtime_state(runtime),
        .error = source->error,
        .network_available = atomic_load_explicit(
            &runtime->network_available, memory_order_acquire),
        .onboarding_required = atomic_load_explicit(
            &runtime->onboarding_required, memory_order_acquire),
        .approximate_time_available = atomic_load_explicit(
            &runtime->approximate_time_available, memory_order_acquire),
        .local_action_armed = source->armed,
        .local_action_pressed = source->pressed,
        .local_action_held_ms = source->held_ms,
        .local_action_event = source->type,
    };
    publish_event(runtime, &event);
    if (source->error != ESP_OK) {
        publish_error(runtime, source->error);
    }
}

static bool acquire_resource(box3_product_runtime_handle_t runtime,
                             box3_product_runtime_resource_t resource)
{
    return runtime &&
           box3_product_runtime_core_acquire(&runtime->core, resource);
}

static uint32_t remaining_ms(uint64_t deadline_us)
{
    const int64_t now = esp_timer_get_time();
    if (now < 0 || (uint64_t)now >= deadline_us) {
        return 0;
    }
    const uint64_t remaining_us = deadline_us - (uint64_t)now;
    uint64_t milliseconds = (remaining_us + 999U) / 1000U;
    if (milliseconds > UINT32_MAX) {
        milliseconds = UINT32_MAX;
    }
    return (uint32_t)milliseconds;
}

typedef struct {
    box3_product_runtime_handle_t runtime;
    unsigned int cancel_epoch;
} action_consent_operation_t;

static bool action_consent_monotonic_ms(void *ctx, uint64_t *value)
{
    action_consent_operation_t *operation = ctx;
    const int64_t now_us = esp_timer_get_time();
    if (!operation || !operation->runtime || !value || now_us < 0) {
        return false;
    }
    *value = (uint64_t)now_us / 1000U;
    return true;
}

static bool action_consent_operation_available(void *ctx)
{
    action_consent_operation_t *operation = ctx;
    box3_product_runtime_handle_t runtime =
        operation ? operation->runtime : NULL;
    return runtime && !runtime_stopping(runtime) &&
           atomic_load_explicit(&runtime->network_available,
                                memory_order_acquire) &&
           atomic_load_explicit(&runtime->approximate_time_available,
                                memory_order_acquire) &&
           atomic_load_explicit(&runtime->action_consent_cancel_epoch,
                                memory_order_acquire) ==
               operation->cancel_epoch;
}

static bool action_consent_register(
    void *ctx,
    const char *session_id,
    uint32_t request_id,
    bool indicator_on,
    uint32_t lifetime_seconds,
    uint32_t request_timeout_ms,
    void *consent_state)
{
    action_consent_operation_t *operation = ctx;
    return operation && operation->runtime && consent_state &&
           agent_control_plane_client_register_action_consent_bounded(
               operation->runtime->control, session_id, request_id,
               indicator_on, lifetime_seconds, request_timeout_ms,
               consent_state) == ESP_OK;
}

static bool action_consent_poll(
    void *ctx,
    void *consent_state,
    uint32_t request_timeout_ms,
    box3_action_consent_decision_t *decision)
{
    action_consent_operation_t *operation = ctx;
    if (!operation || !operation->runtime || !consent_state || !decision) {
        return false;
    }
    agent_control_plane_action_decision_t source =
        AGENT_CONTROL_PLANE_ACTION_PENDING;
    if (agent_control_plane_client_poll_action_consent_bounded(
            operation->runtime->control, consent_state,
            request_timeout_ms, &source) != ESP_OK) {
        return false;
    }
    switch (source) {
    case AGENT_CONTROL_PLANE_ACTION_PENDING:
        *decision = BOX3_ACTION_CONSENT_PENDING;
        return true;
    case AGENT_CONTROL_PLANE_ACTION_APPROVED:
        *decision = BOX3_ACTION_CONSENT_APPROVED;
        return true;
    case AGENT_CONTROL_PLANE_ACTION_DENIED:
        *decision = BOX3_ACTION_CONSENT_DENIED;
        return true;
    default:
        return false;
    }
}

static void action_consent_wait(void *ctx, uint32_t milliseconds)
{
    (void)ctx;
    vTaskDelay(pdMS_TO_TICKS(milliseconds));
}

static bool product_action_consent(
    void *ctx,
    uint32_t request_id,
    const char *session_id,
    const esp_claw_capability_action_t *action)
{
    box3_product_runtime_handle_t runtime = ctx;
    if (!runtime || request_id == 0 || !session_id || !session_id[0] ||
        !action ||
        action->type != ESP_CLAW_CAPABILITY_ACTION_SET_INDICATOR) {
        return false;
    }
    atomic_fetch_add_explicit(&runtime->action_consents_requested, 1,
                              memory_order_relaxed);
    action_consent_operation_t operation = {
        .runtime = runtime,
        .cancel_epoch = atomic_load_explicit(
            &runtime->action_consent_cancel_epoch, memory_order_acquire),
    };
    const box3_action_consent_core_config_t config = {
        .timeout_ms = runtime->action_consent_timeout_ms,
        .poll_interval_ms = runtime->action_consent_poll_interval_ms,
        .network_timeout_ms = runtime->control_network_timeout_ms,
        .maximum_request_timeout_ms = ACTION_CONSENT_MAXIMUM_REQUEST_MS,
    };
    const box3_action_consent_core_ops_t ops = {
        .monotonic_ms = action_consent_monotonic_ms,
        .available = action_consent_operation_available,
        .register_action = action_consent_register,
        .poll_action = action_consent_poll,
        .wait_ms = action_consent_wait,
    };
    agent_control_plane_action_consent_t consent = {0};
    bool registered = false;
    const box3_action_consent_outcome_t outcome =
        box3_action_consent_core_run(
            &config, &ops, &operation, session_id, request_id,
            action->indicator_on, &consent, &registered);
    secure_zero(&consent, sizeof(consent));
    if (registered) {
        atomic_fetch_add_explicit(&runtime->action_consents_registered, 1,
                                  memory_order_relaxed);
    }
    switch (outcome) {
    case BOX3_ACTION_CONSENT_OUTCOME_APPROVED:
        atomic_fetch_add_explicit(&runtime->action_consents_approved, 1,
                                  memory_order_relaxed);
        return true;
    case BOX3_ACTION_CONSENT_OUTCOME_DENIED:
        atomic_fetch_add_explicit(&runtime->action_consents_denied, 1,
                                  memory_order_relaxed);
        break;
    case BOX3_ACTION_CONSENT_OUTCOME_EXPIRED:
        atomic_fetch_add_explicit(&runtime->action_consents_expired, 1,
                                  memory_order_relaxed);
        break;
    case BOX3_ACTION_CONSENT_OUTCOME_CANCELED:
        atomic_fetch_add_explicit(&runtime->action_consents_canceled, 1,
                                  memory_order_relaxed);
        break;
    default:
        atomic_fetch_add_explicit(&runtime->action_consents_failed, 1,
                                  memory_order_relaxed);
        break;
    }
    return false;
}

static esp_err_t cleanup_runtime(box3_product_runtime_handle_t runtime,
                                 uint32_t timeout_ms)
{
    if (!runtime || timeout_ms == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    atomic_store_explicit(&runtime->stopping, true, memory_order_release);
    atomic_store_explicit(&runtime->state, BOX3_PRODUCT_RUNTIME_STOPPING,
                          memory_order_release);
    atomic_store_explicit(&runtime->physical_presence_grant, false,
                          memory_order_release);
    box3_product_runtime_core_begin_stop(&runtime->core);
    const int64_t start_us = esp_timer_get_time();
    if (start_us < 0 ||
        (uint64_t)start_us > UINT64_MAX - (uint64_t)timeout_ms * 1000U) {
        return ESP_ERR_INVALID_STATE;
    }
    const uint64_t deadline_us =
        (uint64_t)start_us + (uint64_t)timeout_ms * 1000U;

    for (;;) {
        const box3_product_runtime_resource_t resource =
            box3_product_runtime_core_next_cleanup(&runtime->core);
        if (resource == BOX3_PRODUCT_RUNTIME_RESOURCE_NONE) {
            return runtime->core.state == BOX3_PRODUCT_RUNTIME_CORE_STOPPED
                       ? ESP_OK
                       : ESP_ERR_INVALID_STATE;
        }
        uint32_t timeout = remaining_ms(deadline_us);
        if (timeout == 0) {
            box3_product_runtime_core_cleanup_failed(&runtime->core);
            return ESP_ERR_TIMEOUT;
        }
        esp_err_t error = ESP_ERR_INVALID_STATE;
        switch (resource) {
        case BOX3_PRODUCT_RUNTIME_RESOURCE_LOCAL_ACTION:
            error = product_local_action_destroy(runtime->local_action,
                                                 timeout);
            if (error == ESP_OK) {
                runtime->local_action = NULL;
            }
            break;
        case BOX3_PRODUCT_RUNTIME_RESOURCE_PROVISIONING:
            error = product_provisioning_destroy(runtime->provisioning,
                                                 timeout);
            if (error == ESP_OK) {
                runtime->provisioning = NULL;
            }
            break;
        case BOX3_PRODUCT_RUNTIME_RESOURCE_WIFI:
            error = product_wifi_stop(runtime->wifi, timeout);
            if (error == ESP_OK) {
                runtime->wifi = NULL;
            }
            break;
        case BOX3_PRODUCT_RUNTIME_RESOURCE_TIME_BOOTSTRAP:
            error = product_time_bootstrap_destroy(
                runtime->time_bootstrap, timeout);
            if (error == ESP_OK) {
                runtime->time_bootstrap = NULL;
            }
            break;
        case BOX3_PRODUCT_RUNTIME_RESOURCE_SUPERVISOR:
            if (timeout < SUPERVISOR_MINIMUM_STOP_TIMEOUT_MS) {
                error = ESP_ERR_TIMEOUT;
            } else {
                error = box3_agent_supervisor_stop(runtime->supervisor,
                                                   timeout);
            }
            if (error == ESP_OK) {
                runtime->supervisor = NULL;
            }
            break;
        case BOX3_PRODUCT_RUNTIME_RESOURCE_CREDENTIALS:
            error = box3_agent_credentials_client_destroy(
                runtime->credentials);
            if (error == ESP_OK) {
                runtime->credentials = NULL;
            }
            break;
        case BOX3_PRODUCT_RUNTIME_RESOURCE_CONTROL:
            error = agent_control_plane_client_destroy(runtime->control);
            if (error == ESP_OK) {
                runtime->control = NULL;
            }
            break;
        case BOX3_PRODUCT_RUNTIME_RESOURCE_IDENTITY:
            error = agent_device_identity_destroy(runtime->identity);
            if (error == ESP_OK) {
                runtime->identity = NULL;
            }
            break;
        default:
            error = ESP_ERR_INVALID_STATE;
            break;
        }
        if (error != ESP_OK) {
            box3_product_runtime_core_cleanup_failed(&runtime->core);
            return error;
        }
        if (!box3_product_runtime_core_release(&runtime->core, resource)) {
            return ESP_ERR_INVALID_STATE;
        }
    }
}

static esp_err_t fail_start(box3_product_runtime_handle_t runtime,
                            box3_product_runtime_handle_t *out_runtime,
                            esp_err_t failure)
{
    if (!runtime) {
        return failure;
    }
    const esp_err_t cleanup = cleanup_runtime(
        runtime, STARTUP_CLEANUP_TIMEOUT_MS);
    if (cleanup == ESP_OK) {
        release_runtime(runtime);
    } else {
        *out_runtime = runtime;
        ESP_LOGE(TAG,
                 "startup failed and cleanup is incomplete; retry stop: %s",
                 esp_err_to_name(cleanup));
    }
    return failure;
}

esp_err_t box3_product_runtime_start(
    const box3_product_runtime_config_t *config,
    box3_product_runtime_handle_t *out_runtime)
{
    if (!out_runtime) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_runtime = NULL;
    const uint32_t action_consent_timeout_ms =
        config && config->action_consent_timeout_ms
            ? config->action_consent_timeout_ms
            : ACTION_CONSENT_DEFAULT_TIMEOUT_MS;
    const uint32_t action_consent_poll_ms =
        config && config->action_consent_poll_interval_ms
            ? config->action_consent_poll_interval_ms
            : ACTION_CONSENT_DEFAULT_POLL_MS;
    if (!config || !config->device_id || !config->client_id ||
        !config->hostname || !config->control_authority ||
        !config->agent_proxy_authority || config->sntp_server_count == 0 ||
        config->sntp_server_count > PRODUCT_TIME_BOOTSTRAP_SERVER_LIMIT ||
        config->onboarding_button_gpio < 0 ||
        config->onboarding_button_gpio >= GPIO_NUM_MAX ||
        config->product.websocket.uri ||
        config->product.websocket.bearer_token ||
        config->product.websocket.device_id ||
        config->product.websocket.client_id ||
        config->product.agent.api_key || config->product.agent.base_url ||
        config->product.agent.capability_consent ||
        config->product.agent.capability_consent_ctx ||
        action_consent_timeout_ms < ACTION_CONSENT_MINIMUM_TIMEOUT_MS ||
        action_consent_timeout_ms > ACTION_CONSENT_MAXIMUM_TIMEOUT_MS ||
        action_consent_poll_ms < ACTION_CONSENT_MINIMUM_POLL_MS ||
        action_consent_poll_ms > ACTION_CONSENT_MAXIMUM_POLL_MS ||
        action_consent_poll_ms + ACTION_CONSENT_MINIMUM_REQUEST_MS >=
            action_consent_timeout_ms ||
        ((!config->control_server_cert_pem ||
          !config->control_server_cert_pem[0]) ==
         !config->control_use_crt_bundle) ||
        !product_storage_identity_hmac_key_allowed(
            config->identity_hmac_key_id)) {
        return ESP_ERR_INVALID_ARG;
    }

    for (size_t i = 0; i < config->sntp_server_count; ++i) {
        if (!config->sntp_servers[i] || !config->sntp_servers[i][0]) {
            return ESP_ERR_INVALID_ARG;
        }
    }

    char time_endpoint[BOX3_PRODUCT_RUNTIME_ENDPOINT_BYTES];
    char token_endpoint[BOX3_PRODUCT_RUNTIME_ENDPOINT_BYTES];
    char claim_endpoint[BOX3_PRODUCT_RUNTIME_ENDPOINT_BYTES];
    char action_challenge_endpoint[BOX3_PRODUCT_RUNTIME_ENDPOINT_BYTES];
    char action_result_endpoint[BOX3_PRODUCT_RUNTIME_ENDPOINT_BYTES];
    char session_endpoint[BOX3_PRODUCT_RUNTIME_ENDPOINT_BYTES];
    char agent_base_url[BOX3_PRODUCT_RUNTIME_ENDPOINT_BYTES];
    if (!box3_product_runtime_build_endpoint(
            config->control_authority, "/v1/time", time_endpoint,
            sizeof(time_endpoint)) ||
        !box3_product_runtime_build_endpoint(
            config->control_authority, "/v1/agent-token", token_endpoint,
            sizeof(token_endpoint)) ||
        !box3_product_runtime_build_endpoint(
            config->control_authority, "/v1/device-claim/device",
            claim_endpoint, sizeof(claim_endpoint)) ||
        !box3_product_runtime_build_endpoint(
            config->control_authority,
            "/v1/action-consents/device/challenge",
            action_challenge_endpoint, sizeof(action_challenge_endpoint)) ||
        !box3_product_runtime_build_endpoint(
            config->control_authority,
            "/v1/action-consents/device/result",
            action_result_endpoint, sizeof(action_result_endpoint)) ||
        !box3_product_runtime_build_endpoint(
            config->control_authority, "/v1/session", session_endpoint,
            sizeof(session_endpoint)) ||
        !box3_product_runtime_build_endpoint(
            config->agent_proxy_authority, "/v1", agent_base_url,
            sizeof(agent_base_url))) {
        return ESP_ERR_INVALID_ARG;
    }

    box3_product_runtime_handle_t runtime = heap_caps_calloc(
        1, sizeof(*runtime), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!runtime) {
        return ESP_ERR_NO_MEM;
    }
    box3_product_runtime_core_init(&runtime->core);
    runtime->event = config->event;
    runtime->event_ctx = config->event_ctx;
    atomic_init(&runtime->state, BOX3_PRODUCT_RUNTIME_STARTING);
    atomic_init(&runtime->stopping, false);
    atomic_init(&runtime->network_available, false);
    atomic_init(&runtime->onboarding_required, false);
    atomic_init(&runtime->onboarding_open, false);
    atomic_init(&runtime->approximate_time_available, false);
    atomic_init(&runtime->physical_presence_grant, false);
    runtime->control_network_timeout_ms = config->control_network_timeout_ms
                                              ? config->control_network_timeout_ms
                                              : CONTROL_DEFAULT_NETWORK_TIMEOUT_MS;
    runtime->action_consent_timeout_ms = action_consent_timeout_ms;
    runtime->action_consent_poll_interval_ms = action_consent_poll_ms;
    atomic_init(&runtime->action_consent_cancel_epoch, 0);
    atomic_init(&runtime->action_consents_requested, 0);
    atomic_init(&runtime->action_consents_registered, 0);
    atomic_init(&runtime->action_consents_approved, 0);
    atomic_init(&runtime->action_consents_denied, 0);
    atomic_init(&runtime->action_consents_expired, 0);
    atomic_init(&runtime->action_consents_canceled, 0);
    atomic_init(&runtime->action_consents_failed, 0);

    const agent_device_identity_config_t identity_config = {
        .device_id = config->device_id,
        .hmac_key_id = config->identity_hmac_key_id,
    };
    esp_err_t error = agent_device_identity_create(
        &identity_config, &runtime->identity);
    if (error != ESP_OK ||
        !acquire_resource(runtime,
                          BOX3_PRODUCT_RUNTIME_RESOURCE_IDENTITY)) {
        return fail_start(runtime, out_runtime,
                          error == ESP_OK ? ESP_ERR_INVALID_STATE : error);
    }

    const agent_control_plane_client_config_t control_config = {
        .time_endpoint = time_endpoint,
        .agent_token_endpoint = token_endpoint,
        .device_claim_endpoint = claim_endpoint,
        .action_challenge_endpoint = action_challenge_endpoint,
        .action_result_endpoint = action_result_endpoint,
        .device_id = config->device_id,
        .client_id = config->client_id,
        .server_cert_pem = config->control_server_cert_pem,
        .use_crt_bundle = config->control_use_crt_bundle,
        .network_timeout_ms = config->control_network_timeout_ms,
        .sign_agent_proof =
            agent_device_identity_sign_agent_token_proof,
        .sign_device_claim_proof =
            agent_device_identity_sign_device_claim_proof,
        .sign_action_challenge_proof =
            agent_device_identity_sign_action_consent_challenge_proof,
        .sign_action_result_proof =
            agent_device_identity_sign_action_consent_result_proof,
        .sign_ctx = runtime->identity,
        .get_unix_time = agent_device_identity_get_unix_time,
        .time_ctx = runtime->identity,
        .accept_authenticated_time =
            agent_device_identity_accept_authenticated_time_callback,
        .accept_time_ctx = runtime->identity,
    };
    error = agent_control_plane_client_create(&control_config,
                                               &runtime->control);
    if (error != ESP_OK ||
        !acquire_resource(runtime,
                          BOX3_PRODUCT_RUNTIME_RESOURCE_CONTROL)) {
        return fail_start(runtime, out_runtime,
                          error == ESP_OK ? ESP_ERR_INVALID_STATE : error);
    }

    const box3_agent_credentials_client_config_t credential_config = {
        .session_endpoint = session_endpoint,
        .device_id = config->device_id,
        .client_id = config->client_id,
        .server_cert_pem = config->control_server_cert_pem,
        .use_crt_bundle = config->control_use_crt_bundle,
        .network_timeout_ms = config->control_network_timeout_ms,
        .sign_proof = agent_device_identity_sign_proof,
        .sign_ctx = runtime->identity,
        .get_unix_time =
            agent_control_plane_client_get_or_sync_unix_time,
        .time_ctx = runtime->control,
        .refresh_agent_token =
            agent_control_plane_client_refresh_agent_token,
        .agent_ctx = runtime->control,
    };
    error = box3_agent_credentials_client_create(
        &credential_config, &runtime->credentials);
    if (error != ESP_OK ||
        !acquire_resource(runtime,
                          BOX3_PRODUCT_RUNTIME_RESOURCE_CREDENTIALS)) {
        return fail_start(runtime, out_runtime,
                          error == ESP_OK ? ESP_ERR_INVALID_STATE : error);
    }

    box3_agent_voice_config_t product = config->product;
    product.websocket.device_id = config->device_id;
    product.websocket.client_id = config->client_id;
    product.agent.base_url = agent_base_url;
    product.agent.capability_consent = product_action_consent;
    product.agent.capability_consent_ctx = runtime;
    const box3_agent_supervisor_config_t supervisor_config = {
        .product = product,
        .refresh_credentials = box3_agent_credentials_client_refresh,
        .credential_ctx = runtime->credentials,
        .event = supervisor_event,
        .event_ctx = runtime,
        .minimum_backoff_ms = config->supervisor_minimum_backoff_ms,
        .maximum_backoff_ms = config->supervisor_maximum_backoff_ms,
        .refresh_margin_seconds =
            config->supervisor_refresh_margin_seconds,
        .product_stop_timeout_ms = config->product_stop_timeout_ms,
    };
    error = box3_agent_supervisor_create(&supervisor_config,
                                         &runtime->supervisor);
    if (error != ESP_OK ||
        !acquire_resource(runtime,
                          BOX3_PRODUCT_RUNTIME_RESOURCE_SUPERVISOR)) {
        return fail_start(runtime, out_runtime,
                          error == ESP_OK ? ESP_ERR_INVALID_STATE : error);
    }
    error = box3_agent_supervisor_start(runtime->supervisor);
    if (error != ESP_OK) {
        return fail_start(runtime, out_runtime, error);
    }

    const product_time_bootstrap_config_t time_config = {
        .servers = {
            config->sntp_servers[0],
            config->sntp_servers[1],
            config->sntp_servers[2],
        },
        .server_count = config->sntp_server_count,
        .event = time_bootstrap_event,
        .event_ctx = runtime,
        .sync_timeout_ms = config->sntp_sync_timeout_ms,
    };
    error = product_time_bootstrap_create(
        &time_config, &runtime->time_bootstrap);
    if (error != ESP_OK ||
        !acquire_resource(
            runtime, BOX3_PRODUCT_RUNTIME_RESOURCE_TIME_BOOTSTRAP)) {
        return fail_start(runtime, out_runtime,
                          error == ESP_OK ? ESP_ERR_INVALID_STATE : error);
    }

    const product_wifi_config_t wifi_config = {
        .hostname = config->hostname,
        .event = wifi_event,
        .event_ctx = runtime,
        .minimum_backoff_ms = config->wifi_minimum_backoff_ms,
        .maximum_backoff_ms = config->wifi_maximum_backoff_ms,
        .authentication_failure_limit =
            config->wifi_authentication_failure_limit,
    };
    error = product_wifi_create(&wifi_config, &runtime->wifi);
    if (error != ESP_OK ||
        !acquire_resource(runtime, BOX3_PRODUCT_RUNTIME_RESOURCE_WIFI)) {
        return fail_start(runtime, out_runtime,
                          error == ESP_OK ? ESP_ERR_INVALID_STATE : error);
    }

    const product_provisioning_config_t provisioning_config = {
        .wifi = runtime->wifi,
        .physical_presence = consume_physical_presence,
        .physical_presence_ctx = runtime,
        .derive_ap_key =
            agent_device_identity_derive_onboarding_ap_key,
        .derive_ap_key_ctx = runtime->identity,
        .device_id = config->device_id,
        .publish_claim = publish_device_claim,
        .publish_claim_ctx = runtime->control,
        .event = provisioning_event,
        .event_ctx = runtime,
        .window_ms = config->provisioning_window_ms,
        .authentication_failure_limit =
            config->provisioning_authentication_failure_limit,
    };
    error = product_provisioning_create(
        &provisioning_config, &runtime->provisioning);
    if (error != ESP_OK ||
        !acquire_resource(runtime,
                          BOX3_PRODUCT_RUNTIME_RESOURCE_PROVISIONING)) {
        return fail_start(runtime, out_runtime,
                          error == ESP_OK ? ESP_ERR_INVALID_STATE : error);
    }

    const product_local_action_config_t local_action_config = {
        .gpio_num = config->onboarding_button_gpio,
        .active_high = config->onboarding_button_active_high,
        .trigger = trigger_from_local_action,
        .trigger_ctx = runtime,
        .event = local_action_event_callback,
        .event_ctx = runtime,
        .sample_period_ms = config->onboarding_button_sample_period_ms,
        .debounce_ms = config->onboarding_button_debounce_ms,
        .long_press_ms = config->onboarding_button_long_press_ms,
        .factory_reset_press_ms =
            config->onboarding_button_factory_reset_press_ms,
    };
    error = product_local_action_create(&local_action_config,
                                        &runtime->local_action);
    if (error != ESP_OK ||
        !acquire_resource(runtime,
                          BOX3_PRODUCT_RUNTIME_RESOURCE_LOCAL_ACTION)) {
        return fail_start(runtime, out_runtime,
                          error == ESP_OK ? ESP_ERR_INVALID_STATE : error);
    }

    error = product_wifi_start(runtime->wifi);
    if (error != ESP_OK || !box3_product_runtime_core_commit(&runtime->core)) {
        return fail_start(runtime, out_runtime,
                          error == ESP_OK ? ESP_ERR_INVALID_STATE : error);
    }
    error = product_local_action_start(runtime->local_action);
    if (error != ESP_OK) {
        return fail_start(runtime, out_runtime, error);
    }
    set_state(runtime, BOX3_PRODUCT_RUNTIME_WAIT_NETWORK, ESP_OK);
    *out_runtime = runtime;
    return ESP_OK;
}

esp_err_t box3_product_runtime_open_onboarding(
    box3_product_runtime_handle_t runtime)
{
    if (runtime_stopping(runtime) || !runtime->provisioning) {
        return ESP_ERR_INVALID_STATE;
    }
    bool expected = false;
    if (!atomic_compare_exchange_strong_explicit(
            &runtime->physical_presence_grant, &expected, true,
            memory_order_acq_rel, memory_order_acquire)) {
        return ESP_ERR_INVALID_STATE;
    }
    const esp_err_t error = product_provisioning_open(
        runtime->provisioning);
    atomic_store_explicit(&runtime->physical_presence_grant, false,
                          memory_order_release);
    return error;
}

esp_err_t box3_product_runtime_close_onboarding(
    box3_product_runtime_handle_t runtime)
{
    if (runtime_stopping(runtime) || !runtime->provisioning) {
        return ESP_ERR_INVALID_STATE;
    }
    return product_provisioning_close(runtime->provisioning);
}

esp_err_t box3_product_runtime_interrupt(
    box3_product_runtime_handle_t runtime,
    agent_bridge_interrupt_reason_t reason)
{
    if (runtime_stopping(runtime) || !runtime->supervisor) {
        return ESP_ERR_INVALID_STATE;
    }
    atomic_fetch_add_explicit(&runtime->action_consent_cancel_epoch, 1,
                              memory_order_acq_rel);
    return box3_agent_supervisor_interrupt(runtime->supervisor, reason);
}

esp_err_t box3_product_runtime_entitlement_changed(
    box3_product_runtime_handle_t runtime)
{
    if (runtime_stopping(runtime) || !runtime->supervisor) {
        return ESP_ERR_INVALID_STATE;
    }
    return box3_agent_supervisor_entitlement_changed(runtime->supervisor);
}

esp_err_t box3_product_runtime_get_stats(
    box3_product_runtime_handle_t runtime,
    box3_product_runtime_stats_t *stats)
{
    if (runtime_stopping(runtime) || !stats || !runtime->wifi ||
        !runtime->provisioning || !runtime->local_action ||
        !runtime->supervisor) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(stats, 0, sizeof(*stats));
    stats->state = runtime_state(runtime);
    stats->cleanup_retries = runtime->core.cleanup_retries;
    stats->action_consents_requested = atomic_load_explicit(
        &runtime->action_consents_requested, memory_order_relaxed);
    stats->action_consents_registered = atomic_load_explicit(
        &runtime->action_consents_registered, memory_order_relaxed);
    stats->action_consents_approved = atomic_load_explicit(
        &runtime->action_consents_approved, memory_order_relaxed);
    stats->action_consents_denied = atomic_load_explicit(
        &runtime->action_consents_denied, memory_order_relaxed);
    stats->action_consents_expired = atomic_load_explicit(
        &runtime->action_consents_expired, memory_order_relaxed);
    stats->action_consents_canceled = atomic_load_explicit(
        &runtime->action_consents_canceled, memory_order_relaxed);
    stats->action_consents_failed = atomic_load_explicit(
        &runtime->action_consents_failed, memory_order_relaxed);
    esp_err_t error = product_time_bootstrap_get_stats(
        runtime->time_bootstrap, &stats->time_bootstrap);
    if (error == ESP_OK) {
        error = product_wifi_get_stats(runtime->wifi, &stats->wifi);
    }
    if (error == ESP_OK) {
        error = product_provisioning_get_stats(
            runtime->provisioning, &stats->provisioning);
    }
    if (error == ESP_OK) {
        error = product_local_action_get_stats(
            runtime->local_action, &stats->local_action);
    }
    if (error == ESP_OK) {
        error = box3_agent_supervisor_get_stats(
            runtime->supervisor, &stats->supervisor);
    }
    return error;
}

esp_err_t box3_product_runtime_stop(
    box3_product_runtime_handle_t runtime,
    uint32_t timeout_ms)
{
    if (!runtime) {
        return ESP_OK;
    }
    if (timeout_ms < SUPERVISOR_MINIMUM_STOP_TIMEOUT_MS ||
        timeout_ms > 60000) {
        return ESP_ERR_INVALID_ARG;
    }
    const esp_err_t error = cleanup_runtime(runtime, timeout_ms);
    if (error == ESP_OK) {
        release_runtime(runtime);
    }
    return error;
}
