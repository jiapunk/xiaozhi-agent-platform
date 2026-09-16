#include "box3_agent_supervisor.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "esp_heap_caps.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"

enum {
    SIGNAL_WAKE = BIT0,
    SIGNAL_STOP = BIT1,
    SIGNAL_TASK_STOPPED = BIT2,
    SIGNAL_CLIENT_READY = BIT3,
    SIGNAL_CLIENT_FAILED = BIT4,
    SIGNAL_INTERRUPT = BIT5,
    SIGNAL_ENTITLEMENT_CHANGED = BIT6,
    SIGNAL_INPUT_MASK = SIGNAL_WAKE | SIGNAL_STOP | SIGNAL_CLIENT_READY |
                        SIGNAL_CLIENT_FAILED | SIGNAL_INTERRUPT |
                        SIGNAL_ENTITLEMENT_CHANGED,
    AGENT_BACKEND_MAX = 32,
    AGENT_MODEL_MAX = 128,
    AGENT_BASE_URL_MAX = 512,
    AGENT_AUTH_TYPE_MAX = 32,
    AGENT_MAX_TOKENS_FIELD_MAX = 64,
    AGENT_SYSTEM_PROMPT_MAX = 2048,
    SERVER_CERT_PEM_MAX = 16384,
    DEFAULT_MINIMUM_BACKOFF_MS = 5000,
    DEFAULT_MAXIMUM_BACKOFF_MS = 60000,
    DEFAULT_REFRESH_MARGIN_SECONDS = 60,
    DEFAULT_PRODUCT_STOP_TIMEOUT_MS = 5000,
    DEFAULT_TASK_STACK_SIZE = 8192,
    DEFAULT_TASK_PRIORITY = 5,
    MAXIMUM_TASK_STACK_SIZE = 32768,
    WORKER_WAIT_CEILING_MS = 1000,
    CLEANUP_RETRY_DELAY_MS = 100,
};

typedef struct {
    char device_id[DEVICE_WEBSOCKET_IDENTIFIER_MAX + 1];
    char client_id[DEVICE_WEBSOCKET_IDENTIFIER_MAX + 1];
    char backend_type[AGENT_BACKEND_MAX + 1];
    char model[AGENT_MODEL_MAX + 1];
    char base_url[AGENT_BASE_URL_MAX + 1];
    char auth_type[AGENT_AUTH_TYPE_MAX + 1];
    char max_tokens_field[AGENT_MAX_TOKENS_FIELD_MAX + 1];
    char system_prompt[AGENT_SYSTEM_PROMPT_MAX + 1];
} owned_strings_t;

typedef struct {
    atomic_uint credential_refreshes;
    atomic_uint credential_failures;
    atomic_uint session_starts;
    atomic_uint session_failures;
    atomic_uint disconnects;
    atomic_uint cleanup_retries;
    atomic_uint interrupt_rejections;
} atomic_stats_t;

struct box3_agent_supervisor {
    box3_agent_voice_config_t product_config;
    owned_strings_t *strings;
    char *server_cert_pem;
    box3_agent_credentials_t *credentials;

    box3_agent_refresh_credentials_fn refresh_credentials;
    void *credential_ctx;
    box3_agent_supervisor_event_fn event;
    void *supervisor_event_ctx;

    void (*state_changed_cb)(void *ctx,
                             agent_bridge_state_t from,
                             agent_bridge_state_t to,
                             uint32_t request_id);
    void (*client_event_cb)(void *ctx,
                            const device_voice_client_event_t *event);
    void (*audio_event_cb)(void *ctx,
                           box3_voice_audio_event_t event,
                           uint32_t request_id);
    void *product_event_ctx;

    uint32_t product_stop_timeout_ms;
    uint32_t task_stack_size;
    uint32_t task_priority;
    box3_agent_supervisor_core_t core;
    box3_agent_voice_handle_t product;
    EventGroupHandle_t signals;
    TaskHandle_t worker;

    atomic_bool started;
    atomic_bool stopping;
    atomic_bool network_available;
    atomic_bool has_session;
    atomic_bool ready;
    atomic_int pending_interrupt_reason;
    atomic_int published_state;
    atomic_uint api_calls;
    atomic_stats_t stats;
};

static void *allocate_prefer_psram(size_t size)
{
    void *memory = heap_caps_calloc(1, size,
                                    MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!memory) {
        memory = heap_caps_calloc(1, size,
                                  MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    }
    return memory;
}

static void secure_zero(void *memory, size_t size)
{
    volatile unsigned char *bytes = memory;
    while (bytes && size > 0) {
        *bytes++ = 0;
        --size;
    }
}

static bool copy_bounded(char *output,
                         size_t output_size,
                         const char *input,
                         bool required)
{
    if (!output || output_size == 0 || !input || !input[0]) {
        if (output && output_size > 0) {
            output[0] = '\0';
        }
        return !required;
    }
    const size_t size = strnlen(input, output_size);
    if (size == output_size) {
        return false;
    }
    memcpy(output, input, size + 1);
    return true;
}

static bool safe_identifier(const char *value)
{
    if (!value || !value[0]) {
        return false;
    }
    const size_t size = strnlen(value,
                                DEVICE_WEBSOCKET_IDENTIFIER_MAX + 1);
    if (size == 0 || size > DEVICE_WEBSOCKET_IDENTIFIER_MAX) {
        return false;
    }
    for (size_t index = 0; index < size; ++index) {
        const unsigned char c = (unsigned char)value[index];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == ':' || c == '-' ||
            c == '_' || c == '.') {
            continue;
        }
        return false;
    }
    return true;
}

static bool safe_token(const char *value, size_t capacity)
{
    if (!value || !value[0]) {
        return false;
    }
    const size_t size = strnlen(value, capacity);
    if (size == capacity) {
        return false;
    }
    for (size_t index = 0; index < size; ++index) {
        const unsigned char c = (unsigned char)value[index];
        if (c <= 0x20 || c >= 0x7f) {
            return false;
        }
    }
    return true;
}

static bool safe_wss_uri(const char *value)
{
    if (!value || strncmp(value, "wss://", 6) != 0) {
        return false;
    }
    const size_t size = strnlen(value, DEVICE_WEBSOCKET_URI_MAX);
    if (size <= 6 || size == DEVICE_WEBSOCKET_URI_MAX) {
        return false;
    }
    for (size_t index = 0; index < size; ++index) {
        const unsigned char c = (unsigned char)value[index];
        if (c <= 0x20 || c == 0x7f) {
            return false;
        }
    }
    return true;
}

static bool valid_binding_id(const char *value)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    enum { ENCODED_SIZE = 22 };
    if (!value || strnlen(value, ENCODED_SIZE + 1) != ENCODED_SIZE) {
        return false;
    }
    for (size_t index = 0; index < ENCODED_SIZE; ++index) {
        const char *found = strchr(alphabet, value[index]);
        if (!found || (index == ENCODED_SIZE - 1 &&
                       (((size_t)(found - alphabet)) & 0x0fU) != 0)) {
            return false;
        }
    }
    return true;
}

static bool valid_credentials(const box3_agent_credentials_t *credentials)
{
    return credentials && safe_wss_uri(credentials->voice_uri) &&
           safe_token(credentials->voice_bearer_token,
                      sizeof(credentials->voice_bearer_token)) &&
           safe_token(credentials->agent_bearer_token,
                      sizeof(credentials->agent_bearer_token)) &&
           strcmp(credentials->voice_bearer_token,
           credentials->agent_bearer_token) != 0 &&
           credentials->binding_revision > 0 &&
           valid_binding_id(credentials->binding_id) &&
           credentials->voice_ttl_seconds >= 60 &&
           credentials->voice_ttl_seconds <= 3600 &&
           credentials->agent_ttl_seconds >= 60 &&
           credentials->agent_ttl_seconds <= 3600;
}

static uint64_t monotonic_ms(void)
{
    return (uint64_t)esp_timer_get_time() / 1000;
}

static bool enter_api(box3_agent_supervisor_handle_t supervisor)
{
    if (!supervisor ||
        atomic_load_explicit(&supervisor->stopping,
                             memory_order_acquire)) {
        return false;
    }
    atomic_fetch_add_explicit(&supervisor->api_calls, 1,
                              memory_order_acq_rel);
    if (atomic_load_explicit(&supervisor->stopping,
                             memory_order_acquire)) {
        atomic_fetch_sub_explicit(&supervisor->api_calls, 1,
                                  memory_order_acq_rel);
        return false;
    }
    return true;
}

static void leave_api(box3_agent_supervisor_handle_t supervisor)
{
    atomic_fetch_sub_explicit(&supervisor->api_calls, 1,
                              memory_order_release);
}

static void publish_state(box3_agent_supervisor_handle_t supervisor,
                          esp_err_t last_error)
{
    const int current = (int)supervisor->core.state;
    const int previous = atomic_exchange_explicit(
        &supervisor->published_state, current, memory_order_acq_rel);
    if (supervisor->event &&
        (previous != current || last_error != ESP_OK)) {
        supervisor->event(supervisor->supervisor_event_ctx,
                          supervisor->core.state, last_error);
    }
}

static void product_state_changed(void *ctx,
                                  agent_bridge_state_t from,
                                  agent_bridge_state_t to,
                                  uint32_t request_id)
{
    box3_agent_supervisor_handle_t supervisor = ctx;
    if (supervisor && supervisor->state_changed_cb &&
        !atomic_load_explicit(&supervisor->stopping,
                              memory_order_acquire)) {
        supervisor->state_changed_cb(supervisor->product_event_ctx,
                                     from, to, request_id);
    }
}

static void product_client_event(void *ctx,
                                 const device_voice_client_event_t *event)
{
    box3_agent_supervisor_handle_t supervisor = ctx;
    if (!supervisor || !event ||
        atomic_load_explicit(&supervisor->stopping,
                             memory_order_acquire)) {
        return;
    }
    if (event->type == DEVICE_VOICE_CLIENT_EVENT_READY) {
        atomic_store_explicit(&supervisor->ready, true,
                              memory_order_release);
        xEventGroupSetBits(supervisor->signals, SIGNAL_CLIENT_READY);
    } else if (event->type == DEVICE_VOICE_CLIENT_EVENT_DISCONNECTED ||
               event->type == DEVICE_VOICE_CLIENT_EVENT_PROTOCOL_ERROR ||
               event->type == DEVICE_VOICE_CLIENT_EVENT_QUEUE_OVERFLOW ||
               event->type == DEVICE_VOICE_CLIENT_EVENT_TRANSPORT_ERROR ||
               event->type ==
                   DEVICE_VOICE_CLIENT_EVENT_SPEECH_BUDGET_UNAVAILABLE) {
        atomic_store_explicit(&supervisor->ready, false,
                              memory_order_release);
        xEventGroupSetBits(supervisor->signals, SIGNAL_CLIENT_FAILED);
    }
    if (supervisor->client_event_cb) {
        supervisor->client_event_cb(supervisor->product_event_ctx, event);
    }
}

static void product_audio_event(void *ctx,
                                box3_voice_audio_event_t event,
                                uint32_t request_id)
{
    box3_agent_supervisor_handle_t supervisor = ctx;
    if (supervisor && supervisor->audio_event_cb &&
        !atomic_load_explicit(&supervisor->stopping,
                              memory_order_acquire)) {
        supervisor->audio_event_cb(supervisor->product_event_ctx,
                                   event, request_id);
    }
}

static bool copy_product_config(
    box3_agent_supervisor_handle_t supervisor,
    const box3_agent_voice_config_t *input)
{
    owned_strings_t *strings = supervisor->strings;
    if (!input || !strings || input->websocket.uri ||
        input->websocket.bearer_token || input->agent.api_key ||
        input->websocket.event || input->websocket.event_ctx ||
        input->agent.response_cb || input->agent.response_user_ctx ||
        !safe_identifier(input->websocket.device_id) ||
        !safe_identifier(input->websocket.client_id) ||
        input->websocket.protocol_version < 1 ||
        input->websocket.protocol_version > 3 ||
        input->websocket.network_timeout_ms < 1000 ||
        input->websocket.network_timeout_ms > 60000 ||
        input->websocket.send_timeout_ms < 50 ||
        input->websocket.send_timeout_ms > 2000 ||
        input->websocket.ping_interval_seconds < 5 ||
        input->websocket.ping_interval_seconds > 120 ||
        input->websocket.pong_timeout_seconds < 5 ||
        input->websocket.pong_timeout_seconds > 120 ||
        input->output_volume_percent < 0 ||
        input->output_volume_percent > 100 ||
        (input->hello_timeout_ms != 0 &&
         (input->hello_timeout_ms < 1000 ||
          input->hello_timeout_ms > 30000)) ||
        ((!input->websocket.server_cert_pem ||
          !input->websocket.server_cert_pem[0]) ==
         !input->websocket.use_crt_bundle) ||
        !copy_bounded(strings->device_id, sizeof(strings->device_id),
                      input->websocket.device_id, true) ||
        !copy_bounded(strings->client_id, sizeof(strings->client_id),
                      input->websocket.client_id, true) ||
        !copy_bounded(strings->backend_type,
                      sizeof(strings->backend_type),
                      input->agent.backend_type, true) ||
        !copy_bounded(strings->model, sizeof(strings->model),
                      input->agent.model, true) ||
        !copy_bounded(strings->base_url, sizeof(strings->base_url),
                      input->agent.base_url, true) ||
        !copy_bounded(strings->auth_type, sizeof(strings->auth_type),
                      input->agent.auth_type, false) ||
        !copy_bounded(strings->max_tokens_field,
                      sizeof(strings->max_tokens_field),
                      input->agent.max_tokens_field, false) ||
        !copy_bounded(strings->system_prompt,
                      sizeof(strings->system_prompt),
                      input->agent.system_prompt, true)) {
        return false;
    }

    supervisor->product_config = *input;
    supervisor->product_config.websocket.uri = NULL;
    supervisor->product_config.websocket.bearer_token = NULL;
    supervisor->product_config.websocket.device_id = strings->device_id;
    supervisor->product_config.websocket.client_id = strings->client_id;
    supervisor->product_config.agent.api_key = NULL;
    supervisor->product_config.agent.backend_type = strings->backend_type;
    supervisor->product_config.agent.model = strings->model;
    supervisor->product_config.agent.base_url = strings->base_url;
    supervisor->product_config.agent.auth_type = strings->auth_type[0]
                                                        ? strings->auth_type
                                                        : NULL;
    supervisor->product_config.agent.max_tokens_field =
        strings->max_tokens_field[0] ? strings->max_tokens_field : NULL;
    supervisor->product_config.agent.system_prompt = strings->system_prompt;
    return true;
}

static esp_err_t copy_server_certificate(
    box3_agent_supervisor_handle_t supervisor,
    const char *certificate)
{
    if (!certificate || !certificate[0]) {
        supervisor->product_config.websocket.server_cert_pem = NULL;
        return ESP_OK;
    }
    const size_t size = strnlen(certificate, SERVER_CERT_PEM_MAX + 1);
    if (size > SERVER_CERT_PEM_MAX) {
        return ESP_ERR_INVALID_SIZE;
    }
    supervisor->server_cert_pem = allocate_prefer_psram(size + 1);
    if (!supervisor->server_cert_pem) {
        return ESP_ERR_NO_MEM;
    }
    memcpy(supervisor->server_cert_pem, certificate, size + 1);
    supervisor->product_config.websocket.server_cert_pem =
        supervisor->server_cert_pem;
    return ESP_OK;
}

static void release_storage(box3_agent_supervisor_handle_t supervisor)
{
    if (!supervisor) {
        return;
    }
    if (supervisor->signals) {
        vEventGroupDelete(supervisor->signals);
        supervisor->signals = NULL;
    }
    if (supervisor->credentials) {
        secure_zero(supervisor->credentials,
                    sizeof(*supervisor->credentials));
        heap_caps_free(supervisor->credentials);
        supervisor->credentials = NULL;
    }
    heap_caps_free(supervisor->server_cert_pem);
    supervisor->server_cert_pem = NULL;
    if (supervisor->strings) {
        secure_zero(supervisor->strings, sizeof(*supervisor->strings));
        heap_caps_free(supervisor->strings);
        supervisor->strings = NULL;
    }
    secure_zero(supervisor, sizeof(*supervisor));
    heap_caps_free(supervisor);
}

static box3_agent_supervisor_action_t stop_product(
    box3_agent_supervisor_handle_t supervisor)
{
    while (supervisor->product) {
        const esp_err_t result = box3_agent_voice_stop(
            supervisor->product, supervisor->product_stop_timeout_ms);
        if (result == ESP_OK) {
            supervisor->product = NULL;
            atomic_store_explicit(&supervisor->has_session, false,
                                  memory_order_release);
            atomic_store_explicit(&supervisor->ready, false,
                                  memory_order_release);
            break;
        }
        atomic_fetch_add_explicit(&supervisor->stats.cleanup_retries, 1,
                                  memory_order_relaxed);
        publish_state(supervisor, result);
        vTaskDelay(pdMS_TO_TICKS(CLEANUP_RETRY_DELAY_MS));
    }
    if (atomic_load_explicit(&supervisor->stopping,
                             memory_order_acquire)) {
        return BOX3_AGENT_SUPERVISOR_ACTION_NONE;
    }
    const box3_agent_supervisor_action_t action =
        box3_agent_supervisor_core_session_stopped(&supervisor->core);
    publish_state(supervisor, ESP_OK);
    return action;
}

static box3_agent_supervisor_action_t refresh_and_start(
    box3_agent_supervisor_handle_t supervisor)
{
    box3_agent_credentials_t *credentials = supervisor->credentials;
    secure_zero(credentials, sizeof(*credentials));
    atomic_fetch_add_explicit(&supervisor->stats.credential_refreshes, 1,
                              memory_order_relaxed);
    publish_state(supervisor, ESP_OK);

    esp_err_t result = supervisor->refresh_credentials(
        supervisor->credential_ctx, credentials);
    if (atomic_load_explicit(&supervisor->stopping,
                             memory_order_acquire)) {
        secure_zero(credentials, sizeof(*credentials));
        return BOX3_AGENT_SUPERVISOR_ACTION_NONE;
    }
    if (!atomic_load_explicit(&supervisor->network_available,
                              memory_order_acquire)) {
        (void)box3_agent_supervisor_core_set_network(
            &supervisor->core, false, monotonic_ms());
        secure_zero(credentials, sizeof(*credentials));
        publish_state(supervisor, ESP_OK);
        return BOX3_AGENT_SUPERVISOR_ACTION_NONE;
    }
    bool valid = result == ESP_OK && valid_credentials(credentials);
    if (valid && supervisor->product_config.agent.memory) {
        result = product_agent_memory_reconcile_binding(
            supervisor->product_config.agent.memory,
            credentials->binding_id,
            credentials->binding_revision);
        valid = result == ESP_OK;
    }
    box3_agent_supervisor_action_t action;
    if (result == ESP_ERR_NOT_ALLOWED) {
        action = box3_agent_supervisor_core_entitlement_denied(
            &supervisor->core);
    } else {
        action = box3_agent_supervisor_core_credentials_result(
            &supervisor->core, valid,
            credentials->voice_ttl_seconds,
            credentials->agent_ttl_seconds,
            monotonic_ms(), esp_random());
    }
    if (!valid) {
        if (result == ESP_OK) {
            result = ESP_ERR_INVALID_RESPONSE;
        }
        atomic_fetch_add_explicit(&supervisor->stats.credential_failures, 1,
                                  memory_order_relaxed);
        secure_zero(credentials, sizeof(*credentials));
        publish_state(supervisor, result);
        return action;
    }
    if (action != BOX3_AGENT_SUPERVISOR_ACTION_START) {
        secure_zero(credentials, sizeof(*credentials));
        publish_state(supervisor, ESP_ERR_INVALID_STATE);
        return action;
    }

    box3_agent_voice_config_t product_config = supervisor->product_config;
    product_config.websocket.uri = credentials->voice_uri;
    product_config.websocket.bearer_token =
        credentials->voice_bearer_token;
    product_config.agent.api_key = credentials->agent_bearer_token;
    box3_agent_voice_handle_t product = NULL;
    result = box3_agent_voice_create(&product_config, &product);
    secure_zero(credentials, sizeof(*credentials));
    supervisor->product = product;
    if (product) {
        atomic_store_explicit(&supervisor->has_session, true,
                              memory_order_release);
    }
    if (result == ESP_OK) {
        result = box3_agent_voice_start(product);
    }
    if (result != ESP_OK) {
        atomic_fetch_add_explicit(&supervisor->stats.session_failures, 1,
                                  memory_order_relaxed);
        action = box3_agent_supervisor_core_start_failed(
            &supervisor->core, product != NULL,
            monotonic_ms(), esp_random());
        publish_state(supervisor, result);
        return action;
    }

    atomic_fetch_add_explicit(&supervisor->stats.session_starts, 1,
                              memory_order_relaxed);
    publish_state(supervisor, ESP_OK);
    return BOX3_AGENT_SUPERVISOR_ACTION_NONE;
}

static void process_actions(box3_agent_supervisor_handle_t supervisor,
                            box3_agent_supervisor_action_t action)
{
    while (action != BOX3_AGENT_SUPERVISOR_ACTION_NONE &&
           !atomic_load_explicit(&supervisor->stopping,
                                 memory_order_acquire)) {
        if (action == BOX3_AGENT_SUPERVISOR_ACTION_STOP) {
            action = stop_product(supervisor);
        } else if (action == BOX3_AGENT_SUPERVISOR_ACTION_REFRESH) {
            action = refresh_and_start(supervisor);
        } else {
            action = BOX3_AGENT_SUPERVISOR_ACTION_NONE;
        }
    }
}

static void worker_entry(void *argument)
{
    box3_agent_supervisor_handle_t supervisor = argument;
    publish_state(supervisor, ESP_OK);
    box3_agent_supervisor_action_t action =
        box3_agent_supervisor_core_set_network(
            &supervisor->core,
            atomic_load_explicit(&supervisor->network_available,
                                 memory_order_acquire),
            monotonic_ms());

    for (;;) {
        process_actions(supervisor, action);
        if (atomic_load_explicit(&supervisor->stopping,
                                 memory_order_acquire)) {
            (void)stop_product(supervisor);
            break;
        }

        const uint64_t now_ms = monotonic_ms();
        const uint32_t wait_ms = box3_agent_supervisor_core_wait_ms(
            &supervisor->core, now_ms, WORKER_WAIT_CEILING_MS);
        const EventBits_t bits = xEventGroupWaitBits(
            supervisor->signals, SIGNAL_INPUT_MASK, pdTRUE, pdFALSE,
            pdMS_TO_TICKS(wait_ms));
        if ((bits & SIGNAL_STOP) != 0 ||
            atomic_load_explicit(&supervisor->stopping,
                                 memory_order_acquire)) {
            action = BOX3_AGENT_SUPERVISOR_ACTION_NONE;
            continue;
        }

        action = BOX3_AGENT_SUPERVISOR_ACTION_NONE;
        if ((bits & SIGNAL_WAKE) != 0) {
            const box3_agent_supervisor_action_t network_action =
                box3_agent_supervisor_core_set_network(
                &supervisor->core,
                atomic_load_explicit(&supervisor->network_available,
                                     memory_order_acquire),
                monotonic_ms());
            if (network_action != BOX3_AGENT_SUPERVISOR_ACTION_NONE) {
                action = network_action;
            }
            publish_state(supervisor, ESP_OK);
        }
        if ((bits & SIGNAL_ENTITLEMENT_CHANGED) != 0) {
            const box3_agent_supervisor_action_t entitlement_action =
                box3_agent_supervisor_core_entitlement_changed(
                    &supervisor->core);
            if (entitlement_action != BOX3_AGENT_SUPERVISOR_ACTION_NONE) {
                action = entitlement_action;
            }
            publish_state(supervisor, ESP_OK);
        }
        if ((bits & SIGNAL_CLIENT_FAILED) != 0) {
            const box3_agent_supervisor_action_t disconnect_action =
                box3_agent_supervisor_core_disconnected(
                &supervisor->core, monotonic_ms(), esp_random());
            if (disconnect_action != BOX3_AGENT_SUPERVISOR_ACTION_NONE) {
                atomic_fetch_add_explicit(
                    &supervisor->stats.disconnects, 1,
                    memory_order_relaxed);
                action = disconnect_action;
            }
            publish_state(supervisor, ESP_FAIL);
        } else if ((bits & SIGNAL_CLIENT_READY) != 0 &&
                   box3_agent_supervisor_core_ready(&supervisor->core)) {
            publish_state(supervisor, ESP_OK);
        }
        if ((bits & SIGNAL_INTERRUPT) != 0) {
            const agent_bridge_interrupt_reason_t reason =
                (agent_bridge_interrupt_reason_t)atomic_load_explicit(
                    &supervisor->pending_interrupt_reason,
                    memory_order_acquire);
            if (!supervisor->product ||
                box3_agent_voice_interrupt(supervisor->product,
                                           reason) != ESP_OK) {
                atomic_fetch_add_explicit(
                    &supervisor->stats.interrupt_rejections, 1,
                    memory_order_relaxed);
            }
        }
        if (action == BOX3_AGENT_SUPERVISOR_ACTION_NONE) {
            action = box3_agent_supervisor_core_poll(
                &supervisor->core, monotonic_ms());
        }
    }

    supervisor->worker = NULL;
    xEventGroupSetBits(supervisor->signals, SIGNAL_TASK_STOPPED);
    vTaskDelete(NULL);
}

esp_err_t box3_agent_supervisor_create(
    const box3_agent_supervisor_config_t *config,
    box3_agent_supervisor_handle_t *out_supervisor)
{
    if (!out_supervisor) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_supervisor = NULL;
    if (!config || !config->refresh_credentials) {
        return ESP_ERR_INVALID_ARG;
    }

    box3_agent_supervisor_core_config_t core_config = {
        .minimum_backoff_ms = config->minimum_backoff_ms
                                  ? config->minimum_backoff_ms
                                  : DEFAULT_MINIMUM_BACKOFF_MS,
        .maximum_backoff_ms = config->maximum_backoff_ms
                                  ? config->maximum_backoff_ms
                                  : DEFAULT_MAXIMUM_BACKOFF_MS,
        .refresh_margin_seconds = config->refresh_margin_seconds
                                      ? config->refresh_margin_seconds
                                      : DEFAULT_REFRESH_MARGIN_SECONDS,
    };
    const uint32_t stop_timeout = config->product_stop_timeout_ms
                                      ? config->product_stop_timeout_ms
                                      : DEFAULT_PRODUCT_STOP_TIMEOUT_MS;
    const uint32_t stack_size = config->task_stack_size
                                    ? config->task_stack_size
                                    : DEFAULT_TASK_STACK_SIZE;
    const uint32_t priority = config->task_priority
                                  ? config->task_priority
                                  : DEFAULT_TASK_PRIORITY;
    if (stop_timeout < 100 || stop_timeout > 60000 || stack_size < 6144 ||
        stack_size > MAXIMUM_TASK_STACK_SIZE || priority == 0 ||
        priority >= configMAX_PRIORITIES) {
        return ESP_ERR_INVALID_ARG;
    }

    box3_agent_supervisor_core_t validated_core;
    if (!box3_agent_supervisor_core_init(&validated_core, &core_config)) {
        return ESP_ERR_INVALID_ARG;
    }

    box3_agent_supervisor_handle_t supervisor = heap_caps_calloc(
        1, sizeof(*supervisor), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!supervisor) {
        return ESP_ERR_NO_MEM;
    }
    supervisor->strings = allocate_prefer_psram(sizeof(*supervisor->strings));
    supervisor->credentials = allocate_prefer_psram(
        sizeof(*supervisor->credentials));
    supervisor->signals = xEventGroupCreate();
    if (!supervisor->strings || !supervisor->credentials ||
        !supervisor->signals) {
        release_storage(supervisor);
        return ESP_ERR_NO_MEM;
    }
    supervisor->core = validated_core;
    if (!copy_product_config(supervisor, &config->product)) {
        release_storage(supervisor);
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t result = copy_server_certificate(
        supervisor, config->product.websocket.server_cert_pem);
    if (result != ESP_OK) {
        release_storage(supervisor);
        return result;
    }

    supervisor->refresh_credentials = config->refresh_credentials;
    supervisor->credential_ctx = config->credential_ctx;
    supervisor->event = config->event;
    supervisor->supervisor_event_ctx = config->event_ctx;
    supervisor->state_changed_cb = config->product.state_changed;
    supervisor->client_event_cb = config->product.client_event;
    supervisor->audio_event_cb = config->product.audio_event;
    supervisor->product_event_ctx = config->product.event_ctx;
    supervisor->product_config.state_changed = product_state_changed;
    supervisor->product_config.client_event = product_client_event;
    supervisor->product_config.audio_event = product_audio_event;
    supervisor->product_config.event_ctx = supervisor;
    supervisor->product_stop_timeout_ms = stop_timeout;
    supervisor->task_stack_size = stack_size;
    supervisor->task_priority = priority;
    atomic_init(&supervisor->started, false);
    atomic_init(&supervisor->stopping, false);
    atomic_init(&supervisor->network_available, false);
    atomic_init(&supervisor->has_session, false);
    atomic_init(&supervisor->ready, false);
    atomic_init(&supervisor->pending_interrupt_reason,
                AGENT_BRIDGE_INTERRUPT_USER_BARGE_IN);
    atomic_init(&supervisor->published_state, -1);
    atomic_init(&supervisor->api_calls, 0);
    atomic_init(&supervisor->stats.credential_refreshes, 0);
    atomic_init(&supervisor->stats.credential_failures, 0);
    atomic_init(&supervisor->stats.session_starts, 0);
    atomic_init(&supervisor->stats.session_failures, 0);
    atomic_init(&supervisor->stats.disconnects, 0);
    atomic_init(&supervisor->stats.cleanup_retries, 0);
    atomic_init(&supervisor->stats.interrupt_rejections, 0);
    *out_supervisor = supervisor;
    return ESP_OK;
}

esp_err_t box3_agent_supervisor_start(
    box3_agent_supervisor_handle_t supervisor)
{
    bool expected = false;
    if (!enter_api(supervisor)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!atomic_compare_exchange_strong_explicit(
            &supervisor->started, &expected, true,
            memory_order_acq_rel, memory_order_acquire)) {
        leave_api(supervisor);
        return ESP_ERR_INVALID_STATE;
    }
    if (xTaskCreate(worker_entry, "box3_agent_supervisor",
                    supervisor->task_stack_size, supervisor,
                    supervisor->task_priority,
                    &supervisor->worker) != pdPASS) {
        atomic_store_explicit(&supervisor->started, false,
                              memory_order_release);
        leave_api(supervisor);
        return ESP_ERR_NO_MEM;
    }
    leave_api(supervisor);
    return ESP_OK;
}

esp_err_t box3_agent_supervisor_set_network_available(
    box3_agent_supervisor_handle_t supervisor,
    bool available)
{
    if (!enter_api(supervisor)) {
        return ESP_ERR_INVALID_STATE;
    }
    atomic_store_explicit(&supervisor->network_available, available,
                          memory_order_release);
    if (!available) {
        atomic_store_explicit(&supervisor->ready, false,
                              memory_order_release);
    }
    xEventGroupSetBits(supervisor->signals, SIGNAL_WAKE);
    leave_api(supervisor);
    return ESP_OK;
}

esp_err_t box3_agent_supervisor_interrupt(
    box3_agent_supervisor_handle_t supervisor,
    agent_bridge_interrupt_reason_t reason)
{
    if (!enter_api(supervisor)) {
        return ESP_ERR_INVALID_STATE;
    }
    if (reason < AGENT_BRIDGE_INTERRUPT_USER_BARGE_IN ||
        reason > AGENT_BRIDGE_INTERRUPT_SESSION_CLOSED ||
        !atomic_load_explicit(&supervisor->ready, memory_order_acquire)) {
        leave_api(supervisor);
        return ESP_ERR_INVALID_STATE;
    }
    atomic_store_explicit(&supervisor->pending_interrupt_reason, reason,
                          memory_order_release);
    xEventGroupSetBits(supervisor->signals, SIGNAL_INTERRUPT);
    leave_api(supervisor);
    return ESP_OK;
}

esp_err_t box3_agent_supervisor_entitlement_changed(
    box3_agent_supervisor_handle_t supervisor)
{
    if (!enter_api(supervisor)) {
        return ESP_ERR_INVALID_STATE;
    }
    xEventGroupSetBits(supervisor->signals, SIGNAL_ENTITLEMENT_CHANGED);
    leave_api(supervisor);
    return ESP_OK;
}

esp_err_t box3_agent_supervisor_get_stats(
    box3_agent_supervisor_handle_t supervisor,
    box3_agent_supervisor_stats_t *stats)
{
    if (!stats || !enter_api(supervisor)) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(stats, 0, sizeof(*stats));
    const int published_state = atomic_load_explicit(
        &supervisor->published_state, memory_order_acquire);
    stats->state = published_state < 0
                       ? BOX3_AGENT_SUPERVISOR_WAIT_NETWORK
                       : (box3_agent_supervisor_state_t)published_state;
    stats->started = atomic_load_explicit(&supervisor->started,
                                          memory_order_acquire);
    stats->network_available = atomic_load_explicit(
        &supervisor->network_available, memory_order_acquire);
    stats->has_session = atomic_load_explicit(&supervisor->has_session,
                                              memory_order_acquire);
    stats->ready = atomic_load_explicit(&supervisor->ready,
                                        memory_order_acquire);
    stats->credential_refreshes = atomic_load_explicit(
        &supervisor->stats.credential_refreshes, memory_order_relaxed);
    stats->credential_failures = atomic_load_explicit(
        &supervisor->stats.credential_failures, memory_order_relaxed);
    stats->session_starts = atomic_load_explicit(
        &supervisor->stats.session_starts, memory_order_relaxed);
    stats->session_failures = atomic_load_explicit(
        &supervisor->stats.session_failures, memory_order_relaxed);
    stats->disconnects = atomic_load_explicit(
        &supervisor->stats.disconnects, memory_order_relaxed);
    stats->cleanup_retries = atomic_load_explicit(
        &supervisor->stats.cleanup_retries, memory_order_relaxed);
    stats->interrupt_rejections = atomic_load_explicit(
        &supervisor->stats.interrupt_rejections, memory_order_relaxed);
    leave_api(supervisor);
    return ESP_OK;
}

esp_err_t box3_agent_supervisor_stop(
    box3_agent_supervisor_handle_t supervisor,
    uint32_t timeout_ms)
{
    if (!supervisor) {
        return ESP_OK;
    }
    if (timeout_ms < 100 || timeout_ms > 60000) {
        return ESP_ERR_INVALID_ARG;
    }
    const uint64_t deadline_ms = monotonic_ms() + timeout_ms;
    atomic_store_explicit(&supervisor->stopping, true,
                          memory_order_release);
    while (atomic_load_explicit(&supervisor->api_calls,
                                memory_order_acquire) != 0) {
        if (monotonic_ms() >= deadline_ms) {
            return ESP_ERR_TIMEOUT;
        }
        vTaskDelay(1);
    }
    if (!atomic_load_explicit(&supervisor->started,
                              memory_order_acquire)) {
        release_storage(supervisor);
        return ESP_OK;
    }
    atomic_store_explicit(&supervisor->ready, false,
                          memory_order_release);
    xEventGroupSetBits(supervisor->signals, SIGNAL_STOP);
    const uint64_t now_ms = monotonic_ms();
    if (now_ms >= deadline_ms) {
        return ESP_ERR_TIMEOUT;
    }
    uint64_t remaining_ms = deadline_ms - now_ms;
    if (remaining_ms > UINT32_MAX) {
        remaining_ms = UINT32_MAX;
    }
    const EventBits_t bits = xEventGroupWaitBits(
        supervisor->signals, SIGNAL_TASK_STOPPED, pdFALSE, pdTRUE,
        pdMS_TO_TICKS((uint32_t)remaining_ms));
    if ((bits & SIGNAL_TASK_STOPPED) == 0) {
        return ESP_ERR_TIMEOUT;
    }
    release_storage(supervisor);
    return ESP_OK;
}
