#include "box3_agent_voice.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "esp_heap_caps.h"
#include "esp_log.h"

static const char *TAG = "box3_agent_voice";

enum {
    AGENT_API_KEY_MAX = 2048,
    AGENT_BACKEND_MAX = 32,
    AGENT_MODEL_MAX = 128,
    AGENT_BASE_URL_MAX = 512,
    AGENT_AUTH_TYPE_MAX = 32,
    AGENT_MAX_TOKENS_FIELD_MAX = 64,
    AGENT_SYSTEM_PROMPT_MAX = 2048,
    SERVER_CERT_PEM_MAX = 16384,
    DEFAULT_HELLO_TIMEOUT_MS = 5000,
    STARTUP_CLEANUP_TIMEOUT_MS = 5000,
};

typedef struct {
    char api_key[AGENT_API_KEY_MAX + 1];
    char backend_type[AGENT_BACKEND_MAX + 1];
    char model[AGENT_MODEL_MAX + 1];
    char base_url[AGENT_BASE_URL_MAX + 1];
    char auth_type[AGENT_AUTH_TYPE_MAX + 1];
    char max_tokens_field[AGENT_MAX_TOKENS_FIELD_MAX + 1];
    char system_prompt[AGENT_SYSTEM_PROMPT_MAX + 1];
} agent_owned_strings_t;

struct box3_agent_voice {
    esp_claw_runtime_config_t agent_config;
    box3_audio_t *audio;
    box3_voice_audio_t *stream;
    esp_claw_runtime_handle_t agent;
    device_voice_client_handle_t client;
    agent_owned_strings_t *strings;
    char *server_cert_pem;

    void (*state_changed_cb)(void *ctx,
                             agent_bridge_state_t from,
                             agent_bridge_state_t to,
                             uint32_t request_id);
    void (*client_event_cb)(void *ctx,
                            const device_voice_client_event_t *event);
    void (*audio_event_cb)(void *ctx,
                           box3_voice_audio_event_t event,
                           uint32_t request_id);
    void *event_ctx;

    atomic_bool started;
    atomic_bool shutting_down;
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
    size_t size;
    if (!output || output_size == 0) {
        return false;
    }
    if (!input || !input[0]) {
        output[0] = '\0';
        return !required;
    }
    size = strnlen(input, output_size);
    if (size == output_size) {
        return false;
    }
    memcpy(output, input, size + 1);
    return true;
}

static bool copy_agent_config(box3_agent_voice_handle_t product,
                              const esp_claw_runtime_config_t *input)
{
    agent_owned_strings_t *strings = product->strings;
    if (!strings ||
        !copy_bounded(strings->api_key, sizeof(strings->api_key),
                      input->api_key, true) ||
        !copy_bounded(strings->backend_type, sizeof(strings->backend_type),
                      input->backend_type, true) ||
        !copy_bounded(strings->model, sizeof(strings->model),
                      input->model, true) ||
        !copy_bounded(strings->base_url, sizeof(strings->base_url),
                      input->base_url, true) ||
        !copy_bounded(strings->auth_type, sizeof(strings->auth_type),
                      input->auth_type, false) ||
        !copy_bounded(strings->max_tokens_field,
                      sizeof(strings->max_tokens_field),
                      input->max_tokens_field, false) ||
        !copy_bounded(strings->system_prompt,
                      sizeof(strings->system_prompt),
                      input->system_prompt, true)) {
        return false;
    }

    product->agent_config = *input;
    product->agent_config.api_key = strings->api_key;
    product->agent_config.backend_type = strings->backend_type;
    product->agent_config.model = strings->model;
    product->agent_config.base_url = strings->base_url;
    product->agent_config.auth_type = strings->auth_type[0]
                                             ? strings->auth_type
                                             : NULL;
    product->agent_config.max_tokens_field = strings->max_tokens_field[0]
                                                   ? strings->max_tokens_field
                                                   : NULL;
    product->agent_config.system_prompt = strings->system_prompt;
    product->agent_config.response_cb = NULL;
    product->agent_config.response_user_ctx = NULL;
    return true;
}

static esp_err_t copy_server_certificate(
    box3_agent_voice_handle_t product,
    const char *certificate)
{
    if (!certificate || !certificate[0]) {
        return ESP_OK;
    }
    size_t size = strnlen(certificate, SERVER_CERT_PEM_MAX + 1);
    if (size > SERVER_CERT_PEM_MAX) {
        return ESP_ERR_INVALID_SIZE;
    }
    product->server_cert_pem = allocate_prefer_psram(size + 1);
    if (!product->server_cert_pem) {
        return ESP_ERR_NO_MEM;
    }
    memcpy(product->server_cert_pem, certificate, size + 1);
    return ESP_OK;
}

static bool shutting_down(box3_agent_voice_handle_t product)
{
    return atomic_load_explicit(&product->shutting_down,
                                memory_order_acquire);
}

static int submit_agent(void *ctx,
                        uint32_t request_id,
                        const char *session_id,
                        const char *text)
{
    box3_agent_voice_handle_t product = ctx;
    if (!product || shutting_down(product) || !product->agent) {
        return -1;
    }
    return esp_claw_runtime_submit(product->agent, request_id,
                                   session_id, text) == ESP_OK
               ? 0
               : -1;
}

static int cancel_agent(void *ctx, uint32_t request_id)
{
    box3_agent_voice_handle_t product = ctx;
    if (!product || !product->agent) {
        return -1;
    }
    return esp_claw_runtime_cancel(product->agent, request_id) == ESP_OK
               ? 0
               : -1;
}

static int receive_binary(void *ctx,
                          const uint8_t *packet,
                          size_t packet_size)
{
    box3_agent_voice_handle_t product = ctx;
    if (!product || shutting_down(product) || !product->stream) {
        return -1;
    }
    return box3_voice_audio_push_binary(product->stream,
                                        packet, packet_size) == ESP_OK
               ? 0
               : -1;
}

static void playback_event(void *ctx,
                           voice_agent_playback_event_t event,
                           uint32_t request_id)
{
    box3_agent_voice_handle_t product = ctx;
    if (product && product->stream) {
        box3_voice_audio_playback_event(product->stream, event, request_id);
    }
}

static void capture_enabled(void *ctx, bool enabled)
{
    box3_agent_voice_handle_t product = ctx;
    esp_err_t result;
    if (!product || !product->stream || (enabled && shutting_down(product))) {
        return;
    }
    result = enabled ? box3_voice_audio_start_capture(product->stream)
                     : box3_voice_audio_stop_capture(product->stream);
    if (result != ESP_OK && result != ESP_ERR_INVALID_STATE) {
        ESP_LOGW(TAG, "Capture state change failed: %s",
                 esp_err_to_name(result));
    }
}

static void state_changed(void *ctx,
                          agent_bridge_state_t from,
                          agent_bridge_state_t to,
                          uint32_t request_id)
{
    box3_agent_voice_handle_t product = ctx;
    if (product && !shutting_down(product) &&
        product->state_changed_cb) {
        product->state_changed_cb(product->event_ctx, from, to, request_id);
    }
}

static void client_event(void *ctx,
                         const device_voice_client_event_t *event)
{
    box3_agent_voice_handle_t product = ctx;
    if (product && !shutting_down(product) &&
        product->client_event_cb) {
        product->client_event_cb(product->event_ctx, event);
    }
}

static void audio_event(void *ctx,
                        box3_voice_audio_event_t event,
                        uint32_t request_id)
{
    box3_agent_voice_handle_t product = ctx;
    if (product && !shutting_down(product) &&
        product->audio_event_cb) {
        product->audio_event_cb(product->event_ctx, event, request_id);
    }
}

static int send_binary(void *ctx, const uint8_t *data, size_t size)
{
    box3_agent_voice_handle_t product = ctx;
    if (!product || shutting_down(product) || !product->client) {
        return -1;
    }
    return device_voice_client_send_audio(product->client, data, size);
}

static void agent_response(uint32_t request_id,
                           bool success,
                           const char *text,
                           const char *error_message,
                           void *user_ctx)
{
    box3_agent_voice_handle_t product = user_ctx;
    esp_err_t result;
    (void)error_message; /* Provider text is deliberately not logged here. */
    if (!product || shutting_down(product) || !product->client) {
        return;
    }
    if (success && text && text[0]) {
        result = device_voice_client_on_agent_final(product->client,
                                                     request_id, text);
        if (result == ESP_ERR_INVALID_SIZE) {
            (void)device_voice_client_on_agent_error(product->client,
                                                      request_id);
        }
    } else {
        (void)device_voice_client_on_agent_error(product->client, request_id);
    }
}

static void release_storage(box3_agent_voice_handle_t product)
{
    if (!product) {
        return;
    }
    heap_caps_free(product->server_cert_pem);
    product->server_cert_pem = NULL;
    if (product->strings) {
        secure_zero(product->strings, sizeof(*product->strings));
        heap_caps_free(product->strings);
        product->strings = NULL;
    }
    secure_zero(product, sizeof(*product));
    heap_caps_free(product);
}

static esp_err_t stop_remaining(box3_agent_voice_handle_t product,
                                uint32_t timeout_ms)
{
    esp_err_t result;

    atomic_store_explicit(&product->shutting_down, true,
                          memory_order_release);
    atomic_store_explicit(&product->started, false, memory_order_release);

    if (product->client) {
        result = device_voice_client_destroy(product->client);
        if (result != ESP_OK) {
            return result;
        }
        product->client = NULL;
    }
    if (product->agent) {
        result = esp_claw_runtime_stop(product->agent, timeout_ms);
        if (result != ESP_OK) {
            return result;
        }
        product->agent = NULL;
    }
    if (product->stream) {
        result = box3_voice_audio_destroy(product->stream);
        if (result != ESP_OK) {
            return result;
        }
        product->stream = NULL;
    }
    if (product->audio) {
        box3_audio_destroy(product->audio);
        product->audio = NULL;
    }
    return ESP_OK;
}

static esp_err_t fail_create(box3_agent_voice_handle_t product,
                             box3_agent_voice_handle_t *out_product,
                             esp_err_t failure)
{
    if (!product) {
        return failure;
    }
    esp_err_t result = stop_remaining(product, STARTUP_CLEANUP_TIMEOUT_MS);
    if (result == ESP_OK) {
        release_storage(product);
    } else {
        /* Fail closed: callback context remains live rather than risking UAF. */
        *out_product = product;
        ESP_LOGE(TAG, "Startup cleanup incomplete; retaining resources: %s",
                 esp_err_to_name(result));
    }
    return failure;
}

esp_err_t box3_agent_voice_create(
    const box3_agent_voice_config_t *config,
    box3_agent_voice_handle_t *out_product)
{
    box3_agent_voice_handle_t product;
    box3_voice_audio_config_t audio_config;
    device_voice_client_config_t client_config;
    device_websocket_transport_config_t websocket_config;
    esp_err_t result;

    if (!out_product) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_product = NULL;
    if (!config || config->websocket.event ||
        config->websocket.event_ctx || config->agent.response_cb ||
        config->agent.response_user_ctx || !config->agent.api_key ||
        !config->agent.api_key[0] || !config->agent.backend_type ||
        !config->agent.backend_type[0] || !config->agent.model ||
        !config->agent.model[0] || !config->agent.base_url ||
        !config->agent.base_url[0] || !config->agent.system_prompt ||
        !config->agent.system_prompt[0] ||
        config->output_volume_percent < 0 ||
        config->output_volume_percent > 100 ||
        (config->hello_timeout_ms != 0 &&
         (config->hello_timeout_ms < 1000 ||
          config->hello_timeout_ms > 30000))) {
        return ESP_ERR_INVALID_ARG;
    }
    product = heap_caps_calloc(1, sizeof(*product),
                               MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!product) {
        return ESP_ERR_NO_MEM;
    }
    atomic_init(&product->started, false);
    atomic_init(&product->shutting_down, false);
    product->strings = allocate_prefer_psram(sizeof(*product->strings));
    product->state_changed_cb = config->state_changed;
    product->client_event_cb = config->client_event;
    product->audio_event_cb = config->audio_event;
    product->event_ctx = config->event_ctx;
    if (!product->strings) {
        return fail_create(product, out_product, ESP_ERR_NO_MEM);
    }
    if (!copy_agent_config(product, &config->agent)) {
        return fail_create(product, out_product, ESP_ERR_INVALID_SIZE);
    }
    result = copy_server_certificate(product,
                                     config->websocket.server_cert_pem);
    if (result != ESP_OK) {
        return fail_create(product, out_product, result);
    }

    /* Validate and own the secure transport before touching board hardware. */
    websocket_config = config->websocket;
    websocket_config.server_cert_pem = product->server_cert_pem;
    client_config = (device_voice_client_config_t){
        .websocket = websocket_config,
        .ops = {
            .submit_agent = submit_agent,
            .cancel_agent = cancel_agent,
            .receive_binary = receive_binary,
            .playback_event = playback_event,
            .capture_enabled = capture_enabled,
            .state_changed = state_changed,
            .event = client_event,
        },
        .ops_ctx = product,
        .uplink_sample_rate = BOX3_VOICE_AUDIO_UPLINK_SAMPLE_RATE,
        .downlink_sample_rate = BOX3_VOICE_AUDIO_DOWNLINK_SAMPLE_RATE,
        .frame_duration_ms = BOX3_VOICE_AUDIO_FRAME_DURATION_MS,
        .hello_timeout_ms = config->hello_timeout_ms
                                ? config->hello_timeout_ms
                                : DEFAULT_HELLO_TIMEOUT_MS,
    };
    result = device_voice_client_create(&client_config, &product->client);
    if (result != ESP_OK) {
        return fail_create(product, out_product, result);
    }

    result = box3_audio_create(&product->audio);
    if (result == ESP_OK) {
        result = box3_audio_set_output_volume(
            product->audio, config->output_volume_percent);
    }
    if (result != ESP_OK) {
        return fail_create(product, out_product, result);
    }

    audio_config = (box3_voice_audio_config_t){
        .audio = product->audio,
        .transport_version = config->websocket.protocol_version,
        .send_binary = send_binary,
        .event = audio_event,
        .ops_ctx = product,
    };
    result = box3_voice_audio_create(&audio_config, &product->stream);
    if (result != ESP_OK) {
        return fail_create(product, out_product, result);
    }

    product->agent_config.response_cb = agent_response;
    product->agent_config.response_user_ctx = product;
    result = esp_claw_runtime_start(&product->agent_config,
                                    &product->agent);
    if (result != ESP_OK) {
        return fail_create(product, out_product, result);
    }

    *out_product = product;
    return ESP_OK;
}

esp_err_t box3_agent_voice_start(box3_agent_voice_handle_t product)
{
    bool expected = false;
    esp_err_t result;
    if (!product || shutting_down(product)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!atomic_compare_exchange_strong_explicit(
            &product->started, &expected, true,
            memory_order_acq_rel, memory_order_acquire)) {
        return ESP_ERR_INVALID_STATE;
    }
    result = device_voice_client_start(product->client);
    if (result != ESP_OK) {
        atomic_store_explicit(&product->started, false,
                              memory_order_release);
    }
    return result;
}

esp_err_t box3_agent_voice_interrupt(
    box3_agent_voice_handle_t product,
    agent_bridge_interrupt_reason_t reason)
{
    if (!product || shutting_down(product) || !product->client) {
        return ESP_ERR_INVALID_STATE;
    }
    return device_voice_client_interrupt(product->client, reason);
}

bool box3_agent_voice_ready(box3_agent_voice_handle_t product)
{
    return product && !shutting_down(product) && product->client &&
           device_voice_client_ready(product->client);
}

esp_err_t box3_agent_voice_get_stats(
    box3_agent_voice_handle_t product,
    box3_agent_voice_stats_t *stats)
{
    esp_err_t result;
    if (!product || !stats || !product->client || !product->stream) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(stats, 0, sizeof(*stats));
    stats->started = atomic_load_explicit(&product->started,
                                          memory_order_acquire);
    stats->ready = box3_agent_voice_ready(product);
    result = device_voice_client_get_stats(product->client, &stats->client);
    if (result != ESP_OK) {
        return result;
    }
    return box3_voice_audio_get_stats(product->stream, &stats->audio);
}

esp_err_t box3_agent_voice_stop(box3_agent_voice_handle_t product,
                                uint32_t timeout_ms)
{
    esp_err_t result;
    if (!product) {
        return ESP_OK;
    }
    if (timeout_ms < 100 || timeout_ms > 60000) {
        return ESP_ERR_INVALID_ARG;
    }
    result = stop_remaining(product, timeout_ms);
    if (result != ESP_OK) {
        return result;
    }
    release_storage(product);
    return ESP_OK;
}
