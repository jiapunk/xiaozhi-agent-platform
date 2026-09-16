#include "box3_bringup.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "box3_audio.h"
#include "driver/gpio.h"
#include "esp_claw_runtime.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "product_sku.h"
#include "product_status_indicator.h"

static const char *TAG = "box3_bringup";

enum {
    BUTTON_GPIO = 0,
    BUTTON_POLL_MS = 20,
    BUTTON_DEBOUNCE_MS = 60,
    AUDIO_REPEAT_HOLD_MS = 1500,
    AUDIO_TEST_VOLUME_PERCENT = 35,
    AUDIO_TONE_HZ = 750,
    AUDIO_TONE_DURATION_MS = 240,
    AUDIO_CHUNK_FRAMES = 240,
    AUDIO_CAPTURE_FRAMES = 1440,
    AUDIO_CAPTURE_SAMPLES =
        AUDIO_CAPTURE_FRAMES * BOX3_AUDIO_INPUT_CHANNELS,
    BRINGUP_TASK_STACK_BYTES = 6144,
};

typedef struct {
    box3_audio_t *audio;
    product_status_indicator_handle_t indicator;
    esp_claw_runtime_handle_t claw;
    TaskHandle_t task;
    /* Keep audio work buffers out of the FreeRTOS task stack. */
    int16_t tone_samples[AUDIO_CHUNK_FRAMES];
    int16_t mic_samples[AUDIO_CAPTURE_SAMPLES];
    atomic_bool physical_consent;
    atomic_bool indicator_on;
    atomic_bool audio_io_ok;
    atomic_uint mic_peak;
    atomic_uint mic_mean_abs;
    atomic_uint audio_test_count;
    atomic_uint capability_calls;
    uint32_t next_request_id;
} box3_bringup_state_t;

static box3_bringup_state_t s_bringup;

static const char *json_bool(bool value)
{
    return value ? "true" : "false";
}

static esp_err_t get_status_json(void *ctx, char *output, size_t output_size)
{
    box3_bringup_state_t *state = ctx;
    if (!state || !output || output_size == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    const int written = snprintf(
        output, output_size,
        "{\"profile\":\"box3-bringup\",\"hardware_geometry\":true,"
        "\"audio_io_ok\":%s,\"audio_test_count\":%u,"
        "\"mic_peak\":%u,\"mic_mean_abs\":%u,"
        "\"indicator_on\":%s}",
        json_bool(atomic_load_explicit(&state->audio_io_ok,
                                       memory_order_acquire)),
        (unsigned)atomic_load_explicit(&state->audio_test_count,
                                       memory_order_acquire),
        (unsigned)atomic_load_explicit(&state->mic_peak,
                                       memory_order_acquire),
        (unsigned)atomic_load_explicit(&state->mic_mean_abs,
                                       memory_order_acquire),
        json_bool(atomic_load_explicit(&state->indicator_on,
                                       memory_order_acquire)));
    return written >= 0 && (size_t)written < output_size
               ? ESP_OK
               : ESP_ERR_INVALID_SIZE;
}

static esp_err_t set_indicator(void *ctx, bool on)
{
    box3_bringup_state_t *state = ctx;
    if (!state || !state->indicator) {
        return ESP_ERR_INVALID_STATE;
    }
    const esp_err_t error =
        product_status_indicator_set(state->indicator, on);
    if (error == ESP_OK) {
        atomic_store_explicit(&state->indicator_on, on,
                              memory_order_release);
    }
    return error;
}

static bool consume_physical_consent(
    void *ctx,
    uint32_t request_id,
    const char *session_id,
    const esp_claw_capability_action_t *action)
{
    box3_bringup_state_t *state = ctx;
    bool expected = true;
    return state && request_id != 0 && session_id &&
           strcmp(session_id, "box3-physical-button") == 0 && action &&
           action->type == ESP_CLAW_CAPABILITY_ACTION_SET_INDICATOR &&
           atomic_compare_exchange_strong_explicit(
               &state->physical_consent, &expected, false,
               memory_order_acq_rel, memory_order_acquire);
}

static void capability_audit(
    void *ctx,
    const esp_claw_capability_audit_event_t *event)
{
    box3_bringup_state_t *state = ctx;
    if (!state || !event) {
        return;
    }
    atomic_fetch_add_explicit(&state->capability_calls, 1,
                              memory_order_relaxed);
    ESP_LOGI(TAG, "ESP-Claw audit capability=%s request=%u decision=%d result=%s",
             event->capability_id ? event->capability_id : "unknown",
             (unsigned)event->request_id, (int)event->decision,
             esp_err_to_name(event->result));
}

static uint32_t next_request_id(box3_bringup_state_t *state)
{
    ++state->next_request_id;
    if (state->next_request_id == 0) {
        ++state->next_request_id;
    }
    return state->next_request_id;
}

static void log_agent_status(box3_bringup_state_t *state)
{
    char output[320] = {0};
    const esp_err_t error = esp_claw_runtime_call_local_capability(
        state->claw, next_request_id(state), "box3-bringup",
        "device.get_status", "{}", output, sizeof(output));
    if (error == ESP_OK) {
        ESP_LOGI(TAG, "[PASS] ESP-Claw device.get_status => %s", output);
    } else {
        ESP_LOGE(TAG, "[FAIL] ESP-Claw device.get_status: %s",
                 esp_err_to_name(error));
    }
}

static void toggle_indicator_through_agent(box3_bringup_state_t *state)
{
    const bool target =
        !atomic_load_explicit(&state->indicator_on, memory_order_acquire);
    char input[24] = {0};
    char output[96] = {0};
    (void)snprintf(input, sizeof(input), "{\"on\":%s}",
                   json_bool(target));
    atomic_store_explicit(&state->physical_consent, true,
                          memory_order_release);
    const esp_err_t error = esp_claw_runtime_call_local_capability(
        state->claw, next_request_id(state), "box3-physical-button",
        "device.set_indicator", input, output, sizeof(output));
    /* A failed call must not leave consent available for a later request. */
    atomic_store_explicit(&state->physical_consent, false,
                          memory_order_release);
    if (error == ESP_OK) {
        ESP_LOGI(TAG,
                 "[PASS] physical-consent ESP-Claw device.set_indicator => %s",
                 output);
    } else {
        ESP_LOGE(TAG, "[FAIL] ESP-Claw device.set_indicator: %s",
                 esp_err_to_name(error));
    }
    log_agent_status(state);
}

static int16_t triangle_sample(size_t sample_index)
{
    const unsigned period = BOX3_AUDIO_SAMPLE_RATE / AUDIO_TONE_HZ;
    const unsigned position = (unsigned)(sample_index % period);
    const unsigned half = period / 2U;
    const int32_t amplitude = 6000;
    if (position < half) {
        return (int16_t)(-amplitude +
                         (2 * amplitude * (int32_t)position) /
                             (int32_t)half);
    }
    return (int16_t)(amplitude -
                     (2 * amplitude * (int32_t)(position - half)) /
                         (int32_t)half);
}

static esp_err_t play_test_tone(box3_bringup_state_t *state)
{
    const size_t total_frames =
        (BOX3_AUDIO_SAMPLE_RATE * AUDIO_TONE_DURATION_MS) / 1000U;
    esp_err_t error = box3_audio_set_output_volume(
        state->audio, AUDIO_TEST_VOLUME_PERCENT);
    if (error == ESP_OK) {
        error = box3_audio_enable_output(state->audio, true);
    }
    for (size_t base = 0; error == ESP_OK && base < total_frames;
         base += AUDIO_CHUNK_FRAMES) {
        const size_t count =
            total_frames - base < AUDIO_CHUNK_FRAMES
                ? total_frames - base
                : AUDIO_CHUNK_FRAMES;
        for (size_t index = 0; index < count; ++index) {
            state->tone_samples[index] = triangle_sample(base + index);
        }
        size_t written = 0;
        error = box3_audio_write(state->audio, state->tone_samples,
                                 count, &written);
        if (error == ESP_OK && written != count) {
            error = ESP_ERR_INVALID_SIZE;
        }
    }
    const esp_err_t close_error =
        box3_audio_enable_output(state->audio, false);
    return error == ESP_OK ? close_error : error;
}

static esp_err_t sample_microphone(box3_bringup_state_t *state)
{
    esp_err_t error = box3_audio_enable_input(state->audio, true);
    size_t samples_read = 0;
    if (error == ESP_OK) {
        error = box3_audio_read(state->audio, state->mic_samples,
                                AUDIO_CAPTURE_SAMPLES, &samples_read);
    }
    const esp_err_t close_error =
        box3_audio_enable_input(state->audio, false);
    if (error == ESP_OK) {
        error = close_error;
    }
    if (error != ESP_OK || samples_read != AUDIO_CAPTURE_SAMPLES) {
        return error == ESP_OK ? ESP_ERR_INVALID_SIZE : error;
    }

    uint32_t peak = 0;
    uint64_t absolute_sum = 0;
    for (size_t frame = 0; frame < AUDIO_CAPTURE_FRAMES; ++frame) {
        const int32_t sample =
            state->mic_samples[frame * BOX3_AUDIO_INPUT_CHANNELS];
        const uint32_t absolute =
            (uint32_t)(sample < 0 ? -sample : sample);
        if (absolute > peak) {
            peak = absolute;
        }
        absolute_sum += absolute;
    }
    atomic_store_explicit(&state->mic_peak, peak, memory_order_release);
    atomic_store_explicit(&state->mic_mean_abs,
                          (unsigned)(absolute_sum /
                                     AUDIO_CAPTURE_FRAMES),
                          memory_order_release);
    return ESP_OK;
}

static void run_audio_test(box3_bringup_state_t *state)
{
    ESP_LOGI(TAG, "Running BOX-3 speaker and microphone I/O test");
    const esp_err_t tone_error = play_test_tone(state);
    const esp_err_t mic_error = sample_microphone(state);
    const bool passed = tone_error == ESP_OK && mic_error == ESP_OK;
    atomic_store_explicit(&state->audio_io_ok, passed,
                          memory_order_release);
    atomic_fetch_add_explicit(&state->audio_test_count, 1,
                              memory_order_relaxed);
    if (passed) {
        ESP_LOGI(TAG,
                 "[PASS] audio codec/I2S I/O; mic_peak=%u mic_mean_abs=%u "
                 "(signal levels are observations, not acoustic qualification)",
                 (unsigned)atomic_load_explicit(&state->mic_peak,
                                                memory_order_acquire),
                 (unsigned)atomic_load_explicit(&state->mic_mean_abs,
                                                memory_order_acquire));
    } else {
        ESP_LOGE(TAG, "[FAIL] audio tone=%s microphone=%s",
                 esp_err_to_name(tone_error), esp_err_to_name(mic_error));
    }
    log_agent_status(state);
}

static void bringup_task(void *argument)
{
    box3_bringup_state_t *state = argument;
    bool raw_pressed = gpio_get_level(BUTTON_GPIO) == 0;
    bool stable_pressed = raw_pressed;
    TickType_t raw_changed_at = xTaskGetTickCount();
    TickType_t pressed_at = 0;

    /* A short direct blink is a local boot-ready indication, not an Agent action. */
    (void)set_indicator(state, true);
    vTaskDelay(pdMS_TO_TICKS(180));
    (void)set_indicator(state, false);
    run_audio_test(state);

    for (;;) {
        const TickType_t now = xTaskGetTickCount();
        const bool pressed = gpio_get_level(BUTTON_GPIO) == 0;
        if (pressed != raw_pressed) {
            raw_pressed = pressed;
            raw_changed_at = now;
        }
        if (raw_pressed != stable_pressed &&
            (now - raw_changed_at) >= pdMS_TO_TICKS(BUTTON_DEBOUNCE_MS)) {
            stable_pressed = raw_pressed;
            if (stable_pressed) {
                pressed_at = now;
            } else {
                const uint32_t held_ms =
                    (uint32_t)((now - pressed_at) * portTICK_PERIOD_MS);
                if (held_ms >= AUDIO_REPEAT_HOLD_MS) {
                    ESP_LOGI(TAG, "BOOT held %u ms: repeating audio test",
                             (unsigned)held_ms);
                    run_audio_test(state);
                } else {
                    ESP_LOGI(TAG,
                             "BOOT short press: granting one physical Agent action");
                    toggle_indicator_through_agent(state);
                }
            }
        }
        vTaskDelay(pdMS_TO_TICKS(BUTTON_POLL_MS));
    }
}

esp_err_t box3_bringup_start(void)
{
    if (s_bringup.task || s_bringup.audio || s_bringup.indicator ||
        s_bringup.claw) {
        return ESP_ERR_INVALID_STATE;
    }
    memset(&s_bringup, 0, sizeof(s_bringup));
    atomic_init(&s_bringup.physical_consent, false);
    atomic_init(&s_bringup.indicator_on, false);
    atomic_init(&s_bringup.audio_io_ok, false);
    atomic_init(&s_bringup.mic_peak, 0);
    atomic_init(&s_bringup.mic_mean_abs, 0);
    atomic_init(&s_bringup.audio_test_count, 0);
    atomic_init(&s_bringup.capability_calls, 0);

    const product_sku_profile_t *profile =
        product_sku_get_compiled_profile();
    esp_err_t error = product_status_indicator_create(
        profile, &s_bringup.indicator);
    if (error != ESP_OK) {
        return error;
    }
    error = box3_audio_create(&s_bringup.audio);
    if (error != ESP_OK) {
        (void)product_status_indicator_destroy(s_bringup.indicator);
        s_bringup.indicator = NULL;
        return error;
    }
    const esp_claw_local_capability_config_t claw_config = {
        .enabled_capabilities =
            ESP_CLAW_CAPABILITY_DEVICE_GET_STATUS |
            ESP_CLAW_CAPABILITY_DEVICE_SET_INDICATOR,
        .device_ops = {
            .get_status_json = get_status_json,
            .set_indicator = set_indicator,
            .ctx = &s_bringup,
        },
        .capability_consent = consume_physical_consent,
        .capability_consent_ctx = &s_bringup,
        .capability_audit = capability_audit,
        .capability_audit_ctx = &s_bringup,
    };
    error = esp_claw_runtime_start_local_capabilities(
        &claw_config, &s_bringup.claw);
    if (error != ESP_OK) {
        if (s_bringup.claw) {
            (void)esp_claw_runtime_stop(s_bringup.claw, 5000);
            s_bringup.claw = NULL;
        }
        box3_audio_destroy(s_bringup.audio);
        s_bringup.audio = NULL;
        (void)product_status_indicator_destroy(s_bringup.indicator);
        s_bringup.indicator = NULL;
        return error;
    }

    const gpio_config_t button_config = {
        .pin_bit_mask = UINT64_C(1) << BUTTON_GPIO,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    error = gpio_config(&button_config);
    if (error != ESP_OK ||
        xTaskCreate(bringup_task, "box3_bringup",
                    BRINGUP_TASK_STACK_BYTES, &s_bringup, 5,
                    &s_bringup.task) != pdPASS) {
        if (error == ESP_OK) {
            error = ESP_ERR_NO_MEM;
        }
        (void)esp_claw_runtime_stop(s_bringup.claw, 5000);
        s_bringup.claw = NULL;
        box3_audio_destroy(s_bringup.audio);
        s_bringup.audio = NULL;
        (void)product_status_indicator_destroy(s_bringup.indicator);
        s_bringup.indicator = NULL;
        return error;
    }

    ESP_LOGI(TAG,
             "Development harness started: no Wi-Fi, cloud token, eFuse "
             "write, or remote command path is active");
    return ESP_OK;
}
