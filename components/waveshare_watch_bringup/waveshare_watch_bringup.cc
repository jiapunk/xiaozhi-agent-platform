#include "waveshare_watch_bringup.h"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstdio>

#include "bsp/esp-bsp.h"
#include "esp_codec_dev.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lvgl.h"

namespace {

constexpr char kTag[] = "watch_bringup";
constexpr int kSampleRate = 16000;
constexpr int kChannels = 2;
constexpr int kFramesPerRead = 512;
constexpr int kToneChunkFrames = 320;
constexpr int kToneDurationMs = 320;
constexpr int kToneFrequencyHz = 760;
constexpr int kOutputVolumePercent = 92;

std::atomic<int> s_microphone_percent{0};
std::atomic<unsigned> s_touch_count{0};
std::atomic<bool> s_tone_requested{true};

esp_codec_dev_handle_t s_speaker = nullptr;
esp_codec_dev_handle_t s_microphone = nullptr;
lv_obj_t *s_microphone_bar = nullptr;
lv_obj_t *s_microphone_label = nullptr;
lv_obj_t *s_touch_label = nullptr;

void set_text_color(lv_obj_t *object, uint32_t rgb)
{
    lv_obj_set_style_text_color(object, lv_color_hex(rgb), 0);
}

lv_obj_t *make_label(lv_obj_t *parent, const char *text,
                     const lv_font_t *font, int x, int y)
{
    lv_obj_t *label = lv_label_create(parent);
    lv_label_set_text(label, text);
    lv_obj_set_style_text_font(label, font, 0);
    set_text_color(label, 0xf4f7fb);
    lv_obj_set_pos(label, x, y);
    return label;
}

void tone_button_event(lv_event_t *event)
{
    if (lv_event_get_code(event) != LV_EVENT_CLICKED) {
        return;
    }
    s_touch_count.fetch_add(1, std::memory_order_relaxed);
    s_tone_requested.store(true, std::memory_order_release);
}

void ui_timer(lv_timer_t *)
{
    const int level = s_microphone_percent.load(std::memory_order_relaxed);
    lv_bar_set_value(s_microphone_bar, level, LV_ANIM_ON);
    lv_label_set_text_fmt(s_microphone_label, "MIC LEVEL  %d%%", level);
    lv_label_set_text_fmt(s_touch_label, "TOUCH OK  %u",
                          s_touch_count.load(std::memory_order_relaxed));
}

void create_ui()
{
    lv_obj_t *screen = lv_screen_active();
    lv_obj_set_style_bg_color(screen, lv_color_hex(0x07111f), 0);
    lv_obj_set_style_bg_opa(screen, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(screen, 0, 0);

    lv_obj_t *header = lv_obj_create(screen);
    lv_obj_remove_style_all(header);
    lv_obj_set_size(header, 362, 100);
    lv_obj_set_pos(header, 24, 30);
    lv_obj_set_style_bg_color(header, lv_color_hex(0x102a43), 0);
    lv_obj_set_style_bg_opa(header, LV_OPA_COVER, 0);
    lv_obj_set_style_radius(header, 24, 0);

    lv_obj_t *title = make_label(header, "SAFE AGENT", &lv_font_montserrat_28,
                                 20, 14);
    set_text_color(title, 0xffffff);
    lv_obj_t *subtitle = make_label(header, "WATCH HARDWARE TEST",
                                    &lv_font_montserrat_18, 20, 57);
    set_text_color(subtitle, 0x78dce8);

    s_microphone_label = make_label(screen, "MIC LEVEL  0%",
                                    &lv_font_montserrat_22, 40, 160);
    s_microphone_bar = lv_bar_create(screen);
    lv_obj_set_size(s_microphone_bar, 330, 36);
    lv_obj_set_pos(s_microphone_bar, 40, 205);
    lv_bar_set_range(s_microphone_bar, 0, 100);
    lv_bar_set_value(s_microphone_bar, 0, LV_ANIM_OFF);
    lv_obj_set_style_bg_color(s_microphone_bar, lv_color_hex(0x20344a),
                              LV_PART_MAIN);
    lv_obj_set_style_bg_color(s_microphone_bar, lv_color_hex(0x31d0aa),
                              LV_PART_INDICATOR);
    lv_obj_set_style_radius(s_microphone_bar, 18, LV_PART_MAIN);
    lv_obj_set_style_radius(s_microphone_bar, 18, LV_PART_INDICATOR);

    lv_obj_t *hint = make_label(screen, "SPEAK TO TEST BOTH MICS",
                                &lv_font_montserrat_18, 40, 263);
    set_text_color(hint, 0x9fb3c8);

    lv_obj_t *button = lv_button_create(screen);
    lv_obj_set_size(button, 330, 76);
    lv_obj_set_pos(button, 40, 325);
    lv_obj_set_style_bg_color(button, lv_color_hex(0x2f80ed), 0);
    lv_obj_set_style_radius(button, 24, 0);
    lv_obj_add_event_cb(button, tone_button_event, LV_EVENT_CLICKED, nullptr);
    lv_obj_t *button_label = lv_label_create(button);
    lv_label_set_text(button_label, "PLAY SPEAKER TEST");
    lv_obj_set_style_text_font(button_label, &lv_font_montserrat_22, 0);
    set_text_color(button_label, 0xffffff);
    lv_obj_center(button_label);

    s_touch_label = make_label(screen, "TOUCH OK  0",
                               &lv_font_montserrat_20, 40, 427);
    lv_obj_t *status = make_label(screen, "32MB FLASH  |  8MB PSRAM",
                                  &lv_font_montserrat_16, 40, 462);
    set_text_color(status, 0x68d391);

    lv_timer_create(ui_timer, 80, nullptr);
}

esp_err_t open_audio()
{
    s_speaker = bsp_audio_codec_speaker_init();
    s_microphone = bsp_audio_codec_microphone_init();
    if (!s_speaker || !s_microphone) {
        return ESP_ERR_NOT_FOUND;
    }
    esp_codec_dev_sample_info_t format = {};
    format.bits_per_sample = 16;
    format.channel = kChannels;
    format.sample_rate = kSampleRate;
    esp_err_t error = esp_codec_dev_open(s_speaker, &format);
    if (error != ESP_OK) {
        return error;
    }
    error = esp_codec_dev_open(s_microphone, &format);
    if (error != ESP_OK) {
        return error;
    }
    return esp_codec_dev_set_out_vol(s_speaker, kOutputVolumePercent);
}

void play_test_tone()
{
    int16_t samples[kToneChunkFrames * kChannels] = {};
    constexpr float kPi = 3.14159265358979323846f;
    const int total_frames = kSampleRate * kToneDurationMs / 1000;
    int frame_index = 0;
    while (frame_index < total_frames) {
        const int frames = std::min(kToneChunkFrames,
                                    total_frames - frame_index);
        for (int index = 0; index < frames; ++index) {
            const int absolute = frame_index + index;
            const float position = static_cast<float>(absolute) /
                                   static_cast<float>(total_frames);
            const float envelope = std::min(1.0f, std::min(position * 12.0f,
                                                           (1.0f - position) * 12.0f));
            const float phase = 2.0f * kPi * kToneFrequencyHz *
                                static_cast<float>(absolute) / kSampleRate;
            const int16_t value = static_cast<int16_t>(
                std::sin(phase) * envelope * 21000.0f);
            samples[index * 2] = value;
            samples[index * 2 + 1] = value;
        }
        const esp_err_t error = esp_codec_dev_write(
            s_speaker, samples,
            static_cast<int>(frames * kChannels * sizeof(int16_t)));
        if (error != ESP_OK) {
            ESP_LOGE(kTag, "Speaker write failed: %s",
                     esp_err_to_name(error));
            return;
        }
        frame_index += frames;
    }
}

void audio_task(void *)
{
    esp_err_t error = open_audio();
    if (error != ESP_OK) {
        ESP_LOGE(kTag, "Audio initialization failed: %s",
                 esp_err_to_name(error));
        vTaskDelete(nullptr);
        return;
    }
    ESP_LOGI(kTag, "Duplex audio ready: 16000Hz stereo, volume=%d%%",
             kOutputVolumePercent);

    int16_t samples[kFramesPerRead * kChannels] = {};
    while (true) {
        if (s_tone_requested.exchange(false, std::memory_order_acq_rel)) {
            play_test_tone();
        }
        error = esp_codec_dev_read(s_microphone, samples, sizeof(samples));
        if (error != ESP_OK) {
            ESP_LOGW(kTag, "Microphone read failed: %s",
                     esp_err_to_name(error));
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }
        int peak = 0;
        for (int index = 0; index < kFramesPerRead * kChannels; ++index) {
            const int value = std::abs(static_cast<int>(samples[index]));
            peak = std::max(peak, value);
        }
        const int percent = std::min(100, peak * 100 / 12000);
        const int previous = s_microphone_percent.load(
            std::memory_order_relaxed);
        s_microphone_percent.store(
            percent >= previous ? percent : std::max(0, previous - 4),
            std::memory_order_relaxed);
    }
}

}  // namespace

extern "C" esp_err_t waveshare_watch_bringup_start(void)
{
    lv_display_t *display = bsp_display_start();
    if (!display) {
        return ESP_ERR_NOT_FOUND;
    }
    ESP_ERROR_CHECK(bsp_display_backlight_on());
    ESP_ERROR_CHECK(bsp_display_brightness_set(82));

    if (!bsp_display_lock(2000)) {
        return ESP_ERR_TIMEOUT;
    }
    create_ui();
    bsp_display_unlock();

    const BaseType_t created = xTaskCreate(
        audio_task, "watch_audio", 8192, nullptr, 6, nullptr);
    return created == pdPASS ? ESP_OK : ESP_ERR_NO_MEM;
}
