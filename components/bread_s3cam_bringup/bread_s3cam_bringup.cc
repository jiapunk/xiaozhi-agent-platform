#include "bread_s3cam_bringup.h"

#include "sdkconfig.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "cJSON.h"
#include "driver/gpio.h"
#include "driver/i2s_std.h"
#include "driver/ledc.h"
#include "driver/spi_master.h"
#include "esp_app_desc.h"
#include "esp_audio_dec.h"
#include "esp_audio_enc.h"
#include "esp_chip_info.h"
#include "esp_claw_runtime.h"
#include "esp_crt_bundle.h"
#include "esp_flash.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"
#include "esp_http_server.h"
#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_panel_vendor.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_opus_dec.h"
#include "esp_opus_enc.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_video_device.h"
#include "esp_video_init.h"
#include "esp_websocket_client.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/idf_additions.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "linux/videodev2.h"
#include "nvs.h"
#include "product_sku.h"
#include "product_status_indicator.h"
#include "product_storage.h"
#include "product_wifi.h"

namespace {

constexpr char kTag[] = "bread_s3cam_test";

constexpr gpio_num_t kButton = GPIO_NUM_0;
constexpr gpio_num_t kVolumeDownButton = GPIO_NUM_41;
constexpr gpio_num_t kVolumeUpButton = GPIO_NUM_40;
constexpr gpio_num_t kBacklight = GPIO_NUM_38;
constexpr gpio_num_t kDisplayMosi = GPIO_NUM_17;
constexpr gpio_num_t kDisplayClock = GPIO_NUM_15;
constexpr gpio_num_t kDisplayDc = GPIO_NUM_7;
constexpr gpio_num_t kDisplayReset = GPIO_NUM_NC;
constexpr gpio_num_t kDisplayCs = GPIO_NUM_16;
constexpr int kDisplayWidth = 240;
constexpr int kDisplayHeight = 320;
constexpr uint32_t kBacklightPwmHz = 25000;
constexpr uint32_t kBacklightFullDuty = 1023;
/* Empirically verified on the connected production sample: GPIO38 is routed
 * through an active-low backlight switch. A non-inverted 100% PWM command
 * leaves the screen dark, while the consent test's logical-off pulse lights
 * it briefly. Keep logical brightness conventional and invert at LEDC. */
constexpr bool kBacklightOutputInvert = true;

/* This production sample reports the public bread-compact-wifi-s3cam board
 * name, but its factory image contains a different camera wiring variant.
 * These values were recovered from that image's esp_video DVP configuration
 * and are verified independently from the public board profile. */
constexpr gpio_num_t kCameraD0 = GPIO_NUM_19;
constexpr gpio_num_t kCameraD1 = GPIO_NUM_8;
constexpr gpio_num_t kCameraD2 = GPIO_NUM_18;
constexpr gpio_num_t kCameraD3 = GPIO_NUM_3;
constexpr gpio_num_t kCameraD4 = GPIO_NUM_20;
constexpr gpio_num_t kCameraD5 = GPIO_NUM_45;
constexpr gpio_num_t kCameraD6 = GPIO_NUM_48;
constexpr gpio_num_t kCameraD7 = GPIO_NUM_21;
constexpr gpio_num_t kCameraXclk = GPIO_NUM_47;
constexpr gpio_num_t kCameraPclk = GPIO_NUM_46;
constexpr gpio_num_t kCameraVsync = GPIO_NUM_12;
constexpr gpio_num_t kCameraHref = GPIO_NUM_14;
constexpr gpio_num_t kCameraScl = GPIO_NUM_11;
constexpr gpio_num_t kCameraSda = GPIO_NUM_10;
constexpr gpio_num_t kCameraPwdn = GPIO_NUM_13;
constexpr uint32_t kCameraXclkHz = 24 * 1000 * 1000;
// Match XiaoZhi's proven GC0308 behavior. The sensor's QVGA register table
// enables horizontal mirroring by default, so both axes must be set explicitly
// after VIDIOC_S_FMT rather than inheriting register-table side effects.
constexpr bool kCameraHorizontalMirror = false;
constexpr bool kCameraVerticalFlip = false;

constexpr gpio_num_t kMicWordSelect = GPIO_NUM_4;
constexpr gpio_num_t kMicClock = GPIO_NUM_6;
constexpr gpio_num_t kMicData = GPIO_NUM_5;
constexpr gpio_num_t kSpeakerData = GPIO_NUM_42;
constexpr gpio_num_t kSpeakerClock = GPIO_NUM_2;
constexpr gpio_num_t kSpeakerWordSelect = GPIO_NUM_1;
constexpr int kInputSampleRate = 16000;
constexpr int kOutputSampleRate = 24000;
constexpr int kToneHz = 750;
constexpr int kToneDurationMs = 240;
constexpr int kToneSamples = kOutputSampleRate * kToneDurationMs / 1000;
constexpr int kCaptureSamples = kInputSampleRate / 10;
constexpr int kButtonPollMs = 20;
constexpr int kButtonDebounceMs = 60;
constexpr int kRepeatHoldMs = 1500;
constexpr int kWifiSetupHoldMs = 4000;
constexpr int kDefaultOutputVolumePercent = 70;
constexpr char kSettingsNvsPartition[] = "nvs";
constexpr char kSettingsNvsNamespace[] = "s3cam_ui";
constexpr char kVolumeNvsKey[] = "volume";
constexpr int64_t kWifiSetupTimeoutUs = 5 * 60 * 1000 * 1000LL;
constexpr int64_t kWifiSuccessDisplayUs = 8 * 1000 * 1000LL;
constexpr int64_t kWifiStationRecoveryUs = 60 * 1000 * 1000LL;
constexpr int64_t kCloudRetryDelayUs = 30 * 1000 * 1000LL;
constexpr int64_t kVoiceRetryDelayUs = 10 * 1000 * 1000LL;
constexpr int64_t kVoiceThinkingTimeoutUs = 120 * 1000 * 1000LL;
// A catalog song can be several minutes long. The user can still stop it at
// any time with the voice button, which sends an abort and clears the queue.
constexpr int64_t kVoiceSpeakingTimeoutUs = 7 * 60 * 1000 * 1000LL;
constexpr int64_t kConsentMaximumUs = 20 * 1000 * 1000LL;
constexpr int kCameraPreviewIntervalMs = 180;
constexpr int kMicrophonePreviewIntervalMs = 120;
constexpr size_t kCameraBufferCount = 1;
constexpr size_t kCloudResponseCapacity = 8192;
constexpr char kVoiceBootstrapUrl[] =
    CONFIG_PRODUCT_BREAD_S3CAM_VOICE_BOOTSTRAP_URL;
constexpr char kVoiceBootstrapToken[] =
    CONFIG_PRODUCT_BREAD_S3CAM_BOOTSTRAP_TOKEN;
#ifdef CONFIG_PRODUCT_BREAD_S3CAM_ALLOW_INSECURE_VOICE_GATEWAY
constexpr bool kAllowInsecureVoiceGateway = true;
#else
constexpr bool kAllowInsecureVoiceGateway = false;
#endif
constexpr int kVoiceFrameDurationMs = 60;
constexpr int kVoiceSendTimeoutMs = 8000;
// Endpointing stays on-device: the user can begin naturally, pause inside a
// sentence, and finish by becoming quiet instead of racing a fixed timer.
constexpr int kVoiceEndpointWarmupFrames = 5;
constexpr int kVoiceSpeechStartFrames = 3;
// A short request should still finish promptly, while a longer request needs
// enough room for natural pauses and breaths. Since each frame is 60 ms, the
// three trailing-silence windows are about 1.7, 2.4, and 3.3 seconds.
constexpr int kVoiceShortTrailingSilenceFrames = 28;
constexpr int kVoiceMediumTrailingSilenceFrames = 40;
constexpr int kVoiceLongTrailingSilenceFrames = 55;
constexpr int kVoiceMediumCaptureFrames = 75;
constexpr int kVoiceLongCaptureFrames = 167;
constexpr int kVoiceNoSpeechFrames = 167;
constexpr int kVoiceMaximumCaptureFrames = 750;
constexpr UBaseType_t kVoicePlaybackPrebufferPackets = 24;
constexpr UBaseType_t kVoicePlaybackRebufferPackets = 6;
constexpr UBaseType_t kVoiceAudioQueuePackets = 64;
constexpr int kVoicePlaybackTailPackets = 2;
constexpr int kVoicePlaybackUnderrunGracePackets = 3;
constexpr int kVoiceInputSamples =
    kInputSampleRate * kVoiceFrameDurationMs / 1000;
constexpr int kVoiceOutputSamples =
    kOutputSampleRate * kVoiceFrameDurationMs / 1000;
constexpr size_t kVoiceOpusCapacity = 1536;
constexpr size_t kVoiceTextCapacity = 2048;
constexpr size_t kCameraUploadChunkBytes = 2048;
constexpr size_t kCameraUploadMaximumBytes = 320 * 240 * 2;

constexpr uint16_t kUiBackground = 0x0861;
constexpr uint16_t kUiHeader = 0x11a6;
constexpr uint16_t kUiCard = 0x18e3;
constexpr uint16_t kUiCardAlt = 0x2124;
constexpr uint16_t kUiWhite = 0xffff;
constexpr uint16_t kUiMuted = 0xad75;
constexpr uint16_t kUiGreen = 0x4e69;
constexpr uint16_t kUiRed = 0xf9e7;
constexpr uint16_t kUiCyan = 0x4e7f;
constexpr uint16_t kUiYellow = 0xff0a;

enum class UiPage : uint8_t {
  kStatus,
  kCamera,
  kMicrophone,
  kWifiSetup,
  kActivation,
  kConsent,
  kVoiceEnrollment,
};

enum class ConsentKind : uint8_t {
  kNone,
  kDeviceIndicator,
  kDeviceVolume,
  kCamera,
  kMemory,
  kVoice,
};

enum class CloudStage : uint8_t {
  kOff,
  kFetching,
  kNeedsActivation,
  kActivating,
  kReady,
  kError,
};

enum class VoiceStage : uint8_t {
  kOff,
  kConnecting,
  kReady,
  kListening,
  kThinking,
  kSpeaking,
  kError,
};

enum class ButtonEvent : uint8_t {
  kShortPress,
  kVolumeDown,
  kVolumeUp,
  kRetest,
  kWifiSetup,
};

struct CameraBuffer {
  void *start = nullptr;
  size_t length = 0;
};

struct VoiceAudioPacket {
  size_t length = 0;
  uint8_t data[kVoiceOpusCapacity] = {};
};

struct VoiceTextPacket {
  size_t length = 0;
  char data[kVoiceTextCapacity] = {};
};

struct VoiceWorkBuffers {
  int32_t microphone_raw[kVoiceInputSamples] = {};
  int16_t microphone_pcm[kVoiceInputSamples] = {};
  uint8_t encoded[kVoiceOpusCapacity] = {};
  int16_t speaker_pcm[kVoiceOutputSamples] = {};
  int32_t speaker_raw[kVoiceOutputSamples] = {};
  VoiceTextPacket text_packet = {};
  VoiceAudioPacket audio_packet = {};
};

struct BringupState {
  product_status_indicator_handle_t backlight = nullptr;
  esp_lcd_panel_handle_t panel = nullptr;
  SemaphoreHandle_t display_transfer_done = nullptr;
  i2s_chan_handle_t speaker = nullptr;
  i2s_chan_handle_t microphone = nullptr;
  esp_claw_runtime_handle_t claw = nullptr;
  product_wifi_handle_t wifi = nullptr;
  httpd_handle_t onboarding_httpd = nullptr;
  TaskHandle_t task = nullptr;
  TaskHandle_t button_task = nullptr;
  TaskHandle_t cloud_task = nullptr;
  TaskHandle_t voice_task = nullptr;
  QueueHandle_t button_events = nullptr;
  QueueHandle_t voice_audio_queue = nullptr;
  QueueHandle_t voice_text_queue = nullptr;
  esp_websocket_client_handle_t voice_websocket = nullptr;
  int camera_fd = -1;
  CameraBuffer camera_buffers[kCameraBufferCount] = {};
  size_t camera_buffer_count = 0;
  bool camera_streaming = false;
  std::atomic_bool physical_consent{false};
  std::atomic_bool consent_pending{false};
  std::atomic_bool consent_ui_dirty{false};
  std::atomic_bool voice_enrollment_ui_dirty{false};
  std::atomic_int pending_consent_kind{static_cast<int>(ConsentKind::kNone)};
  std::atomic_int approved_consent_kind{static_cast<int>(ConsentKind::kNone)};
  std::atomic_int pending_consent_value{0};
  std::atomic_int approved_consent_value{0};
  std::atomic_bool pending_consent_flag{false};
  std::atomic_bool approved_consent_flag{false};
  std::atomic_bool backlight_on{false};
  bool backlight_pwm_ready = false;
  std::atomic_bool display_ok{false};
  std::atomic_bool camera_ok{false};
  std::atomic_bool audio_ok{false};
  std::atomic_bool speaker_ok{false};
  std::atomic_bool microphone_ok{false};
  std::atomic_uint camera_width{0};
  std::atomic_uint camera_height{0};
  std::atomic_uint camera_checksum{0};
  std::atomic_uint camera_pid{0};
  std::atomic_uint mic_peak{0};
  std::atomic_uint mic_mean_abs{0};
  std::atomic_uint test_count{0};
  std::atomic_int output_volume_percent{kDefaultOutputVolumePercent};
  std::atomic_int wifi_state{PRODUCT_WIFI_STATE_STOPPED};
  std::atomic_bool wifi_online{false};
  std::atomic_bool wifi_ui_dirty{false};
  std::atomic_bool wifi_credentials_rejected{false};
  std::atomic_int wifi_last_error{ESP_OK};
  std::atomic_int cloud_stage{static_cast<int>(CloudStage::kOff)};
  std::atomic_bool cloud_ui_dirty{false};
  std::atomic_int cloud_last_error{ESP_OK};
  std::atomic_int voice_stage{static_cast<int>(VoiceStage::kOff)};
  std::atomic_llong voice_stage_since_us{0};
  std::atomic_llong voice_last_audio_us{0};
  std::atomic_bool voice_ui_dirty{false};
  std::atomic_bool voice_ws_connected{false};
  std::atomic_bool voice_listen_toggle{false};
  std::atomic_bool voice_playback_drain_requested{false};
  std::atomic_int voice_last_error{ESP_OK};
  uint16_t *ui_framebuffer = nullptr;
  uint16_t *ui_transfer_buffer = nullptr;
  UiPage ui_page = UiPage::kStatus;
  bool agent_action_tested = false;
  bool agent_action_ok = false;
  bool microphone_monitoring = false;
  char wifi_ap_ssid[PRODUCT_WIFI_SOFTAP_SSID_MAX + 1] = {};
  char wifi_ap_password[PRODUCT_WIFI_SOFTAP_PASSWORD_MAX + 1] = {};
  char activation_code[24] = {};
  char websocket_url[256] = {};
  char websocket_token[512] = {};
  char voice_session_id[96] = {};
  char voice_rx_text[kVoiceTextCapacity] = {};
  size_t voice_rx_text_length = 0;
  int64_t wifi_onboarding_started_us = 0;
  int64_t wifi_online_since_us = 0;
  int64_t wifi_offline_since_us = 0;
  int64_t cloud_retry_after_us = 0;
  int64_t voice_retry_after_us = 0;
  int64_t voice_last_ui_us = 0;
  int64_t pending_consent_expires_us = 0;
  int64_t approved_consent_expires_us = 0;
  char pending_consent_request_id[64] = {};
  char pending_consent_summary[48] = {};
  char voice_enrollment_code[8] = {};
  uint32_t request_id = 0;
};

BringupState s_state;

esp_err_t set_backlight(void *ctx, bool on);
esp_err_t ui_draw_wifi_setup(BringupState *state);
esp_err_t ui_draw_cloud_activation(BringupState *state);
esp_err_t ui_draw_voice(BringupState *state);
esp_err_t ui_draw_volume(BringupState *state);
esp_err_t ui_draw_consent(BringupState *state);
esp_err_t ui_draw_voice_enrollment(BringupState *state);
esp_err_t capture_and_upload_camera_frame(BringupState *state,
                                          const char *request_id,
                                          char *output, size_t output_size);

/* Compact 5x7 font. Each byte is one column, least-significant bit first. */
constexpr uint8_t kDigitFont[10][5] = {
    {0x3e, 0x51, 0x49, 0x45, 0x3e}, {0x00, 0x42, 0x7f, 0x40, 0x00},
    {0x42, 0x61, 0x51, 0x49, 0x46}, {0x21, 0x41, 0x45, 0x4b, 0x31},
    {0x18, 0x14, 0x12, 0x7f, 0x10}, {0x27, 0x45, 0x45, 0x45, 0x39},
    {0x3c, 0x4a, 0x49, 0x49, 0x30}, {0x01, 0x71, 0x09, 0x05, 0x03},
    {0x36, 0x49, 0x49, 0x49, 0x36}, {0x06, 0x49, 0x49, 0x29, 0x1e},
};

constexpr uint8_t kUpperFont[26][5] = {
    {0x7e, 0x11, 0x11, 0x11, 0x7e}, // A
    {0x7f, 0x49, 0x49, 0x49, 0x36}, // B
    {0x3e, 0x41, 0x41, 0x41, 0x22}, // C
    {0x7f, 0x41, 0x41, 0x22, 0x1c}, // D
    {0x7f, 0x49, 0x49, 0x49, 0x41}, // E
    {0x7f, 0x09, 0x09, 0x09, 0x01}, // F
    {0x3e, 0x41, 0x49, 0x49, 0x7a}, // G
    {0x7f, 0x08, 0x08, 0x08, 0x7f}, // H
    {0x00, 0x41, 0x7f, 0x41, 0x00}, // I
    {0x20, 0x40, 0x41, 0x3f, 0x01}, // J
    {0x7f, 0x08, 0x14, 0x22, 0x41}, // K
    {0x7f, 0x40, 0x40, 0x40, 0x40}, // L
    {0x7f, 0x02, 0x0c, 0x02, 0x7f}, // M
    {0x7f, 0x04, 0x08, 0x10, 0x7f}, // N
    {0x3e, 0x41, 0x41, 0x41, 0x3e}, // O
    {0x7f, 0x09, 0x09, 0x09, 0x06}, // P
    {0x3e, 0x41, 0x51, 0x21, 0x5e}, // Q
    {0x7f, 0x09, 0x19, 0x29, 0x46}, // R
    {0x46, 0x49, 0x49, 0x49, 0x31}, // S
    {0x01, 0x01, 0x7f, 0x01, 0x01}, // T
    {0x3f, 0x40, 0x40, 0x40, 0x3f}, // U
    {0x1f, 0x20, 0x40, 0x20, 0x1f}, // V
    {0x3f, 0x40, 0x38, 0x40, 0x3f}, // W
    {0x63, 0x14, 0x08, 0x14, 0x63}, // X
    {0x07, 0x08, 0x70, 0x08, 0x07}, // Y
    {0x61, 0x51, 0x49, 0x45, 0x43}, // Z
};

const uint8_t *ui_glyph(char character) {
  if (character >= '0' && character <= '9') {
    return kDigitFont[character - '0'];
  }
  if (character >= 'A' && character <= 'Z') {
    return kUpperFont[character - 'A'];
  }
  static constexpr uint8_t kBlank[5] = {};
  static constexpr uint8_t kDash[5] = {0x08, 0x08, 0x08, 0x08, 0x08};
  static constexpr uint8_t kColon[5] = {0x00, 0x36, 0x36, 0x00, 0x00};
  static constexpr uint8_t kDot[5] = {0x00, 0x60, 0x60, 0x00, 0x00};
  static constexpr uint8_t kSlash[5] = {0x20, 0x10, 0x08, 0x04, 0x02};
  switch (character) {
  case '-':
    return kDash;
  case ':':
    return kColon;
  case '.':
    return kDot;
  case '/':
    return kSlash;
  default:
    return kBlank;
  }
}

void ui_fill(BringupState *state, uint16_t color) {
  if (state && state->ui_framebuffer) {
    std::fill(state->ui_framebuffer,
              state->ui_framebuffer + kDisplayWidth * kDisplayHeight, color);
  }
}

void ui_fill_rect(BringupState *state, int x, int y, int width, int height,
                  uint16_t color) {
  if (!state || !state->ui_framebuffer || width <= 0 || height <= 0) {
    return;
  }
  const int left = std::max(0, x);
  const int top = std::max(0, y);
  const int right = std::min(kDisplayWidth, x + width);
  const int bottom = std::min(kDisplayHeight, y + height);
  for (int row = top; row < bottom; ++row) {
    std::fill(state->ui_framebuffer + row * kDisplayWidth + left,
              state->ui_framebuffer + row * kDisplayWidth + right, color);
  }
}

void ui_draw_text(BringupState *state, int x, int y, const char *text,
                  int scale, uint16_t color) {
  if (!state || !state->ui_framebuffer || !text || scale <= 0) {
    return;
  }
  int cursor = x;
  for (const char *character = text; *character; ++character) {
    const uint8_t *glyph = ui_glyph(*character);
    for (int column = 0; column < 5; ++column) {
      for (int row = 0; row < 7; ++row) {
        if ((glyph[column] & (UINT8_C(1) << row)) == 0) {
          continue;
        }
        ui_fill_rect(state, cursor + column * scale, y + row * scale, scale,
                     scale, color);
      }
    }
    cursor += 6 * scale;
  }
}

bool ui_transfer_done(esp_lcd_panel_io_handle_t,
                      esp_lcd_panel_io_event_data_t *, void *user_ctx) {
  auto *state = static_cast<BringupState *>(user_ctx);
  if (!state || !state->display_transfer_done) {
    return false;
  }
  BaseType_t higher_priority_task_woken = pdFALSE;
  xSemaphoreGiveFromISR(state->display_transfer_done,
                        &higher_priority_task_woken);
  return higher_priority_task_woken == pdTRUE;
}

esp_err_t ui_flush(BringupState *state) {
  if (!state || !state->panel || !state->ui_framebuffer ||
      !state->ui_transfer_buffer) {
    return ESP_ERR_INVALID_STATE;
  }
  constexpr int kRows = 20;
  esp_err_t error = ESP_OK;
  for (int y = 0; y < kDisplayHeight && error == ESP_OK; y += kRows) {
    const int rows = std::min(kRows, kDisplayHeight - y);
    std::memcpy(state->ui_transfer_buffer,
                state->ui_framebuffer + y * kDisplayWidth,
                kDisplayWidth * rows * sizeof(uint16_t));
    error = esp_lcd_panel_draw_bitmap(state->panel, 0, y, kDisplayWidth,
                                      y + rows, state->ui_transfer_buffer);
    if (error == ESP_OK && xSemaphoreTake(state->display_transfer_done,
                                          pdMS_TO_TICKS(100)) != pdTRUE) {
      error = ESP_ERR_TIMEOUT;
    }
  }
  return error;
}

void ui_draw_header(BringupState *state, const char *subtitle) {
  ui_fill(state, kUiBackground);
  ui_fill_rect(state, 0, 0, kDisplayWidth, 50, kUiHeader);
  ui_draw_text(state, 12, 7, "XIAOZHI AGENT", 2, kUiWhite);
  ui_draw_text(state, 12, 31, subtitle, 2, kUiCyan);
}

void ui_draw_status_row(BringupState *state, int y, const char *label,
                        const char *value, uint16_t accent) {
  ui_fill_rect(state, 8, y, 224, 33, kUiCard);
  ui_fill_rect(state, 8, y, 5, 33, accent);
  ui_draw_text(state, 20, y + 9, label, 2, kUiWhite);
  const int width = static_cast<int>(std::strlen(value)) * 12;
  ui_draw_text(state, 228 - width, y + 9, value, 2, accent);
}

esp_err_t ui_draw_progress(BringupState *state, const char *stage, int step) {
  ui_draw_header(state, "DEVICE TEST UI");
  ui_draw_text(state, 18, 78, "HARDWARE CHECK", 2, kUiWhite);
  ui_draw_text(state, 18, 112, stage, 2, kUiYellow);
  for (int index = 0; index < 4; ++index) {
    ui_fill_rect(state, 18 + index * 52, 158, 40, 8,
                 index < step ? kUiGreen : kUiCardAlt);
  }
  ui_draw_text(state, 18, 198, "PLEASE WAIT", 1, kUiMuted);
  ui_draw_text(state, 18, 282, "HOLD BOOT TO RETEST", 1, kUiMuted);
  const esp_err_t error = ui_flush(state);
  if (error == ESP_OK) {
    set_backlight(state, true);
  }
  return error;
}

uint32_t next_request_id(BringupState *state) {
  if (++state->request_id == 0) {
    ++state->request_id;
  }
  return state->request_id;
}

const char *json_bool(bool value) { return value ? "true" : "false"; }

esp_err_t set_backlight(void *ctx, bool on) {
  auto *state = static_cast<BringupState *>(ctx);
  if (!state || !state->backlight) {
    return ESP_ERR_INVALID_STATE;
  }
  esp_err_t error = ESP_OK;
  if (state->backlight_pwm_ready) {
    error = ledc_set_duty(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0,
                          on ? kBacklightFullDuty : 0);
    if (error == ESP_OK) {
      error = ledc_update_duty(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0);
    }
  } else {
    error = product_status_indicator_set(state->backlight, on);
  }
  if (error == ESP_OK) {
    state->backlight_on.store(on, std::memory_order_release);
  }
  return error;
}

esp_err_t initialize_backlight_pwm(BringupState *state) {
  if (!state || !state->backlight) {
    return ESP_ERR_INVALID_ARG;
  }
  const ledc_timer_config_t timer_config = {
      .speed_mode = LEDC_LOW_SPEED_MODE,
      .duty_resolution = LEDC_TIMER_10_BIT,
      .timer_num = LEDC_TIMER_0,
      .freq_hz = kBacklightPwmHz,
      .clk_cfg = LEDC_AUTO_CLK,
      .deconfigure = false,
  };
  esp_err_t error = ledc_timer_config(&timer_config);
  const ledc_channel_config_t channel_config = {
      .gpio_num = kBacklight,
      .speed_mode = LEDC_LOW_SPEED_MODE,
      .channel = LEDC_CHANNEL_0,
      .intr_type = LEDC_INTR_DISABLE,
      .timer_sel = LEDC_TIMER_0,
      .duty = kBacklightFullDuty,
      .hpoint = 0,
      .sleep_mode = LEDC_SLEEP_MODE_NO_ALIVE_NO_PD,
      .flags =
          {
              .output_invert = kBacklightOutputInvert,
          },
  };
  if (error == ESP_OK) {
    error = ledc_channel_config(&channel_config);
  }
  if (error == ESP_OK) {
    error = gpio_set_drive_capability(kBacklight, GPIO_DRIVE_CAP_3);
  }
  if (error == ESP_OK) {
    state->backlight_pwm_ready = true;
    state->backlight_on.store(true, std::memory_order_release);
    ESP_LOGI(kTag,
             "Backlight forced on with PWM: GPIO=%d active_low=%d freq=%u "
             "duty=%u/1023",
             static_cast<int>(kBacklight), kBacklightOutputInvert ? 1 : 0,
             static_cast<unsigned>(kBacklightPwmHz),
             static_cast<unsigned>(
                 ledc_get_duty(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0)));
  }
  return error;
}

esp_err_t get_status_json(void *ctx, char *output, size_t output_size) {
  auto *state = static_cast<BringupState *>(ctx);
  if (!state || !output || output_size == 0) {
    return ESP_ERR_INVALID_ARG;
  }
  product_wifi_stats_t wifi_stats = {};
  const bool wifi_stats_available =
      state->wifi &&
      product_wifi_get_stats(state->wifi, &wifi_stats) == ESP_OK;
  const int written = std::snprintf(
      output, output_size,
      "{\"profile\":\"bread-compact-wifi-s3cam\","
      "\"display_ok\":%s,\"camera_ok\":%s,\"audio_ok\":%s,"
      "\"speaker_ok\":%s,\"microphone_ok\":%s,"
      "\"camera_width\":%u,\"camera_height\":%u,"
      "\"camera_checksum\":%u,\"camera_pid\":%u,\"mic_peak\":%u,"
      "\"mic_mean_abs\":%u,\"test_count\":%u,\"output_volume\":%d,"
      "\"backlight_on\":%s,\"wifi_online\":%s,\"wifi_state\":%d,"
      "\"wifi_saved_networks\":%u}",
      json_bool(state->display_ok.load(std::memory_order_acquire)),
      json_bool(state->camera_ok.load(std::memory_order_acquire)),
      json_bool(state->audio_ok.load(std::memory_order_acquire)),
      json_bool(state->speaker_ok.load(std::memory_order_acquire)),
      json_bool(state->microphone_ok.load(std::memory_order_acquire)),
      state->camera_width.load(std::memory_order_acquire),
      state->camera_height.load(std::memory_order_acquire),
      state->camera_checksum.load(std::memory_order_acquire),
      state->camera_pid.load(std::memory_order_acquire),
      state->mic_peak.load(std::memory_order_acquire),
      state->mic_mean_abs.load(std::memory_order_acquire),
      state->test_count.load(std::memory_order_acquire),
      state->output_volume_percent.load(std::memory_order_acquire),
      json_bool(state->backlight_on.load(std::memory_order_acquire)),
      json_bool(state->wifi_online.load(std::memory_order_acquire)),
      state->wifi_state.load(std::memory_order_acquire),
      static_cast<unsigned>(wifi_stats_available
                                ? wifi_stats.saved_networks
                                : 0));
  return written >= 0 && static_cast<size_t>(written) < output_size
             ? ESP_OK
             : ESP_ERR_INVALID_SIZE;
}

bool consume_physical_consent(void *ctx, uint32_t request_id,
                              const char *session_id,
                              const esp_claw_capability_action_t *action) {
  auto *state = static_cast<BringupState *>(ctx);
  if (!state || request_id == 0 || !session_id || !action) {
    return false;
  }
  if (std::strcmp(session_id, "s3cam-agent-confirmed") == 0 &&
      esp_timer_get_time() <= state->approved_consent_expires_us) {
    const auto approved = static_cast<ConsentKind>(
        state->approved_consent_kind.load(std::memory_order_acquire));
    const bool exact_indicator =
        approved == ConsentKind::kDeviceIndicator &&
        action->type == ESP_CLAW_CAPABILITY_ACTION_SET_INDICATOR &&
        action->indicator_on ==
            state->approved_consent_flag.load(std::memory_order_acquire);
    const bool exact_volume =
        approved == ConsentKind::kDeviceVolume &&
        action->type == ESP_CLAW_CAPABILITY_ACTION_SET_VOLUME &&
        action->volume_percent ==
            state->approved_consent_value.load(std::memory_order_acquire);
    bool expected = true;
    if ((exact_indicator || exact_volume) &&
        state->physical_consent.compare_exchange_strong(
            expected, false, std::memory_order_acq_rel,
            std::memory_order_acquire)) {
      state->approved_consent_kind.store(static_cast<int>(ConsentKind::kNone),
                                         std::memory_order_release);
      return true;
    }
    return false;
  }
  bool expected = true;
  return std::strcmp(session_id, "s3cam-physical-button") == 0 &&
         action->type == ESP_CLAW_CAPABILITY_ACTION_SET_INDICATOR &&
         state->physical_consent.compare_exchange_strong(
             expected, false, std::memory_order_acq_rel,
             std::memory_order_acquire);
}

void capability_audit(void *, const esp_claw_capability_audit_event_t *event) {
  if (event) {
    ESP_LOGI(kTag,
             "ESP-Claw audit capability=%s request=%u decision=%d result=%s",
             event->capability_id ? event->capability_id : "unknown",
             static_cast<unsigned>(event->request_id),
             static_cast<int>(event->decision), esp_err_to_name(event->result));
  }
}

void log_agent_status(BringupState *state) {
  char output[400] = {};
  const esp_err_t error = esp_claw_runtime_call_local_capability(
      state->claw, next_request_id(state), "s3cam-diagnostic",
      "device.get_status", "{}", output, sizeof(output));
  if (error == ESP_OK) {
    ESP_LOGI(kTag, "[PASS] ESP-Claw device.get_status => %s", output);
  } else {
    ESP_LOGE(kTag, "[FAIL] ESP-Claw device.get_status: %s",
             esp_err_to_name(error));
  }
}

void secure_clear(void *memory, size_t size) {
  volatile uint8_t *bytes = static_cast<volatile uint8_t *>(memory);
  while (bytes && size > 0) {
    *bytes++ = 0;
    --size;
  }
}

esp_err_t load_output_volume(BringupState *state) {
  if (!state || product_storage_require_ready() != ESP_OK) {
    return ESP_ERR_INVALID_STATE;
  }
  nvs_handle_t settings = 0;
  esp_err_t error = nvs_open_from_partition(
      kSettingsNvsPartition, kSettingsNvsNamespace, NVS_READONLY, &settings);
  if (error == ESP_ERR_NVS_NOT_FOUND) {
    state->output_volume_percent.store(kDefaultOutputVolumePercent,
                                       std::memory_order_release);
    return ESP_OK;
  }
  if (error != ESP_OK) {
    return error;
  }
  uint8_t stored = kDefaultOutputVolumePercent;
  error = nvs_get_u8(settings, kVolumeNvsKey, &stored);
  nvs_close(settings);
  if (error == ESP_ERR_NVS_NOT_FOUND) {
    error = ESP_OK;
    stored = kDefaultOutputVolumePercent;
  }
  if (error != ESP_OK || stored > 100) {
    return error == ESP_OK ? ESP_ERR_INVALID_RESPONSE : error;
  }
  state->output_volume_percent.store(stored, std::memory_order_release);
  ESP_LOGI(kTag, "Speaker volume restored: %u%%",
           static_cast<unsigned>(stored));
  return ESP_OK;
}

esp_err_t save_output_volume(BringupState *state, int volume_percent) {
  if (!state || volume_percent < 0 || volume_percent > 100 ||
      product_storage_require_ready() != ESP_OK) {
    return ESP_ERR_INVALID_ARG;
  }
  nvs_handle_t settings = 0;
  esp_err_t error = nvs_open_from_partition(
      kSettingsNvsPartition, kSettingsNvsNamespace, NVS_READWRITE, &settings);
  if (error == ESP_OK) {
    error = nvs_set_u8(settings, kVolumeNvsKey,
                       static_cast<uint8_t>(volume_percent));
  }
  if (error == ESP_OK) {
    error = nvs_commit(settings);
  }
  if (settings) {
    nvs_close(settings);
  }
  return error;
}

int change_output_volume(BringupState *state, int delta) {
  const int current =
      state->output_volume_percent.load(std::memory_order_acquire);
  const int adjusted = std::max(0, std::min(100, current + delta));
  state->output_volume_percent.store(adjusted, std::memory_order_release);
  const esp_err_t error = save_output_volume(state, adjusted);
  if (error != ESP_OK) {
    ESP_LOGW(kTag, "Speaker volume save failed: %s", esp_err_to_name(error));
  }
  ESP_LOGI(kTag, "Speaker volume changed: %d%%", adjusted);
  return adjusted;
}

esp_err_t set_output_volume(void *ctx, uint8_t volume_percent) {
  auto *state = static_cast<BringupState *>(ctx);
  if (!state || volume_percent > 100) {
    return ESP_ERR_INVALID_ARG;
  }
  const esp_err_t error = save_output_volume(state, volume_percent);
  if (error != ESP_OK) {
    return error;
  }
  state->output_volume_percent.store(volume_percent, std::memory_order_release);
  state->voice_ui_dirty.store(true, std::memory_order_release);
  ESP_LOGI(kTag, "Agent set speaker volume: %u%%",
           static_cast<unsigned>(volume_percent));
  return ESP_OK;
}

int32_t scale_speaker_sample(int16_t sample, int volume_percent) {
  const int safe_volume = std::max(0, std::min(100, volume_percent));
  int64_t scaled = static_cast<int64_t>(sample) * safe_volume / 100;
  // The small enclosure benefits from additional mid-level speech energy at
  // high volume. A headroom-aware curve boosts quiet/mid samples while mapping
  // full scale to full scale, so 100% becomes louder without hard clipping.
  const int boost_percent =
      safe_volume > 70 ? (safe_volume - 70) * 70 / 30 : 0;
  const int64_t magnitude =
      scaled < 0 ? -scaled : scaled;
  const int64_t headroom = std::max<int64_t>(0, 32767 - magnitude);
  scaled += scaled * boost_percent * headroom / (100 * INT64_C(32767));
  scaled = std::max<int64_t>(-32768, std::min<int64_t>(32767, scaled));
  // The speaker I2S slot is 32-bit and the decoded PCM is signed 16-bit.
  // Align the PCM sign bit with bit 31 (the same full-scale mapping used by
  // XiaoZhi's NoAudioCodec).  Shifting by only 15 bits made the old "100%"
  // setting half-scale, approximately 6 dB quieter than the hardware allows.
  return static_cast<int32_t>(scaled * INT64_C(65536));
}

struct CloudHttpResponse {
  char *data = nullptr;
  size_t capacity = 0;
  size_t length = 0;
  bool overflow = false;
};

struct CloudBootstrapResult {
  bool activation_required = false;
  bool websocket_ready = false;
};

esp_err_t cloud_http_event(esp_http_client_event_t *event) {
  if (!event || !event->user_data) {
    return ESP_OK;
  }
  auto *response = static_cast<CloudHttpResponse *>(event->user_data);
  if (event->event_id != HTTP_EVENT_ON_DATA || !event->data ||
      event->data_len <= 0) {
    return ESP_OK;
  }
  const size_t received = static_cast<size_t>(event->data_len);
  if (!response->data || response->capacity == 0 ||
      received > response->capacity - 1 - response->length) {
    response->overflow = true;
    return ESP_OK;
  }
  std::memcpy(response->data + response->length, event->data, received);
  response->length += received;
  response->data[response->length] = '\0';
  return ESP_OK;
}

void format_cloud_identity(char *mac_text, size_t mac_size, char *uuid_text,
                           size_t uuid_size) {
  uint8_t mac[6] = {};
  if (esp_read_mac(mac, ESP_MAC_WIFI_STA) != ESP_OK) {
    if (mac_text && mac_size) {
      mac_text[0] = '\0';
    }
    if (uuid_text && uuid_size) {
      uuid_text[0] = '\0';
    }
    return;
  }
  std::snprintf(mac_text, mac_size, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0],
                mac[1], mac[2], mac[3], mac[4], mac[5]);
  /* Keep the development identity deterministic across reflashes without
   * storing a cloud secret. This matches the identity used during the
   * preflight API compatibility probe for this physical sample. */
  std::snprintf(uuid_text, uuid_size,
                "%02x%02x%02x00-0000-4000-8000-"
                "%02x%02x%02x%02x%02x%02x",
                mac[3], mac[4], mac[5], mac[0], mac[1], mac[2], mac[3], mac[4],
                mac[5]);
}

esp_err_t build_cloud_system_info(char *output, size_t output_size,
                                  const char *mac, const char *uuid) {
  if (!output || output_size == 0 || !mac || !uuid || !mac[0] || !uuid[0]) {
    return ESP_ERR_INVALID_ARG;
  }
  uint32_t flash_size = 0;
  const esp_err_t flash_error = esp_flash_get_size(nullptr, &flash_size);
  esp_chip_info_t chip = {};
  esp_chip_info(&chip);
  const esp_app_desc_t *app = esp_app_get_description();
  if (flash_error != ESP_OK || !app) {
    return flash_error == ESP_OK ? ESP_FAIL : flash_error;
  }
  const int written = std::snprintf(
      output, output_size,
      "{\"version\":2,\"language\":\"zh-CN\","
      "\"flash_size\":%u,\"psram_size\":%u,"
      "\"minimum_free_heap_size\":%u,"
      "\"mac_address\":\"%s\",\"uuid\":\"%s\","
      "\"chip_model_name\":\"esp32s3\","
      "\"chip_info\":{\"model\":%d,\"cores\":%d,"
      "\"revision\":%d,\"features\":%u},"
      "\"application\":{\"name\":\"%s\",\"version\":\"%s\","
      "\"compile_time\":\"%sT%sZ\",\"idf_version\":\"%s\"},"
      "\"partition_table\":[],\"ota\":{\"label\":\"ota_0\"},"
      "\"display\":{\"monochrome\":false,\"width\":240,"
      "\"height\":320},"
      "\"board\":{\"type\":\"bread-compact-wifi-s3cam\","
      "\"name\":\"bread-compact-wifi-s3cam\",\"revision\":1}}",
      static_cast<unsigned>(flash_size),
      static_cast<unsigned>(heap_caps_get_total_size(MALLOC_CAP_SPIRAM)),
      static_cast<unsigned>(esp_get_minimum_free_heap_size()), mac, uuid,
      static_cast<int>(chip.model), chip.cores, chip.revision,
      static_cast<unsigned>(chip.features), app->project_name, app->version,
      app->date, app->time, app->idf_ver);
  return written >= 0 && static_cast<size_t>(written) < output_size
             ? ESP_OK
             : ESP_ERR_INVALID_SIZE;
}

esp_err_t cloud_post_json(const char *url, const char *payload,
                          char *response_data, size_t response_capacity,
                          int *status_code) {
  if (!url || !payload || !response_data || response_capacity < 2 ||
      !status_code) {
    return ESP_ERR_INVALID_ARG;
  }
  response_data[0] = '\0';
  CloudHttpResponse response = {
      .data = response_data,
      .capacity = response_capacity,
  };
  const bool secure_transport = std::strncmp(url, "https://", 8) == 0;
  const bool insecure_transport = std::strncmp(url, "http://", 7) == 0;
  if (!secure_transport &&
      !(kAllowInsecureVoiceGateway && insecure_transport)) {
    return ESP_ERR_NOT_SUPPORTED;
  }
  esp_http_client_config_t config = {};
  config.url = url;
  if (secure_transport) {
    config.tls_version = ESP_HTTP_CLIENT_TLS_VER_TLS_1_2;
    config.crt_bundle_attach = esp_crt_bundle_attach;
  }
  config.method = HTTP_METHOD_POST;
  config.timeout_ms = 15000;
  // Do not forward the prototype bootstrap credential through a redirect.
  config.disable_auto_redirect = true;
  config.max_redirection_count = 0;
  config.max_authorization_retries = -1;
  config.event_handler = cloud_http_event;
  config.buffer_size = 2048;
  config.buffer_size_tx = 2048;
  config.user_data = &response;
  config.keep_alive_enable = true;
  esp_http_client_handle_t client = esp_http_client_init(&config);
  if (!client) {
    return ESP_ERR_NO_MEM;
  }
  char mac[18] = {};
  char uuid[37] = {};
  format_cloud_identity(mac, sizeof(mac), uuid, sizeof(uuid));
  const esp_app_desc_t *app = esp_app_get_description();
  char user_agent[96] = {};
  char authorization[sizeof(kVoiceBootstrapToken) + 8] = {};
  std::snprintf(user_agent, sizeof(user_agent), "bread-compact-wifi-s3cam/%s",
                app ? app->version : "development");
  esp_err_t error = mac[0] && uuid[0] ? ESP_OK : ESP_FAIL;
  if (error == ESP_OK) {
    error = esp_http_client_set_header(client, "Activation-Version", "1");
  }
  if (error == ESP_OK) {
    error = esp_http_client_set_header(client, "Device-Id", mac);
  }
  if (error == ESP_OK) {
    error = esp_http_client_set_header(client, "Client-Id", uuid);
  }
  if (error == ESP_OK) {
    error = esp_http_client_set_header(client, "User-Agent", user_agent);
  }
  if (error == ESP_OK) {
    error = esp_http_client_set_header(client, "Accept-Language", "zh-CN");
  }
  if (error == ESP_OK) {
    error =
        esp_http_client_set_header(client, "Content-Type", "application/json");
  }
  if (error == ESP_OK && kVoiceBootstrapToken[0]) {
    std::snprintf(authorization, sizeof(authorization), "Bearer %s",
                  kVoiceBootstrapToken);
    error = esp_http_client_set_header(client, "Authorization", authorization);
  }
  if (error == ESP_OK) {
    error = esp_http_client_set_post_field(
        client, payload, static_cast<int>(std::strlen(payload)));
  }
  if (error == ESP_OK) {
    error = esp_http_client_perform(client);
  }
  *status_code = esp_http_client_get_status_code(client);
  esp_http_client_cleanup(client);
  secure_clear(authorization, sizeof(authorization));
  if (response.overflow) {
    return ESP_ERR_INVALID_SIZE;
  }
  return error;
}

bool copy_json_string(cJSON *object, const char *key, char *output,
                      size_t output_size) {
  cJSON *value = cJSON_GetObjectItemCaseSensitive(object, key);
  if (!cJSON_IsString(value) || !value->valuestring || !output ||
      output_size == 0) {
    return false;
  }
  const size_t length = std::strlen(value->valuestring);
  if (length >= output_size) {
    return false;
  }
  std::memcpy(output, value->valuestring, length + 1);
  return true;
}

esp_err_t parse_cloud_bootstrap(BringupState *state, const char *json,
                                CloudBootstrapResult *result) {
  if (!state || !json || !result) {
    return ESP_ERR_INVALID_ARG;
  }
  cJSON *root = cJSON_Parse(json);
  if (!root) {
    return ESP_ERR_INVALID_RESPONSE;
  }
  CloudBootstrapResult parsed = {};
  char next_code[sizeof(state->activation_code)] = {};
  char next_url[sizeof(state->websocket_url)] = {};
  char next_token[sizeof(state->websocket_token)] = {};
  cJSON *activation = cJSON_GetObjectItemCaseSensitive(root, "activation");
  cJSON *challenge =
      cJSON_IsObject(activation)
          ? cJSON_GetObjectItemCaseSensitive(activation, "challenge")
          : nullptr;
  if (cJSON_IsString(challenge) && challenge->valuestring &&
      challenge->valuestring[0]) {
    parsed.activation_required = true;
    (void)copy_json_string(activation, "code", next_code, sizeof(next_code));
  }
  cJSON *websocket = cJSON_GetObjectItemCaseSensitive(root, "websocket");
  parsed.websocket_ready =
      cJSON_IsObject(websocket) &&
      copy_json_string(websocket, "url", next_url, sizeof(next_url)) &&
      copy_json_string(websocket, "token", next_token, sizeof(next_token));
  const bool valid = parsed.activation_required || parsed.websocket_ready;
  if (valid) {
    std::snprintf(state->activation_code, sizeof(state->activation_code), "%s",
                  next_code);
    std::snprintf(state->websocket_url, sizeof(state->websocket_url), "%s",
                  next_url);
    secure_clear(state->websocket_token, sizeof(state->websocket_token));
    std::snprintf(state->websocket_token, sizeof(state->websocket_token), "%s",
                  next_token);
    *result = parsed;
  }
  secure_clear(next_token, sizeof(next_token));
  cJSON_Delete(root);
  return valid ? ESP_OK : ESP_ERR_INVALID_RESPONSE;
}

esp_err_t fetch_cloud_bootstrap(BringupState *state,
                                CloudBootstrapResult *result) {
  if (!state || !result) {
    return ESP_ERR_INVALID_ARG;
  }
  char mac[18] = {};
  char uuid[37] = {};
  char payload[1400] = {};
  format_cloud_identity(mac, sizeof(mac), uuid, sizeof(uuid));
  esp_err_t error =
      build_cloud_system_info(payload, sizeof(payload), mac, uuid);
  auto *response = static_cast<char *>(heap_caps_calloc(
      1, kCloudResponseCapacity, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
  if (!response) {
    response = static_cast<char *>(
        heap_caps_calloc(1, kCloudResponseCapacity, MALLOC_CAP_8BIT));
  }
  int status_code = 0;
  if (error == ESP_OK && !response) {
    error = ESP_ERR_NO_MEM;
  }
  if (error == ESP_OK) {
    error = cloud_post_json(kVoiceBootstrapUrl, payload, response,
                            kCloudResponseCapacity, &status_code);
  }
  if (error == ESP_OK && status_code != 200) {
    error = ESP_FAIL;
  }
  if (error == ESP_OK) {
    error = parse_cloud_bootstrap(state, response, result);
  }
  secure_clear(payload, sizeof(payload));
  if (response) {
    secure_clear(response, kCloudResponseCapacity);
    heap_caps_free(response);
  }
  return error;
}

esp_err_t poll_cloud_activation(int *status_code) {
  if (!status_code) {
    return ESP_ERR_INVALID_ARG;
  }
  char url[sizeof(kVoiceBootstrapUrl) + 16] = {};
  std::snprintf(url, sizeof(url), "%sactivate", kVoiceBootstrapUrl);
  char response[512] = {};
  const esp_err_t error =
      cloud_post_json(url, "{}", response, sizeof(response), status_code);
  secure_clear(response, sizeof(response));
  return error;
}

void set_cloud_stage(BringupState *state, CloudStage stage,
                     esp_err_t error = ESP_OK) {
  state->cloud_last_error.store(error, std::memory_order_release);
  state->cloud_stage.store(static_cast<int>(stage), std::memory_order_release);
  state->cloud_ui_dirty.store(true, std::memory_order_release);
}

void cloud_bootstrap_task(void *argument) {
  auto *state = static_cast<BringupState *>(argument);
  esp_err_t final_error = ESP_OK;
  for (;;) {
    if (!state->wifi_online.load(std::memory_order_acquire)) {
      set_cloud_stage(state, CloudStage::kOff);
      break;
    }
    set_cloud_stage(state, CloudStage::kFetching);
    CloudBootstrapResult result = {};
    final_error = fetch_cloud_bootstrap(state, &result);
    if (final_error != ESP_OK) {
      ESP_LOGE(kTag, "XiaoZhi bootstrap failed: %s",
               esp_err_to_name(final_error));
      set_cloud_stage(state, CloudStage::kError, final_error);
      break;
    }
    if (!result.activation_required) {
      if (!result.websocket_ready) {
        final_error = ESP_ERR_INVALID_RESPONSE;
        set_cloud_stage(state, CloudStage::kError, final_error);
        break;
      }
      ESP_LOGI(kTag, "Configured voice Gateway is ready; WebSocket settings "
                     "held in RAM and secrets omitted from logs");
      set_cloud_stage(state, CloudStage::kReady);
      break;
    }

    ESP_LOGI(kTag,
             "XiaoZhi activation is waiting for user confirmation on "
             "xiaozhi.me; activation code is shown only on the device UI");
    set_cloud_stage(state, CloudStage::kNeedsActivation);
    bool activated = false;
    while (state->wifi_online.load(std::memory_order_acquire)) {
      int status_code = 0;
      final_error = poll_cloud_activation(&status_code);
      if (final_error == ESP_OK && status_code == 200) {
        activated = true;
        break;
      }
      if (final_error == ESP_OK && status_code == 202) {
        vTaskDelay(pdMS_TO_TICKS(3000));
        continue;
      }
      ESP_LOGW(kTag, "XiaoZhi activation poll deferred: transport=%s status=%d",
               esp_err_to_name(final_error), status_code);
      vTaskDelay(pdMS_TO_TICKS(10000));
    }
    if (!activated) {
      set_cloud_stage(state, CloudStage::kOff);
      break;
    }
    set_cloud_stage(state, CloudStage::kActivating);
    /* A fresh bootstrap response after activation supplies the durable
     * connection configuration and no longer includes an activation
     * challenge. */
  }
  state->cloud_retry_after_us =
      final_error == ESP_OK ? 0 : esp_timer_get_time() + kCloudRetryDelayUs;
  state->cloud_task = nullptr;
  vTaskDelete(nullptr);
}

void set_voice_stage(BringupState *state, VoiceStage stage,
                     esp_err_t error = ESP_OK) {
  if (!state) {
    return;
  }
  state->voice_last_error.store(error, std::memory_order_release);
  const int previous =
      state->voice_stage.load(std::memory_order_acquire);
  if (previous != static_cast<int>(stage)) {
    state->voice_stage_since_us.store(esp_timer_get_time(),
                                      std::memory_order_release);
  }
  state->voice_stage.store(static_cast<int>(stage), std::memory_order_release);
  state->voice_ui_dirty.store(true, std::memory_order_release);
}

int voice_send_text(BringupState *state, const char *text) {
  if (!state || !state->voice_websocket || !text ||
      !state->voice_ws_connected.load(std::memory_order_acquire)) {
    return -1;
  }
  return esp_websocket_client_send_text(state->voice_websocket, text,
                                        static_cast<int>(std::strlen(text)),
                                        pdMS_TO_TICKS(kVoiceSendTimeoutMs));
}

bool valid_image_request_id(const char *value) {
  constexpr char kPrefix[] = "image-";
  if (!value || std::strlen(value) != 38 ||
      std::strncmp(value, kPrefix, sizeof(kPrefix) - 1) != 0) {
    return false;
  }
  for (size_t index = sizeof(kPrefix) - 1; value[index]; ++index) {
    const char character = value[index];
    if (!((character >= '0' && character <= '9') ||
          (character >= 'a' && character <= 'f'))) {
      return false;
    }
  }
  return true;
}

int voice_send_image_control(BringupState *state, const char *request_id,
                             const char *image_state, size_t byte_count = 0) {
  if (!state || !valid_image_request_id(request_id) || !image_state) {
    return -1;
  }
  cJSON *envelope = cJSON_CreateObject();
  if (!envelope) {
    return -1;
  }
  cJSON_AddStringToObject(envelope, "session_id", state->voice_session_id);
  cJSON_AddStringToObject(envelope, "type", "image");
  cJSON_AddStringToObject(envelope, "state", image_state);
  cJSON_AddStringToObject(envelope, "request_id", request_id);
  if (std::strcmp(image_state, "begin") == 0) {
    cJSON_AddStringToObject(envelope, "format", "yuyv422");
    cJSON_AddNumberToObject(
        envelope, "width",
        state->camera_width.load(std::memory_order_acquire));
    cJSON_AddNumberToObject(
        envelope, "height",
        state->camera_height.load(std::memory_order_acquire));
    cJSON_AddNumberToObject(envelope, "bytes", byte_count);
  }
  char *json = cJSON_PrintUnformatted(envelope);
  const int result = json ? voice_send_text(state, json) : -1;
  if (json) {
    cJSON_free(json);
  }
  cJSON_Delete(envelope);
  return result;
}

void voice_send_mcp_payload(BringupState *state, cJSON *payload) {
  if (!state || !payload) {
    return;
  }
  cJSON *envelope = cJSON_CreateObject();
  if (!envelope) {
    return;
  }
  if (state->voice_session_id[0]) {
    cJSON_AddStringToObject(envelope, "session_id", state->voice_session_id);
  }
  cJSON_AddStringToObject(envelope, "type", "mcp");
  cJSON_AddItemToObject(envelope, "payload", payload);
  char *json = cJSON_PrintUnformatted(envelope);
  if (json) {
    if (voice_send_text(state, json) <= 0) {
      ESP_LOGW(kTag, "MCP response send failed");
    }
    cJSON_free(json);
  }
  /* Deletes payload as an owned child. */
  cJSON_Delete(envelope);
}

void voice_mcp_error(BringupState *state, const cJSON *id, int code,
                     const char *message) {
  cJSON *payload = cJSON_CreateObject();
  if (!payload) {
    return;
  }
  cJSON_AddStringToObject(payload, "jsonrpc", "2.0");
  if (id) {
    cJSON_AddItemToObject(payload, "id", cJSON_Duplicate(id, true));
  }
  cJSON *error = cJSON_AddObjectToObject(payload, "error");
  cJSON_AddNumberToObject(error, "code", code);
  cJSON_AddStringToObject(error, "message", message);
  voice_send_mcp_payload(state, payload);
}

bool valid_consent_request_id(const char *value) {
  constexpr char kPrefix[] = "consent-";
  if (!value || std::strlen(value) != 40 ||
      std::strncmp(value, kPrefix, sizeof(kPrefix) - 1) != 0) {
    return false;
  }
  for (size_t index = sizeof(kPrefix) - 1; value[index]; ++index) {
    const char character = value[index];
    if (!((character >= '0' && character <= '9') ||
          (character >= 'a' && character <= 'f'))) {
      return false;
    }
  }
  return true;
}

bool valid_consent_summary(const char *value) {
  if (!value) {
    return false;
  }
  const size_t length = std::strlen(value);
  if (length == 0 || length >= sizeof(s_state.pending_consent_summary)) {
    return false;
  }
  for (size_t index = 0; index < length; ++index) {
    const unsigned char character = static_cast<unsigned char>(value[index]);
    if (character < 0x20 || character > 0x7e) {
      return false;
    }
  }
  return true;
}

void voice_send_consent_decision(BringupState *state, const char *request_id,
                                 const char *decision) {
  if (!state || !valid_consent_request_id(request_id) || !decision) {
    return;
  }
  cJSON *response = cJSON_CreateObject();
  if (!response) {
    return;
  }
  cJSON_AddStringToObject(response, "session_id", state->voice_session_id);
  cJSON_AddStringToObject(response, "type", "consent");
  cJSON_AddStringToObject(response, "state", decision);
  cJSON_AddStringToObject(response, "request_id", request_id);
  char *json = cJSON_PrintUnformatted(response);
  if (json) {
    (void)voice_send_text(state, json);
    cJSON_free(json);
  }
  cJSON_Delete(response);
}

void handle_voice_consent_request(BringupState *state, cJSON *root) {
  if (!state || !cJSON_IsObject(root)) {
    return;
  }
  cJSON *request_id = cJSON_GetObjectItemCaseSensitive(root, "request_id");
  cJSON *tool = cJSON_GetObjectItemCaseSensitive(root, "tool");
  cJSON *summary = cJSON_GetObjectItemCaseSensitive(root, "summary");
  cJSON *arguments = cJSON_GetObjectItemCaseSensitive(root, "arguments");
  cJSON *expires_in = cJSON_GetObjectItemCaseSensitive(root, "expires_in");
  if (!cJSON_IsString(request_id) ||
      !valid_consent_request_id(request_id->valuestring) ||
      !cJSON_IsString(tool) || !tool->valuestring || !cJSON_IsString(summary) ||
      !valid_consent_summary(summary->valuestring) ||
      !cJSON_IsObject(arguments) || !cJSON_IsNumber(expires_in) ||
      expires_in->valueint < 1 || expires_in->valueint > 20 ||
      expires_in->valuedouble != expires_in->valueint) {
    return;
  }

  ConsentKind kind = ConsentKind::kNone;
  int value = 0;
  bool flag = false;
  if (std::strcmp(tool->valuestring, "device.set_volume") == 0) {
    cJSON *level = cJSON_GetObjectItemCaseSensitive(arguments, "level");
    if (cJSON_GetArraySize(arguments) != 1 || !cJSON_IsNumber(level) ||
        level->valueint < 0 || level->valueint > 100 ||
        level->valuedouble != level->valueint) {
      return;
    }
    kind = ConsentKind::kDeviceVolume;
    value = level->valueint;
  } else if (std::strcmp(tool->valuestring, "device.set_indicator") == 0) {
    cJSON *on = cJSON_GetObjectItemCaseSensitive(arguments, "on");
    if (cJSON_GetArraySize(arguments) != 1 || !cJSON_IsBool(on)) {
      return;
    }
    kind = ConsentKind::kDeviceIndicator;
    flag = cJSON_IsTrue(on);
  } else if (std::strcmp(tool->valuestring, "camera.capture") == 0) {
    if (cJSON_GetArraySize(arguments) != 0) {
      return;
    }
    kind = ConsentKind::kCamera;
  } else if (std::strcmp(tool->valuestring, "memory.remember") == 0 ||
             std::strcmp(tool->valuestring, "memory.forget") == 0) {
    kind = ConsentKind::kMemory;
  } else if (std::strcmp(tool->valuestring, "speaker.identity.enroll") == 0 ||
             std::strcmp(tool->valuestring, "speaker.identity.forget") == 0) {
    // Speaker identity is a biometric personalization feature.  It may only
    // proceed after the same explicit physical confirmation as other voice
    // profile operations; voice content alone is never approval.
    kind = ConsentKind::kVoice;
  } else if (std::strcmp(tool->valuestring, "voice.clone") == 0 ||
             std::strcmp(tool->valuestring, "voice.delete") == 0 ||
             std::strcmp(tool->valuestring, "voice.activate") == 0) {
    kind = ConsentKind::kVoice;
  } else {
    return;
  }

  if (state->consent_pending.load(std::memory_order_acquire) ||
      (state->physical_consent.load(std::memory_order_acquire) &&
       esp_timer_get_time() <= state->approved_consent_expires_us)) {
    voice_send_consent_decision(state, request_id->valuestring, "denied");
    return;
  }
  std::snprintf(state->pending_consent_request_id,
                sizeof(state->pending_consent_request_id), "%s",
                request_id->valuestring);
  std::snprintf(state->pending_consent_summary,
                sizeof(state->pending_consent_summary), "%s",
                summary->valuestring);
  state->pending_consent_kind.store(static_cast<int>(kind),
                                    std::memory_order_relaxed);
  state->pending_consent_value.store(value, std::memory_order_relaxed);
  state->pending_consent_flag.store(flag, std::memory_order_relaxed);
  state->pending_consent_expires_us =
      esp_timer_get_time() +
      static_cast<int64_t>(expires_in->valueint) * 1000 * 1000;
  state->consent_pending.store(true, std::memory_order_release);
  state->consent_ui_dirty.store(true, std::memory_order_release);
  ESP_LOGI(kTag, "Agent confirmation requested for approved tool class");
}

void handle_voice_mcp(BringupState *state, cJSON *payload) {
  if (!state || !cJSON_IsObject(payload)) {
    return;
  }
  cJSON *method = cJSON_GetObjectItemCaseSensitive(payload, "method");
  cJSON *id = cJSON_GetObjectItemCaseSensitive(payload, "id");
  if (!cJSON_IsString(method) || !method->valuestring) {
    return;
  }
  if (std::strcmp(method->valuestring, "notifications/initialized") == 0) {
    return;
  }
  if (!id) {
    return;
  }
  cJSON *response = cJSON_CreateObject();
  if (!response) {
    return;
  }
  cJSON_AddStringToObject(response, "jsonrpc", "2.0");
  cJSON_AddItemToObject(response, "id", cJSON_Duplicate(id, true));

  if (std::strcmp(method->valuestring, "initialize") == 0) {
    cJSON *result = cJSON_AddObjectToObject(response, "result");
    cJSON_AddStringToObject(result, "protocolVersion", "2024-11-05");
    cJSON *capabilities = cJSON_AddObjectToObject(result, "capabilities");
    cJSON_AddObjectToObject(capabilities, "tools");
    cJSON *server = cJSON_AddObjectToObject(result, "serverInfo");
    cJSON_AddStringToObject(server, "name", "xiaozhi-esp-claw-s3cam");
    cJSON_AddStringToObject(server, "version", "0.20.0");
    voice_send_mcp_payload(state, response);
    return;
  }
  if (std::strcmp(method->valuestring, "tools/list") == 0) {
    cJSON *result = cJSON_AddObjectToObject(response, "result");
    cJSON *tools = cJSON_AddArrayToObject(result, "tools");
    cJSON *tool = cJSON_CreateObject();
    cJSON_AddStringToObject(tool, "name", "device.get_status");
    cJSON_AddStringToObject(
        tool, "description",
        "Read the ESP32 camera, microphone, speaker, Wi-Fi and ESP-Claw "
        "status. This tool never changes device state.");
    cJSON *schema = cJSON_AddObjectToObject(tool, "inputSchema");
    cJSON_AddStringToObject(schema, "type", "object");
    cJSON_AddObjectToObject(schema, "properties");
    cJSON_AddBoolToObject(schema, "additionalProperties", false);
    cJSON_AddItemToArray(tools, tool);

    tool = cJSON_CreateObject();
    cJSON_AddStringToObject(tool, "name", "device.set_volume");
    cJSON_AddStringToObject(tool, "description",
                            "Set speaker output volume after an exact physical "
                            "confirmation on this ESP32.");
    schema = cJSON_AddObjectToObject(tool, "inputSchema");
    cJSON_AddStringToObject(schema, "type", "object");
    cJSON *properties = cJSON_AddObjectToObject(schema, "properties");
    cJSON *level = cJSON_AddObjectToObject(properties, "level");
    cJSON_AddStringToObject(level, "type", "integer");
    cJSON_AddNumberToObject(level, "minimum", 0);
    cJSON_AddNumberToObject(level, "maximum", 100);
    cJSON *required = cJSON_AddArrayToObject(schema, "required");
    cJSON_AddItemToArray(required, cJSON_CreateString("level"));
    cJSON_AddBoolToObject(schema, "additionalProperties", false);
    cJSON_AddItemToArray(tools, tool);

    tool = cJSON_CreateObject();
    cJSON_AddStringToObject(tool, "name", "device.set_indicator");
    cJSON_AddStringToObject(tool, "description",
                            "Turn the screen backlight on or off after an "
                            "exact physical confirmation on this ESP32.");
    schema = cJSON_AddObjectToObject(tool, "inputSchema");
    cJSON_AddStringToObject(schema, "type", "object");
    properties = cJSON_AddObjectToObject(schema, "properties");
    cJSON *on = cJSON_AddObjectToObject(properties, "on");
    cJSON_AddStringToObject(on, "type", "boolean");
    required = cJSON_AddArrayToObject(schema, "required");
    cJSON_AddItemToArray(required, cJSON_CreateString("on"));
    cJSON_AddBoolToObject(schema, "additionalProperties", false);
    cJSON_AddItemToArray(tools, tool);

    tool = cJSON_CreateObject();
    cJSON_AddStringToObject(tool, "name", "camera.capture");
    cJSON_AddStringToObject(
        tool, "description",
        "Capture the current 320x240 camera frame only after the user "
        "physically approves the live preview on this ESP32.");
    schema = cJSON_AddObjectToObject(tool, "inputSchema");
    cJSON_AddStringToObject(schema, "type", "object");
    properties = cJSON_AddObjectToObject(schema, "properties");
    cJSON *image_request_id = cJSON_AddObjectToObject(properties, "request_id");
    cJSON_AddStringToObject(image_request_id, "type", "string");
    cJSON_AddNumberToObject(image_request_id, "minLength", 38);
    cJSON_AddNumberToObject(image_request_id, "maxLength", 38);
    required = cJSON_AddArrayToObject(schema, "required");
    cJSON_AddItemToArray(required, cJSON_CreateString("request_id"));
    cJSON_AddBoolToObject(schema, "additionalProperties", false);
    cJSON_AddItemToArray(tools, tool);
    cJSON_AddStringToObject(result, "nextCursor", "");
    voice_send_mcp_payload(state, response);
    return;
  }
  if (std::strcmp(method->valuestring, "tools/call") == 0) {
    cJSON *params = cJSON_GetObjectItemCaseSensitive(payload, "params");
    cJSON *name = cJSON_IsObject(params)
                      ? cJSON_GetObjectItemCaseSensitive(params, "name")
                      : nullptr;
    cJSON *arguments =
        cJSON_IsObject(params)
            ? cJSON_GetObjectItemCaseSensitive(params, "arguments")
            : nullptr;
    const bool supported =
        cJSON_IsString(name) && name->valuestring &&
        (std::strcmp(name->valuestring, "device.get_status") == 0 ||
         std::strcmp(name->valuestring, "device.set_volume") == 0 ||
         std::strcmp(name->valuestring, "device.set_indicator") == 0 ||
         std::strcmp(name->valuestring, "camera.capture") == 0);
    if (!supported || !cJSON_IsObject(arguments)) {
      cJSON_Delete(response);
      voice_mcp_error(state, id, -32601,
                      "Tool is not in the ESP32 capability allowlist");
      return;
    }
    const bool camera_capture =
        std::strcmp(name->valuestring, "camera.capture") == 0;
    char *input = cJSON_PrintUnformatted(arguments);
    if (!input || std::strlen(input) > 192) {
      if (input) {
        cJSON_free(input);
      }
      cJSON_Delete(response);
      voice_mcp_error(state, id, -32602, "Invalid tool arguments");
      return;
    }
    char output[512] = {};
    esp_err_t error = ESP_OK;
    if (camera_capture) {
      cJSON *request_id =
          cJSON_GetObjectItemCaseSensitive(arguments, "request_id");
      const auto approved = static_cast<ConsentKind>(
          state->approved_consent_kind.load(std::memory_order_acquire));
      bool expected = true;
      const bool exact_approval =
          cJSON_GetArraySize(arguments) == 1 && cJSON_IsString(request_id) &&
          valid_image_request_id(request_id->valuestring) &&
          approved == ConsentKind::kCamera &&
          esp_timer_get_time() <= state->approved_consent_expires_us &&
          state->physical_consent.compare_exchange_strong(
              expected, false, std::memory_order_acq_rel,
              std::memory_order_acquire);
      if (!exact_approval) {
        error = ESP_ERR_INVALID_STATE;
      } else {
        error = capture_and_upload_camera_frame(
            state, request_id->valuestring, output, sizeof(output));
      }
    } else {
      error = esp_claw_runtime_call_local_capability(
          state->claw, next_request_id(state),
          std::strcmp(name->valuestring, "device.get_status") == 0
              ? "xiaozhi-mcp"
              : "s3cam-agent-confirmed",
          name->valuestring, input, output, sizeof(output));
    }
    cJSON_free(input);
    if (std::strcmp(name->valuestring, "device.get_status") != 0) {
      state->physical_consent.store(false, std::memory_order_release);
      state->approved_consent_kind.store(static_cast<int>(ConsentKind::kNone),
                                         std::memory_order_release);
    }
    cJSON *result = cJSON_AddObjectToObject(response, "result");
    cJSON *content = cJSON_AddArrayToObject(result, "content");
    cJSON *text = cJSON_CreateObject();
    cJSON_AddStringToObject(text, "type", "text");
    cJSON_AddStringToObject(
        text, "text", error == ESP_OK ? output : "Device action unavailable");
    cJSON_AddItemToArray(content, text);
    cJSON_AddBoolToObject(result, "isError", error != ESP_OK);
    voice_send_mcp_payload(state, response);
    ESP_LOGI(kTag, "XiaoZhi MCP allowlisted ESP-Claw call %s: %s",
             name->valuestring, esp_err_to_name(error));
    return;
  }
  cJSON_Delete(response);
  voice_mcp_error(state, id, -32601, "Method not found");
}

void handle_voice_text(BringupState *state, const char *data, size_t length) {
  cJSON *root = cJSON_ParseWithLength(data, length);
  if (!root) {
    ESP_LOGW(kTag, "Ignored malformed voice control message");
    return;
  }
  cJSON *type = cJSON_GetObjectItemCaseSensitive(root, "type");
  if (!cJSON_IsString(type) || !type->valuestring) {
    cJSON_Delete(root);
    return;
  }
  if (std::strcmp(type->valuestring, "hello") == 0) {
    cJSON *transport = cJSON_GetObjectItemCaseSensitive(root, "transport");
    cJSON *session = cJSON_GetObjectItemCaseSensitive(root, "session_id");
    cJSON *audio = cJSON_GetObjectItemCaseSensitive(root, "audio_params");
    cJSON *sample_rate =
        cJSON_IsObject(audio)
            ? cJSON_GetObjectItemCaseSensitive(audio, "sample_rate")
            : nullptr;
    const bool valid =
        cJSON_IsString(transport) &&
        std::strcmp(transport->valuestring, "websocket") == 0 &&
        cJSON_IsString(session) && session->valuestring &&
        std::strlen(session->valuestring) < sizeof(state->voice_session_id) &&
        (!cJSON_IsNumber(sample_rate) || sample_rate->valueint == 24000);
    if (valid) {
      std::snprintf(state->voice_session_id, sizeof(state->voice_session_id),
                    "%s", session->valuestring);
      set_voice_stage(state, VoiceStage::kReady);
      ESP_LOGI(kTag, "XiaoZhi WebSocket hello accepted; Opus 16 kHz uplink / "
                     "24 kHz downlink ready");
    } else {
      set_voice_stage(state, VoiceStage::kError, ESP_ERR_INVALID_RESPONSE);
    }
  } else if (std::strcmp(type->valuestring, "stt") == 0) {
    set_voice_stage(state, VoiceStage::kThinking);
    ESP_LOGI(kTag, "Voice transcription received (content omitted)");
  } else if (std::strcmp(type->valuestring, "listen") == 0) {
    cJSON *listen_state = cJSON_GetObjectItemCaseSensitive(root, "state");
    if (cJSON_IsString(listen_state) && listen_state->valuestring &&
        std::strcmp(listen_state->valuestring, "stop") == 0 &&
        static_cast<VoiceStage>(state->voice_stage.load(
            std::memory_order_acquire)) == VoiceStage::kListening) {
      set_voice_stage(state, VoiceStage::kThinking);
      ESP_LOGI(kTag, "Gateway captured the voice window; uplink stopped");
    }
  } else if (std::strcmp(type->valuestring, "tts") == 0) {
    cJSON *tts_state = cJSON_GetObjectItemCaseSensitive(root, "state");
    if (cJSON_IsString(tts_state) && tts_state->valuestring) {
      if (std::strcmp(tts_state->valuestring, "start") == 0) {
        state->voice_playback_drain_requested.store(
            false, std::memory_order_release);
        set_voice_stage(state, VoiceStage::kSpeaking);
      } else if (std::strcmp(tts_state->valuestring, "drain") == 0) {
        state->voice_playback_drain_requested.store(
            true, std::memory_order_release);
      } else if (std::strcmp(tts_state->valuestring, "stop") == 0) {
        state->voice_playback_drain_requested.store(
            false, std::memory_order_release);
        set_voice_stage(state, VoiceStage::kReady);
      } else if (std::strcmp(tts_state->valuestring, "error") == 0) {
        state->voice_playback_drain_requested.store(
            false, std::memory_order_release);
        set_voice_stage(state, VoiceStage::kError, ESP_FAIL);
      }
    }
  } else if (std::strcmp(type->valuestring, "mcp") == 0) {
    handle_voice_mcp(state, cJSON_GetObjectItemCaseSensitive(root, "payload"));
  } else if (std::strcmp(type->valuestring, "consent") == 0) {
    cJSON *consent_state = cJSON_GetObjectItemCaseSensitive(root, "state");
    if (cJSON_IsString(consent_state) && consent_state->valuestring &&
        std::strcmp(consent_state->valuestring, "request") == 0) {
      handle_voice_consent_request(state, root);
    }
  } else if (std::strcmp(type->valuestring, "voice_enrollment") == 0) {
    cJSON *enrollment_state = cJSON_GetObjectItemCaseSensitive(root, "state");
    cJSON *code = cJSON_GetObjectItemCaseSensitive(root, "code");
    bool valid_code = cJSON_IsString(code) && code->valuestring &&
                      std::strlen(code->valuestring) == 6;
    for (size_t index = 0; valid_code && index < 6; ++index) {
      valid_code =
          code->valuestring[index] >= '0' && code->valuestring[index] <= '9';
    }
    if (cJSON_IsString(enrollment_state) &&
        std::strcmp(enrollment_state->valuestring, "ready") == 0 &&
        valid_code) {
      std::snprintf(state->voice_enrollment_code,
                    sizeof(state->voice_enrollment_code), "%s",
                    code->valuestring);
      state->voice_enrollment_ui_dirty.store(true, std::memory_order_release);
    }
  } else if (std::strcmp(type->valuestring, "error") == 0) {
    set_voice_stage(state, VoiceStage::kError, ESP_FAIL);
  }
  cJSON_Delete(root);
}

void voice_websocket_event(void *handler_args, esp_event_base_t,
                           int32_t event_id, void *event_data) {
  auto *state = static_cast<BringupState *>(handler_args);
  auto *data = static_cast<esp_websocket_event_data_t *>(event_data);
  if (!state) {
    return;
  }
  if (event_id == WEBSOCKET_EVENT_CONNECTED) {
    state->voice_ws_connected.store(true, std::memory_order_release);
    state->voice_ui_dirty.store(true, std::memory_order_release);
    return;
  }
  if (event_id == WEBSOCKET_EVENT_DISCONNECTED) {
    state->voice_ws_connected.store(false, std::memory_order_release);
    set_voice_stage(state, VoiceStage::kError, ESP_ERR_INVALID_STATE);
    return;
  }
  if (event_id == WEBSOCKET_EVENT_ERROR) {
    const esp_err_t error = data && data->error_handle.esp_tls_last_esp_err
                                ? data->error_handle.esp_tls_last_esp_err
                                : ESP_FAIL;
    set_voice_stage(state, VoiceStage::kError, error);
    return;
  }
  if (event_id != WEBSOCKET_EVENT_DATA || !data || !data->data_ptr ||
      data->data_len <= 0) {
    return;
  }
  const size_t chunk = static_cast<size_t>(data->data_len);
  const size_t total = static_cast<size_t>(data->payload_len);
  const size_t offset = static_cast<size_t>(data->payload_offset);
  if (data->op_code == 0x2) {
    if (offset != 0 || chunk != total || total > kVoiceOpusCapacity) {
      ESP_LOGW(kTag, "Dropped oversized or fragmented Opus packet");
      return;
    }
    const auto stage = static_cast<VoiceStage>(
        state->voice_stage.load(std::memory_order_acquire));
    if (stage != VoiceStage::kThinking && stage != VoiceStage::kSpeaking) {
      // A cancelled provider request can still have frames in transit. Never
      // allow them to leak into a newer voice turn or play while the UI is
      // ready/listening.
      ESP_LOGD(kTag, "Dropped stale Opus packet outside active playback");
      return;
    }
    state->voice_last_audio_us.store(esp_timer_get_time(),
                                     std::memory_order_release);
    if (stage == VoiceStage::kThinking) {
      // Binary downlink is authoritative evidence that the reply is ready.
      // This also recovers if the small preceding TTS control frame was lost.
      set_voice_stage(state, VoiceStage::kSpeaking);
    }
    VoiceAudioPacket packet = {};
    packet.length = total;
    std::memcpy(packet.data, data->data_ptr, total);
    if (!state->voice_audio_queue ||
        xQueueSend(state->voice_audio_queue, &packet, 0) != pdTRUE) {
      ESP_LOGW(kTag, "Dropped Opus packet because playback queue is full");
    }
    return;
  }
  if (total == 0 || total >= sizeof(state->voice_rx_text) ||
      offset + chunk > total ||
      offset + chunk >= sizeof(state->voice_rx_text)) {
    state->voice_rx_text_length = 0;
    return;
  }
  if (offset == 0) {
    state->voice_rx_text_length = 0;
  }
  if (offset != state->voice_rx_text_length) {
    state->voice_rx_text_length = 0;
    return;
  }
  std::memcpy(state->voice_rx_text + offset, data->data_ptr, chunk);
  state->voice_rx_text_length += chunk;
  if (state->voice_rx_text_length == total) {
    state->voice_rx_text[total] = '\0';
    // Playback completion is a transport control signal, not ordinary UI
    // text. Recognize it in the WebSocket callback before the small text
    // queue so a burst of sentence/status events can never delay or drop the
    // final drain request.
    if (std::strstr(state->voice_rx_text, "\"type\":\"tts\"") &&
        std::strstr(state->voice_rx_text, "\"state\":\"drain\"")) {
      state->voice_playback_drain_requested.store(
          true, std::memory_order_release);
    }
    VoiceTextPacket packet = {};
    packet.length = total;
    std::memcpy(packet.data, state->voice_rx_text, total);
    packet.data[total] = '\0';
    state->voice_rx_text_length = 0;
    if (!state->voice_text_queue ||
        xQueueSend(state->voice_text_queue, &packet, 0) != pdTRUE) {
      ESP_LOGW(kTag, "Dropped voice control message because queue is full");
    }
  }
}

esp_err_t initialize_voice_websocket(BringupState *state) {
  if (!state || !state->websocket_url[0] || !state->websocket_token[0]) {
    return ESP_ERR_INVALID_STATE;
  }
  const bool secure_transport =
      std::strncmp(state->websocket_url, "wss://", 6) == 0;
  const bool insecure_transport =
      std::strncmp(state->websocket_url, "ws://", 5) == 0;
  if (!secure_transport &&
      !(kAllowInsecureVoiceGateway && insecure_transport)) {
    return ESP_ERR_NOT_SUPPORTED;
  }
  esp_websocket_client_config_t config = {};
  config.uri = state->websocket_url;
  config.disable_auto_reconnect = true;
  config.user_context = state;
  config.task_prio = 5;
  config.task_name = "s3cam_voice_ws";
  config.task_stack = 8192;
  config.buffer_size = kVoiceTextCapacity;
  if (secure_transport) {
    config.crt_bundle_attach = esp_crt_bundle_attach;
    config.skip_cert_common_name_check = false;
  }
  config.keep_alive_enable = true;
  config.keep_alive_idle = 15;
  config.keep_alive_interval = 5;
  config.keep_alive_count = 3;
  config.network_timeout_ms = 30000;
  config.ping_interval_sec = 10;
  state->voice_websocket = esp_websocket_client_init(&config);
  if (!state->voice_websocket) {
    return ESP_ERR_NO_MEM;
  }
  char mac[18] = {};
  char uuid[37] = {};
  char authorization[sizeof(state->websocket_token) + 8] = {};
  format_cloud_identity(mac, sizeof(mac), uuid, sizeof(uuid));
  if (std::strchr(state->websocket_token, ' ')) {
    std::snprintf(authorization, sizeof(authorization), "%s",
                  state->websocket_token);
  } else {
    std::snprintf(authorization, sizeof(authorization), "Bearer %s",
                  state->websocket_token);
  }
  esp_err_t error = esp_websocket_client_append_header(
      state->voice_websocket, "Authorization", authorization);
  if (error == ESP_OK) {
    error = esp_websocket_client_append_header(state->voice_websocket,
                                               "Protocol-Version", "1");
  }
  if (error == ESP_OK) {
    error = esp_websocket_client_append_header(state->voice_websocket,
                                               "Device-Id", mac);
  }
  if (error == ESP_OK) {
    error = esp_websocket_client_append_header(state->voice_websocket,
                                               "Client-Id", uuid);
  }
  if (error == ESP_OK) {
    error = esp_websocket_register_events(state->voice_websocket,
                                          WEBSOCKET_EVENT_ANY,
                                          voice_websocket_event, state);
  }
  secure_clear(authorization, sizeof(authorization));
  if (error != ESP_OK) {
    esp_websocket_client_destroy(state->voice_websocket);
    state->voice_websocket = nullptr;
    return error;
  }
  return esp_websocket_client_start(state->voice_websocket);
}

esp_err_t initialize_voice_codecs(void **encoder, int *encoder_input_size,
                                  int *encoder_output_size, void **decoder) {
  if (!encoder || !encoder_input_size || !encoder_output_size || !decoder) {
    return ESP_ERR_INVALID_ARG;
  }
  esp_opus_enc_config_t encoder_config = {
      .sample_rate = 16000,
      .channel = ESP_AUDIO_MONO,
      .bits_per_sample = ESP_AUDIO_BIT16,
      .bitrate = ESP_OPUS_BITRATE_AUTO,
      .frame_duration = ESP_OPUS_ENC_FRAME_DURATION_60_MS,
      .application_mode = ESP_OPUS_ENC_APPLICATION_VOIP,
      .complexity = 2,
      .enable_fec = false,
      .enable_dtx = true,
      .enable_vbr = true,
  };
  if (esp_opus_enc_open(&encoder_config, sizeof(encoder_config), encoder) !=
          ESP_AUDIO_ERR_OK ||
      !*encoder ||
      esp_opus_enc_get_frame_size(*encoder, encoder_input_size,
                                  encoder_output_size) != ESP_AUDIO_ERR_OK ||
      *encoder_input_size !=
          kVoiceInputSamples * static_cast<int>(sizeof(int16_t)) ||
      *encoder_output_size > static_cast<int>(kVoiceOpusCapacity)) {
    if (*encoder) {
      esp_opus_enc_close(*encoder);
      *encoder = nullptr;
    }
    return ESP_ERR_NOT_SUPPORTED;
  }
  esp_opus_dec_cfg_t decoder_config = {
      .sample_rate = 24000,
      .channel = ESP_AUDIO_MONO,
      .frame_duration = ESP_OPUS_DEC_FRAME_DURATION_60_MS,
      .self_delimited = false,
  };
  if (esp_opus_dec_open(&decoder_config, sizeof(decoder_config), decoder) !=
          ESP_AUDIO_ERR_OK ||
      !*decoder) {
    esp_opus_enc_close(*encoder);
    *encoder = nullptr;
    return ESP_ERR_NOT_SUPPORTED;
  }
  return ESP_OK;
}

void voice_task(void *argument) {
  auto *state = static_cast<BringupState *>(argument);
  auto *buffers = static_cast<VoiceWorkBuffers *>(heap_caps_calloc(
      1, sizeof(VoiceWorkBuffers), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
  void *encoder = nullptr;
  void *decoder = nullptr;
  int encoder_input_size = 0;
  int encoder_output_size = 0;
  bool microphone_enabled = false;
  bool speaker_enabled = false;
  bool wifi_full_power = false;
  bool first_audio_frame_logged = false;
  bool playback_started = false;
  int playback_underrun_grace = 0;
  int capture_frames = 0;
  int consecutive_speech_frames = 0;
  int speech_frames_total = 0;
  int trailing_silence_frames = 0;
  uint32_t noise_floor = 0;
  uint32_t minimum_energy = UINT32_MAX;
  uint32_t maximum_energy = 0;
  bool speech_started = false;
  auto reset_endpointing = [&capture_frames, &consecutive_speech_frames,
                            &speech_frames_total, &trailing_silence_frames,
                            &noise_floor, &minimum_energy, &maximum_energy,
                            &speech_started]() {
    capture_frames = 0;
    consecutive_speech_frames = 0;
    speech_frames_total = 0;
    trailing_silence_frames = 0;
    noise_floor = 0;
    minimum_energy = UINT32_MAX;
    maximum_energy = 0;
    speech_started = false;
  };
  auto restore_wifi_power_save = [&wifi_full_power]() {
    if (wifi_full_power) {
      (void)esp_wifi_set_ps(WIFI_PS_MIN_MODEM);
      wifi_full_power = false;
    }
  };
  esp_err_t final_error =
      buffers ? initialize_voice_codecs(&encoder, &encoder_input_size,
                                        &encoder_output_size, &decoder)
              : ESP_ERR_NO_MEM;
  if (final_error == ESP_OK) {
    set_voice_stage(state, VoiceStage::kConnecting);
    final_error = initialize_voice_websocket(state);
  }
  if (final_error == ESP_OK) {
    const TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(15000);
    while (!state->voice_ws_connected.load(std::memory_order_acquire) &&
           xTaskGetTickCount() < deadline) {
      vTaskDelay(pdMS_TO_TICKS(50));
    }
    if (!state->voice_ws_connected.load(std::memory_order_acquire)) {
      final_error = ESP_ERR_TIMEOUT;
    }
  }
  constexpr char hello[] =
      "{\"type\":\"hello\",\"version\":1,\"features\":{\"mcp\":true},"
      "\"transport\":\"websocket\",\"audio_params\":{\"format\":\"opus\","
      "\"sample_rate\":16000,\"channels\":1,\"frame_duration\":60}}";
  if (final_error == ESP_OK && voice_send_text(state, hello) <= 0) {
    final_error = ESP_FAIL;
  }

  while (final_error == ESP_OK &&
         state->wifi_online.load(std::memory_order_acquire) &&
         static_cast<CloudStage>(state->cloud_stage.load(
             std::memory_order_acquire)) == CloudStage::kReady) {
    while (xQueueReceive(state->voice_text_queue, &buffers->text_packet, 0) ==
           pdTRUE) {
      handle_voice_text(state, buffers->text_packet.data,
                        buffers->text_packet.length);
    }
    auto stage = static_cast<VoiceStage>(
        state->voice_stage.load(std::memory_order_acquire));
    if (stage == VoiceStage::kError ||
        !state->voice_ws_connected.load(std::memory_order_acquire)) {
      final_error = state->voice_last_error.load(std::memory_order_acquire);
      if (final_error == ESP_OK) {
        final_error = ESP_FAIL;
      }
      break;
    }
    if (state->voice_listen_toggle.exchange(false, std::memory_order_acq_rel)) {
      char command[192] = {};
      if (stage == VoiceStage::kReady) {
        // Modem sleep can add enough latency on a weak or cross-border link to
        // exhaust the WebSocket write window. Keep Wi-Fi fully awake only for
        // the complete microphone, inference, and playback portion of a turn.
        if (esp_wifi_set_ps(WIFI_PS_NONE) == ESP_OK) {
          wifi_full_power = true;
        }
        // The previous answer may have a few decoded frames waiting when the
        // user starts quickly. A new turn is an explicit stale-audio boundary.
        xQueueReset(state->voice_audio_queue);
        playback_started = false;
        playback_underrun_grace = 0;
        state->voice_playback_drain_requested.store(
            false, std::memory_order_release);
        std::snprintf(command, sizeof(command),
                      "{\"session_id\":\"%s\",\"type\":\"listen\","
                      "\"state\":\"start\",\"mode\":\"auto\"}",
                      state->voice_session_id);
        if (voice_send_text(state, command) > 0) {
          reset_endpointing();
          set_voice_stage(state, VoiceStage::kListening);
          stage = VoiceStage::kListening;
        } else {
          restore_wifi_power_save();
        }
      } else if (stage == VoiceStage::kListening) {
        std::snprintf(command, sizeof(command),
                      "{\"session_id\":\"%s\",\"type\":\"listen\","
                      "\"state\":\"stop\"}",
                      state->voice_session_id);
        (void)voice_send_text(state, command);
        reset_endpointing();
        set_voice_stage(state, VoiceStage::kThinking);
        stage = VoiceStage::kThinking;
      } else if (stage == VoiceStage::kSpeaking) {
        std::snprintf(command, sizeof(command),
                      "{\"session_id\":\"%s\",\"type\":\"abort\"}",
                      state->voice_session_id);
        (void)voice_send_text(state, command);
        xQueueReset(state->voice_audio_queue);
        playback_started = false;
        playback_underrun_grace = 0;
        state->voice_playback_drain_requested.store(
            false, std::memory_order_release);
        set_voice_stage(state, VoiceStage::kReady);
        stage = VoiceStage::kReady;
      } else if (stage == VoiceStage::kThinking) {
        // Reconnecting is the only reliable cancellation boundary: it also
        // cancels an in-flight provider request at the Gateway.
        std::snprintf(command, sizeof(command),
                      "{\"session_id\":\"%s\",\"type\":\"abort\"}",
                      state->voice_session_id);
        (void)voice_send_text(state, command);
        final_error = ESP_ERR_TIMEOUT;
        break;
      }
    }

    stage = static_cast<VoiceStage>(
        state->voice_stage.load(std::memory_order_acquire));
    if (stage == VoiceStage::kListening) {
      if (!microphone_enabled) {
        final_error = i2s_channel_enable(state->microphone);
        microphone_enabled = final_error == ESP_OK;
        if (microphone_enabled) {
          // The microphone's first DMA window can arrive later than
          // steady-state frames after its clocks are restarted. The
          // hardware diagnostic already discards this window; do the
          // same before beginning the 60 ms Opus stream.
          constexpr size_t kWarmupSamples = 240;
          size_t warmup_bytes = 0;
          final_error = i2s_channel_read(
              state->microphone, buffers->microphone_raw,
              kWarmupSamples * sizeof(buffers->microphone_raw[0]),
              &warmup_bytes, pdMS_TO_TICKS(1000));
          if (final_error == ESP_OK &&
              warmup_bytes !=
                  kWarmupSamples * sizeof(buffers->microphone_raw[0])) {
            final_error = ESP_ERR_INVALID_SIZE;
          }
          if (final_error != ESP_OK) {
            ESP_LOGW(kTag, "Voice microphone warm-up failed: %s bytes=%u",
                     esp_err_to_name(final_error),
                     static_cast<unsigned>(warmup_bytes));
          }
        }
      }
      size_t bytes_read = 0;
      if (final_error == ESP_OK) {
        final_error = i2s_channel_read(
            state->microphone, buffers->microphone_raw,
            sizeof(buffers->microphone_raw), &bytes_read, pdMS_TO_TICKS(1000));
      }
      if (final_error == ESP_OK &&
          bytes_read == sizeof(buffers->microphone_raw)) {
        uint32_t peak = 0;
        uint64_t total = 0;
        for (int index = 0; index < kVoiceInputSamples; ++index) {
          const int32_t scaled = buffers->microphone_raw[index] >> 12;
          const int sample =
              std::max(-32768, std::min(32767, static_cast<int>(scaled)));
          buffers->microphone_pcm[index] = static_cast<int16_t>(sample);
          const uint32_t absolute = static_cast<uint32_t>(
              sample < 0 ? -static_cast<int64_t>(sample) : sample);
          peak = std::max(peak, absolute);
          total += absolute;
        }
        state->mic_peak.store(peak, std::memory_order_release);
        state->mic_mean_abs.store(
            static_cast<uint32_t>(total / kVoiceInputSamples),
            std::memory_order_release);
        state->voice_ui_dirty.store(true, std::memory_order_release);
        esp_audio_enc_in_frame_t input = {
            .buffer = reinterpret_cast<uint8_t *>(buffers->microphone_pcm),
            .len = static_cast<uint32_t>(encoder_input_size),
        };
        esp_audio_enc_out_frame_t output = {
            .buffer = buffers->encoded,
            .len = static_cast<uint32_t>(encoder_output_size),
            .encoded_bytes = 0,
            .pts = 0,
        };
        if (esp_opus_enc_process(encoder, &input, &output) !=
            ESP_AUDIO_ERR_OK) {
          final_error = ESP_FAIL;
        } else if (esp_websocket_client_send_bin(
                       state->voice_websocket,
                       reinterpret_cast<const char *>(buffers->encoded),
                       static_cast<int>(output.encoded_bytes),
                       pdMS_TO_TICKS(kVoiceSendTimeoutMs)) <= 0) {
          final_error = ESP_FAIL;
        } else {
          ++capture_frames;
          const uint32_t mean_abs =
              state->mic_mean_abs.load(std::memory_order_acquire);
          minimum_energy = std::min(minimum_energy, mean_abs);
          maximum_energy = std::max(maximum_energy, mean_abs);
          const bool past_warmup =
              capture_frames > kVoiceEndpointWarmupFrames;
          if (noise_floor == 0) {
            noise_floor = std::max<uint32_t>(1, mean_abs);
          } else if (!past_warmup) {
            // Use the quietest 60 ms window during the initial calibration.
            // A user may start speaking immediately after the button press;
            // averaging those first syllables into the baseline would make
            // the remainder of the command look like ambient noise.
            noise_floor = std::max<uint32_t>(
                1, std::min<uint32_t>(noise_floor, mean_abs));
          }
          const uint32_t speech_start_delta =
              std::max<uint32_t>(64, noise_floor / 6);
          // After speech has started, use a gentler continuation boundary so
          // quiet syllables and sentence endings do not look like silence.
          // Initial detection remains stricter to avoid ambient-noise starts.
          const uint32_t speech_continue_delta =
              std::max<uint32_t>(48, noise_floor / 8);
          const uint32_t speech_delta =
              speech_started ? speech_continue_delta : speech_start_delta;
          const bool energy_speech = mean_abs > noise_floor + speech_delta;
          // Opus packet length cannot be used as a VAD signal. With DTX/VBR,
          // steady microphone noise can still produce packets larger than a
          // nominal silence threshold and keep the turn open until the
          // 45-second safety limit. Endpoint only from calibrated PCM energy.
          const bool speech_frame = past_warmup && energy_speech;
          if (!speech_started && !speech_frame) {
            // Once calibration is complete, follow only readings that remain
            // below the speech boundary. A louder candidate frame must not
            // pull the baseline upward before it satisfies the consecutive
            // speech-frame requirement.
            if (past_warmup && mean_abs <= noise_floor + speech_delta) {
              noise_floor = std::max<uint32_t>(
                  1, (noise_floor * 15 + mean_abs) / 16);
            }
          }
          if (speech_frame) {
            ++consecutive_speech_frames;
            ++speech_frames_total;
            trailing_silence_frames = 0;
            if (!speech_started &&
                consecutive_speech_frames >= kVoiceSpeechStartFrames) {
              speech_started = true;
              ESP_LOGI(kTag, "Voice activity detected after %d frames",
                       capture_frames);
            }
          } else {
            consecutive_speech_frames = 0;
            if (speech_started) {
              ++trailing_silence_frames;
            }
          }

          const int trailing_silence_limit =
              capture_frames >= kVoiceLongCaptureFrames
                  ? kVoiceLongTrailingSilenceFrames
                  : capture_frames >= kVoiceMediumCaptureFrames
                        ? kVoiceMediumTrailingSilenceFrames
                        : kVoiceShortTrailingSilenceFrames;
          const bool reached_no_speech_deadline =
              !speech_started && capture_frames >= kVoiceNoSpeechFrames;
          const uint32_t fallback_delta = std::max<uint32_t>(
              128, minimum_energy == UINT32_MAX ? 128 : minimum_energy / 5);
          const bool fallback_activity =
              reached_no_speech_deadline && minimum_energy != UINT32_MAX &&
              maximum_energy > minimum_energy + fallback_delta;
          bool finish_turn = speech_started &&
                             trailing_silence_frames >=
                                 trailing_silence_limit;
          finish_turn = finish_turn || fallback_activity ||
                        capture_frames >= kVoiceMaximumCaptureFrames;
          const bool no_speech_timeout =
              reached_no_speech_deadline && !fallback_activity;
          if (finish_turn || no_speech_timeout) {
            char endpoint_command[192] = {};
            std::snprintf(endpoint_command, sizeof(endpoint_command),
                          "{\"session_id\":\"%s\",\"type\":\"%s\"%s}",
                          state->voice_session_id,
                          no_speech_timeout ? "abort" : "listen",
                          no_speech_timeout ? "" : ",\"state\":\"stop\"");
            if (voice_send_text(state, endpoint_command) <= 0) {
              final_error = ESP_FAIL;
            } else if (no_speech_timeout) {
              ESP_LOGI(kTag, "Voice turn cancelled after waiting for speech");
              set_voice_stage(state, VoiceStage::kReady);
              stage = VoiceStage::kReady;
            } else {
              if (fallback_activity) {
                ESP_LOGI(kTag,
                         "Voice activity fallback kept captured audio: "
                         "minimum=%u maximum=%u delta=%u",
                         static_cast<unsigned>(minimum_energy),
                         static_cast<unsigned>(maximum_energy),
                         static_cast<unsigned>(fallback_delta));
              }
              ESP_LOGI(kTag,
                       "Voice endpoint reached: frames=%d speech_frames=%d "
                       "silence=%d limit=%d noise=%u mean=%u peak=%u",
                       capture_frames, speech_frames_total,
                       trailing_silence_frames, trailing_silence_limit,
                       static_cast<unsigned>(noise_floor),
                       static_cast<unsigned>(mean_abs),
                       static_cast<unsigned>(peak));
              set_voice_stage(state, VoiceStage::kThinking);
              stage = VoiceStage::kThinking;
            }
            reset_endpointing();
          }
          if (!first_audio_frame_logged) {
            first_audio_frame_logged = true;
            ESP_LOGI(
                kTag,
                "Voice microphone streaming; task stack reserve=%u bytes",
                static_cast<unsigned>(uxTaskGetStackHighWaterMark(nullptr)));
          }
        }
      } else if (final_error == ESP_OK) {
        final_error = ESP_ERR_INVALID_SIZE;
      }
    } else if (microphone_enabled) {
      (void)i2s_channel_disable(state->microphone);
      microphone_enabled = false;
    }

    const UBaseType_t queued_audio =
        uxQueueMessagesWaiting(state->voice_audio_queue);
    const bool playback_drain_requested =
        state->voice_playback_drain_requested.load(std::memory_order_acquire);
    const UBaseType_t playback_threshold =
        playback_started ? kVoicePlaybackRebufferPackets
                         : kVoicePlaybackPrebufferPackets;
    const bool audio_ready =
        speaker_enabled || queued_audio >= playback_threshold ||
        (playback_drain_requested && queued_audio > 0) ||
        (stage != VoiceStage::kSpeaking && queued_audio > 0);
    if (audio_ready &&
        xQueueReceive(state->voice_audio_queue, &buffers->audio_packet,
                      stage == VoiceStage::kListening
                          ? 0
                          : pdMS_TO_TICKS(20)) == pdTRUE) {
      esp_audio_dec_in_raw_t raw = {
          .buffer = buffers->audio_packet.data,
          .len = static_cast<uint32_t>(buffers->audio_packet.length),
          .consumed = 0,
          .frame_recover = ESP_AUDIO_DEC_RECOVERY_NONE,
      };
      esp_audio_dec_out_frame_t frame = {
          .buffer = reinterpret_cast<uint8_t *>(buffers->speaker_pcm),
          .len = sizeof(buffers->speaker_pcm),
          .needed_size = 0,
          .decoded_size = 0,
      };
      esp_audio_dec_info_t info = {};
      if (esp_opus_dec_decode(decoder, &raw, &frame, &info) ==
              ESP_AUDIO_ERR_OK &&
          frame.decoded_size > 0 &&
          frame.decoded_size <= sizeof(buffers->speaker_pcm)) {
        const size_t samples = frame.decoded_size / sizeof(int16_t);
        const int volume =
            state->output_volume_percent.load(std::memory_order_acquire);
        for (size_t index = 0; index < samples; ++index) {
          buffers->speaker_raw[index] =
              scale_speaker_sample(buffers->speaker_pcm[index], volume);
        }
        if (!speaker_enabled) {
          final_error = i2s_channel_enable(state->speaker);
          speaker_enabled = final_error == ESP_OK;
          if (speaker_enabled) {
            playback_started = true;
            playback_underrun_grace = 0;
            ESP_LOGI(kTag, "Voice playback prebuffer ready: packets=%u",
                     static_cast<unsigned>(queued_audio));
          }
        }
        size_t written = 0;
        if (final_error == ESP_OK) {
          final_error =
              i2s_channel_write(state->speaker, buffers->speaker_raw,
                                samples * sizeof(buffers->speaker_raw[0]),
                                &written, pdMS_TO_TICKS(500));
          if (final_error == ESP_OK) {
            playback_underrun_grace = 0;
          }
        }
      } else {
        final_error = ESP_ERR_INVALID_RESPONSE;
      }
    } else if (speaker_enabled && stage == VoiceStage::kSpeaking &&
               uxQueueMessagesWaiting(state->voice_audio_queue) == 0) {
      if (playback_drain_requested) {
        std::memset(buffers->speaker_raw, 0, sizeof(buffers->speaker_raw));
        for (int packet = 0; packet < kVoicePlaybackTailPackets; ++packet) {
          size_t tail_written = 0;
          if (i2s_channel_write(state->speaker, buffers->speaker_raw,
                                sizeof(buffers->speaker_raw), &tail_written,
                                pdMS_TO_TICKS(500)) != ESP_OK ||
              tail_written != sizeof(buffers->speaker_raw)) {
            ESP_LOGW(kTag, "Voice playback tail drain was incomplete");
            break;
          }
        }
        (void)i2s_channel_disable(state->speaker);
        speaker_enabled = false;
        ESP_LOGI(kTag, "Voice playback queue and DMA tail drained");
      } else if (playback_underrun_grace <
                 kVoicePlaybackUnderrunGracePackets) {
        // Do not turn a brief packet scheduling delay into a full rebuffer
        // pause. Keep I2S alive with at most 180 ms of silence; if the link
        // remains empty after that, fall back to the smaller rebuffer window.
        std::memset(buffers->speaker_raw, 0, sizeof(buffers->speaker_raw));
        size_t silence_written = 0;
        if (i2s_channel_write(state->speaker, buffers->speaker_raw,
                              sizeof(buffers->speaker_raw), &silence_written,
                              pdMS_TO_TICKS(500)) != ESP_OK ||
            silence_written != sizeof(buffers->speaker_raw)) {
          final_error = ESP_FAIL;
        } else {
          ++playback_underrun_grace;
          if (playback_underrun_grace == 1) {
            ESP_LOGW(kTag, "Voice downlink jitter entered playback grace");
          }
        }
      } else {
        (void)i2s_channel_disable(state->speaker);
        speaker_enabled = false;
        ESP_LOGW(kTag, "Voice downlink jitter exhausted playback buffer; "
                       "rebuffering");
      }
    } else if (speaker_enabled && stage != VoiceStage::kSpeaking) {
      // Silent tail frames let the final speech frame leave the I2S DMA ring
      // before the channel is disabled. Without them, the last audible
      // syllable can be cut even though every Opus packet arrived and decoded.
      std::memset(buffers->speaker_raw, 0, sizeof(buffers->speaker_raw));
      for (int packet = 0; packet < kVoicePlaybackTailPackets; ++packet) {
        size_t tail_written = 0;
        if (i2s_channel_write(state->speaker, buffers->speaker_raw,
                              sizeof(buffers->speaker_raw), &tail_written,
                              pdMS_TO_TICKS(500)) != ESP_OK ||
            tail_written != sizeof(buffers->speaker_raw)) {
          ESP_LOGW(kTag, "Voice playback tail drain was incomplete");
          break;
        }
      }
      (void)i2s_channel_disable(state->speaker);
      speaker_enabled = false;
      ESP_LOGI(kTag, "Voice playback completed; DMA tail drained");
    }
    if (playback_drain_requested && !speaker_enabled &&
        uxQueueMessagesWaiting(state->voice_audio_queue) == 0) {
      char drained[192] = {};
      std::snprintf(drained, sizeof(drained),
                    "{\"session_id\":\"%s\",\"type\":\"tts\","
                    "\"state\":\"drained\"}",
                    state->voice_session_id);
      if (voice_send_text(state, drained) > 0) {
        state->voice_playback_drain_requested.store(
            false, std::memory_order_release);
        set_voice_stage(state, VoiceStage::kReady);
        stage = VoiceStage::kReady;
        playback_started = false;
        playback_underrun_grace = 0;
        ESP_LOGI(kTag, "Voice playback drain acknowledged to Gateway");
      } else {
        final_error = ESP_FAIL;
      }
    }
    if (stage != VoiceStage::kListening &&
        (!audio_ready ||
         uxQueueMessagesWaiting(state->voice_audio_queue) == 0)) {
      vTaskDelay(pdMS_TO_TICKS(10));
    }
    if (!microphone_enabled && !speaker_enabled &&
        uxQueueMessagesWaiting(state->voice_audio_queue) == 0 &&
        (stage == VoiceStage::kReady || stage == VoiceStage::kError)) {
      restore_wifi_power_save();
    }
  }

  if (microphone_enabled) {
    (void)i2s_channel_disable(state->microphone);
  }
  restore_wifi_power_save();
  if (speaker_enabled) {
    (void)i2s_channel_disable(state->speaker);
  }
  if (state->voice_websocket) {
    (void)esp_websocket_client_stop(state->voice_websocket);
    (void)esp_websocket_client_destroy(state->voice_websocket);
    state->voice_websocket = nullptr;
  }
  state->voice_ws_connected.store(false, std::memory_order_release);
  if (encoder) {
    esp_opus_enc_close(encoder);
  }
  if (decoder) {
    esp_opus_dec_close(decoder);
  }
  heap_caps_free(buffers);
  xQueueReset(state->voice_audio_queue);
  xQueueReset(state->voice_text_queue);
  state->voice_retry_after_us = esp_timer_get_time() + kVoiceRetryDelayUs;
  set_voice_stage(state, VoiceStage::kError,
                  final_error == ESP_OK ? ESP_FAIL : final_error);
  ESP_LOGW(kTag, "Voice session stopped safely: %s; retry scheduled",
           esp_err_to_name(final_error));
  state->voice_task = nullptr;
  vTaskDelete(nullptr);
}

int hex_value(char character) {
  if (character >= '0' && character <= '9') {
    return character - '0';
  }
  if (character >= 'a' && character <= 'f') {
    return character - 'a' + 10;
  }
  if (character >= 'A' && character <= 'F') {
    return character - 'A' + 10;
  }
  return -1;
}

bool decode_form_value(const char *input, size_t input_size, char *output,
                       size_t output_size) {
  if (!input || !output || output_size == 0) {
    return false;
  }
  size_t written = 0;
  for (size_t index = 0; index < input_size; ++index) {
    unsigned char value = static_cast<unsigned char>(input[index]);
    if (value == '+') {
      value = ' ';
    } else if (value == '%') {
      if (index + 2 >= input_size) {
        return false;
      }
      const int high = hex_value(input[index + 1]);
      const int low = hex_value(input[index + 2]);
      if (high < 0 || low < 0) {
        return false;
      }
      value = static_cast<unsigned char>((high << 4) | low);
      index += 2;
    }
    if (value == 0 || written + 1 >= output_size) {
      return false;
    }
    output[written++] = static_cast<char>(value);
  }
  output[written] = '\0';
  return true;
}

bool form_value(const char *body, const char *name, char *output,
                size_t output_size) {
  if (!body || !name || !output) {
    return false;
  }
  const size_t name_size = std::strlen(name);
  const char *cursor = body;
  while (*cursor) {
    const char *end = std::strchr(cursor, '&');
    if (!end) {
      end = cursor + std::strlen(cursor);
    }
    const char *equals = static_cast<const char *>(
        std::memchr(cursor, '=', static_cast<size_t>(end - cursor)));
    if (equals && static_cast<size_t>(equals - cursor) == name_size &&
        std::memcmp(cursor, name, name_size) == 0) {
      return decode_form_value(equals + 1,
                               static_cast<size_t>(end - equals - 1), output,
                               output_size);
    }
    cursor = *end ? end + 1 : end;
  }
  return false;
}

constexpr char kWifiPortalPage[] = R"HTML(<!doctype html>
<html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>小智 Agent Wi-Fi 設定</title><style>
body{margin:0;background:#08131a;color:#f5fbff;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{max-width:420px;margin:auto;padding:28px 20px}.brand{color:#63e6be;font-size:14px;letter-spacing:.12em}
h1{font-size:28px;margin:10px 0 8px}.hint{color:#abc1cc;line-height:1.6}.card{background:#132731;border:1px solid #24414d;border-radius:18px;padding:20px;margin-top:22px}
label{display:block;margin:14px 0 7px;color:#cfe2ea}input,select{box-sizing:border-box;width:100%;font-size:18px;padding:13px;border-radius:10px;border:1px solid #42616e;background:#09181f;color:white}
button{width:100%;margin-top:20px;padding:14px;border:0;border-radius:12px;background:#63e6be;color:#082017;font-size:17px;font-weight:700}
#rescan{margin-top:10px;background:#24414d;color:#eaf7f1}#scan-status{min-height:22px;margin-top:8px;color:#8fb8aa;font-size:14px}
#status{min-height:24px;margin-top:16px;color:#ffd166}.small{font-size:13px;color:#8299a3;margin-top:20px}</style></head>
<body><main><div class="brand">XIAOZHI AGENT</div><h1>管理 Wi-Fi</h1>
<p class="hint">裝置最多保留 5 組 2.4 GHz Wi-Fi，外出時會自動切換。新增成功不會刪除原有網路；資料只送到眼前這台裝置。</p>
<p class="hint" id="saved">正在讀取已儲存數量…</p>
<form class="card" method="post" action="/configure"><label for="networks">附近的 Wi-Fi</label>
<select id="networks"><option value="">正在搜尋附近網路…</option></select>
<button id="rescan" type="button">重新搜尋</button><div id="scan-status"></div>
<label for="ssid">Wi-Fi 名稱（可手動修改）</label><input id="ssid" name="ssid" maxlength="32" autocomplete="off" required>
<label for="password">Wi-Fi 密碼</label><input id="password" name="password" type="password" minlength="8" maxlength="63" autocomplete="current-password" required>
<button type="submit">儲存並連線</button><div id="status">等待輸入</div></form>
<p class="small">成功後可再次長按 BOOT 新增其他網路；超過 5 組時會淘汰最久未使用的一組。</p></main>
<script>
const list=document.querySelector('#networks'),ssid=document.querySelector('#ssid'),scanStatus=document.querySelector('#scan-status'),saved=document.querySelector('#saved');
function signal(rssi){return rssi>=-55?'訊號強':rssi>=-70?'訊號中等':'訊號較弱'}
async function scan(){list.disabled=true;scanStatus.textContent='正在掃描 2.4 GHz Wi-Fi…';try{const r=await fetch('/networks',{cache:'no-store'});if(!r.ok)throw Error();const data=await r.json(),usable=data.networks.filter(n=>n.secured);list.textContent='';if(!usable.length){const o=document.createElement('option');o.value='';o.textContent='沒有找到可用網路，請重新搜尋或手動輸入';list.appendChild(o);scanStatus.textContent='找不到支援密碼保護的 2.4 GHz 網路';return}for(const n of usable){const o=document.createElement('option');o.value=n.ssid;o.textContent=n.ssid+' · '+signal(n.rssi)+' · 需密碼';list.appendChild(o)}if(!ssid.value)ssid.value=usable[0].ssid;scanStatus.textContent='找到 '+usable.length+' 個可用網路'}catch(e){scanStatus.textContent='掃描暫時失敗，請按重新搜尋或手動輸入'}finally{list.disabled=false}}
list.addEventListener('change',()=>{if(list.value)ssid.value=list.value});document.querySelector('#rescan').addEventListener('click',scan);scan();
setInterval(async()=>{try{let r=await fetch('/status',{cache:'no-store'}),s=await r.json();saved.textContent='目前已儲存 '+s.saved_networks+' / 5 組網路';if(s.online)document.querySelector('#status').textContent='已儲存並連線，設定入口即將關閉';else if(s.rejected)document.querySelector('#status').textContent='無法連線，請檢查名稱與密碼後重試';else if(s.connecting)document.querySelector('#status').textContent='正在驗證並連線…';}catch(e){}},1200)
</script></body></html>)HTML";

constexpr char kWifiSubmittedPage[] =
    R"HTML(<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>正在儲存</title><style>body{background:#08131a;color:#fff;font-family:-apple-system,sans-serif;padding:28px}main{max-width:420px;margin:auto}h1{color:#63e6be}p{line-height:1.7;color:#cfe2ea}a{color:#63e6be}</style></head><body><main><h1>正在儲存並連線</h1><p>請保持此頁開啟。連線成功後，這組 Wi-Fi 會加入裝置，原有網路仍會保留。</p><p><a href="/">返回重新輸入</a></p><script>setInterval(async()=>{try{let r=await fetch('/status',{cache:'no-store'}),s=await r.json();if(s.online)document.body.innerHTML='<main><h1>儲存成功</h1><p>目前已保留 '+s.saved_networks+' 組 Wi-Fi，之後會依環境自動切換。</p></main>';}catch(e){}},900)</script></main></body></html>)HTML";

void set_http_headers(httpd_req_t *request) {
  httpd_resp_set_type(request, "text/html; charset=utf-8");
  httpd_resp_set_hdr(request, "Cache-Control", "no-store");
  httpd_resp_set_hdr(request, "X-Content-Type-Options", "nosniff");
  httpd_resp_set_hdr(request, "Content-Security-Policy",
                     "default-src 'self' 'unsafe-inline'; connect-src 'self'");
}

esp_err_t wifi_portal_get(httpd_req_t *request) {
  set_http_headers(request);
  return httpd_resp_send(request, kWifiPortalPage, HTTPD_RESP_USE_STRLEN);
}

esp_err_t wifi_portal_status(httpd_req_t *request) {
  auto *state = static_cast<BringupState *>(request->user_ctx);
  product_wifi_stats_t stats = {};
  const bool available = state && state->wifi &&
                         product_wifi_get_stats(state->wifi, &stats) == ESP_OK;
  char response[160] = {};
  std::snprintf(
      response, sizeof(response),
      "{\"online\":%s,\"connecting\":%s,\"rejected\":%s,"
      "\"saved_networks\":%u}",
      json_bool(available && stats.network_available),
      json_bool(available && stats.state == PRODUCT_WIFI_STATE_CONNECTING),
      json_bool(state && state->wifi_credentials_rejected.load(
                             std::memory_order_acquire)),
      static_cast<unsigned>(available ? stats.saved_networks : 0));
  httpd_resp_set_type(request, "application/json");
  httpd_resp_set_hdr(request, "Cache-Control", "no-store");
  return httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
}

esp_err_t wifi_portal_networks(httpd_req_t *request) {
  auto *state = static_cast<BringupState *>(request->user_ctx);
  product_wifi_scan_result_t networks[PRODUCT_WIFI_SCAN_RESULT_LIMIT] = {};
  size_t count = 0;
  const esp_err_t scan_error =
      state && state->wifi
          ? product_wifi_scan_networks(state->wifi, networks,
                                       PRODUCT_WIFI_SCAN_RESULT_LIMIT, &count)
          : ESP_ERR_INVALID_STATE;
  httpd_resp_set_type(request, "application/json; charset=utf-8");
  httpd_resp_set_hdr(request, "Cache-Control", "no-store");
  httpd_resp_set_hdr(request, "X-Content-Type-Options", "nosniff");
  if (scan_error != ESP_OK) {
    ESP_LOGW(kTag, "Nearby Wi-Fi scan unavailable without logging SSIDs: %s",
             esp_err_to_name(scan_error));
    httpd_resp_set_status(request, "503 Service Unavailable");
    return httpd_resp_send(request, "{\"networks\":[],\"busy\":true}",
                           HTTPD_RESP_USE_STRLEN);
  }

  cJSON *root = cJSON_CreateObject();
  cJSON *items = root ? cJSON_AddArrayToObject(root, "networks") : nullptr;
  if (!root || !items) {
    cJSON_Delete(root);
    httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                        "Scan response unavailable");
    return ESP_ERR_NO_MEM;
  }
  for (size_t index = 0; index < count; ++index) {
    cJSON *item = cJSON_CreateObject();
    if (!item) {
      cJSON_Delete(root);
      httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                          "Scan response unavailable");
      return ESP_ERR_NO_MEM;
    }
    cJSON_AddStringToObject(item, "ssid", networks[index].ssid);
    cJSON_AddNumberToObject(item, "rssi", networks[index].rssi);
    cJSON_AddBoolToObject(item, "secured", networks[index].secured);
    cJSON_AddItemToArray(items, item);
  }
  char *response = cJSON_PrintUnformatted(root);
  cJSON_Delete(root);
  if (!response) {
    httpd_resp_send_err(request, HTTPD_500_INTERNAL_SERVER_ERROR,
                        "Scan response unavailable");
    return ESP_ERR_NO_MEM;
  }
  const esp_err_t send_error =
      httpd_resp_send(request, response, HTTPD_RESP_USE_STRLEN);
  cJSON_free(response);
  return send_error;
}

esp_err_t wifi_portal_submit(httpd_req_t *request) {
  auto *state = static_cast<BringupState *>(request->user_ctx);
  if (!state || !state->wifi || request->content_len <= 0 ||
      request->content_len >= 256) {
    httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST, "Invalid request");
    return ESP_FAIL;
  }
  char body[256] = {};
  size_t received = 0;
  while (received < static_cast<size_t>(request->content_len)) {
    const int result =
        httpd_req_recv(request, body + received,
                       static_cast<size_t>(request->content_len) - received);
    if (result == HTTPD_SOCK_ERR_TIMEOUT) {
      continue;
    }
    if (result <= 0) {
      secure_clear(body, sizeof(body));
      return ESP_FAIL;
    }
    received += static_cast<size_t>(result);
  }
  body[received] = '\0';
  char ssid[33] = {};
  char password[64] = {};
  const bool decoded = form_value(body, "ssid", ssid, sizeof(ssid)) &&
                       form_value(body, "password", password, sizeof(password));
  esp_err_t error =
      decoded ? product_wifi_submit_credentials(state->wifi, ssid, password)
              : ESP_ERR_INVALID_ARG;
  secure_clear(password, sizeof(password));
  secure_clear(body, sizeof(body));
  secure_clear(ssid, sizeof(ssid));
  if (error != ESP_OK) {
    ESP_LOGW(kTag, "Wi-Fi credential form rejected without logging secrets: %s",
             esp_err_to_name(error));
    httpd_resp_send_err(request, HTTPD_400_BAD_REQUEST,
                        "Wi-Fi name or password is invalid");
    return error;
  }
  state->wifi_credentials_rejected.store(false, std::memory_order_release);
  state->wifi_ui_dirty.store(true, std::memory_order_release);
  set_http_headers(request);
  return httpd_resp_send(request, kWifiSubmittedPage, HTTPD_RESP_USE_STRLEN);
}

esp_err_t start_wifi_portal(BringupState *state) {
  if (!state || state->onboarding_httpd) {
    return state && state->onboarding_httpd ? ESP_OK : ESP_ERR_INVALID_ARG;
  }
  httpd_config_t config = HTTPD_DEFAULT_CONFIG();
  config.server_port = 80;
  config.max_uri_handlers = 4;
  config.stack_size = 6144;
  config.lru_purge_enable = true;
  esp_err_t error = httpd_start(&state->onboarding_httpd, &config);
  if (error != ESP_OK) {
    return error;
  }
  httpd_uri_t root = {};
  root.uri = "/";
  root.method = HTTP_GET;
  root.handler = wifi_portal_get;
  root.user_ctx = state;
  httpd_uri_t submit = {};
  submit.uri = "/configure";
  submit.method = HTTP_POST;
  submit.handler = wifi_portal_submit;
  submit.user_ctx = state;
  httpd_uri_t status = {};
  status.uri = "/status";
  status.method = HTTP_GET;
  status.handler = wifi_portal_status;
  status.user_ctx = state;
  httpd_uri_t networks = {};
  networks.uri = "/networks";
  networks.method = HTTP_GET;
  networks.handler = wifi_portal_networks;
  networks.user_ctx = state;
  error = httpd_register_uri_handler(state->onboarding_httpd, &root);
  if (error == ESP_OK) {
    error = httpd_register_uri_handler(state->onboarding_httpd, &submit);
  }
  if (error == ESP_OK) {
    error = httpd_register_uri_handler(state->onboarding_httpd, &status);
  }
  if (error == ESP_OK) {
    error = httpd_register_uri_handler(state->onboarding_httpd, &networks);
  }
  if (error != ESP_OK) {
    httpd_stop(state->onboarding_httpd);
    state->onboarding_httpd = nullptr;
  }
  return error;
}

void stop_wifi_portal(BringupState *state) {
  if (state && state->onboarding_httpd) {
    (void)httpd_stop(state->onboarding_httpd);
    state->onboarding_httpd = nullptr;
  }
}

void wifi_event(void *ctx, const product_wifi_event_t *event) {
  auto *state = static_cast<BringupState *>(ctx);
  if (!state || !event) {
    return;
  }
  state->wifi_state.store(event->state, std::memory_order_release);
  state->wifi_online.store(event->network_available, std::memory_order_release);
  if (event->type == PRODUCT_WIFI_EVENT_CREDENTIALS_REJECTED) {
    state->wifi_credentials_rejected.store(true, std::memory_order_release);
  } else if (event->type == PRODUCT_WIFI_EVENT_CREDENTIALS_ACCEPTED) {
    state->wifi_credentials_rejected.store(false, std::memory_order_release);
  }
  if (event->error != ESP_OK) {
    state->wifi_last_error.store(event->error, std::memory_order_release);
  }
  state->wifi_ui_dirty.store(true, std::memory_order_release);
  ESP_LOGI(kTag, "Wi-Fi event=%d state=%d online=%d error=%s",
           static_cast<int>(event->type), static_cast<int>(event->state),
           event->network_available ? 1 : 0, esp_err_to_name(event->error));
}

esp_err_t initialize_product_wifi(BringupState *state) {
  if (!state || state->wifi) {
    return ESP_ERR_INVALID_ARG;
  }
  esp_err_t error = product_storage_initialize();
  if (error != ESP_OK) {
    return error;
  }
  uint8_t mac[6] = {};
  error = esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);
  if (error != ESP_OK) {
    return error;
  }
  std::snprintf(state->wifi_ap_ssid, sizeof(state->wifi_ap_ssid),
                "XIAOZHI-%02X%02X%02X", mac[3], mac[4], mac[5]);
  constexpr char kPasswordAlphabet[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  uint8_t random_bytes[12] = {};
  esp_fill_random(random_bytes, sizeof(random_bytes));
  for (size_t index = 0; index < sizeof(random_bytes); ++index) {
    state->wifi_ap_password[index] =
        kPasswordAlphabet[random_bytes[index] %
                          (sizeof(kPasswordAlphabet) - 1)];
  }
  state->wifi_ap_password[sizeof(random_bytes)] = '\0';
  secure_clear(random_bytes, sizeof(random_bytes));
  char hostname[PRODUCT_WIFI_HOSTNAME_MAX + 1] = {};
  std::snprintf(hostname, sizeof(hostname), "xiaozhi-%02x%02x%02x", mac[3],
                mac[4], mac[5]);
  const product_wifi_config_t config = {
      .hostname = hostname,
      .event = wifi_event,
      .event_ctx = state,
      .minimum_backoff_ms = 1000,
      .maximum_backoff_ms = 15000,
      .authentication_failure_limit = 5,
      .task_stack_size = 0,
      .task_priority = 0,
  };
  error = product_wifi_create(&config, &state->wifi);
  if (error == ESP_OK) {
    error = product_wifi_start(state->wifi);
  }
  if (error == ESP_OK) {
    ESP_LOGI(kTag,
             "Product Wi-Fi manager ready; all-channel reconnect and "
             "60-second station self-recovery enabled; SoftAP remains off "
             "until a 4-second physical button hold");
  }
  return error;
}

esp_err_t initialize_display(BringupState *state) {
  ESP_LOGI(kTag,
           "Display config: ST7789 %dx%d MOSI=%d CLK=%d DC=%d CS=%d "
           "RESET=NC SPI3 80MHz invert=1 mirror=1,1 RGB565=little-endian",
           kDisplayWidth, kDisplayHeight, static_cast<int>(kDisplayMosi),
           static_cast<int>(kDisplayClock), static_cast<int>(kDisplayDc),
           static_cast<int>(kDisplayCs));
  const spi_bus_config_t bus_config = {
      .mosi_io_num = kDisplayMosi,
      .miso_io_num = GPIO_NUM_NC,
      .sclk_io_num = kDisplayClock,
      .quadwp_io_num = GPIO_NUM_NC,
      .quadhd_io_num = GPIO_NUM_NC,
      .data4_io_num = GPIO_NUM_NC,
      .data5_io_num = GPIO_NUM_NC,
      .data6_io_num = GPIO_NUM_NC,
      .data7_io_num = GPIO_NUM_NC,
      .data_io_default_level = false,
      .max_transfer_sz = kDisplayWidth * kDisplayHeight * sizeof(uint16_t),
      .flags = 0,
      .isr_cpu_id = ESP_INTR_CPU_AFFINITY_AUTO,
      .intr_flags = 0,
  };
  esp_err_t error = spi_bus_initialize(SPI3_HOST, &bus_config, SPI_DMA_CH_AUTO);
  if (error != ESP_OK) {
    return error;
  }
  esp_lcd_panel_io_handle_t panel_io = nullptr;
  state->display_transfer_done = xSemaphoreCreateBinary();
  if (!state->display_transfer_done) {
    return ESP_ERR_NO_MEM;
  }
  const esp_lcd_panel_io_spi_config_t io_config = {
      .cs_gpio_num = kDisplayCs,
      .dc_gpio_num = kDisplayDc,
      .spi_mode = 0,
      .pclk_hz = 80 * 1000 * 1000,
      .trans_queue_depth = 10,
      .on_color_trans_done = ui_transfer_done,
      .user_ctx = state,
      .lcd_cmd_bits = 8,
      .lcd_param_bits = 8,
      .cs_ena_pretrans = 0,
      .cs_ena_posttrans = 0,
      .flags = {},
  };
  error = esp_lcd_new_panel_io_spi(SPI3_HOST, &io_config, &panel_io);
  if (error != ESP_OK) {
    return error;
  }
  esp_lcd_panel_dev_config_t panel_config = {};
  panel_config.reset_gpio_num = kDisplayReset;
  panel_config.rgb_ele_order = LCD_RGB_ELEMENT_ORDER_RGB;
  /* The UI framebuffer contains native ESP32 uint16_t RGB565 values, so its
   * byte stream is low-byte first. XiaoZhi's LVGL path performs its own byte
   * handling; this direct framebuffer path must ask ST7789 RAMCTRL to accept
   * little-endian pixels or every non-symmetric color is corrupted. */
  panel_config.data_endian = LCD_RGB_DATA_ENDIAN_LITTLE;
  panel_config.bits_per_pixel = 16;
  error = esp_lcd_new_panel_st7789(panel_io, &panel_config, &state->panel);
  if (error == ESP_OK) {
    error = esp_lcd_panel_reset(state->panel);
  }
  if (error == ESP_OK) {
    error = esp_lcd_panel_init(state->panel);
  }
  if (error == ESP_OK) {
    error = esp_lcd_panel_invert_color(state->panel, true);
  }
  if (error == ESP_OK) {
    error = esp_lcd_panel_swap_xy(state->panel, false);
  }
  if (error == ESP_OK) {
    error = esp_lcd_panel_mirror(state->panel, true, true);
  }
  if (error == ESP_OK) {
    error = esp_lcd_panel_disp_on_off(state->panel, true);
  }
  if (error == ESP_OK) {
    state->ui_framebuffer = static_cast<uint16_t *>(
        heap_caps_malloc(kDisplayWidth * kDisplayHeight * sizeof(uint16_t),
                         MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    state->ui_transfer_buffer = static_cast<uint16_t *>(
        heap_caps_malloc(kDisplayWidth * 20 * sizeof(uint16_t),
                         MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL));
    if (!state->ui_framebuffer || !state->ui_transfer_buffer) {
      error = ESP_ERR_NO_MEM;
    }
  }
  return error;
}

esp_err_t draw_startup_test_card(BringupState *state) {
  if (!state || !state->ui_framebuffer) {
    return ESP_ERR_INVALID_STATE;
  }
  /* A bright, persistent card makes the panel test observable without a
   * serial console. It is shown before camera/audio initialization can
   * claim any other peripheral. */
  ui_fill(state, kUiWhite);
  ui_fill_rect(state, 0, 0, 80, kDisplayHeight, 0xf800);
  ui_fill_rect(state, 80, 0, 80, kDisplayHeight, 0x07e0);
  ui_fill_rect(state, 160, 0, 80, kDisplayHeight, 0x001f);
  ui_fill_rect(state, 8, 18, 224, 58, 0x0000);
  ui_draw_text(state, 20, 30, "DISPLAY TEST", 2, kUiWhite);
  ui_fill_rect(state, 8, 244, 224, 58, 0x0000);
  ui_draw_text(state, 35, 257, "RGB 240X320", 2, kUiWhite);
  const esp_err_t error = ui_flush(state);
  ESP_LOGI(kTag, "Visible RGB test card transfer: %s", esp_err_to_name(error));
  return error;
}

esp_err_t draw_display_pattern(BringupState *state) {
  const esp_err_t error = ui_draw_progress(state, "DISPLAY PASS", 1);
  state->display_ok.store(error == ESP_OK, std::memory_order_release);
  return error;
}

esp_err_t initialize_camera(BringupState *state) {
  if (!state) {
    return ESP_ERR_INVALID_ARG;
  }

  const esp_cam_ctlr_dvp_pin_config_t pins = {
      .data_width = CAM_CTLR_DATA_WIDTH_8,
      .data_io =
          {
              kCameraD0,
              kCameraD1,
              kCameraD2,
              kCameraD3,
              kCameraD4,
              kCameraD5,
              kCameraD6,
              kCameraD7,
          },
      .vsync_io = kCameraVsync,
      .de_io = kCameraHref,
      .pclk_io = kCameraPclk,
      .xclk_io = kCameraXclk,
  };
  const esp_video_init_sccb_config_t sccb = {
      .init_sccb = true,
      .i2c_config =
          {
              .port = 0,
              .scl_pin = kCameraScl,
              .sda_pin = kCameraSda,
          },
      .freq = 100000,
  };
  const esp_video_init_dvp_config_t dvp = {
      .sccb_config = sccb,
      .reset_pin = GPIO_NUM_NC,
      .pwdn_pin = kCameraPwdn,
      .dvp_pin = pins,
      .xclk_freq = kCameraXclkHz,
  };
  const esp_video_init_config_t config = {
      .dvp = &dvp,
  };

  esp_err_t error = esp_video_init(&config);
  if (error != ESP_OK) {
    return error;
  }
  state->camera_fd = open(ESP_VIDEO_DVP_DEVICE_NAME, O_RDWR);
  if (state->camera_fd < 0) {
    ESP_LOGE(kTag, "open %s failed: errno=%d", ESP_VIDEO_DVP_DEVICE_NAME,
             errno);
    return ESP_FAIL;
  }

  v4l2_capability capability = {};
  if (ioctl(state->camera_fd, VIDIOC_QUERYCAP, &capability) != 0 ||
      !(capability.device_caps & V4L2_CAP_VIDEO_CAPTURE) ||
      !(capability.device_caps & V4L2_CAP_STREAMING)) {
    ESP_LOGE(kTag, "DVP video capability query failed");
    return ESP_FAIL;
  }

  v4l2_format format = {};
  format.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  format.fmt.pix.width = 320;
  format.fmt.pix.height = 240;
  format.fmt.pix.pixelformat = V4L2_PIX_FMT_YUV422P;
  if (ioctl(state->camera_fd, VIDIOC_S_FMT, &format) != 0 ||
      format.fmt.pix.width == 0 || format.fmt.pix.height == 0) {
    ESP_LOGE(kTag, "VIDIOC_S_FMT failed: errno=%d", errno);
    return ESP_FAIL;
  }

  v4l2_ext_control orientation[2] = {};
  orientation[0].id = V4L2_CID_HFLIP;
  orientation[0].value = kCameraHorizontalMirror ? 1 : 0;
  orientation[1].id = V4L2_CID_VFLIP;
  orientation[1].value = kCameraVerticalFlip ? 1 : 0;
  v4l2_ext_controls orientation_controls = {};
  orientation_controls.ctrl_class = V4L2_CTRL_CLASS_USER;
  orientation_controls.count = 2;
  orientation_controls.controls = orientation;
  if (ioctl(state->camera_fd, VIDIOC_S_EXT_CTRLS,
            &orientation_controls) != 0) {
    ESP_LOGE(kTag, "GC0308 orientation controls failed: errno=%d", errno);
    return ESP_FAIL;
  }

  v4l2_requestbuffers request = {};
  request.count = kCameraBufferCount;
  request.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  request.memory = V4L2_MEMORY_MMAP;
  if (ioctl(state->camera_fd, VIDIOC_REQBUFS, &request) != 0 ||
      request.count == 0 || request.count > kCameraBufferCount) {
    ESP_LOGE(kTag, "VIDIOC_REQBUFS failed: errno=%d count=%u", errno,
             static_cast<unsigned>(request.count));
    return ESP_FAIL;
  }
  state->camera_buffer_count = request.count;
  for (size_t index = 0; index < state->camera_buffer_count; ++index) {
    v4l2_buffer buffer = {};
    buffer.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    buffer.memory = V4L2_MEMORY_MMAP;
    buffer.index = index;
    if (ioctl(state->camera_fd, VIDIOC_QUERYBUF, &buffer) != 0) {
      ESP_LOGE(kTag, "VIDIOC_QUERYBUF failed: errno=%d", errno);
      return ESP_FAIL;
    }
    void *mapped = mmap(nullptr, buffer.length, PROT_READ | PROT_WRITE,
                        MAP_SHARED, state->camera_fd, buffer.m.offset);
    if (!mapped || mapped == MAP_FAILED) {
      ESP_LOGE(kTag, "camera mmap failed: errno=%d", errno);
      return ESP_FAIL;
    }
    state->camera_buffers[index] = {mapped, buffer.length};
    if (ioctl(state->camera_fd, VIDIOC_QBUF, &buffer) != 0) {
      ESP_LOGE(kTag, "VIDIOC_QBUF failed: errno=%d", errno);
      return ESP_FAIL;
    }
  }
  int type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  if (ioctl(state->camera_fd, VIDIOC_STREAMON, &type) != 0) {
    ESP_LOGE(kTag, "VIDIOC_STREAMON failed: errno=%d", errno);
    return ESP_FAIL;
  }
  state->camera_streaming = true;
  state->camera_pid.store(0x9b, std::memory_order_release);
  state->camera_width.store(format.fmt.pix.width, std::memory_order_release);
  state->camera_height.store(format.fmt.pix.height, std::memory_order_release);
  ESP_LOGI(kTag,
           "[PASS] GC0308 PID=0x9b esp_video DVP initialized %ux%u "
           "hmirror=%d vflip=%d",
           static_cast<unsigned>(format.fmt.pix.width),
           static_cast<unsigned>(format.fmt.pix.height),
           kCameraHorizontalMirror ? 1 : 0, kCameraVerticalFlip ? 1 : 0);
  return ESP_OK;
}

esp_err_t capture_camera_frame(BringupState *state) {
  if (!state || !state->camera_streaming || state->camera_fd < 0) {
    state->camera_ok.store(false, std::memory_order_release);
    return ESP_ERR_INVALID_STATE;
  }
  v4l2_buffer frame = {};
  frame.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  frame.memory = V4L2_MEMORY_MMAP;
  if (ioctl(state->camera_fd, VIDIOC_DQBUF, &frame) != 0 ||
      frame.index >= state->camera_buffer_count || frame.bytesused == 0 ||
      frame.bytesused > state->camera_buffers[frame.index].length) {
    state->camera_ok.store(false, std::memory_order_release);
    ESP_LOGE(kTag, "VIDIOC_DQBUF failed: errno=%d index=%u bytes=%u", errno,
             static_cast<unsigned>(frame.index),
             static_cast<unsigned>(frame.bytesused));
    return ESP_FAIL;
  }
  const auto *bytes =
      static_cast<const uint8_t *>(state->camera_buffers[frame.index].start);
  uint32_t checksum = 2166136261U;
  for (size_t index = 0; index < frame.bytesused; index += 97) {
    checksum = (checksum ^ bytes[index]) * 16777619U;
  }
  state->camera_checksum.store(checksum, std::memory_order_release);
  state->camera_ok.store(true, std::memory_order_release);
  ESP_LOGI(kTag, "[PASS] camera frame %ux%u bytes=%u checksum=%08x",
           static_cast<unsigned>(
               state->camera_width.load(std::memory_order_acquire)),
           static_cast<unsigned>(
               state->camera_height.load(std::memory_order_acquire)),
           static_cast<unsigned>(frame.bytesused),
           static_cast<unsigned>(checksum));
  if (ioctl(state->camera_fd, VIDIOC_QBUF, &frame) != 0) {
    state->camera_ok.store(false, std::memory_order_release);
    ESP_LOGE(kTag, "VIDIOC_QBUF failed after capture: errno=%d", errno);
    return ESP_FAIL;
  }
  return ESP_OK;
}

esp_err_t capture_and_upload_camera_frame(BringupState *state,
                                          const char *request_id,
                                          char *output, size_t output_size) {
  if (!state || !valid_image_request_id(request_id) || !output ||
      output_size == 0 || !state->camera_streaming || state->camera_fd < 0 ||
      !state->voice_websocket ||
      !state->voice_ws_connected.load(std::memory_order_acquire)) {
    return ESP_ERR_INVALID_STATE;
  }

  v4l2_buffer frame = {};
  frame.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  frame.memory = V4L2_MEMORY_MMAP;
  if (ioctl(state->camera_fd, VIDIOC_DQBUF, &frame) != 0 ||
      frame.index >= state->camera_buffer_count || frame.bytesused == 0 ||
      frame.bytesused > state->camera_buffers[frame.index].length) {
    ESP_LOGE(kTag, "camera Agent capture dequeue failed: errno=%d", errno);
    return ESP_FAIL;
  }

  const unsigned width =
      state->camera_width.load(std::memory_order_acquire);
  const unsigned height =
      state->camera_height.load(std::memory_order_acquire);
  const size_t expected_bytes = static_cast<size_t>(width) * height * 2;
  const bool valid = width == 320 && height == 240 &&
                     frame.bytesused == expected_bytes &&
                     frame.bytesused <= kCameraUploadMaximumBytes;
  const auto *bytes = static_cast<const uint8_t *>(
      state->camera_buffers[frame.index].start);
  esp_err_t result = valid ? ESP_OK : ESP_ERR_INVALID_SIZE;
  bool upload_started = false;
  if (result == ESP_OK &&
      voice_send_image_control(state, request_id, "begin", frame.bytesused) <=
          0) {
    result = ESP_FAIL;
  } else if (result == ESP_OK) {
    upload_started = true;
  }
  for (size_t offset = 0; result == ESP_OK && offset < frame.bytesused;
       offset += kCameraUploadChunkBytes) {
    const size_t chunk = std::min<size_t>(
        static_cast<size_t>(kCameraUploadChunkBytes),
        static_cast<size_t>(frame.bytesused) - offset);
    if (esp_websocket_client_send_bin(
            state->voice_websocket,
            reinterpret_cast<const char *>(bytes + offset),
            static_cast<int>(chunk),
            pdMS_TO_TICKS(kVoiceSendTimeoutMs)) <= 0) {
      result = ESP_FAIL;
    }
  }
  if (result == ESP_OK &&
      voice_send_image_control(state, request_id, "end") <= 0) {
    result = ESP_FAIL;
  } else if (result != ESP_OK && upload_started) {
    (void)voice_send_image_control(state, request_id, "abort");
  }

  uint32_t checksum = 2166136261U;
  if (valid) {
    for (size_t index = 0; index < frame.bytesused; index += 97) {
      checksum = (checksum ^ bytes[index]) * 16777619U;
    }
    state->camera_checksum.store(checksum, std::memory_order_release);
  }
  if (ioctl(state->camera_fd, VIDIOC_QBUF, &frame) != 0) {
    ESP_LOGE(kTag, "camera Agent capture requeue failed: errno=%d", errno);
    result = ESP_FAIL;
  }
  state->camera_ok.store(result == ESP_OK, std::memory_order_release);
  if (result != ESP_OK) {
    return result;
  }
  const int written = std::snprintf(
      output, output_size,
      "{\"ok\":true,\"request_id\":\"%s\",\"width\":%u,"
      "\"height\":%u,\"bytes\":%u}",
      request_id, width, height, static_cast<unsigned>(frame.bytesused));
  if (written < 0 || static_cast<size_t>(written) >= output_size) {
    return ESP_ERR_INVALID_SIZE;
  }
  ESP_LOGI(kTag,
           "Camera frame uploaded for approved Agent request: bytes=%u "
           "checksum=%08x",
           static_cast<unsigned>(frame.bytesused),
           static_cast<unsigned>(checksum));
  return ESP_OK;
}

uint8_t ui_clamp_color(int value) {
  return static_cast<uint8_t>(std::min(255, std::max(0, value)));
}

uint16_t yuyv_to_rgb565(uint8_t y, uint8_t u, uint8_t v) {
  const int c = std::max(0, static_cast<int>(y) - 16);
  const int d = static_cast<int>(u) - 128;
  const int e = static_cast<int>(v) - 128;
  const uint8_t red = ui_clamp_color((298 * c + 409 * e + 128) >> 8);
  const uint8_t green =
      ui_clamp_color((298 * c - 100 * d - 208 * e + 128) >> 8);
  const uint8_t blue = ui_clamp_color((298 * c + 516 * d + 128) >> 8);
  return static_cast<uint16_t>(((red & 0xf8) << 8) | ((green & 0xfc) << 3) |
                               (blue >> 3));
}

esp_err_t ui_draw_camera_preview(BringupState *state) {
  if (!state || !state->camera_streaming || state->camera_fd < 0 ||
      !state->ui_framebuffer) {
    return ESP_ERR_INVALID_STATE;
  }
  v4l2_buffer frame = {};
  frame.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
  frame.memory = V4L2_MEMORY_MMAP;
  if (ioctl(state->camera_fd, VIDIOC_DQBUF, &frame) != 0 ||
      frame.index >= state->camera_buffer_count || frame.bytesused == 0 ||
      frame.bytesused > state->camera_buffers[frame.index].length) {
    ESP_LOGE(kTag, "camera preview dequeue failed: errno=%d", errno);
    return ESP_FAIL;
  }

  constexpr int kPreviewY = 48;
  constexpr int kPreviewHeight = 180;
  const int source_width =
      static_cast<int>(state->camera_width.load(std::memory_order_acquire));
  const int source_height =
      static_cast<int>(state->camera_height.load(std::memory_order_acquire));
  const auto *source =
      static_cast<const uint8_t *>(state->camera_buffers[frame.index].start);

  const bool capture_confirmation =
      state->consent_pending.load(std::memory_order_acquire) &&
      static_cast<ConsentKind>(state->pending_consent_kind.load(
          std::memory_order_acquire)) == ConsentKind::kCamera;
  ui_draw_header(state, capture_confirmation ? "CAMERA CONFIRMATION"
                                             : "LIVE CAMERA PREVIEW");
  bool valid =
      source_width > 1 && source_height > 0 &&
      frame.bytesused >= static_cast<size_t>(source_width * source_height * 2);
  if (valid) {
    for (int y = 0; y < kPreviewHeight; ++y) {
      const int source_y = y * source_height / kPreviewHeight;
      uint16_t *destination =
          state->ui_framebuffer + (kPreviewY + y) * kDisplayWidth;
      for (int x = 0; x < kDisplayWidth; ++x) {
        const int source_x = x * source_width / kDisplayWidth;
        const size_t pair =
            static_cast<size_t>(source_y * source_width + (source_x & ~1)) * 2;
        const uint8_t luminance = source[pair + ((source_x & 1) ? 2 : 0)];
        destination[x] =
            yuyv_to_rgb565(luminance, source[pair + 1], source[pair + 3]);
      }
    }
  } else {
    ui_fill_rect(state, 0, kPreviewY, kDisplayWidth, kPreviewHeight, kUiRed);
    ui_draw_text(state, 36, 124, "NO CAMERA", 2, kUiWhite);
  }

  uint32_t checksum = 2166136261U;
  for (size_t index = 0; index < frame.bytesused; index += 97) {
    checksum = (checksum ^ source[index]) * 16777619U;
  }
  state->camera_checksum.store(checksum, std::memory_order_release);
  state->camera_ok.store(valid, std::memory_order_release);

  const int queue_result = ioctl(state->camera_fd, VIDIOC_QBUF, &frame);
  if (queue_result != 0) {
    ESP_LOGE(kTag, "camera preview requeue failed: errno=%d", errno);
    return ESP_FAIL;
  }

  ui_fill_rect(state, 0, 228, kDisplayWidth, 92, kUiBackground);
  if (capture_confirmation) {
    ui_draw_text(state, 12, 238, "NOT UPLOADED YET", 2, kUiGreen);
    ui_draw_text(state, 12, 264, "BOOT: TAKE PHOTO", 2, kUiWhite);
    ui_draw_text(state, 12, 290, "VOL-: CANCEL", 2, kUiMuted);
  } else {
    ui_draw_text(state, 12, 238, "CAMERA 320X240", 2, kUiGreen);
    ui_draw_text(state, 12, 264, "TAP: MIC", 2, kUiWhite);
    ui_draw_text(state, 12, 290, "HOLD: RETEST", 2, kUiMuted);
  }
  return valid ? ui_flush(state) : ESP_FAIL;
}

i2s_std_config_t audio_config(int sample_rate, gpio_num_t clock,
                              gpio_num_t word_select, gpio_num_t data_out,
                              gpio_num_t data_in) {
  return {
      .clk_cfg =
          {
              .sample_rate_hz = static_cast<uint32_t>(sample_rate),
              .clk_src = I2S_CLK_SRC_DEFAULT,
              .ext_clk_freq_hz = 0,
              .mclk_multiple = I2S_MCLK_MULTIPLE_256,
              .bclk_div = 0,
          },
      .slot_cfg =
          {
              .data_bit_width = I2S_DATA_BIT_WIDTH_32BIT,
              .slot_bit_width = I2S_SLOT_BIT_WIDTH_AUTO,
              .slot_mode = I2S_SLOT_MODE_MONO,
              .slot_mask = I2S_STD_SLOT_LEFT,
              .ws_width = I2S_DATA_BIT_WIDTH_32BIT,
              .ws_pol = false,
              .bit_shift = true,
              .left_align = true,
              .big_endian = false,
              .bit_order_lsb = false,
          },
      .gpio_cfg =
          {
              .mclk = I2S_GPIO_UNUSED,
              .bclk = clock,
              .ws = word_select,
              .dout = data_out,
              .din = data_in,
              .invert_flags = {},
          },
  };
}

esp_err_t initialize_audio(BringupState *state) {
  i2s_chan_config_t channel =
      I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_0, I2S_ROLE_MASTER);
  channel.dma_desc_num = 6;
  channel.dma_frame_num = 240;
  channel.auto_clear_after_cb = true;
  esp_err_t error = i2s_new_channel(&channel, &state->speaker, nullptr);
  i2s_std_config_t speaker_config =
      audio_config(kOutputSampleRate, kSpeakerClock, kSpeakerWordSelect,
                   kSpeakerData, I2S_GPIO_UNUSED);
  if (error == ESP_OK) {
    error = i2s_channel_init_std_mode(state->speaker, &speaker_config);
  }

  channel = I2S_CHANNEL_DEFAULT_CONFIG(I2S_NUM_1, I2S_ROLE_MASTER);
  channel.dma_desc_num = 6;
  channel.dma_frame_num = 240;
  i2s_std_config_t microphone_config = audio_config(
      kInputSampleRate, kMicClock, kMicWordSelect, I2S_GPIO_UNUSED, kMicData);
  if (error == ESP_OK) {
    error = i2s_new_channel(&channel, nullptr, &state->microphone);
  }
  if (error == ESP_OK) {
    error = i2s_channel_init_std_mode(state->microphone, &microphone_config);
  }
  return error;
}

int16_t triangle_sample(int index) {
  const int period = kOutputSampleRate / kToneHz;
  const int position = index % period;
  const int half = period / 2;
  constexpr int amplitude = 9000;
  return static_cast<int16_t>(
      position < half ? -amplitude + 2 * amplitude * position / half
                      : amplitude - 2 * amplitude * (position - half) / half);
}

esp_err_t test_audio(BringupState *state) {
  if (!state || !state->speaker || !state->microphone) {
    if (state) {
      state->audio_ok.store(false, std::memory_order_release);
      state->speaker_ok.store(false, std::memory_order_release);
      state->microphone_ok.store(false, std::memory_order_release);
    }
    return ESP_ERR_INVALID_STATE;
  }
  auto *output = static_cast<int32_t *>(heap_caps_malloc(
      kToneSamples * sizeof(int32_t), MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL));
  auto *input = static_cast<int32_t *>(heap_caps_malloc(
      kCaptureSamples * sizeof(int32_t), MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL));
  if (!output || !input) {
    heap_caps_free(output);
    heap_caps_free(input);
    return ESP_ERR_NO_MEM;
  }
  const int volume =
      state->output_volume_percent.load(std::memory_order_acquire);
  for (int index = 0; index < kToneSamples; ++index) {
    output[index] = scale_speaker_sample(triangle_sample(index), volume);
  }
  esp_err_t tone_error = i2s_channel_enable(state->speaker);
  size_t written = 0;
  if (tone_error == ESP_OK) {
    tone_error = i2s_channel_write(state->speaker, output,
                                   kToneSamples * sizeof(int32_t), &written,
                                   pdMS_TO_TICKS(1000));
  }
  const esp_err_t speaker_close_error = i2s_channel_disable(state->speaker);
  if (tone_error == ESP_OK) {
    tone_error = speaker_close_error;
  }
  esp_err_t mic_error = i2s_channel_enable(state->microphone);
  size_t read = 0;
  if (mic_error == ESP_OK) {
    // Discard the first DMA window so startup zeros cannot create a false
    // microphone pass immediately after enabling the channel.
    mic_error = i2s_channel_read(state->microphone, input,
                                 kCaptureSamples * sizeof(int32_t), &read,
                                 pdMS_TO_TICKS(1000));
  }
  if (mic_error == ESP_OK) {
    read = 0;
    mic_error = i2s_channel_read(state->microphone, input,
                                 kCaptureSamples * sizeof(int32_t), &read,
                                 pdMS_TO_TICKS(1000));
  }
  const esp_err_t mic_close_error = i2s_channel_disable(state->microphone);
  if (mic_error == ESP_OK) {
    mic_error = mic_close_error;
  }
  uint32_t peak = 0;
  uint64_t total = 0;
  const size_t samples = read / sizeof(int32_t);
  for (size_t index = 0; index < samples; ++index) {
    const int32_t scaled = input[index] >> 12;
    const uint32_t absolute = static_cast<uint32_t>(
        scaled < 0 ? -static_cast<int64_t>(scaled) : scaled);
    peak = std::max(peak, absolute);
    total += absolute;
  }
  state->mic_peak.store(peak, std::memory_order_release);
  state->mic_mean_abs.store(samples ? static_cast<uint32_t>(total / samples)
                                    : 0,
                            std::memory_order_release);
  heap_caps_free(output);
  heap_caps_free(input);
  const bool speaker_passed =
      tone_error == ESP_OK && written == kToneSamples * sizeof(int32_t);
  const bool microphone_passed =
      mic_error == ESP_OK && samples == kCaptureSamples && peak > 0;
  const bool passed = speaker_passed && microphone_passed;
  state->speaker_ok.store(speaker_passed, std::memory_order_release);
  state->microphone_ok.store(microphone_passed, std::memory_order_release);
  state->audio_ok.store(passed, std::memory_order_release);
  if (passed) {
    ESP_LOGI(kTag, "[PASS] simplex I2S speaker/microphone; mic_peak=%u mean=%u",
             static_cast<unsigned>(peak),
             static_cast<unsigned>(
                 state->mic_mean_abs.load(std::memory_order_acquire)));
    return ESP_OK;
  }
  ESP_LOGE(kTag,
           "[FAIL] audio speaker=%s (%u bytes) microphone=%s (%u samples)",
           esp_err_to_name(tone_error), static_cast<unsigned>(written),
           esp_err_to_name(mic_error), static_cast<unsigned>(samples));
  return ESP_FAIL;
}

esp_err_t stop_microphone_monitor(BringupState *state) {
  if (!state || !state->microphone_monitoring) {
    return ESP_OK;
  }
  const esp_err_t error = i2s_channel_disable(state->microphone);
  state->microphone_monitoring = false;
  return error;
}

esp_err_t ui_draw_microphone_meter(BringupState *state) {
  if (!state || !state->microphone || !state->ui_framebuffer) {
    return ESP_ERR_INVALID_STATE;
  }
  if (!state->microphone_monitoring) {
    const esp_err_t enable_error = i2s_channel_enable(state->microphone);
    if (enable_error != ESP_OK) {
      return enable_error;
    }
    state->microphone_monitoring = true;
  }

  constexpr size_t kMeterSamples = 320;
  int32_t samples[kMeterSamples] = {};
  size_t bytes_read = 0;
  const esp_err_t read_error =
      i2s_channel_read(state->microphone, samples, sizeof(samples), &bytes_read,
                       pdMS_TO_TICKS(250));
  if (read_error != ESP_OK) {
    return read_error;
  }

  const size_t sample_count = bytes_read / sizeof(samples[0]);
  uint32_t peak = 0;
  uint64_t total = 0;
  for (size_t index = 0; index < sample_count; ++index) {
    const int32_t scaled = samples[index] >> 12;
    const uint32_t absolute = static_cast<uint32_t>(
        scaled < 0 ? -static_cast<int64_t>(scaled) : scaled);
    peak = std::max(peak, absolute);
    total += absolute;
  }
  const uint32_t mean =
      sample_count ? static_cast<uint32_t>(total / sample_count) : 0;
  state->mic_peak.store(peak, std::memory_order_release);
  state->mic_mean_abs.store(mean, std::memory_order_release);
  state->microphone_ok.store(sample_count == kMeterSamples && peak > 0,
                             std::memory_order_release);

  ui_draw_header(state, "LIVE MICROPHONE");
  ui_draw_text(state, 18, 72, "SPEAK NOW", 2, kUiWhite);
  ui_draw_text(state, 18, 108, "INPUT LEVEL", 2, kUiMuted);
  ui_fill_rect(state, 18, 132, 204, 32, kUiCardAlt);
  const int meter_width = std::min(
      200, static_cast<int>((static_cast<uint64_t>(peak) * 200) / 30000));
  if (meter_width > 0) {
    ui_fill_rect(state, 20, 134, meter_width, 28,
                 meter_width > 170 ? kUiYellow : kUiGreen);
  }
  char detail[32] = {};
  std::snprintf(detail, sizeof(detail), "PEAK %u", static_cast<unsigned>(peak));
  ui_fill_rect(state, 18, 178, 204, 40, kUiCard);
  ui_draw_text(state, 30, 194, detail, 2, kUiCyan);
  ui_fill_rect(state, 0, 228, kDisplayWidth, 92, kUiBackground);
  ui_draw_text(state, 12, 238, "SPEAK: WATCH BAR", 2, kUiGreen);
  ui_draw_text(state, 12, 264, "TAP: AGENT", 2, kUiWhite);
  ui_draw_text(state, 12, 290, "HOLD: RETEST", 2, kUiMuted);
  return ui_flush(state);
}

esp_err_t ui_draw_agent_result(BringupState *state, int outcome) {
  if (!state || !state->ui_framebuffer) {
    return ESP_ERR_INVALID_STATE;
  }
  ui_draw_header(state, "LOCAL AGENT TEST");
  ui_draw_text(state, 18, 64, "USER APPROVED", 2, kUiGreen);
  ui_draw_text(state, 18, 101, "ESP-CLAW TOOL", 2, kUiWhite);
  ui_draw_text(state, 18, 137, "SET INDICATOR", 2, kUiCyan);
  const bool running = outcome < 0;
  const bool passed = outcome > 0;
  ui_fill_rect(state, 18, 190, 204, 54,
               running ? kUiYellow : (passed ? kUiGreen : kUiRed));
  ui_draw_text(state, running ? 68 : (passed ? 62 : 62), 206,
               running ? "RUNNING" : (passed ? "AGENT PASS" : "AGENT FAIL"), 2,
               0x0000);
  ui_draw_text(state, 18, 278, "BACK TO STATUS", 2, kUiMuted);
  return ui_flush(state);
}

const char *wifi_status_value(product_wifi_state_t wifi_state) {
  switch (wifi_state) {
  case PRODUCT_WIFI_STATE_ONLINE:
    return "ONLINE";
  case PRODUCT_WIFI_STATE_ONBOARDING:
    return "SETUP";
  case PRODUCT_WIFI_STATE_CONNECTING:
    return "SEARCH";
  case PRODUCT_WIFI_STATE_BACKOFF:
    return "SEARCH";
  case PRODUCT_WIFI_STATE_CREDENTIAL_REJECTED:
    return "CHECK";
  case PRODUCT_WIFI_STATE_FATAL:
    return "FAIL";
  case PRODUCT_WIFI_STATE_UNPROVISIONED:
    return "NOT SET";
  default:
    return "START";
  }
}

uint16_t wifi_status_color(product_wifi_state_t wifi_state) {
  switch (wifi_state) {
  case PRODUCT_WIFI_STATE_ONLINE:
    return kUiGreen;
  case PRODUCT_WIFI_STATE_FATAL:
  case PRODUCT_WIFI_STATE_CREDENTIAL_REJECTED:
    return kUiRed;
  case PRODUCT_WIFI_STATE_ONBOARDING:
    return kUiCyan;
  default:
    return kUiYellow;
  }
}

esp_err_t ui_draw_wifi_setup(BringupState *state) {
  if (!state || !state->ui_framebuffer) {
    return ESP_ERR_INVALID_STATE;
  }
  product_wifi_stats_t stats = {};
  const unsigned saved_networks =
      state->wifi && product_wifi_get_stats(state->wifi, &stats) == ESP_OK
          ? static_cast<unsigned>(stats.saved_networks)
          : 0;
  if (state->wifi_online.load(std::memory_order_acquire)) {
    ui_draw_header(state, "WIFI CONNECTED");
    ui_draw_text(state, 34, 82, "CONNECTION", 2, kUiWhite);
    ui_draw_text(state, 58, 119, "SUCCESS", 2, kUiGreen);
    ui_fill_rect(state, 18, 166, 204, 50, kUiGreen);
    ui_draw_text(state, 24, 181, "NETWORK READY", 2, 0x0000);
    char saved[24] = {};
    std::snprintf(saved, sizeof(saved), "SAVED WIFI %u/5", saved_networks);
    ui_draw_text(state, 24, 248, saved, 2, kUiCyan);
    ui_draw_text(state, 30, 278, "AUTO SWITCH READY", 2, kUiMuted);
    return ui_flush(state);
  }

  ui_draw_header(
      state, state->wifi_credentials_rejected.load(std::memory_order_acquire)
                 ? "WIFI CHECK PASSWORD"
                 : "WIFI SETUP 5 MIN");
  ui_draw_text(state, 14, 58, "1 CONNECT PHONE", 2, kUiWhite);
  ui_fill_rect(state, 12, 80, 216, 34, kUiCard);
  ui_draw_text(state, 18, 90, state->wifi_ap_ssid, 2, kUiCyan);
  ui_draw_text(state, 14, 124, "PASSWORD", 2, kUiMuted);
  ui_fill_rect(state, 12, 145, 216, 36, kUiCard);
  const int password_width =
      static_cast<int>(std::strlen(state->wifi_ap_password)) * 18;
  ui_draw_text(state, (kDisplayWidth - password_width) / 2, 153,
               state->wifi_ap_password, 3, kUiYellow);
  ui_draw_text(state, 14, 194, "2 OPEN BROWSER", 2, kUiWhite);
  ui_fill_rect(state, 12, 216, 216, 38, kUiCardAlt);
  ui_draw_text(state, 45, 228, "192.168.4.1", 2, kUiGreen);
  ui_fill_rect(state, 0, 270, kDisplayWidth, 50, kUiHeader);
  char footer[28] = {};
  if (state->wifi_credentials_rejected.load(std::memory_order_acquire)) {
    std::snprintf(footer, sizeof(footer), "CHECK AND TRY AGAIN");
  } else {
    std::snprintf(footer, sizeof(footer), "SAVED %u/5", saved_networks);
  }
  ui_draw_text(state, 6, 286, footer, 2, kUiWhite);
  return ui_flush(state);
}

const char *cloud_status_value(CloudStage stage) {
  switch (stage) {
  case CloudStage::kFetching:
    return "VOICE CONNECT";
  case CloudStage::kNeedsActivation:
    return "VOICE ACTIVATE";
  case CloudStage::kActivating:
    return "VOICE LINKING";
  case CloudStage::kReady:
    return "VOICE READY";
  case CloudStage::kError:
    return "VOICE RETRY";
  default:
    return "VOICE OFFLINE";
  }
}

uint16_t cloud_status_color(CloudStage stage) {
  switch (stage) {
  case CloudStage::kReady:
    return kUiGreen;
  case CloudStage::kError:
    return kUiRed;
  case CloudStage::kNeedsActivation:
    return kUiYellow;
  default:
    return kUiCyan;
  }
}

esp_err_t ui_draw_cloud_activation(BringupState *state) {
  if (!state || !state->ui_framebuffer) {
    return ESP_ERR_INVALID_STATE;
  }
  const auto stage = static_cast<CloudStage>(
      state->cloud_stage.load(std::memory_order_acquire));
  if (stage == CloudStage::kNeedsActivation) {
    ui_draw_header(state, "VOICE AGENT SETUP");
    ui_draw_text(state, 14, 61, "1 OPEN ON PHONE", 1, kUiWhite);
    ui_fill_rect(state, 12, 79, 216, 40, kUiCard);
    ui_draw_text(state, 60, 91, "XIAOZHI.ME", 2, kUiCyan);
    ui_draw_text(state, 14, 137, "2 ENTER CODE", 1, kUiWhite);
    ui_fill_rect(state, 12, 156, 216, 58, kUiCardAlt);
    const char *code =
        state->activation_code[0] ? state->activation_code : "WAIT";
    const size_t code_length = std::strlen(code);
    const int scale = code_length <= 7 ? 3 : 2;
    const int width = static_cast<int>(code_length) * 6 * scale;
    ui_draw_text(state, std::max(8, (kDisplayWidth - width) / 2),
                 scale == 3 ? 174 : 179, code, scale, kUiYellow);
    ui_draw_text(state, 27, 237, "WAITING FOR APPROVAL", 1, kUiGreen);
    ui_draw_text(state, 18, 260, "AUTO CONTINUES AFTER LINK", 1, kUiMuted);
    ui_draw_text(state, 27, 291, "NO API KEY ON DEVICE", 1, kUiMuted);
    return ui_flush(state);
  }
  if (stage == CloudStage::kReady) {
    ui_draw_header(state, "VOICE AGENT LINK");
    ui_draw_text(state, 34, 78, "AGENT CLOUD", 2, kUiWhite);
    ui_draw_text(state, 61, 113, "CONNECTED", 2, kUiGreen);
    ui_fill_rect(state, 18, 164, 204, 48, kUiGreen);
    ui_draw_text(state, 48, 181, "VOICE SERVICE READY", 1, 0x0000);
    ui_draw_text(state, 57, 238, "ESP-CLAW READY", 1, kUiCyan);
    ui_draw_text(state, 48, 288, "TAP: DEVICE STATUS", 1, kUiWhite);
    return ui_flush(state);
  }
  ui_draw_header(state, stage == CloudStage::kError ? "VOICE AGENT RETRY"
                                                    : "VOICE AGENT LINK");
  ui_draw_text(state, 30, 84,
               stage == CloudStage::kError ? "LINK TEMPORARILY"
                                           : "SECURE CLOUD",
               2, kUiWhite);
  ui_draw_text(state, stage == CloudStage::kError ? 66 : 54, 120,
               stage == CloudStage::kError ? "UNAVAILABLE" : "CONNECTING", 2,
               stage == CloudStage::kError ? kUiYellow : kUiCyan);
  ui_fill_rect(state, 18, 174, 204, 8, kUiCardAlt);
  ui_fill_rect(state, 18, 174, stage == CloudStage::kActivating ? 170 : 90, 8,
               kUiGreen);
  ui_draw_text(state, 42, 220,
               stage == CloudStage::kError ? "AUTO RETRY IN 30 SEC"
                                           : "PLEASE WAIT",
               1, kUiMuted);
  ui_draw_text(state, 27, 291, "NO API KEY ON DEVICE", 1, kUiMuted);
  return ui_flush(state);
}

esp_err_t ui_draw_voice(BringupState *state) {
  if (!state || !state->ui_framebuffer) {
    return ESP_ERR_INVALID_STATE;
  }
  const auto stage = static_cast<VoiceStage>(
      state->voice_stage.load(std::memory_order_acquire));
  ui_draw_header(state, "VOICE AGENT");
  const char *headline = "CONNECTING";
  const char *instruction = "PLEASE WAIT";
  uint16_t color = kUiCyan;
  switch (stage) {
  case VoiceStage::kReady:
    headline = "READY";
    instruction = "TAP TO TALK";
    color = kUiGreen;
    break;
  case VoiceStage::kListening:
    headline = "LISTENING";
    instruction = "PAUSE TO AUTO END";
    color = kUiYellow;
    break;
  case VoiceStage::kThinking:
    headline = "THINKING";
    instruction = "TAP TO CANCEL";
    color = kUiCyan;
    break;
  case VoiceStage::kSpeaking:
    headline = "SPEAKING";
    instruction = "TAP TO INTERRUPT";
    color = kUiGreen;
    break;
  case VoiceStage::kError:
    headline = "RECONNECTING";
    instruction = "AUTO RETRY";
    color = kUiYellow;
    break;
  default:
    break;
  }
  const int headline_scale = 3;
  const int headline_width =
      static_cast<int>(std::strlen(headline)) * 6 * headline_scale;
  ui_draw_text(state, std::max(8, (kDisplayWidth - headline_width) / 2), 72,
               headline, headline_scale, color);
  ui_fill_rect(state, 18, 119, 204, 64, kUiCardAlt);
  if (stage == VoiceStage::kListening) {
    const uint32_t peak = state->mic_peak.load(std::memory_order_acquire);
    const int meter_width = std::min(
        196, static_cast<int>((static_cast<uint64_t>(peak) * 196) / 30000));
    ui_fill_rect(state, 22, 144, 196, 18, kUiCard);
    if (meter_width > 0) {
      ui_fill_rect(state, 22, 144, meter_width, 18, kUiYellow);
    }
  } else {
    ui_draw_text(state, 30, 143, "AGENT LINKED", 2, kUiCyan);
  }
  const int instruction_width =
      static_cast<int>(std::strlen(instruction)) * 12;
  ui_draw_text(state, std::max(8, (kDisplayWidth - instruction_width) / 2), 211,
               instruction, 2, kUiWhite);
  ui_draw_text(state, 24, 241, "SAFE TOOLS READY", 2, kUiGreen);
  ui_fill_rect(state, 0, 270, kDisplayWidth, 50, kUiHeader);
  ui_draw_text(state, 12, 277,
               stage == VoiceStage::kListening ? "TAP: FINISH"
               : stage == VoiceStage::kThinking
                   ? "TAP: CANCEL"
                   : "TAP: TALK",
               2, kUiWhite);
  ui_draw_text(state, 12, 301, "VOL-       VOL+", 2, kUiCyan);
  return ui_flush(state);
}

esp_err_t ui_draw_consent(BringupState *state) {
  if (!state || !state->ui_framebuffer ||
      !state->consent_pending.load(std::memory_order_acquire)) {
    return ESP_ERR_INVALID_STATE;
  }
  ui_draw_header(state, "AGENT CONFIRMATION");
  ui_draw_text(state, 18, 66, "ALLOW THIS ACTION", 2, kUiYellow);
  ui_fill_rect(state, 12, 96, 216, 74, kUiCardAlt);
  const size_t summary_length = std::strlen(state->pending_consent_summary);
  const int summary_scale = summary_length <= 17 ? 2 : 1;
  const int summary_width =
      static_cast<int>(summary_length) * 6 * summary_scale;
  ui_draw_text(state, std::max(6, (kDisplayWidth - summary_width) / 2),
               summary_scale == 2 ? 121 : 129, state->pending_consent_summary,
               summary_scale, kUiWhite);
  ui_fill_rect(state, 14, 190, 212, 44, kUiGreen);
  ui_draw_text(state, 42, 205, "BOOT: APPROVE", 2, 0x0000);
  ui_fill_rect(state, 14, 242, 212, 44, kUiRed);
  ui_draw_text(state, 54, 257, "VOL-: DENY", 2, kUiWhite);
  ui_draw_text(state, 24, 299, "AUTO DENY 20 SEC", 2, kUiMuted);
  return ui_flush(state);
}

esp_err_t ui_draw_voice_enrollment(BringupState *state) {
  if (!state || !state->ui_framebuffer ||
      std::strlen(state->voice_enrollment_code) != 6) {
    return ESP_ERR_INVALID_STATE;
  }
  ui_draw_header(state, "MY VOICE SETUP");
  ui_draw_text(state, 18, 62, "OPEN GATEWAY PAGE", 2, kUiWhite);
  ui_fill_rect(state, 12, 88, 216, 40, kUiCardAlt);
  ui_draw_text(state, 69, 101, "/VOICE", 2, kUiCyan);
  ui_draw_text(state, 30, 151, "ENTER THIS CODE", 2, kUiMuted);
  ui_fill_rect(state, 12, 176, 216, 62, kUiCard);
  ui_draw_text(state, 39, 192, state->voice_enrollment_code, 3, kUiYellow);
  ui_draw_text(state, 18, 255, "RECORD YOUR VOICE", 2, kUiGreen);
  ui_draw_text(state, 48, 280, "CODE: 10 MIN", 2, kUiMuted);
  ui_fill_rect(state, 0, 301, kDisplayWidth, 19, kUiHeader);
  ui_draw_text(state, 60, 304, "BOOT: BACK", 2, kUiWhite);
  return ui_flush(state);
}

esp_err_t ui_draw_volume(BringupState *state) {
  if (!state || !state->ui_framebuffer) {
    return ESP_ERR_INVALID_STATE;
  }
  const int volume =
      state->output_volume_percent.load(std::memory_order_acquire);
  ui_draw_header(state, "SPEAKER VOLUME");
  char value[8] = {};
  std::snprintf(value, sizeof(value), "%d%%", volume);
  const int value_width = static_cast<int>(std::strlen(value)) * 18;
  ui_draw_text(state, std::max(12, (kDisplayWidth - value_width) / 2), 82,
               value, 3, volume == 0 ? kUiMuted : kUiGreen);
  ui_fill_rect(state, 18, 155, 204, 28, kUiCardAlt);
  const int meter_width = volume * 200 / 100;
  if (meter_width > 0) {
    ui_fill_rect(state, 20, 157, meter_width, 24, kUiCyan);
  }
  ui_draw_text(state, 24, 210, "VOL-       VOL+", 2, kUiWhite);
  ui_draw_text(state, 72, 247, "SAVED", 2, kUiGreen);
  ui_draw_text(state, 48, 286, "TRAVEL READY", 2, kUiMuted);
  return ui_flush(state);
}

esp_err_t ui_draw_dashboard(BringupState *state) {
  if (!state || !state->ui_framebuffer) {
    return ESP_ERR_INVALID_STATE;
  }
  const bool camera_ok = state->camera_ok.load(std::memory_order_acquire);
  const bool microphone_ok =
      state->microphone_ok.load(std::memory_order_acquire);
  const bool speaker_ok = state->speaker_ok.load(std::memory_order_acquire);
  const bool agent_ready =
      state->claw && (!state->agent_action_tested || state->agent_action_ok);
  const auto wifi_state = static_cast<product_wifi_state_t>(
      state->wifi_state.load(std::memory_order_acquire));
  const auto cloud_stage = static_cast<CloudStage>(
      state->cloud_stage.load(std::memory_order_acquire));

  ui_draw_header(state, "DEVICE STATUS");
  ui_draw_status_row(state, 51, "WIFI", wifi_status_value(wifi_state),
                     wifi_status_color(wifi_state));
  ui_draw_status_row(state, 87, "CAMERA", camera_ok ? "PASS" : "FAIL",
                     camera_ok ? kUiGreen : kUiRed);
  ui_draw_status_row(state, 123, "MICROPHONE", microphone_ok ? "PASS" : "FAIL",
                     microphone_ok ? kUiGreen : kUiRed);
  ui_draw_status_row(state, 159, "SPEAKER", speaker_ok ? "PASS" : "FAIL",
                     speaker_ok ? kUiGreen : kUiRed);
  ui_draw_status_row(state, 195, "ESP-CLAW",
                     state->agent_action_tested
                         ? (state->agent_action_ok ? "PASS" : "FAIL")
                         : "READY",
                     agent_ready ? kUiGreen : kUiRed);

  char detail[40] = {};
  std::snprintf(
      detail, sizeof(detail), "RUN %u  MIC %u  VOL %d%%",
      static_cast<unsigned>(state->test_count.load(std::memory_order_acquire)),
      static_cast<unsigned>(state->mic_peak.load(std::memory_order_acquire)),
      state->output_volume_percent.load(std::memory_order_acquire));
  ui_draw_text(state, 12, 235, detail, 1, kUiMuted);
  ui_draw_text(state, 12, 250, cloud_status_value(cloud_stage), 2,
               cloud_status_color(cloud_stage));
  ui_fill_rect(state, 0, 270, kDisplayWidth, 50, kUiHeader);
  ui_draw_text(state, 12, 278,
               cloud_stage == CloudStage::kReady ? "TAP: VOICE"
                                                 : "TAP: CAMERA",
               2, kUiWhite);
  ui_draw_text(state, 12, 300, "HOLD 4S: WIFI", 2, kUiCyan);
  return ui_flush(state);
}

bool wait_for_wifi_condition(BringupState *state, bool require_softap,
                             uint32_t timeout_ms) {
  const TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(timeout_ms);
  do {
    product_wifi_stats_t stats = {};
    if (product_wifi_get_stats(state->wifi, &stats) == ESP_OK &&
        stats.onboarding_active &&
        (!require_softap || stats.onboarding_softap_active)) {
      return true;
    }
    vTaskDelay(pdMS_TO_TICKS(20));
  } while (xTaskGetTickCount() < deadline);
  return false;
}

esp_err_t start_wifi_onboarding(BringupState *state) {
  if (!state || !state->wifi) {
    return ESP_ERR_INVALID_STATE;
  }
  (void)stop_microphone_monitor(state);
  product_wifi_stats_t stats = {};
  esp_err_t error = product_wifi_get_stats(state->wifi, &stats);
  if (error != ESP_OK) {
    return error;
  }
  if (!stats.onboarding_active) {
    error = product_wifi_begin_onboarding(state->wifi);
    if (error != ESP_OK || !wait_for_wifi_condition(state, false, 1500)) {
      return error == ESP_OK ? ESP_ERR_TIMEOUT : error;
    }
  }
  product_wifi_get_stats(state->wifi, &stats);
  if (!stats.onboarding_softap_active) {
    const product_wifi_softap_config_t config = {
        .ssid = {},
        .password = {},
        .channel = 1,
    };
    auto softap = config;
    std::snprintf(softap.ssid, sizeof(softap.ssid), "%s", state->wifi_ap_ssid);
    std::snprintf(softap.password, sizeof(softap.password), "%s",
                  state->wifi_ap_password);
    error = product_wifi_start_onboarding_softap(state->wifi, &softap);
    if (error != ESP_OK || !wait_for_wifi_condition(state, true, 2000)) {
      return error == ESP_OK ? ESP_ERR_TIMEOUT : error;
    }
  }
  error = start_wifi_portal(state);
  if (error != ESP_OK) {
    (void)product_wifi_finish_onboarding(state->wifi);
    return error;
  }
  state->wifi_credentials_rejected.store(false, std::memory_order_release);
  state->wifi_onboarding_started_us = esp_timer_get_time();
  state->wifi_online_since_us = 0;
  state->ui_page = UiPage::kWifiSetup;
  state->wifi_ui_dirty.store(false, std::memory_order_release);
  ESP_LOGI(kTag, "Physical-presence Wi-Fi setup opened for five minutes at "
                 "192.168.4.1; credentials are never logged");
  return ui_draw_wifi_setup(state);
}

void service_wifi(BringupState *state) {
  if (!state || !state->wifi) {
    return;
  }
  product_wifi_stats_t stats = {};
  if (product_wifi_get_stats(state->wifi, &stats) != ESP_OK) {
    return;
  }
  state->wifi_state.store(stats.state, std::memory_order_release);
  state->wifi_online.store(stats.network_available, std::memory_order_release);
  const int64_t now_us = esp_timer_get_time();
  const bool searching_saved_network =
      stats.has_credentials && !stats.onboarding_active &&
      !stats.network_available &&
      (stats.state == PRODUCT_WIFI_STATE_CONNECTING ||
       stats.state == PRODUCT_WIFI_STATE_BACKOFF);
  if (stats.network_available) {
    state->wifi_offline_since_us = 0;
  } else if (searching_saved_network) {
    if (state->wifi_offline_since_us == 0) {
      state->wifi_offline_since_us = now_us;
    } else if (now_us - state->wifi_offline_since_us >=
               kWifiStationRecoveryUs) {
      const esp_err_t recovery = product_wifi_recover_station(state->wifi);
      if (recovery == ESP_OK) {
        state->wifi_offline_since_us = now_us;
        state->wifi_ui_dirty.store(true, std::memory_order_release);
        ESP_LOGW(kTag,
                 "Wi-Fi remained offline for 60 seconds; station radio "
                 "restarted and all channels will be searched again");
      } else if (recovery != ESP_ERR_INVALID_STATE) {
        ESP_LOGW(kTag, "Wi-Fi station self-recovery request failed: %s",
                 esp_err_to_name(recovery));
      }
    }
  } else {
    state->wifi_offline_since_us = 0;
  }
  if (stats.onboarding_active && stats.network_available &&
      state->wifi_online_since_us == 0) {
    state->wifi_online_since_us = now_us;
    state->wifi_ui_dirty.store(true, std::memory_order_release);
  }
  const bool success_complete =
      stats.onboarding_active && state->wifi_online_since_us > 0 &&
      now_us - state->wifi_online_since_us >= kWifiSuccessDisplayUs;
  const bool timed_out =
      stats.onboarding_active && state->wifi_onboarding_started_us > 0 &&
      now_us - state->wifi_onboarding_started_us >= kWifiSetupTimeoutUs;
  if (success_complete || timed_out) {
    stop_wifi_portal(state);
    (void)product_wifi_finish_onboarding(state->wifi);
    state->wifi_onboarding_started_us = 0;
    state->wifi_online_since_us = 0;
    state->ui_page = UiPage::kStatus;
    ESP_LOGI(kTag, "Wi-Fi setup window closed: %s",
             success_complete ? "connection validated" : "timeout");
    (void)ui_draw_dashboard(state);
    return;
  }
  if (state->wifi_ui_dirty.exchange(false, std::memory_order_acq_rel)) {
    if (state->ui_page == UiPage::kWifiSetup) {
      (void)ui_draw_wifi_setup(state);
    } else if (state->ui_page == UiPage::kStatus) {
      (void)ui_draw_dashboard(state);
    }
  }
}

void service_cloud(BringupState *state) {
  if (!state) {
    return;
  }
  const int64_t now_us = esp_timer_get_time();
  const bool online = state->wifi_online.load(std::memory_order_acquire);
  const auto stage = static_cast<CloudStage>(
      state->cloud_stage.load(std::memory_order_acquire));
  const bool retry_due =
      stage == CloudStage::kError && now_us >= state->cloud_retry_after_us;
  if (online && !state->cloud_task &&
      (stage == CloudStage::kOff || retry_due)) {
    if (xTaskCreate(cloud_bootstrap_task, "s3cam_cloud", 12288, state, 4,
                    &state->cloud_task) != pdPASS) {
      state->cloud_retry_after_us = now_us + kCloudRetryDelayUs;
      set_cloud_stage(state, CloudStage::kError, ESP_ERR_NO_MEM);
    }
  }
  if (!state->cloud_ui_dirty.exchange(false, std::memory_order_acq_rel)) {
    return;
  }
  const auto updated_stage = static_cast<CloudStage>(
      state->cloud_stage.load(std::memory_order_acquire));
  if (state->ui_page == UiPage::kWifiSetup ||
      state->ui_page == UiPage::kCamera ||
      state->ui_page == UiPage::kMicrophone ||
      state->ui_page == UiPage::kConsent ||
      state->ui_page == UiPage::kVoiceEnrollment) {
    return;
  }
  if (updated_stage == CloudStage::kOff) {
    state->ui_page = UiPage::kStatus;
    (void)ui_draw_dashboard(state);
    return;
  }
  state->ui_page = UiPage::kActivation;
  (void)ui_draw_cloud_activation(state);
}

void decide_agent_consent(BringupState *state, bool approve) {
  if (!state ||
      !state->consent_pending.exchange(false, std::memory_order_acq_rel)) {
    return;
  }
  char request_id[sizeof(state->pending_consent_request_id)] = {};
  std::snprintf(request_id, sizeof(request_id), "%s",
                state->pending_consent_request_id);
  const auto kind = static_cast<ConsentKind>(
      state->pending_consent_kind.load(std::memory_order_acquire));
  const bool device_action = kind == ConsentKind::kDeviceIndicator ||
                             kind == ConsentKind::kDeviceVolume ||
                             kind == ConsentKind::kCamera;
  if (approve && device_action) {
    state->approved_consent_kind.store(static_cast<int>(kind),
                                       std::memory_order_relaxed);
    state->approved_consent_value.store(
        state->pending_consent_value.load(std::memory_order_acquire),
        std::memory_order_relaxed);
    state->approved_consent_flag.store(
        state->pending_consent_flag.load(std::memory_order_acquire),
        std::memory_order_relaxed);
    state->approved_consent_expires_us =
        esp_timer_get_time() + 5 * 1000 * 1000LL;
    state->physical_consent.store(true, std::memory_order_release);
  } else {
    state->physical_consent.store(false, std::memory_order_release);
    state->approved_consent_kind.store(static_cast<int>(ConsentKind::kNone),
                                       std::memory_order_release);
  }
  voice_send_consent_decision(state, request_id,
                              approve ? "approved" : "denied");
  state->pending_consent_kind.store(static_cast<int>(ConsentKind::kNone),
                                    std::memory_order_release);
  state->pending_consent_request_id[0] = '\0';
  state->pending_consent_summary[0] = '\0';
  state->ui_page = UiPage::kActivation;
  state->voice_ui_dirty.store(true, std::memory_order_release);
  ESP_LOGI(kTag, "Agent confirmation decision: %s",
           approve ? "approved" : "denied");
}

void service_agent_consent(BringupState *state) {
  if (!state) {
    return;
  }
  const int64_t now_us = esp_timer_get_time();
  if (state->physical_consent.load(std::memory_order_acquire) &&
      now_us > state->approved_consent_expires_us) {
    state->physical_consent.store(false, std::memory_order_release);
    state->approved_consent_kind.store(static_cast<int>(ConsentKind::kNone),
                                       std::memory_order_release);
  }
  if (state->consent_pending.load(std::memory_order_acquire) &&
      now_us > state->pending_consent_expires_us) {
    decide_agent_consent(state, false);
    return;
  }
  if (state->consent_pending.load(std::memory_order_acquire) &&
      state->consent_ui_dirty.exchange(false, std::memory_order_acq_rel)) {
    const auto kind = static_cast<ConsentKind>(
        state->pending_consent_kind.load(std::memory_order_acquire));
    if (kind == ConsentKind::kCamera) {
      state->ui_page = UiPage::kCamera;
      (void)ui_draw_camera_preview(state);
    } else {
      state->ui_page = UiPage::kConsent;
      (void)ui_draw_consent(state);
    }
  }
}

void service_voice_enrollment(BringupState *state) {
  if (!state || !state->voice_enrollment_ui_dirty.exchange(
                    false, std::memory_order_acq_rel)) {
    return;
  }
  state->ui_page = UiPage::kVoiceEnrollment;
  (void)ui_draw_voice_enrollment(state);
}

void service_voice(BringupState *state) {
  if (!state) {
    return;
  }
  const int64_t now_us = esp_timer_get_time();
  const auto cloud_stage = static_cast<CloudStage>(
      state->cloud_stage.load(std::memory_order_acquire));
  const auto voice_stage = static_cast<VoiceStage>(
      state->voice_stage.load(std::memory_order_acquire));
  const int64_t voice_stage_since_us =
      state->voice_stage_since_us.load(std::memory_order_acquire);
  const int64_t voice_last_audio_us =
      state->voice_last_audio_us.load(std::memory_order_acquire);
  const bool thinking_timed_out =
      voice_stage == VoiceStage::kThinking && voice_stage_since_us > 0 &&
      now_us - voice_stage_since_us >= kVoiceThinkingTimeoutUs;
  const bool speaking_timed_out =
      voice_stage == VoiceStage::kSpeaking && voice_stage_since_us > 0 &&
      now_us - std::max(voice_stage_since_us, voice_last_audio_us) >=
          kVoiceSpeakingTimeoutUs;
  if (thinking_timed_out || speaking_timed_out) {
    ESP_LOGW(kTag, "Voice turn watchdog recovered a stalled %s state",
             thinking_timed_out ? "thinking" : "speaking");
    set_voice_stage(state, VoiceStage::kError, ESP_ERR_TIMEOUT);
  }
  const bool retry_due = voice_stage == VoiceStage::kError &&
                         now_us >= state->voice_retry_after_us;
  if (cloud_stage == CloudStage::kReady && !state->voice_task &&
      (voice_stage == VoiceStage::kOff || retry_due)) {
    if (xTaskCreate(voice_task, "s3cam_voice", 49152, state, 6,
                    &state->voice_task) != pdPASS) {
      state->voice_retry_after_us = now_us + kVoiceRetryDelayUs;
      set_voice_stage(state, VoiceStage::kError, ESP_ERR_NO_MEM);
    }
  }
  if (!state->voice_ui_dirty.load(std::memory_order_acquire)) {
    return;
  }
  const bool listening =
      static_cast<VoiceStage>(state->voice_stage.load(
          std::memory_order_acquire)) == VoiceStage::kListening;
  if (listening && state->voice_last_ui_us > 0 &&
      now_us - state->voice_last_ui_us < 200000) {
    return;
  }
  state->voice_ui_dirty.store(false, std::memory_order_release);
  if (cloud_stage != CloudStage::kReady ||
      state->ui_page == UiPage::kWifiSetup ||
      state->ui_page == UiPage::kCamera ||
      state->ui_page == UiPage::kMicrophone ||
      state->ui_page == UiPage::kConsent ||
      state->ui_page == UiPage::kVoiceEnrollment) {
    return;
  }
  state->ui_page = UiPage::kActivation;
  state->voice_last_ui_us = now_us;
  (void)ui_draw_voice(state);
}

void run_hardware_test(BringupState *state) {
  (void)stop_microphone_monitor(state);
  ESP_LOGI(kTag, "Running display/camera/speaker/microphone diagnostic");
  const esp_err_t display_error = draw_display_pattern(state);
  ui_draw_progress(state, "CAMERA TEST", 1);
  const esp_err_t camera_error = capture_camera_frame(state);
  ui_draw_progress(state,
                   camera_error == ESP_OK ? "CAMERA PASS" : "CAMERA FAIL", 2);
  ui_draw_progress(state, "AUDIO TEST", 2);
  const esp_err_t audio_error = test_audio(state);
  state->test_count.fetch_add(1, std::memory_order_relaxed);
  ESP_LOGI(kTag, "Diagnostic summary display=%s camera=%s audio=%s",
           esp_err_to_name(display_error), esp_err_to_name(camera_error),
           esp_err_to_name(audio_error));
  log_agent_status(state);
  state->ui_page = UiPage::kStatus;
  const esp_err_t ui_error = ui_draw_dashboard(state);
  if (ui_error != ESP_OK) {
    state->display_ok.store(false, std::memory_order_release);
    ESP_LOGE(kTag, "status UI render failed: %s", esp_err_to_name(ui_error));
  }
}

void toggle_backlight_through_agent(BringupState *state) {
  (void)stop_microphone_monitor(state);
  ui_draw_agent_result(state, -1);
  const bool was_on = state->backlight_on.load(std::memory_order_acquire);
  const bool target = !was_on;
  char input[24] = {};
  char output[96] = {};
  std::snprintf(input, sizeof(input), "{\"on\":%s}", json_bool(target));
  state->physical_consent.store(true, std::memory_order_release);
  const esp_err_t error = esp_claw_runtime_call_local_capability(
      state->claw, next_request_id(state), "s3cam-physical-button",
      "device.set_indicator", input, output, sizeof(output));
  state->physical_consent.store(false, std::memory_order_release);
  state->agent_action_tested = true;
  state->agent_action_ok = error == ESP_OK;
  if (error == ESP_OK) {
    ESP_LOGI(kTag,
             "[PASS] physical-consent ESP-Claw device.set_indicator => %s",
             output);
  } else {
    ESP_LOGE(kTag, "[FAIL] ESP-Claw device.set_indicator: %s",
             esp_err_to_name(error));
  }
  /* The test action deliberately flashes the screen. Restore an illuminated
   * UI after the one-use Agent action so the result remains visible. */
  if (error == ESP_OK && !target) {
    vTaskDelay(pdMS_TO_TICKS(250));
    set_backlight(state, true);
  }
  ui_draw_agent_result(state, error == ESP_OK ? 1 : 0);
  vTaskDelay(pdMS_TO_TICKS(1200));
  log_agent_status(state);
  state->ui_page = UiPage::kStatus;
  ui_draw_dashboard(state);
}

void diagnostic_task(void *argument) {
  auto *state = static_cast<BringupState *>(argument);
  TickType_t preview_at = 0;
  run_hardware_test(state);
  for (;;) {
    ButtonEvent event = ButtonEvent::kShortPress;
    if (xQueueReceive(state->button_events, &event,
                      pdMS_TO_TICKS(kButtonPollMs)) == pdTRUE) {
      if (state->consent_pending.load(std::memory_order_acquire)) {
        if (event == ButtonEvent::kShortPress) {
          decide_agent_consent(state, true);
        } else if (event == ButtonEvent::kVolumeDown ||
                   event == ButtonEvent::kRetest ||
                   event == ButtonEvent::kWifiSetup) {
          decide_agent_consent(state, false);
        }
      } else if (event == ButtonEvent::kVolumeDown ||
                 event == ButtonEvent::kVolumeUp) {
        const int delta = event == ButtonEvent::kVolumeUp ? 10 : -10;
        change_output_volume(state, delta);
        (void)ui_draw_volume(state);
        vTaskDelay(pdMS_TO_TICKS(650));
        if (state->ui_page == UiPage::kStatus) {
          (void)ui_draw_dashboard(state);
        } else if (state->ui_page == UiPage::kActivation) {
          (void)ui_draw_voice(state);
        } else {
          preview_at = 0;
        }
      } else if (event == ButtonEvent::kWifiSetup) {
        ESP_LOGI(kTag, "BOOT four-second hold: open Wi-Fi setup window");
        const esp_err_t wifi_error = start_wifi_onboarding(state);
        if (wifi_error != ESP_OK) {
          state->wifi_last_error.store(wifi_error, std::memory_order_release);
          state->wifi_state.store(PRODUCT_WIFI_STATE_FATAL,
                                  std::memory_order_release);
          ESP_LOGE(kTag, "Wi-Fi setup failed to open: %s",
                   esp_err_to_name(wifi_error));
          state->ui_page = UiPage::kStatus;
          (void)ui_draw_dashboard(state);
        }
      } else if (event == ButtonEvent::kRetest) {
        const auto voice_stage = static_cast<VoiceStage>(
            state->voice_stage.load(std::memory_order_acquire));
        if (voice_stage == VoiceStage::kListening ||
            voice_stage == VoiceStage::kThinking ||
            voice_stage == VoiceStage::kSpeaking) {
          ESP_LOGI(
              kTag,
              "BOOT long press: stop active voice turn before hardware retest");
          state->voice_listen_toggle.store(true, std::memory_order_release);
        } else {
          ESP_LOGI(kTag, "BOOT long press: repeat diagnostic");
          run_hardware_test(state);
        }
      } else if (state->ui_page == UiPage::kStatus) {
        const auto cloud_stage = static_cast<CloudStage>(
            state->cloud_stage.load(std::memory_order_acquire));
        if (cloud_stage == CloudStage::kReady) {
          ESP_LOGI(kTag, "BOOT short press: open/toggle voice Agent");
          state->ui_page = UiPage::kActivation;
          const auto voice_stage = static_cast<VoiceStage>(
              state->voice_stage.load(std::memory_order_acquire));
          if (voice_stage == VoiceStage::kReady ||
              voice_stage == VoiceStage::kListening ||
              voice_stage == VoiceStage::kThinking ||
              voice_stage == VoiceStage::kSpeaking) {
            state->voice_listen_toggle.store(true, std::memory_order_release);
          }
          (void)ui_draw_voice(state);
        } else {
          ESP_LOGI(kTag, "BOOT short press: open live camera UI");
          state->ui_page = UiPage::kCamera;
          preview_at = 0;
        }
      } else if (state->ui_page == UiPage::kCamera) {
        ESP_LOGI(kTag, "BOOT short press: open live microphone UI");
        state->ui_page = UiPage::kMicrophone;
        preview_at = 0;
      } else if (state->ui_page == UiPage::kMicrophone) {
        ESP_LOGI(kTag, "BOOT short press: run consent-bound Agent action");
        toggle_backlight_through_agent(state);
      } else if (state->ui_page == UiPage::kVoiceEnrollment) {
        ESP_LOGI(kTag,
                 "BOOT short press: return from voice enrollment to Agent");
        state->voice_enrollment_code[0] = '\0';
        state->ui_page = UiPage::kActivation;
        (void)ui_draw_voice(state);
      } else if (state->ui_page == UiPage::kActivation) {
        const auto cloud_stage = static_cast<CloudStage>(
            state->cloud_stage.load(std::memory_order_acquire));
        const auto voice_stage = static_cast<VoiceStage>(
            state->voice_stage.load(std::memory_order_acquire));
        if (cloud_stage == CloudStage::kReady &&
            (voice_stage == VoiceStage::kReady ||
             voice_stage == VoiceStage::kListening ||
             voice_stage == VoiceStage::kThinking ||
             voice_stage == VoiceStage::kSpeaking)) {
          ESP_LOGI(kTag, "BOOT short press: toggle voice turn");
          state->voice_listen_toggle.store(true, std::memory_order_release);
        } else if (cloud_stage != CloudStage::kReady) {
          ESP_LOGI(kTag,
                   "BOOT short press: return from activation UI to status");
          state->ui_page = UiPage::kStatus;
          (void)ui_draw_dashboard(state);
        }
      } else {
        ESP_LOGI(kTag, "BOOT short press: return to status UI");
        state->ui_page = UiPage::kStatus;
        (void)ui_draw_dashboard(state);
      }
    }
    service_wifi(state);
    service_cloud(state);
    service_agent_consent(state);
    service_voice_enrollment(state);
    service_voice(state);
    const TickType_t now = xTaskGetTickCount();
    if (state->ui_page == UiPage::kCamera &&
        now - preview_at >= pdMS_TO_TICKS(kCameraPreviewIntervalMs)) {
      preview_at = now;
      const esp_err_t preview_error = ui_draw_camera_preview(state);
      if (preview_error != ESP_OK) {
        ESP_LOGE(kTag, "camera UI update failed: %s",
                 esp_err_to_name(preview_error));
      }
    } else if (state->ui_page == UiPage::kMicrophone &&
               now - preview_at >=
                   pdMS_TO_TICKS(kMicrophonePreviewIntervalMs)) {
      preview_at = now;
      const esp_err_t meter_error = ui_draw_microphone_meter(state);
      if (meter_error != ESP_OK) {
        ESP_LOGE(kTag, "microphone UI update failed: %s",
                 esp_err_to_name(meter_error));
      }
    }
  }
}

void button_task(void *argument) {
  auto *state = static_cast<BringupState *>(argument);
  bool raw_pressed = gpio_get_level(kButton) == 0;
  bool stable_pressed = raw_pressed;
  bool volume_down_raw = gpio_get_level(kVolumeDownButton) == 0;
  bool volume_down_stable = volume_down_raw;
  bool volume_up_raw = gpio_get_level(kVolumeUpButton) == 0;
  bool volume_up_stable = volume_up_raw;
  TickType_t changed_at = xTaskGetTickCount();
  TickType_t volume_down_changed_at = changed_at;
  TickType_t volume_up_changed_at = changed_at;
  TickType_t pressed_at = 0;
  for (;;) {
    const TickType_t now = xTaskGetTickCount();
    const bool pressed = gpio_get_level(kButton) == 0;
    if (pressed != raw_pressed) {
      raw_pressed = pressed;
      changed_at = now;
    }
    if (raw_pressed != stable_pressed &&
        now - changed_at >= pdMS_TO_TICKS(kButtonDebounceMs)) {
      stable_pressed = raw_pressed;
      if (stable_pressed) {
        pressed_at = now;
      } else {
        const uint32_t held_ms =
            static_cast<uint32_t>((now - pressed_at) * portTICK_PERIOD_MS);
        const ButtonEvent event =
            held_ms >= kWifiSetupHoldMs
                ? ButtonEvent::kWifiSetup
                : (held_ms >= kRepeatHoldMs ? ButtonEvent::kRetest
                                            : ButtonEvent::kShortPress);
        xQueueSend(state->button_events, &event, 0);
      }
    }
    const bool volume_down_pressed = gpio_get_level(kVolumeDownButton) == 0;
    if (volume_down_pressed != volume_down_raw) {
      volume_down_raw = volume_down_pressed;
      volume_down_changed_at = now;
    }
    if (volume_down_raw != volume_down_stable &&
        now - volume_down_changed_at >= pdMS_TO_TICKS(kButtonDebounceMs)) {
      volume_down_stable = volume_down_raw;
      if (volume_down_stable) {
        ESP_LOGI(kTag, "Volume-down button detected: GPIO=%d",
                 static_cast<int>(kVolumeDownButton));
        const ButtonEvent event = ButtonEvent::kVolumeDown;
        xQueueSend(state->button_events, &event, 0);
      }
    }
    const bool volume_up_pressed = gpio_get_level(kVolumeUpButton) == 0;
    if (volume_up_pressed != volume_up_raw) {
      volume_up_raw = volume_up_pressed;
      volume_up_changed_at = now;
    }
    if (volume_up_raw != volume_up_stable &&
        now - volume_up_changed_at >= pdMS_TO_TICKS(kButtonDebounceMs)) {
      volume_up_stable = volume_up_raw;
      if (volume_up_stable) {
        ESP_LOGI(kTag, "Volume-up button detected: GPIO=%d",
                 static_cast<int>(kVolumeUpButton));
        const ButtonEvent event = ButtonEvent::kVolumeUp;
        xQueueSend(state->button_events, &event, 0);
      }
    }
    vTaskDelay(pdMS_TO_TICKS(kButtonPollMs));
  }
}

} // namespace

extern "C" esp_err_t bread_s3cam_bringup_start(void) {
  if (s_state.task || s_state.button_task || s_state.cloud_task ||
      s_state.voice_task || s_state.button_events ||
      s_state.voice_audio_queue || s_state.voice_text_queue ||
      s_state.voice_websocket || s_state.backlight || s_state.panel ||
      s_state.speaker || s_state.microphone || s_state.claw || s_state.wifi ||
      s_state.onboarding_httpd) {
    return ESP_ERR_INVALID_STATE;
  }
  const product_sku_profile_t *profile = product_sku_get_compiled_profile();
  if (!profile || profile->status_indicator_gpio != kBacklight ||
      profile->physical_presence_gpio != kButton) {
    return ESP_ERR_INVALID_STATE;
  }
  esp_err_t error =
      product_status_indicator_create(profile, &s_state.backlight);
  if (error != ESP_OK) {
    ESP_LOGE(kTag, "status indicator initialization failed: %s",
             esp_err_to_name(error));
    return error;
  }
  const esp_err_t backlight_error = initialize_backlight_pwm(&s_state);
  if (backlight_error != ESP_OK) {
    ESP_LOGE(kTag, "factory PWM backlight initialization failed: %s",
             esp_err_to_name(backlight_error));
    return backlight_error;
  }
  const esp_err_t display_init_error = initialize_display(&s_state);
  if (display_init_error != ESP_OK) {
    ESP_LOGE(kTag, "display initialization failed: %s",
             esp_err_to_name(display_init_error));
  } else {
    const esp_err_t test_card_error = draw_startup_test_card(&s_state);
    if (test_card_error != ESP_OK) {
      ESP_LOGE(kTag, "startup RGB test card failed: %s",
               esp_err_to_name(test_card_error));
    }
    vTaskDelay(pdMS_TO_TICKS(1500));
  }
  const esp_err_t camera_init_error = initialize_camera(&s_state);
  if (camera_init_error != ESP_OK) {
    ESP_LOGE(kTag, "camera initialization failed: %s; continuing tests",
             esp_err_to_name(camera_init_error));
  }
  const esp_err_t audio_init_error = initialize_audio(&s_state);
  if (audio_init_error != ESP_OK) {
    ESP_LOGE(kTag, "audio initialization failed: %s; continuing tests",
             esp_err_to_name(audio_init_error));
  }
  const esp_claw_local_capability_config_t claw_config = {
      .enabled_capabilities = ESP_CLAW_CAPABILITY_DEVICE_GET_STATUS |
                              ESP_CLAW_CAPABILITY_DEVICE_SET_INDICATOR |
                              ESP_CLAW_CAPABILITY_DEVICE_SET_VOLUME,
      .device_ops =
          {
              .get_status_json = get_status_json,
              .set_indicator = set_backlight,
              .set_volume = set_output_volume,
              .ctx = &s_state,
          },
      .capability_consent = consume_physical_consent,
      .capability_consent_ctx = &s_state,
      .capability_audit = capability_audit,
      .capability_audit_ctx = &s_state,
  };
  error =
      esp_claw_runtime_start_local_capabilities(&claw_config, &s_state.claw);
  if (error == ESP_OK) {
    const esp_err_t wifi_error = initialize_product_wifi(&s_state);
    if (wifi_error != ESP_OK) {
      s_state.wifi_last_error.store(wifi_error, std::memory_order_release);
      s_state.wifi_state.store(PRODUCT_WIFI_STATE_FATAL,
                               std::memory_order_release);
      ESP_LOGE(kTag,
               "Development Wi-Fi manager initialization failed: %s; hardware "
               "tests remain available",
               esp_err_to_name(wifi_error));
    }
    if (product_storage_require_ready() == ESP_OK) {
      const esp_err_t volume_error = load_output_volume(&s_state);
      if (volume_error != ESP_OK) {
        ESP_LOGW(kTag, "Speaker volume restore failed: %s; using %d%%",
                 esp_err_to_name(volume_error), kDefaultOutputVolumePercent);
      }
    }
  }
  const gpio_config_t button_config = {
      .pin_bit_mask = (UINT64_C(1) << kButton) |
                      (UINT64_C(1) << kVolumeDownButton) |
                      (UINT64_C(1) << kVolumeUpButton),
      .mode = GPIO_MODE_INPUT,
      .pull_up_en = GPIO_PULLUP_ENABLE,
      .pull_down_en = GPIO_PULLDOWN_DISABLE,
      .intr_type = GPIO_INTR_DISABLE,
  };
  if (error == ESP_OK) {
    error = gpio_config(&button_config);
  }
  if (error == ESP_OK) {
    s_state.button_events = xQueueCreate(8, sizeof(ButtonEvent));
    if (!s_state.button_events) {
      error = ESP_ERR_NO_MEM;
    }
  }
  if (error == ESP_OK) {
    // A 64-packet Opus queue reserves about 99 KiB. Keeping that storage in
    // internal RAM starves mbedTLS during the WSS handshake on this S3 board.
    // ESP-IDF's capability-aware queue keeps the full jitter buffer in PSRAM
    // while leaving scarce DMA/internal memory available to Wi-Fi, TLS and
    // I2S. This queue is task-only (never accessed from an ISR), so external
    // RAM is appropriate here.
    s_state.voice_audio_queue = xQueueCreateWithCaps(
        kVoiceAudioQueuePackets, sizeof(VoiceAudioPacket),
        MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    s_state.voice_text_queue = xQueueCreate(4, sizeof(VoiceTextPacket));
    if (!s_state.voice_audio_queue || !s_state.voice_text_queue) {
      error = ESP_ERR_NO_MEM;
    }
  }
  if (error == ESP_OK && xTaskCreate(diagnostic_task, "bread_s3cam_test", 8192,
                                     &s_state, 5, &s_state.task) != pdPASS) {
    error = ESP_ERR_NO_MEM;
  }
  if (error == ESP_OK &&
      xTaskCreate(button_task, "bread_s3cam_button", 2048, &s_state, 6,
                  &s_state.button_task) != pdPASS) {
    error = ESP_ERR_NO_MEM;
  }
  if (error != ESP_OK) {
    ESP_LOGE(kTag, "Hardware diagnostic initialization failed: %s",
             esp_err_to_name(error));
    return error;
  }
  ESP_LOGI(kTag, "Voice Agent prototype started: Wi-Fi setup requires a "
                 "four-second physical hold; cloud token remains RAM-only and "
                 "MCP exposes read-only device status");
  return ESP_OK;
}
