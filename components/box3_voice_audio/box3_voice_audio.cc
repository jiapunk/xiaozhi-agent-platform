/*
 * Product-owned bounded PCM/Opus pipeline.  Codec and rate-conversion setup is
 * selectively adapted from XiaoZhi AudioService at
 * 18a60b8051f5ee6a25beed6248ed84c7fcc742bf (MIT License); see
 * third_party/xiaozhi-esp32-LICENSE.txt.  Task ownership, request generations,
 * fixed packet pool, transport framing, lifecycle API, and error policy are
 * original to this product shell.
 */

#include "box3_voice_audio.h"

#include <atomic>
#include <cstring>
#include <mutex>
#include <new>

#include "esp_ae_rate_cvt.h"
#include "esp_audio_enc.h"
#include "esp_audio_types.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_opus_dec.h"
#include "esp_opus_enc.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "voice_audio_protocol.h"
#include "voice_audio_session.h"

namespace {

constexpr char kTag[] = "box3_voice_audio";
constexpr size_t kRawInputFrames =
    static_cast<size_t>(BOX3_AUDIO_SAMPLE_RATE) *
    static_cast<size_t>(BOX3_VOICE_AUDIO_FRAME_DURATION_MS) / 1000;
constexpr size_t kRawInputSamples =
    kRawInputFrames * static_cast<size_t>(BOX3_AUDIO_INPUT_CHANNELS);
constexpr size_t kEncoderSamples =
    static_cast<size_t>(BOX3_VOICE_AUDIO_UPLINK_SAMPLE_RATE) *
    static_cast<size_t>(BOX3_VOICE_AUDIO_FRAME_DURATION_MS) / 1000;
constexpr size_t kDecoderSamples =
    static_cast<size_t>(BOX3_VOICE_AUDIO_DOWNLINK_SAMPLE_RATE) *
    static_cast<size_t>(BOX3_VOICE_AUDIO_FRAME_DURATION_MS) / 1000;
constexpr size_t kMaxWireBytes =
    VOICE_AUDIO_PROTOCOL_V2_HEADER_BYTES +
    VOICE_AUDIO_PROTOCOL_MAX_OPUS_BYTES;
constexpr uint32_t kCaptureTaskStackBytes = 8192;
constexpr uint32_t kPlaybackTaskStackBytes = 10240;
constexpr UBaseType_t kCaptureTaskPriority = 7;
constexpr UBaseType_t kPlaybackTaskPriority = 6;
constexpr TickType_t kTaskStopTimeout = pdMS_TO_TICKS(3000);

constexpr EventBits_t kCaptureEnabled = BIT0;
constexpr EventBits_t kStopRequested = BIT1;
constexpr EventBits_t kCaptureIdle = BIT2;
constexpr EventBits_t kCaptureStopped = BIT3;
constexpr EventBits_t kPlaybackStopped = BIT4;

struct downlink_item_t {
    voice_audio_token_t token;
    uint32_t timestamp_ms;
    size_t opus_size;
    uint8_t opus[VOICE_AUDIO_PROTOCOL_MAX_OPUS_BYTES];
};

static esp_opus_enc_frame_duration_t opus_encoder_duration(void)
{
    return ESP_OPUS_ENC_FRAME_DURATION_60_MS;
}

static esp_opus_dec_frame_duration_t opus_decoder_duration(void)
{
    return static_cast<esp_opus_dec_frame_duration_t>(
        ESP_OPUS_ENC_FRAME_DURATION_60_MS);
}

template <typename T>
static T *allocate_internal(size_t count)
{
    if (count == 0 || count > SIZE_MAX / sizeof(T)) {
        return nullptr;
    }
    return static_cast<T *>(heap_caps_calloc(
        count, sizeof(T), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
}

}  // namespace

struct box3_voice_audio {
    box3_voice_audio_config_t config = {};
    void *encoder = nullptr;
    void *decoder = nullptr;
    esp_ae_rate_cvt_handle_t resampler = nullptr;

    EventGroupHandle_t events = nullptr;
    QueueHandle_t free_items = nullptr;
    QueueHandle_t decode_items = nullptr;
    TaskHandle_t capture_task = nullptr;
    TaskHandle_t playback_task = nullptr;

    downlink_item_t *item_pool = nullptr;
    int16_t *raw_input = nullptr;
    int16_t *mono_input = nullptr;
    int16_t *resampler_output = nullptr;
    int16_t *encoder_pcm = nullptr;
    int16_t *decoder_pcm = nullptr;
    uint8_t *encoded_opus = nullptr;
    uint8_t *wire_packet = nullptr;
    size_t encoder_frame_samples = 0;
    size_t encoder_output_capacity = 0;
    size_t resampler_output_capacity = 0;
    size_t encoder_pcm_capacity = 0;
    size_t encoder_pending_samples = 0;

    std::mutex lifecycle_mutex;
    voice_audio_session_t session = {};
    uint32_t decoder_generation = 0;

    std::atomic<uint32_t> captured_frames{0};
    std::atomic<uint32_t> sent_packets{0};
    std::atomic<uint32_t> send_errors{0};
    std::atomic<uint32_t> decoded_packets{0};
    std::atomic<uint32_t> played_frames{0};
    std::atomic<uint32_t> downlink_drops{0};
    std::atomic<uint32_t> stale_packets{0};
    std::atomic<uint32_t> codec_errors{0};
};

static void notify_event(box3_voice_audio *stream,
                         box3_voice_audio_event_t event,
                         uint32_t request_id)
{
    if (stream->config.event) {
        stream->config.event(stream->config.ops_ctx, event, request_id);
    }
}

static void close_processing(box3_voice_audio *stream)
{
    if (stream->encoder) {
        esp_opus_enc_close(stream->encoder);
        stream->encoder = nullptr;
    }
    if (stream->decoder) {
        esp_opus_dec_close(stream->decoder);
        stream->decoder = nullptr;
    }
    if (stream->resampler) {
        esp_ae_rate_cvt_close(stream->resampler);
        stream->resampler = nullptr;
    }
}

static esp_err_t open_decoder(box3_voice_audio *stream)
{
    esp_opus_dec_cfg_t config = {
        .sample_rate = BOX3_VOICE_AUDIO_DOWNLINK_SAMPLE_RATE,
        .channel = ESP_AUDIO_MONO,
        .frame_duration = opus_decoder_duration(),
        .self_delimited = false,
    };
    if (stream->decoder) {
        esp_opus_dec_close(stream->decoder);
        stream->decoder = nullptr;
    }
    const int result = esp_opus_dec_open(&config, sizeof(config), &stream->decoder);
    return result == ESP_AUDIO_ERR_OK && stream->decoder ? ESP_OK : ESP_FAIL;
}

static esp_err_t open_processing(box3_voice_audio *stream)
{
    esp_opus_enc_config_t encoder_config = {
        .sample_rate = ESP_AUDIO_SAMPLE_RATE_16K,
        .channel = ESP_AUDIO_MONO,
        .bits_per_sample = ESP_AUDIO_BIT16,
        .bitrate = ESP_OPUS_BITRATE_AUTO,
        .frame_duration = opus_encoder_duration(),
        .application_mode = ESP_OPUS_ENC_APPLICATION_AUDIO,
        .complexity = 0,
        .enable_fec = false,
        .enable_dtx = true,
        .enable_vbr = true,
    };
    int frame_bytes = 0;
    int output_bytes = 0;
    int result = esp_opus_enc_open(&encoder_config, sizeof(encoder_config),
                                   &stream->encoder);
    if (result != ESP_AUDIO_ERR_OK || !stream->encoder) {
        return ESP_FAIL;
    }
    result = esp_opus_enc_get_frame_size(stream->encoder, &frame_bytes,
                                         &output_bytes);
    if (result != ESP_AUDIO_ERR_OK || frame_bytes <= 0 || output_bytes <= 0 ||
        (frame_bytes % static_cast<int>(sizeof(int16_t))) != 0) {
        return ESP_FAIL;
    }
    stream->encoder_frame_samples =
        static_cast<size_t>(frame_bytes) / sizeof(int16_t);
    stream->encoder_output_capacity = static_cast<size_t>(output_bytes);
    if (stream->encoder_frame_samples != kEncoderSamples ||
        stream->encoder_output_capacity > VOICE_AUDIO_PROTOCOL_MAX_OPUS_BYTES) {
        ESP_LOGE(kTag, "Unexpected Opus frame=%u output=%u",
                 static_cast<unsigned>(stream->encoder_frame_samples),
                 static_cast<unsigned>(stream->encoder_output_capacity));
        return ESP_ERR_NOT_SUPPORTED;
    }
    esp_err_t decoder_result = open_decoder(stream);
    if (decoder_result != ESP_OK) {
        return decoder_result;
    }

    esp_ae_rate_cvt_cfg_t resampler_config = {
        .src_rate = BOX3_AUDIO_SAMPLE_RATE,
        .dest_rate = BOX3_VOICE_AUDIO_UPLINK_SAMPLE_RATE,
        .channel = 1,
        .bits_per_sample = ESP_AUDIO_BIT16,
        .complexity = 2,
        .perf_type = ESP_AE_RATE_CVT_PERF_TYPE_SPEED,
    };
    result = esp_ae_rate_cvt_open(&resampler_config, &stream->resampler);
    if (result != ESP_AE_ERR_OK || !stream->resampler) {
        return ESP_FAIL;
    }
    uint32_t maximum_output_samples = 0;
    result = esp_ae_rate_cvt_get_max_out_sample_num(
        stream->resampler, kRawInputFrames, &maximum_output_samples);
    if (result != ESP_AE_ERR_OK || maximum_output_samples == 0 ||
        maximum_output_samples > kRawInputFrames) {
        return ESP_FAIL;
    }
    stream->resampler_output_capacity = maximum_output_samples;
    stream->encoder_pcm_capacity =
        kEncoderSamples + stream->resampler_output_capacity;
    return ESP_OK;
}

static esp_err_t allocate_buffers(box3_voice_audio *stream)
{
    stream->item_pool = static_cast<downlink_item_t *>(heap_caps_calloc(
        BOX3_VOICE_AUDIO_DOWNLINK_QUEUE_DEPTH, sizeof(downlink_item_t),
        MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
    if (!stream->item_pool) {
        stream->item_pool = allocate_internal<downlink_item_t>(
            BOX3_VOICE_AUDIO_DOWNLINK_QUEUE_DEPTH);
    }
    stream->raw_input = allocate_internal<int16_t>(kRawInputSamples);
    stream->mono_input = allocate_internal<int16_t>(kRawInputFrames);
    stream->resampler_output = allocate_internal<int16_t>(
        stream->resampler_output_capacity);
    stream->encoder_pcm = allocate_internal<int16_t>(
        stream->encoder_pcm_capacity);
    stream->decoder_pcm = allocate_internal<int16_t>(kDecoderSamples);
    stream->encoded_opus = allocate_internal<uint8_t>(
        stream->encoder_output_capacity);
    stream->wire_packet = allocate_internal<uint8_t>(kMaxWireBytes);
    if (!stream->item_pool || !stream->raw_input || !stream->mono_input ||
        !stream->resampler_output || !stream->encoder_pcm ||
        !stream->decoder_pcm ||
        !stream->encoded_opus || !stream->wire_packet) {
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

static void free_buffers(box3_voice_audio *stream)
{
    heap_caps_free(stream->wire_packet);
    heap_caps_free(stream->encoded_opus);
    heap_caps_free(stream->decoder_pcm);
    heap_caps_free(stream->encoder_pcm);
    heap_caps_free(stream->resampler_output);
    heap_caps_free(stream->mono_input);
    heap_caps_free(stream->raw_input);
    heap_caps_free(stream->item_pool);
    stream->wire_packet = nullptr;
    stream->encoded_opus = nullptr;
    stream->decoder_pcm = nullptr;
    stream->encoder_pcm = nullptr;
    stream->resampler_output = nullptr;
    stream->mono_input = nullptr;
    stream->raw_input = nullptr;
    stream->item_pool = nullptr;
}

static void return_free_item(box3_voice_audio *stream, downlink_item_t *item)
{
    if (item && xQueueSend(stream->free_items, &item, 0) != pdTRUE) {
        ESP_LOGE(kTag, "Packet pool invariant violated");
    }
}

static void flush_queued_packets(box3_voice_audio *stream)
{
    downlink_item_t *item = nullptr;
    while (xQueueReceive(stream->decode_items, &item, 0) == pdTRUE) {
        return_free_item(stream, item);
    }
}

static void encode_and_send_frame(box3_voice_audio *stream,
                                  const int16_t *pcm)
{
    esp_audio_enc_in_frame_t input = {
        .buffer = reinterpret_cast<uint8_t *>(const_cast<int16_t *>(pcm)),
        .len = static_cast<uint32_t>(stream->encoder_frame_samples *
                                     sizeof(int16_t)),
    };
    esp_audio_enc_out_frame_t output = {
        .buffer = stream->encoded_opus,
        .len = static_cast<uint32_t>(stream->encoder_output_capacity),
        .encoded_bytes = 0,
        .pts = 0,
    };
    int encode_result = esp_opus_enc_process(stream->encoder, &input, &output);
    if (encode_result != ESP_AUDIO_ERR_OK || output.encoded_bytes == 0) {
        stream->codec_errors.fetch_add(1, std::memory_order_relaxed);
        notify_event(stream, BOX3_VOICE_AUDIO_EVENT_CAPTURE_ERROR, 0);
        return;
    }
    size_t wire_size = 0;
    voice_audio_protocol_result_t wire_result = voice_audio_protocol_encode(
        stream->config.transport_version, stream->encoded_opus,
        output.encoded_bytes,
        static_cast<uint32_t>(esp_timer_get_time() / 1000),
        stream->wire_packet, kMaxWireBytes, &wire_size);
    if (wire_result != VOICE_AUDIO_PROTOCOL_OK ||
        stream->config.send_binary(stream->config.ops_ctx,
                                   stream->wire_packet, wire_size) != 0) {
        stream->send_errors.fetch_add(1, std::memory_order_relaxed);
        notify_event(stream, BOX3_VOICE_AUDIO_EVENT_SEND_ERROR, 0);
        return;
    }
    stream->sent_packets.fetch_add(1, std::memory_order_relaxed);
}

static void capture_task_entry(void *argument)
{
    box3_voice_audio *stream = static_cast<box3_voice_audio *>(argument);
    bool input_enabled = false;

    for (;;) {
        EventBits_t bits = xEventGroupWaitBits(
            stream->events, kCaptureEnabled | kStopRequested,
            pdFALSE, pdFALSE, portMAX_DELAY);
        if ((bits & kStopRequested) != 0) {
            break;
        }
        if (!input_enabled) {
            if (box3_audio_enable_input(stream->config.audio, true) != ESP_OK) {
                notify_event(stream, BOX3_VOICE_AUDIO_EVENT_CAPTURE_ERROR, 0);
                xEventGroupClearBits(stream->events, kCaptureEnabled);
                xEventGroupSetBits(stream->events, kCaptureIdle);
                continue;
            }
            input_enabled = true;
            stream->encoder_pending_samples = 0;
            if (esp_ae_rate_cvt_reset(stream->resampler) != ESP_AE_ERR_OK ||
                esp_opus_enc_reset(stream->encoder) != ESP_AUDIO_ERR_OK) {
                stream->codec_errors.fetch_add(1, std::memory_order_relaxed);
                notify_event(stream, BOX3_VOICE_AUDIO_EVENT_CAPTURE_ERROR, 0);
            }
            xEventGroupClearBits(stream->events, kCaptureIdle);
        }

        size_t samples_read = 0;
        esp_err_t read_result = box3_audio_read(
            stream->config.audio, stream->raw_input, kRawInputSamples,
            &samples_read);
        bits = xEventGroupGetBits(stream->events);
        if ((bits & kStopRequested) != 0) {
            break;
        }
        if ((bits & kCaptureEnabled) == 0) {
            (void)box3_audio_enable_input(stream->config.audio, false);
            input_enabled = false;
            xEventGroupSetBits(stream->events, kCaptureIdle);
            continue;
        }
        if (read_result != ESP_OK || samples_read != kRawInputSamples) {
            stream->codec_errors.fetch_add(1, std::memory_order_relaxed);
            notify_event(stream, BOX3_VOICE_AUDIO_EVENT_CAPTURE_ERROR, 0);
            continue;
        }
        stream->captured_frames.fetch_add(1, std::memory_order_relaxed);

        /* Slot 0 is the microphone; slot 1 is retained for future AEC. */
        for (size_t frame = 0; frame < kRawInputFrames; ++frame) {
            stream->mono_input[frame] =
                stream->raw_input[frame * BOX3_AUDIO_INPUT_CHANNELS];
        }
        uint32_t converted_samples = stream->resampler_output_capacity;
        int conversion_result = esp_ae_rate_cvt_process(
            stream->resampler,
            reinterpret_cast<esp_ae_sample_t *>(stream->mono_input),
            kRawInputFrames,
            reinterpret_cast<esp_ae_sample_t *>(stream->resampler_output),
            &converted_samples);
        if (conversion_result != ESP_AE_ERR_OK || converted_samples == 0 ||
            converted_samples > stream->resampler_output_capacity ||
            stream->encoder_pending_samples + converted_samples >
                stream->encoder_pcm_capacity) {
            stream->codec_errors.fetch_add(1, std::memory_order_relaxed);
            notify_event(stream, BOX3_VOICE_AUDIO_EVENT_CAPTURE_ERROR, 0);
            continue;
        }
        memcpy(stream->encoder_pcm + stream->encoder_pending_samples,
               stream->resampler_output,
               converted_samples * sizeof(int16_t));
        stream->encoder_pending_samples += converted_samples;
        while (stream->encoder_pending_samples >=
               stream->encoder_frame_samples) {
            encode_and_send_frame(stream, stream->encoder_pcm);
            stream->encoder_pending_samples -= stream->encoder_frame_samples;
            if (stream->encoder_pending_samples > 0) {
                memmove(stream->encoder_pcm,
                        stream->encoder_pcm + stream->encoder_frame_samples,
                        stream->encoder_pending_samples * sizeof(int16_t));
            }
        }
    }

    if (input_enabled) {
        (void)box3_audio_enable_input(stream->config.audio, false);
    }
    xEventGroupSetBits(stream->events, kCaptureIdle | kCaptureStopped);
    stream->capture_task = nullptr;
    vTaskDelete(nullptr);
}

static bool decode_packet(box3_voice_audio *stream,
                          const downlink_item_t *item,
                          size_t *decoded_samples)
{
    if (stream->decoder_generation != item->token.generation) {
        if (esp_opus_dec_reset(stream->decoder) != ESP_AUDIO_ERR_OK) {
            return false;
        }
        stream->decoder_generation = item->token.generation;
    }
    esp_audio_dec_in_raw_t input = {
        .buffer = const_cast<uint8_t *>(item->opus),
        .len = static_cast<uint32_t>(item->opus_size),
        .consumed = 0,
        .frame_recover = ESP_AUDIO_DEC_RECOVERY_NONE,
    };
    esp_audio_dec_out_frame_t output = {
        .buffer = reinterpret_cast<uint8_t *>(stream->decoder_pcm),
        .len = static_cast<uint32_t>(kDecoderSamples * sizeof(int16_t)),
        .needed_size = 0,
        .decoded_size = 0,
    };
    esp_audio_dec_info_t info = {};
    int result = esp_opus_dec_decode(stream->decoder, &input, &output, &info);
    if (result != ESP_AUDIO_ERR_OK || output.decoded_size == 0 ||
        output.decoded_size > kDecoderSamples * sizeof(int16_t) ||
        (output.decoded_size % sizeof(int16_t)) != 0) {
        return false;
    }
    *decoded_samples = output.decoded_size / sizeof(int16_t);
    return true;
}

static void finish_drain_if_ready(box3_voice_audio *stream)
{
    uint32_t request_id = 0;
    bool finished = false;
    {
        std::lock_guard<std::mutex> lock(stream->lifecycle_mutex);
        finished = voice_audio_session_finish_drain(
            &stream->session,
            uxQueueMessagesWaiting(stream->decode_items) == 0,
            &request_id) == VOICE_AUDIO_SESSION_OK;
    }
    if (finished) {
        (void)box3_audio_enable_output(stream->config.audio, false);
        notify_event(stream, BOX3_VOICE_AUDIO_EVENT_PLAYBACK_DRAINED,
                     request_id);
    }
}

static void playback_task_entry(void *argument)
{
    box3_voice_audio *stream = static_cast<box3_voice_audio *>(argument);

    for (;;) {
        if ((xEventGroupGetBits(stream->events) & kStopRequested) != 0) {
            break;
        }
        downlink_item_t *item = nullptr;
        if (xQueueReceive(stream->decode_items, &item,
                          pdMS_TO_TICKS(50)) != pdTRUE) {
            finish_drain_if_ready(stream);
            continue;
        }

        bool accepted = false;
        {
            std::lock_guard<std::mutex> lock(stream->lifecycle_mutex);
            accepted = voice_audio_session_set_inflight(
                &stream->session, item->token, true) ==
                VOICE_AUDIO_SESSION_OK;
        }
        size_t decoded_samples = 0;
        bool decoded = accepted && decode_packet(stream, item, &decoded_samples);
        if (!decoded && accepted) {
            stream->codec_errors.fetch_add(1, std::memory_order_relaxed);
            notify_event(stream, BOX3_VOICE_AUDIO_EVENT_PLAYBACK_ERROR,
                         item->token.request_id);
        }
        bool write_failed = false;
        if (decoded) {
            std::lock_guard<std::mutex> lock(stream->lifecycle_mutex);
            if (voice_audio_session_is_current(&stream->session,
                                               item->token)) {
                size_t samples_written = 0;
                esp_err_t enable_result = box3_audio_enable_output(
                    stream->config.audio, true);
                esp_err_t write_result = enable_result == ESP_OK
                    ? box3_audio_write(stream->config.audio,
                                       stream->decoder_pcm, decoded_samples,
                                       &samples_written)
                    : enable_result;
                if (write_result == ESP_OK && samples_written == decoded_samples) {
                    stream->played_frames.fetch_add(1, std::memory_order_relaxed);
                } else {
                    stream->codec_errors.fetch_add(1, std::memory_order_relaxed);
                    write_failed = true;
                }
            } else {
                stream->stale_packets.fetch_add(1, std::memory_order_relaxed);
            }
        } else if (!accepted) {
            stream->stale_packets.fetch_add(1, std::memory_order_relaxed);
        }
        if (write_failed) {
            notify_event(stream, BOX3_VOICE_AUDIO_EVENT_PLAYBACK_ERROR,
                         item->token.request_id);
        }
        if (accepted) {
            std::lock_guard<std::mutex> lock(stream->lifecycle_mutex);
            (void)voice_audio_session_set_inflight(
                &stream->session, item->token, false);
        }
        if (decoded) {
            stream->decoded_packets.fetch_add(1, std::memory_order_relaxed);
        }
        return_free_item(stream, item);
        finish_drain_if_ready(stream);
    }

    flush_queued_packets(stream);
    (void)box3_audio_enable_output(stream->config.audio, false);
    xEventGroupSetBits(stream->events, kPlaybackStopped);
    stream->playback_task = nullptr;
    vTaskDelete(nullptr);
}

static bool cleanup(box3_voice_audio *stream)
{
    if (!stream) {
        return true;
    }
    if (stream->events && (stream->capture_task || stream->playback_task)) {
        xEventGroupSetBits(stream->events, kStopRequested | kCaptureEnabled);
        EventBits_t expected = 0;
        if (stream->capture_task) {
            expected |= kCaptureStopped;
        }
        if (stream->playback_task) {
            expected |= kPlaybackStopped;
        }
        if (expected) {
            EventBits_t stopped = xEventGroupWaitBits(
                stream->events, expected, pdFALSE, pdTRUE, kTaskStopTimeout);
            if ((stopped & expected) != expected) {
                /* Never free storage that a stuck I/O task may still touch. */
                ESP_LOGE(kTag, "Worker shutdown timed out; retaining resources");
                return false;
            }
        }
    }
    close_processing(stream);
    if (stream->decode_items) {
        vQueueDelete(stream->decode_items);
    }
    if (stream->free_items) {
        vQueueDelete(stream->free_items);
    }
    if (stream->events) {
        vEventGroupDelete(stream->events);
    }
    free_buffers(stream);
    return true;
}

esp_err_t box3_voice_audio_create(const box3_voice_audio_config_t *config,
                                  box3_voice_audio_t **out_stream)
{
    if (!out_stream) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_stream = nullptr;
    if (!config || !config->audio || !config->send_binary ||
        config->transport_version < 1 || config->transport_version > 3) {
        return ESP_ERR_INVALID_ARG;
    }
    box3_voice_audio *stream = new (std::nothrow) box3_voice_audio();
    if (!stream) {
        return ESP_ERR_NO_MEM;
    }
    stream->config = *config;
    (void)voice_audio_session_init(&stream->session);
    esp_err_t result = open_processing(stream);
    if (result == ESP_OK) {
        result = allocate_buffers(stream);
    }
    if (result == ESP_OK) {
        stream->events = xEventGroupCreate();
        stream->free_items = xQueueCreate(
            BOX3_VOICE_AUDIO_DOWNLINK_QUEUE_DEPTH, sizeof(downlink_item_t *));
        stream->decode_items = xQueueCreate(
            BOX3_VOICE_AUDIO_DOWNLINK_QUEUE_DEPTH, sizeof(downlink_item_t *));
        if (!stream->events || !stream->free_items || !stream->decode_items) {
            result = ESP_ERR_NO_MEM;
        }
    }
    if (result == ESP_OK) {
        for (size_t index = 0;
             index < BOX3_VOICE_AUDIO_DOWNLINK_QUEUE_DEPTH; ++index) {
            downlink_item_t *item = &stream->item_pool[index];
            if (xQueueSend(stream->free_items, &item, 0) != pdTRUE) {
                result = ESP_FAIL;
                break;
            }
        }
    }
    if (result == ESP_OK) {
        xEventGroupSetBits(stream->events, kCaptureIdle);
        if (xTaskCreate(capture_task_entry, "voice_capture",
                        kCaptureTaskStackBytes, stream, kCaptureTaskPriority,
                        &stream->capture_task) != pdPASS) {
            result = ESP_ERR_NO_MEM;
        }
    }
    if (result == ESP_OK &&
        xTaskCreate(playback_task_entry, "voice_playback",
                    kPlaybackTaskStackBytes, stream, kPlaybackTaskPriority,
                    &stream->playback_task) != pdPASS) {
        result = ESP_ERR_NO_MEM;
    }
    if (result != ESP_OK) {
        if (cleanup(stream)) {
            delete stream;
        } else {
            *out_stream = stream;
        }
        return result;
    }
    *out_stream = stream;
    return ESP_OK;
}

esp_err_t box3_voice_audio_destroy(box3_voice_audio_t *stream)
{
    if (!stream) {
        return ESP_OK;
    }
    if (cleanup(stream)) {
        delete stream;
        return ESP_OK;
    }
    return ESP_ERR_TIMEOUT;
}

esp_err_t box3_voice_audio_start_capture(box3_voice_audio_t *stream)
{
    if (!stream) {
        return ESP_ERR_INVALID_ARG;
    }
    EventBits_t bits = xEventGroupGetBits(stream->events);
    if ((bits & kStopRequested) != 0) {
        return ESP_ERR_INVALID_STATE;
    }
    xEventGroupClearBits(stream->events, kCaptureIdle);
    xEventGroupSetBits(stream->events, kCaptureEnabled);
    return ESP_OK;
}

esp_err_t box3_voice_audio_stop_capture(box3_voice_audio_t *stream)
{
    if (!stream) {
        return ESP_ERR_INVALID_ARG;
    }
    xEventGroupClearBits(stream->events, kCaptureEnabled);
    EventBits_t bits = xEventGroupWaitBits(stream->events, kCaptureIdle,
                                           pdFALSE, pdTRUE,
                                           pdMS_TO_TICKS(500));
    return (bits & kCaptureIdle) != 0 ? ESP_OK : ESP_ERR_TIMEOUT;
}

void box3_voice_audio_playback_event(void *ctx,
                                     voice_agent_playback_event_t event,
                                     uint32_t request_id)
{
    box3_voice_audio *stream = static_cast<box3_voice_audio *>(ctx);
    if (!stream || request_id == 0) {
        return;
    }

    bool flush = false;
    if (event == VOICE_AGENT_PLAYBACK_BEGIN) {
        {
            std::lock_guard<std::mutex> lock(stream->lifecycle_mutex);
            /* Keep admission closed until every queued packet from the old
             * generation has been returned to the fixed pool. */
            (void)voice_audio_session_begin(&stream->session, request_id);
            flush_queued_packets(stream);
        }
        return;
    }
    if (event == VOICE_AGENT_PLAYBACK_DRAIN) {
        {
            std::lock_guard<std::mutex> lock(stream->lifecycle_mutex);
            if (voice_audio_session_drain(&stream->session, request_id) !=
                VOICE_AUDIO_SESSION_OK) {
                stream->stale_packets.fetch_add(1, std::memory_order_relaxed);
                return;
            }
        }
        finish_drain_if_ready(stream);
        return;
    }
    if (event == VOICE_AGENT_PLAYBACK_FLUSH) {
        {
            std::lock_guard<std::mutex> lock(stream->lifecycle_mutex);
            if (voice_audio_session_flush(&stream->session, request_id) !=
                VOICE_AUDIO_SESSION_OK) {
                stream->stale_packets.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            flush = true;
        }
    }
    if (flush) {
        flush_queued_packets(stream);
        (void)box3_audio_enable_output(stream->config.audio, false);
    }
}

esp_err_t box3_voice_audio_push_binary(box3_voice_audio_t *stream,
                                       const uint8_t *packet,
                                       size_t packet_size)
{
    if (!stream || !packet || packet_size == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    voice_audio_packet_view_t view;
    if (voice_audio_protocol_decode(stream->config.transport_version, packet,
                                    packet_size, &view) !=
        VOICE_AUDIO_PROTOCOL_OK) {
        return ESP_ERR_INVALID_RESPONSE;
    }

    voice_audio_token_t token;
    {
        std::lock_guard<std::mutex> lock(stream->lifecycle_mutex);
        if (voice_audio_session_admit(&stream->session, &token) !=
            VOICE_AUDIO_SESSION_OK) {
            stream->stale_packets.fetch_add(1, std::memory_order_relaxed);
            return ESP_ERR_INVALID_STATE;
        }
    }

    downlink_item_t *item = nullptr;
    bool dropped = false;
    if (xQueueReceive(stream->free_items, &item, 0) != pdTRUE) {
        if (xQueueReceive(stream->decode_items, &item, 0) != pdTRUE) {
            stream->downlink_drops.fetch_add(1, std::memory_order_relaxed);
            notify_event(stream, BOX3_VOICE_AUDIO_EVENT_DOWNLINK_DROPPED,
                         token.request_id);
            return ESP_ERR_NO_MEM;
        }
        dropped = true;
    }
    item->token = token;
    item->timestamp_ms = view.timestamp_ms;
    item->opus_size = view.opus_size;
    memcpy(item->opus, view.opus, view.opus_size);
    if (xQueueSend(stream->decode_items, &item, 0) != pdTRUE) {
        return_free_item(stream, item);
        stream->downlink_drops.fetch_add(1, std::memory_order_relaxed);
        notify_event(stream, BOX3_VOICE_AUDIO_EVENT_DOWNLINK_DROPPED,
                     token.request_id);
        return ESP_ERR_NO_MEM;
    }
    if (dropped) {
        stream->downlink_drops.fetch_add(1, std::memory_order_relaxed);
        notify_event(stream, BOX3_VOICE_AUDIO_EVENT_DOWNLINK_DROPPED,
                     token.request_id);
    }
    return ESP_OK;
}

esp_err_t box3_voice_audio_get_stats(const box3_voice_audio_t *stream,
                                     box3_voice_audio_stats_t *stats)
{
    if (!stream || !stats) {
        return ESP_ERR_INVALID_ARG;
    }
    *stats = {
        .captured_frames = stream->captured_frames.load(std::memory_order_relaxed),
        .sent_packets = stream->sent_packets.load(std::memory_order_relaxed),
        .send_errors = stream->send_errors.load(std::memory_order_relaxed),
        .decoded_packets = stream->decoded_packets.load(std::memory_order_relaxed),
        .played_frames = stream->played_frames.load(std::memory_order_relaxed),
        .downlink_drops = stream->downlink_drops.load(std::memory_order_relaxed),
        .stale_packets = stream->stale_packets.load(std::memory_order_relaxed),
        .codec_errors = stream->codec_errors.load(std::memory_order_relaxed),
    };
    return ESP_OK;
}
