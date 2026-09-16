#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "box3_audio.h"
#include "esp_err.h"
#include "voice_agent_controller.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct box3_voice_audio box3_voice_audio_t;

enum {
    BOX3_VOICE_AUDIO_UPLINK_SAMPLE_RATE = 16000,
    BOX3_VOICE_AUDIO_DOWNLINK_SAMPLE_RATE = 24000,
    BOX3_VOICE_AUDIO_FRAME_DURATION_MS = 60,
    BOX3_VOICE_AUDIO_DOWNLINK_QUEUE_DEPTH = 4,
};

typedef enum {
    BOX3_VOICE_AUDIO_EVENT_CAPTURE_ERROR = 0,
    BOX3_VOICE_AUDIO_EVENT_SEND_ERROR,
    BOX3_VOICE_AUDIO_EVENT_PLAYBACK_ERROR,
    BOX3_VOICE_AUDIO_EVENT_DOWNLINK_DROPPED,
    BOX3_VOICE_AUDIO_EVENT_PLAYBACK_DRAINED,
} box3_voice_audio_event_t;

typedef struct {
    uint32_t captured_frames;
    uint32_t sent_packets;
    uint32_t send_errors;
    uint32_t decoded_packets;
    uint32_t played_frames;
    uint32_t downlink_drops;
    uint32_t stale_packets;
    uint32_t codec_errors;
} box3_voice_audio_stats_t;

typedef struct {
    box3_audio_t *audio;
    int transport_version;

    /*
     * Must synchronously consume/copy bytes and return promptly; zero means
     * success.  A network transport should enqueue its own copy instead of
     * blocking the real-time capture task on socket I/O.
     */
    int (*send_binary)(void *ctx, const uint8_t *data, size_t size);
    /* Runs on the capture or playback task and must not block. */
    void (*event)(void *ctx,
                  box3_voice_audio_event_t event,
                  uint32_t request_id);
    void *ops_ctx;
} box3_voice_audio_config_t;

/*
 * Creates fixed 16 kHz/60 ms uplink and 24 kHz/60 ms downlink Opus codecs,
 * a 24->16 kHz microphone resampler, and two worker tasks.  The caller retains
 * ownership of config.audio and must destroy this stream before that HAL.
 */
/*
 * On ordinary failure out_stream is NULL. If worker cleanup times out, a
 * retained handle is returned and must be passed to destroy().
 */
esp_err_t box3_voice_audio_create(const box3_voice_audio_config_t *config,
                                  box3_voice_audio_t **out_stream);
/* ESP_OK consumes the handle; on timeout retain it and retry. */
esp_err_t box3_voice_audio_destroy(box3_voice_audio_t *stream);

esp_err_t box3_voice_audio_start_capture(box3_voice_audio_t *stream);
esp_err_t box3_voice_audio_stop_capture(box3_voice_audio_t *stream);

/*
 * Signature-compatible with voice_agent_controller_ops_t.playback_event.
 * When the controller uses a shared product ops_ctx, forward that callback
 * explicitly with the stream pointer rather than registering this function
 * directly.
 */
void box3_voice_audio_playback_event(void *ctx,
                                     voice_agent_playback_event_t event,
                                     uint32_t request_id);

/*
 * Called with an ordered XiaoZhi WebSocket binary frame.  The current request
 * is assigned by the preceding correlated TTS start event.  The packet is
 * copied into a bounded pool before this function returns.
 */
esp_err_t box3_voice_audio_push_binary(box3_voice_audio_t *stream,
                                       const uint8_t *packet,
                                       size_t packet_size);

esp_err_t box3_voice_audio_get_stats(const box3_voice_audio_t *stream,
                                     box3_voice_audio_stats_t *stats);

#ifdef __cplusplus
}
#endif
