#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    VOICE_AUDIO_PROTOCOL_MAX_OPUS_BYTES = 4096,
    VOICE_AUDIO_PROTOCOL_V2_HEADER_BYTES = 16,
    VOICE_AUDIO_PROTOCOL_V3_HEADER_BYTES = 4,
};

typedef enum {
    VOICE_AUDIO_PROTOCOL_OK = 0,
    VOICE_AUDIO_PROTOCOL_ERR_INVALID_ARG = -1,
    VOICE_AUDIO_PROTOCOL_ERR_BUFFER_TOO_SMALL = -2,
    VOICE_AUDIO_PROTOCOL_ERR_MALFORMED_PACKET = -3,
    VOICE_AUDIO_PROTOCOL_ERR_UNSUPPORTED_VERSION = -4,
} voice_audio_protocol_result_t;

typedef struct {
    const uint8_t *opus;
    size_t opus_size;
    uint32_t timestamp_ms;
} voice_audio_packet_view_t;

/*
 * XiaoZhi WebSocket binary framing.  Version 1 is raw Opus, version 2 has a
 * 16-byte big-endian header and timestamp, and version 3 has a 4-byte header.
 * The output may not overlap opus.  encoded_size is reset to zero on error.
 */
voice_audio_protocol_result_t voice_audio_protocol_encode(
    int transport_version,
    const uint8_t *opus,
    size_t opus_size,
    uint32_t timestamp_ms,
    uint8_t *output,
    size_t output_capacity,
    size_t *encoded_size);

/* Returns an immutable view into packet; no allocation or copy is performed. */
voice_audio_protocol_result_t voice_audio_protocol_decode(
    int transport_version,
    const uint8_t *packet,
    size_t packet_size,
    voice_audio_packet_view_t *view);

#ifdef __cplusplus
}
#endif
