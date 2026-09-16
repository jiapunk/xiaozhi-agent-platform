#include "voice_audio_protocol.h"

#include <string.h>

static void write_u16_be(uint8_t *output, uint16_t value)
{
    output[0] = (uint8_t)(value >> 8);
    output[1] = (uint8_t)value;
}

static void write_u32_be(uint8_t *output, uint32_t value)
{
    output[0] = (uint8_t)(value >> 24);
    output[1] = (uint8_t)(value >> 16);
    output[2] = (uint8_t)(value >> 8);
    output[3] = (uint8_t)value;
}

static uint16_t read_u16_be(const uint8_t *input)
{
    return (uint16_t)(((uint16_t)input[0] << 8) | input[1]);
}

static uint32_t read_u32_be(const uint8_t *input)
{
    return ((uint32_t)input[0] << 24) |
           ((uint32_t)input[1] << 16) |
           ((uint32_t)input[2] << 8) |
           (uint32_t)input[3];
}

static voice_audio_protocol_result_t validate_opus_size(size_t opus_size)
{
    return opus_size > 0 && opus_size <= VOICE_AUDIO_PROTOCOL_MAX_OPUS_BYTES
               ? VOICE_AUDIO_PROTOCOL_OK
               : VOICE_AUDIO_PROTOCOL_ERR_INVALID_ARG;
}

voice_audio_protocol_result_t voice_audio_protocol_encode(
    int transport_version,
    const uint8_t *opus,
    size_t opus_size,
    uint32_t timestamp_ms,
    uint8_t *output,
    size_t output_capacity,
    size_t *encoded_size)
{
    size_t header_size;
    size_t required;

    if (encoded_size) {
        *encoded_size = 0;
    }
    if (!opus || !output || !encoded_size ||
        validate_opus_size(opus_size) != VOICE_AUDIO_PROTOCOL_OK) {
        return VOICE_AUDIO_PROTOCOL_ERR_INVALID_ARG;
    }
    switch (transport_version) {
    case 1:
        header_size = 0;
        break;
    case 2:
        header_size = VOICE_AUDIO_PROTOCOL_V2_HEADER_BYTES;
        break;
    case 3:
        header_size = VOICE_AUDIO_PROTOCOL_V3_HEADER_BYTES;
        break;
    default:
        return VOICE_AUDIO_PROTOCOL_ERR_UNSUPPORTED_VERSION;
    }
    required = header_size + opus_size;
    if (output_capacity < required) {
        return VOICE_AUDIO_PROTOCOL_ERR_BUFFER_TOO_SMALL;
    }

    if (transport_version == 2) {
        write_u16_be(output, 2);
        write_u16_be(output + 2, 0); /* Opus message type. */
        write_u32_be(output + 4, 0); /* Reserved. */
        write_u32_be(output + 8, timestamp_ms);
        write_u32_be(output + 12, (uint32_t)opus_size);
    } else if (transport_version == 3) {
        output[0] = 0; /* Opus message type. */
        output[1] = 0; /* Reserved. */
        write_u16_be(output + 2, (uint16_t)opus_size);
    }
    memcpy(output + header_size, opus, opus_size);
    *encoded_size = required;
    return VOICE_AUDIO_PROTOCOL_OK;
}

voice_audio_protocol_result_t voice_audio_protocol_decode(
    int transport_version,
    const uint8_t *packet,
    size_t packet_size,
    voice_audio_packet_view_t *view)
{
    size_t header_size;
    size_t declared_size;
    uint32_t timestamp = 0;

    if (!view) {
        return VOICE_AUDIO_PROTOCOL_ERR_INVALID_ARG;
    }
    memset(view, 0, sizeof(*view));
    if (!packet) {
        return VOICE_AUDIO_PROTOCOL_ERR_INVALID_ARG;
    }

    switch (transport_version) {
    case 1:
        header_size = 0;
        declared_size = packet_size;
        break;
    case 2:
        header_size = VOICE_AUDIO_PROTOCOL_V2_HEADER_BYTES;
        if (packet_size < header_size || read_u16_be(packet) != 2 ||
            read_u16_be(packet + 2) != 0 || read_u32_be(packet + 4) != 0) {
            return VOICE_AUDIO_PROTOCOL_ERR_MALFORMED_PACKET;
        }
        timestamp = read_u32_be(packet + 8);
        declared_size = read_u32_be(packet + 12);
        break;
    case 3:
        header_size = VOICE_AUDIO_PROTOCOL_V3_HEADER_BYTES;
        if (packet_size < header_size || packet[0] != 0 || packet[1] != 0) {
            return VOICE_AUDIO_PROTOCOL_ERR_MALFORMED_PACKET;
        }
        declared_size = read_u16_be(packet + 2);
        break;
    default:
        return VOICE_AUDIO_PROTOCOL_ERR_UNSUPPORTED_VERSION;
    }

    if (declared_size == 0 ||
        declared_size > VOICE_AUDIO_PROTOCOL_MAX_OPUS_BYTES ||
        declared_size != packet_size - header_size) {
        return VOICE_AUDIO_PROTOCOL_ERR_MALFORMED_PACKET;
    }
    view->opus = packet + header_size;
    view->opus_size = declared_size;
    view->timestamp_ms = timestamp;
    return VOICE_AUDIO_PROTOCOL_OK;
}
