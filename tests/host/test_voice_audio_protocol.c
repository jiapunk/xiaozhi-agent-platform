#include "voice_audio_protocol.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                    \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,          \
                    #condition);                                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static int test_round_trip_all_versions(void)
{
    const uint8_t opus[] = {0x11, 0x22, 0x33};
    uint8_t output[32];
    size_t output_size = 99;
    voice_audio_packet_view_t view;

    for (int version = 1; version <= 3; ++version) {
        CHECK(voice_audio_protocol_encode(version, opus, sizeof(opus),
                                          0x01020304, output, sizeof(output),
                                          &output_size) ==
              VOICE_AUDIO_PROTOCOL_OK);
        CHECK(voice_audio_protocol_decode(version, output, output_size, &view) ==
              VOICE_AUDIO_PROTOCOL_OK);
        CHECK(view.opus_size == sizeof(opus));
        CHECK(memcmp(view.opus, opus, sizeof(opus)) == 0);
        CHECK(view.timestamp_ms == (version == 2 ? 0x01020304U : 0U));
    }
    return 0;
}

static int test_exact_headers(void)
{
    const uint8_t opus[] = {0xaa};
    const uint8_t expected_v2[] = {
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x01, 0xaa,
    };
    const uint8_t expected_v3[] = {0x00, 0x00, 0x00, 0x01, 0xaa};
    uint8_t output[32];
    size_t output_size = 0;

    CHECK(voice_audio_protocol_encode(2, opus, sizeof(opus), 0x01020304,
                                      output, sizeof(output), &output_size) ==
          VOICE_AUDIO_PROTOCOL_OK);
    CHECK(output_size == sizeof(expected_v2));
    CHECK(memcmp(output, expected_v2, sizeof(expected_v2)) == 0);
    CHECK(voice_audio_protocol_encode(3, opus, sizeof(opus), 0x01020304,
                                      output, sizeof(output), &output_size) ==
          VOICE_AUDIO_PROTOCOL_OK);
    CHECK(output_size == sizeof(expected_v3));
    CHECK(memcmp(output, expected_v3, sizeof(expected_v3)) == 0);
    return 0;
}

static int test_rejects_invalid_and_malformed_packets(void)
{
    const uint8_t opus[] = {1, 2, 3};
    uint8_t output[32];
    size_t output_size = 7;
    voice_audio_packet_view_t view = {
        .opus = opus, .opus_size = sizeof(opus), .timestamp_ms = 99,
    };

    CHECK(voice_audio_protocol_encode(4, opus, sizeof(opus), 0, output,
                                      sizeof(output), &output_size) ==
          VOICE_AUDIO_PROTOCOL_ERR_UNSUPPORTED_VERSION);
    CHECK(output_size == 0);
    CHECK(voice_audio_protocol_encode(2, opus, sizeof(opus), 0, output, 18,
                                      &output_size) ==
          VOICE_AUDIO_PROTOCOL_ERR_BUFFER_TOO_SMALL);
    CHECK(output_size == 0);
    CHECK(voice_audio_protocol_encode(1, opus, 0, 0, output, sizeof(output),
                                      &output_size) ==
          VOICE_AUDIO_PROTOCOL_ERR_INVALID_ARG);

    CHECK(voice_audio_protocol_encode(2, opus, sizeof(opus), 0, output,
                                      sizeof(output), &output_size) ==
          VOICE_AUDIO_PROTOCOL_OK);
    output[7] = 1; /* Reserved field must remain zero. */
    CHECK(voice_audio_protocol_decode(2, output, output_size, &view) ==
          VOICE_AUDIO_PROTOCOL_ERR_MALFORMED_PACKET);
    CHECK(view.opus == NULL && view.opus_size == 0 && view.timestamp_ms == 0);

    CHECK(voice_audio_protocol_encode(3, opus, sizeof(opus), 0, output,
                                      sizeof(output), &output_size) ==
          VOICE_AUDIO_PROTOCOL_OK);
    output[1] = 1;
    CHECK(voice_audio_protocol_decode(3, output, output_size, &view) ==
          VOICE_AUDIO_PROTOCOL_ERR_MALFORMED_PACKET);
    output[1] = 0;
    output[3] = 4;
    CHECK(voice_audio_protocol_decode(3, output, output_size, &view) ==
          VOICE_AUDIO_PROTOCOL_ERR_MALFORMED_PACKET);
    CHECK(voice_audio_protocol_decode(1, output, 0, &view) ==
          VOICE_AUDIO_PROTOCOL_ERR_MALFORMED_PACKET);
    return 0;
}

int main(void)
{
    CHECK(test_round_trip_all_versions() == 0);
    CHECK(test_exact_headers() == 0);
    CHECK(test_rejects_invalid_and_malformed_packets() == 0);
    puts("voice_audio_protocol: all host tests passed");
    return 0;
}
