#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct box3_audio box3_audio_t;

enum {
    BOX3_AUDIO_SAMPLE_RATE = 24000,
    BOX3_AUDIO_INPUT_CHANNELS = 2,
    BOX3_AUDIO_OUTPUT_CHANNELS = 1,
};

/* Pure build/link probe. Does not touch any peripheral. */
esp_err_t box3_audio_validate_profile(void);

/* Owns I2C1, I2S0, ES8311 output, and ES7210 input until destroyed. */
esp_err_t box3_audio_create(box3_audio_t **out_audio);
void box3_audio_destroy(box3_audio_t *audio);

esp_err_t box3_audio_enable_input(box3_audio_t *audio, bool enable);
esp_err_t box3_audio_enable_output(box3_audio_t *audio, bool enable);
esp_err_t box3_audio_set_output_volume(box3_audio_t *audio, int volume_percent);

/* Counts are int16 PCM samples, not bytes. */
esp_err_t box3_audio_read(box3_audio_t *audio,
                          int16_t *samples,
                          size_t sample_count,
                          size_t *samples_read);
esp_err_t box3_audio_write(box3_audio_t *audio,
                           const int16_t *samples,
                           size_t sample_count,
                           size_t *samples_written);

#ifdef __cplusplus
}
#endif
