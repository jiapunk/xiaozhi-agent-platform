/*
 * Original work Copyright (c) 2025 Shenzhen Xinzhi Future Technology Co., Ltd.
 * and Project Contributors. Licensed under the MIT License; see
 * third_party/xiaozhi-esp32-LICENSE.txt.
 *
 * Product-owned lifecycle/API adaptation of XiaoZhi's BoxAudioCodec at
 * 18a60b8051f5ee6a25beed6248ed84c7fcc742bf (MIT License).
 * The proven BOX-3 pinout, ES8311/ES7210 setup, and I2S/TDM format are retained;
 * XiaoZhi's Board, Application, Settings, UI, and singleton ownership are not.
 */

#include "box3_audio.h"

#include <driver/gpio.h>
#include <driver/i2c_master.h>
#include <driver/i2s_std.h>
#include <driver/i2s_tdm.h>
#include <esp_codec_dev.h>
#include <esp_codec_dev_defaults.h>
#include <new>
#include <mutex>

namespace {

constexpr i2c_port_t kI2CPort = I2C_NUM_1;
// ESP-IDF 6 represents the I2S controller id as int and removed i2s_port_t.
constexpr int kI2SPort = I2S_NUM_0;
constexpr gpio_num_t kMclk = GPIO_NUM_2;
constexpr gpio_num_t kWordSelect = GPIO_NUM_45;
constexpr gpio_num_t kBitClock = GPIO_NUM_17;
constexpr gpio_num_t kDataIn = GPIO_NUM_16;
constexpr gpio_num_t kDataOut = GPIO_NUM_15;
constexpr gpio_num_t kPowerAmplifier = GPIO_NUM_46;
constexpr gpio_num_t kI2CSDA = GPIO_NUM_8;
constexpr gpio_num_t kI2CSCL = GPIO_NUM_18;
constexpr int kDMADescriptors = 6;
constexpr int kDMAFrames = 240;
constexpr float kInputGainDB = 30.0f;

}  // namespace

struct box3_audio {
    i2c_master_bus_handle_t i2c_bus = nullptr;
    i2s_chan_handle_t tx = nullptr;
    i2s_chan_handle_t rx = nullptr;
    const audio_codec_data_if_t *data_if = nullptr;
    const audio_codec_ctrl_if_t *output_ctrl = nullptr;
    const audio_codec_if_t *output_codec = nullptr;
    const audio_codec_ctrl_if_t *input_ctrl = nullptr;
    const audio_codec_if_t *input_codec = nullptr;
    const audio_codec_gpio_if_t *gpio_if = nullptr;
    esp_codec_dev_handle_t output_device = nullptr;
    esp_codec_dev_handle_t input_device = nullptr;
    /*
     * RX and TX are independent I2S channels and must be allowed to block at
     * the same time.  A single lock around read/write serializes 60 ms frames
     * and breaks full-duplex capture during TTS playback.  Keep one lock per
     * direction so lifecycle changes cannot race their own I/O while duplex
     * traffic remains concurrent.
     */
    std::mutex input_mutex;
    std::mutex output_mutex;
    bool input_enabled = false;
    bool output_enabled = false;
    int output_volume = 70;
};

static void cleanup(box3_audio *audio)
{
    if (!audio) {
        return;
    }
    if (audio->output_enabled && audio->output_device) {
        (void)esp_codec_dev_close(audio->output_device);
    }
    if (audio->input_enabled && audio->input_device) {
        (void)esp_codec_dev_close(audio->input_device);
    }
    if (audio->output_device) {
        esp_codec_dev_delete(audio->output_device);
    }
    if (audio->input_device) {
        esp_codec_dev_delete(audio->input_device);
    }
    if (audio->input_codec) {
        audio_codec_delete_codec_if(audio->input_codec);
    }
    if (audio->input_ctrl) {
        audio_codec_delete_ctrl_if(audio->input_ctrl);
    }
    if (audio->output_codec) {
        audio_codec_delete_codec_if(audio->output_codec);
    }
    if (audio->output_ctrl) {
        audio_codec_delete_ctrl_if(audio->output_ctrl);
    }
    if (audio->gpio_if) {
        audio_codec_delete_gpio_if(audio->gpio_if);
    }
    if (audio->data_if) {
        audio_codec_delete_data_if(audio->data_if);
    }
    if (audio->rx) {
        (void)i2s_channel_disable(audio->rx);
        (void)i2s_del_channel(audio->rx);
    }
    if (audio->tx) {
        (void)i2s_channel_disable(audio->tx);
        (void)i2s_del_channel(audio->tx);
    }
    if (audio->i2c_bus) {
        (void)i2c_del_master_bus(audio->i2c_bus);
    }
}

static esp_err_t initialize_i2c(box3_audio *audio)
{
    i2c_master_bus_config_t config = {
        .i2c_port = kI2CPort,
        .sda_io_num = kI2CSDA,
        .scl_io_num = kI2CSCL,
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .intr_priority = 0,
        .trans_queue_depth = 0,
        .flags = {
            .enable_internal_pullup = 1,
            .allow_pd = 0,
        },
    };
    return i2c_new_master_bus(&config, &audio->i2c_bus);
}

static esp_err_t initialize_i2s(box3_audio *audio)
{
    i2s_chan_config_t channel = {
        .id = kI2SPort,
        .role = I2S_ROLE_MASTER,
        .dma_desc_num = kDMADescriptors,
        .dma_frame_num = kDMAFrames,
        .auto_clear_after_cb = true,
        .auto_clear_before_cb = false,
        .allow_pd = false,
        .intr_priority = 0,
    };
    esp_err_t result = i2s_new_channel(&channel, &audio->tx, &audio->rx);
    if (result != ESP_OK) {
        return result;
    }

    i2s_std_config_t output = {
        .clk_cfg = {
            .sample_rate_hz = BOX3_AUDIO_SAMPLE_RATE,
            .clk_src = I2S_CLK_SRC_DEFAULT,
            .ext_clk_freq_hz = 0,
            .mclk_multiple = I2S_MCLK_MULTIPLE_256,
            .bclk_div = 0,
        },
        .slot_cfg = {
            .data_bit_width = I2S_DATA_BIT_WIDTH_16BIT,
            .slot_bit_width = I2S_SLOT_BIT_WIDTH_AUTO,
            .slot_mode = I2S_SLOT_MODE_STEREO,
            .slot_mask = I2S_STD_SLOT_BOTH,
            .ws_width = I2S_DATA_BIT_WIDTH_16BIT,
            .ws_pol = false,
            .bit_shift = true,
            .left_align = true,
            .big_endian = false,
            .bit_order_lsb = false,
        },
        .gpio_cfg = {
            .mclk = kMclk,
            .bclk = kBitClock,
            .ws = kWordSelect,
            .dout = kDataOut,
            .din = I2S_GPIO_UNUSED,
            .invert_flags = {},
        },
    };
    result = i2s_channel_init_std_mode(audio->tx, &output);
    if (result != ESP_OK) {
        return result;
    }

    i2s_tdm_config_t input = {
        .clk_cfg = {
            .sample_rate_hz = BOX3_AUDIO_SAMPLE_RATE,
            .clk_src = I2S_CLK_SRC_DEFAULT,
            .ext_clk_freq_hz = 0,
            .mclk_multiple = I2S_MCLK_MULTIPLE_256,
            .bclk_div = 8,
        },
        .slot_cfg = {
            .data_bit_width = I2S_DATA_BIT_WIDTH_16BIT,
            .slot_bit_width = I2S_SLOT_BIT_WIDTH_AUTO,
            .slot_mode = I2S_SLOT_MODE_STEREO,
            .slot_mask = static_cast<i2s_tdm_slot_mask_t>(
                I2S_TDM_SLOT0 | I2S_TDM_SLOT1 | I2S_TDM_SLOT2 | I2S_TDM_SLOT3),
            .ws_width = I2S_TDM_AUTO_WS_WIDTH,
            .ws_pol = false,
            .bit_shift = true,
            .left_align = false,
            .big_endian = false,
            .bit_order_lsb = false,
            .skip_mask = false,
            .total_slot = I2S_TDM_AUTO_SLOT_NUM,
        },
        .gpio_cfg = {
            .mclk = kMclk,
            .bclk = kBitClock,
            .ws = kWordSelect,
            .dout = I2S_GPIO_UNUSED,
            .din = kDataIn,
            .invert_flags = {},
        },
    };
    result = i2s_channel_init_tdm_mode(audio->rx, &input);
    if (result != ESP_OK) {
        return result;
    }
    result = i2s_channel_enable(audio->tx);
    if (result != ESP_OK) {
        return result;
    }
    return i2s_channel_enable(audio->rx);
}

static esp_err_t initialize_codecs(box3_audio *audio)
{
    audio_codec_i2s_cfg_t i2s = {
        .port = kI2SPort,
        .rx_handle = audio->rx,
        .tx_handle = audio->tx,
        .clk_src = 0,
    };
    audio->data_if = audio_codec_new_i2s_data(&i2s);
    if (!audio->data_if) {
        return ESP_ERR_NO_MEM;
    }
    audio_codec_i2c_cfg_t i2c = {
        .port = kI2CPort,
        .addr = ES8311_CODEC_DEFAULT_ADDR,
        .bus_handle = audio->i2c_bus,
    };
    audio->output_ctrl = audio_codec_new_i2c_ctrl(&i2c);
    audio->gpio_if = audio_codec_new_gpio();
    if (!audio->output_ctrl || !audio->gpio_if) {
        return ESP_ERR_NO_MEM;
    }
    es8311_codec_cfg_t output_codec = {};
    output_codec.ctrl_if = audio->output_ctrl;
    output_codec.gpio_if = audio->gpio_if;
    output_codec.codec_mode = ESP_CODEC_DEV_WORK_MODE_DAC;
    output_codec.pa_pin = kPowerAmplifier;
    output_codec.use_mclk = true;
    output_codec.hw_gain.pa_voltage = 5.0f;
    output_codec.hw_gain.codec_dac_voltage = 3.3f;
    audio->output_codec = es8311_codec_new(&output_codec);
    if (!audio->output_codec) {
        return ESP_ERR_NO_MEM;
    }
    esp_codec_dev_cfg_t device = {
        .dev_type = ESP_CODEC_DEV_TYPE_OUT,
        .codec_if = audio->output_codec,
        .data_if = audio->data_if,
    };
    audio->output_device = esp_codec_dev_new(&device);
    if (!audio->output_device) {
        return ESP_ERR_NO_MEM;
    }

    i2c.addr = ES7210_CODEC_DEFAULT_ADDR;
    audio->input_ctrl = audio_codec_new_i2c_ctrl(&i2c);
    if (!audio->input_ctrl) {
        return ESP_ERR_NO_MEM;
    }
    es7210_codec_cfg_t input_codec = {};
    input_codec.ctrl_if = audio->input_ctrl;
    input_codec.mic_selected =
        ES7210_SEL_MIC1 | ES7210_SEL_MIC2 | ES7210_SEL_MIC3 | ES7210_SEL_MIC4;
    audio->input_codec = es7210_codec_new(&input_codec);
    if (!audio->input_codec) {
        return ESP_ERR_NO_MEM;
    }
    device.dev_type = ESP_CODEC_DEV_TYPE_IN;
    device.codec_if = audio->input_codec;
    audio->input_device = esp_codec_dev_new(&device);
    return audio->input_device ? ESP_OK : ESP_ERR_NO_MEM;
}

esp_err_t box3_audio_validate_profile(void)
{
    static_assert(BOX3_AUDIO_SAMPLE_RATE == 24000);
    static_assert(kI2SPort == I2S_NUM_0);
    static_assert(kI2CPort == I2C_NUM_1);
    return ESP_OK;
}

esp_err_t box3_audio_create(box3_audio_t **out_audio)
{
    if (!out_audio) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_audio = nullptr;
    box3_audio *audio = new (std::nothrow) box3_audio();
    if (!audio) {
        return ESP_ERR_NO_MEM;
    }
    esp_err_t result = initialize_i2c(audio);
    if (result == ESP_OK) {
        result = initialize_i2s(audio);
    }
    if (result == ESP_OK) {
        result = initialize_codecs(audio);
    }
    if (result != ESP_OK) {
        cleanup(audio);
        delete audio;
        return result;
    }
    *out_audio = audio;
    return ESP_OK;
}

void box3_audio_destroy(box3_audio_t *audio)
{
    cleanup(audio);
    delete audio;
}

esp_err_t box3_audio_enable_input(box3_audio_t *audio, bool enable)
{
    if (!audio) {
        return ESP_ERR_INVALID_ARG;
    }
    std::lock_guard<std::mutex> lock(audio->input_mutex);
    if (audio->input_enabled == enable) {
        return ESP_OK;
    }
    esp_err_t result;
    if (enable) {
        esp_codec_dev_sample_info_t format = {
            .bits_per_sample = 16,
            .channel = 4,
            .channel_mask = ESP_CODEC_DEV_MAKE_CHANNEL_MASK(0) |
                            ESP_CODEC_DEV_MAKE_CHANNEL_MASK(1),
            .sample_rate = BOX3_AUDIO_SAMPLE_RATE,
            .mclk_multiple = 0,
        };
        result = esp_codec_dev_open(audio->input_device, &format);
        if (result == ESP_OK) {
            result = esp_codec_dev_set_in_channel_gain(
                audio->input_device, ESP_CODEC_DEV_MAKE_CHANNEL_MASK(0), kInputGainDB);
        }
        if (result != ESP_OK) {
            (void)esp_codec_dev_close(audio->input_device);
            return result;
        }
    } else {
        result = esp_codec_dev_close(audio->input_device);
        if (result != ESP_OK) {
            return result;
        }
    }
    audio->input_enabled = enable;
    return ESP_OK;
}

esp_err_t box3_audio_enable_output(box3_audio_t *audio, bool enable)
{
    if (!audio) {
        return ESP_ERR_INVALID_ARG;
    }
    std::lock_guard<std::mutex> lock(audio->output_mutex);
    if (audio->output_enabled == enable) {
        return ESP_OK;
    }
    esp_err_t result;
    if (enable) {
        esp_codec_dev_sample_info_t format = {
            .bits_per_sample = 16,
            .channel = BOX3_AUDIO_OUTPUT_CHANNELS,
            .channel_mask = 0,
            .sample_rate = BOX3_AUDIO_SAMPLE_RATE,
            .mclk_multiple = 0,
        };
        result = esp_codec_dev_open(audio->output_device, &format);
        if (result == ESP_OK) {
            result = esp_codec_dev_set_out_vol(audio->output_device, audio->output_volume);
        }
        if (result != ESP_OK) {
            (void)esp_codec_dev_close(audio->output_device);
            return result;
        }
    } else {
        result = esp_codec_dev_close(audio->output_device);
        if (result != ESP_OK) {
            return result;
        }
    }
    audio->output_enabled = enable;
    return ESP_OK;
}

esp_err_t box3_audio_set_output_volume(box3_audio_t *audio, int volume_percent)
{
    if (!audio || volume_percent < 0 || volume_percent > 100) {
        return ESP_ERR_INVALID_ARG;
    }
    std::lock_guard<std::mutex> lock(audio->output_mutex);
    if (audio->output_enabled) {
        esp_err_t result = esp_codec_dev_set_out_vol(audio->output_device, volume_percent);
        if (result != ESP_OK) {
            return result;
        }
    }
    audio->output_volume = volume_percent;
    return ESP_OK;
}

esp_err_t box3_audio_read(box3_audio_t *audio,
                          int16_t *samples,
                          size_t sample_count,
                          size_t *samples_read)
{
    if (!audio || !samples || sample_count == 0 || !samples_read ||
        sample_count > SIZE_MAX / sizeof(int16_t)) {
        return ESP_ERR_INVALID_ARG;
    }
    std::lock_guard<std::mutex> lock(audio->input_mutex);
    *samples_read = 0;
    if (!audio->input_enabled) {
        return ESP_ERR_INVALID_STATE;
    }
    esp_err_t result = esp_codec_dev_read(
        audio->input_device, samples, sample_count * sizeof(int16_t));
    if (result == ESP_OK) {
        *samples_read = sample_count;
    }
    return result;
}

esp_err_t box3_audio_write(box3_audio_t *audio,
                           const int16_t *samples,
                           size_t sample_count,
                           size_t *samples_written)
{
    if (!audio || !samples || sample_count == 0 || !samples_written ||
        sample_count > SIZE_MAX / sizeof(int16_t)) {
        return ESP_ERR_INVALID_ARG;
    }
    std::lock_guard<std::mutex> lock(audio->output_mutex);
    *samples_written = 0;
    if (!audio->output_enabled) {
        return ESP_ERR_INVALID_STATE;
    }
    esp_err_t result = esp_codec_dev_write(
        audio->output_device, const_cast<int16_t *>(samples),
        sample_count * sizeof(int16_t));
    if (result == ESP_OK) {
        *samples_written = sample_count;
    }
    return result;
}
