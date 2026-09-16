#include "product_factory_reset_core.h"

#include <string.h>

enum {
    JOURNAL_VERSION = 1,
};

static const uint8_t JOURNAL_MAGIC[4] = {'X', 'F', 'R', '1'};

static bool valid_phase(product_factory_reset_phase_t phase)
{
    return phase >= PRODUCT_FACTORY_RESET_PHASE_PREPARED &&
           phase <= PRODUCT_FACTORY_RESET_PHASE_MEMORY_CLEARED;
}

static uint32_t crc32(const uint8_t *data, size_t size)
{
    uint32_t crc = UINT32_C(0xffffffff);
    for (size_t index = 0; index < size; ++index) {
        crc ^= data[index];
        for (unsigned bit = 0; bit < 8; ++bit) {
            const uint32_t mask =
                (uint32_t)-(int32_t)(crc & UINT32_C(1));
            crc = (crc >> 1) ^ (UINT32_C(0xedb88320) & mask);
        }
    }
    return ~crc;
}

static void write_u32_le(uint8_t *output, uint32_t value)
{
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
    output[2] = (uint8_t)(value >> 16);
    output[3] = (uint8_t)(value >> 24);
}

static uint32_t read_u32_le(const uint8_t *input)
{
    return (uint32_t)input[0] |
           (uint32_t)input[1] << 8 |
           (uint32_t)input[2] << 16 |
           (uint32_t)input[3] << 24;
}

bool product_factory_reset_core_encode(
    product_factory_reset_phase_t phase,
    uint8_t output[PRODUCT_FACTORY_RESET_JOURNAL_BYTES])
{
    if (!output || !valid_phase(phase)) {
        return false;
    }
    memset(output, 0, PRODUCT_FACTORY_RESET_JOURNAL_BYTES);
    memcpy(output, JOURNAL_MAGIC, sizeof(JOURNAL_MAGIC));
    output[4] = JOURNAL_VERSION;
    output[5] = (uint8_t)phase;
    write_u32_le(output + 8, crc32(output, 8));
    return true;
}

bool product_factory_reset_core_decode(
    const uint8_t *input,
    size_t input_size,
    product_factory_reset_phase_t *phase)
{
    if (!input || !phase ||
        input_size != PRODUCT_FACTORY_RESET_JOURNAL_BYTES ||
        memcmp(input, JOURNAL_MAGIC, sizeof(JOURNAL_MAGIC)) != 0 ||
        input[4] != JOURNAL_VERSION || input[6] != 0 || input[7] != 0 ||
        read_u32_le(input + 8) != crc32(input, 8)) {
        return false;
    }
    const product_factory_reset_phase_t decoded =
        (product_factory_reset_phase_t)input[5];
    if (!valid_phase(decoded)) {
        return false;
    }
    *phase = decoded;
    return true;
}

product_factory_reset_action_t product_factory_reset_core_next_action(
    product_factory_reset_phase_t phase)
{
    switch (phase) {
    case PRODUCT_FACTORY_RESET_PHASE_PREPARED:
        return PRODUCT_FACTORY_RESET_ACTION_ERASE_WIFI;
    case PRODUCT_FACTORY_RESET_PHASE_WIFI_CLEARED:
        return PRODUCT_FACTORY_RESET_ACTION_ERASE_MEMORY;
    case PRODUCT_FACTORY_RESET_PHASE_MEMORY_CLEARED:
        return PRODUCT_FACTORY_RESET_ACTION_CLEAR_JOURNAL;
    case PRODUCT_FACTORY_RESET_PHASE_NONE:
    default:
        return PRODUCT_FACTORY_RESET_ACTION_NONE;
    }
}

bool product_factory_reset_core_advance(
    product_factory_reset_phase_t phase,
    product_factory_reset_action_t completed_action,
    product_factory_reset_phase_t *next_phase)
{
    if (!next_phase) {
        return false;
    }
    if (phase == PRODUCT_FACTORY_RESET_PHASE_PREPARED &&
        completed_action == PRODUCT_FACTORY_RESET_ACTION_ERASE_WIFI) {
        *next_phase = PRODUCT_FACTORY_RESET_PHASE_WIFI_CLEARED;
        return true;
    }
    if (phase == PRODUCT_FACTORY_RESET_PHASE_WIFI_CLEARED &&
        completed_action == PRODUCT_FACTORY_RESET_ACTION_ERASE_MEMORY) {
        *next_phase = PRODUCT_FACTORY_RESET_PHASE_MEMORY_CLEARED;
        return true;
    }
    if (phase == PRODUCT_FACTORY_RESET_PHASE_MEMORY_CLEARED &&
        completed_action == PRODUCT_FACTORY_RESET_ACTION_CLEAR_JOURNAL) {
        *next_phase = PRODUCT_FACTORY_RESET_PHASE_NONE;
        return true;
    }
    return false;
}
