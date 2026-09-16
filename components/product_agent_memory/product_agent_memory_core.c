#include "product_agent_memory_core.h"

#include <limits.h>
#include <string.h>

enum {
    FORMAT_VERSION = 2,
    HEADER_SIZE = 52,
    ITEM_HEADER_SIZE = 8,
    CHECKSUM_OFFSET = 16,
};

static const uint8_t FORMAT_MAGIC[4] = {'X', 'A', 'M', '2'};
static const uint8_t LEGACY_FORMAT_MAGIC[4] = {'X', 'A', 'M', '1'};

static size_t bounded_length(const char *text, size_t maximum)
{
    size_t size = 0;
    if (!text) {
        return maximum + 1;
    }
    while (size <= maximum && text[size] != '\0') {
        ++size;
    }
    return size;
}

static uint16_t read_u16_le(const uint8_t *input)
{
    return (uint16_t)input[0] | ((uint16_t)input[1] << 8);
}

static uint32_t read_u32_le(const uint8_t *input)
{
    return (uint32_t)input[0] | ((uint32_t)input[1] << 8) |
           ((uint32_t)input[2] << 16) | ((uint32_t)input[3] << 24);
}

static uint64_t read_u64_le(const uint8_t *input)
{
    uint64_t value = 0;
    for (unsigned index = 0; index < 8; ++index) {
        value |= (uint64_t)input[index] << (index * 8);
    }
    return value;
}

static void write_u16_le(uint8_t *output, uint16_t value)
{
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
}

static void write_u32_le(uint8_t *output, uint32_t value)
{
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
    output[2] = (uint8_t)(value >> 16);
    output[3] = (uint8_t)(value >> 24);
}

static void write_u64_le(uint8_t *output, uint64_t value)
{
    for (unsigned index = 0; index < 8; ++index) {
        output[index] = (uint8_t)(value >> (index * 8));
    }
}

static uint32_t crc32_with_zeroed_checksum(const uint8_t *data, size_t size)
{
    uint32_t crc = UINT32_MAX;
    for (size_t i = 0; i < size; ++i) {
        uint8_t value = (i >= CHECKSUM_OFFSET &&
                         i < CHECKSUM_OFFSET + sizeof(uint32_t))
                            ? 0
                            : data[i];
        crc ^= value;
        for (unsigned bit = 0; bit < 8; ++bit) {
            uint32_t mask = (uint32_t)-(int32_t)(crc & 1U);
            crc = (crc >> 1) ^ (0xedb88320U & mask);
        }
    }
    return ~crc;
}

static bool valid_utf8_scalar(uint32_t scalar)
{
    return scalar <= 0x10ffffU &&
           !(scalar >= 0xd800U && scalar <= 0xdfffU) &&
           scalar != 0xfffeU && scalar != 0xffffU;
}

static bool valid_single_line_utf8(const char *text, size_t maximum)
{
    const size_t size = bounded_length(text, maximum);
    if (size == 0 || size > maximum) {
        return false;
    }
    const uint8_t *bytes = (const uint8_t *)text;
    size_t offset = 0;
    while (offset < size) {
        uint32_t scalar;
        size_t width;
        const uint8_t first = bytes[offset];
        if (first < 0x80U) {
            if (first < 0x20U || first == 0x7fU) {
                return false;
            }
            scalar = first;
            width = 1;
        } else if (first >= 0xc2U && first <= 0xdfU) {
            scalar = first & 0x1fU;
            width = 2;
        } else if (first >= 0xe0U && first <= 0xefU) {
            scalar = first & 0x0fU;
            width = 3;
        } else if (first >= 0xf0U && first <= 0xf4U) {
            scalar = first & 0x07U;
            width = 4;
        } else {
            return false;
        }
        if (offset + width > size) {
            return false;
        }
        for (size_t i = 1; i < width; ++i) {
            if ((bytes[offset + i] & 0xc0U) != 0x80U) {
                return false;
            }
            scalar = (scalar << 6) | (bytes[offset + i] & 0x3fU);
        }
        if ((width == 2 && scalar < 0x80U) ||
            (width == 3 && scalar < 0x800U) ||
            (width == 4 && scalar < 0x10000U) ||
            !valid_utf8_scalar(scalar)) {
            return false;
        }
        offset += width;
    }
    return true;
}

static bool contains_ascii_case_insensitive(const char *text,
                                             const char *needle)
{
    const size_t needle_size = strlen(needle);
    if (needle_size == 0) {
        return true;
    }
    for (size_t offset = 0; text[offset] != '\0'; ++offset) {
        size_t i = 0;
        while (i < needle_size && text[offset + i] != '\0') {
            unsigned char value = (unsigned char)text[offset + i];
            if (value >= 'A' && value <= 'Z') {
                value = (unsigned char)(value - 'A' + 'a');
            }
            if (value != (unsigned char)needle[i]) {
                break;
            }
            ++i;
        }
        if (i == needle_size) {
            return true;
        }
    }
    return false;
}

static bool category_valid(product_agent_memory_core_category_t category)
{
    return category == PRODUCT_AGENT_MEMORY_CATEGORY_PREFERENCE ||
           category == PRODUCT_AGENT_MEMORY_CATEGORY_PROFILE;
}

bool product_agent_memory_core_key_allowed(const char *key)
{
    static const char *const blocked[] = {
        "password", "passwd", "secret", "token", "credential",
        "api_key", "private_key", "auth", "cookie", "pin", "ssn",
        "medical", "health", "biometric", "religion", "politic",
        "sexual", "financial", "payment", "card_number", "location",
        "address", "phone", "email",
    };
    const size_t size = bounded_length(key, PRODUCT_AGENT_MEMORY_KEY_MAX);
    if (size == 0 || size > PRODUCT_AGENT_MEMORY_KEY_MAX ||
        key[0] < 'a' || key[0] > 'z') {
        return false;
    }
    for (size_t i = 1; i < size; ++i) {
        const char value = key[i];
        if (!((value >= 'a' && value <= 'z') ||
              (value >= '0' && value <= '9') || value == '_' ||
              value == '-' || value == '.')) {
            return false;
        }
    }
    for (size_t i = 0; i < sizeof(blocked) / sizeof(blocked[0]); ++i) {
        if (strstr(key, blocked[i])) {
            return false;
        }
    }
    return true;
}

bool product_agent_memory_core_value_allowed(const char *value)
{
    static const char *const blocked[] = {
        "password=", "passwd=", "secret=", "token=", "api_key",
        "private_key", "bearer ", "-----begin ",
    };
    if (!valid_single_line_utf8(value, PRODUCT_AGENT_MEMORY_VALUE_MAX)) {
        return false;
    }
    for (size_t i = 0; i < sizeof(blocked) / sizeof(blocked[0]); ++i) {
        if (contains_ascii_case_insensitive(value, blocked[i])) {
            return false;
        }
    }
    return true;
}

bool product_agent_memory_core_binding_id_allowed(const char *value)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const size_t size = bounded_length(
        value, PRODUCT_AGENT_MEMORY_BINDING_ID_MAX);
    if (size != PRODUCT_AGENT_MEMORY_BINDING_ID_MAX) {
        return false;
    }
    for (size_t index = 0; index < size; ++index) {
        const char *found = strchr(alphabet, value[index]);
        if (!found || (index == size - 1 &&
                       (((size_t)(found - alphabet)) & 0x0fU) != 0)) {
            return false;
        }
    }
    return true;
}

bool product_agent_memory_core_is_bound(
    const product_agent_memory_core_state_t *state)
{
    return state && state->binding_revision > 0 &&
           state->binding_revision <= UINT32_MAX &&
           product_agent_memory_core_binding_id_allowed(state->binding_id);
}

static bool state_valid(const product_agent_memory_core_state_t *state,
                        bool persisted)
{
    const bool bound = product_agent_memory_core_is_bound(state);
    if (!state || state->count > PRODUCT_AGENT_MEMORY_MAX_ITEMS ||
        (persisted && state->generation == 0) ||
        (!persisted && state->generation == 0 &&
         (state->count != 0 || state->binding_revision != 0 ||
          state->binding_id[0] != '\0')) ||
        (!bound && (state->binding_revision != 0 ||
                    state->binding_id[0] != '\0' || state->count != 0))) {
        return false;
    }
    for (uint8_t i = 0; i < state->count; ++i) {
        const product_agent_memory_core_item_t *item = &state->items[i];
        if (!category_valid(item->category) ||
            !product_agent_memory_core_key_allowed(item->key) ||
            !product_agent_memory_core_value_allowed(item->value) ||
            item->revision == 0 || item->revision > state->generation ||
            (i > 0 && strcmp(state->items[i - 1].key, item->key) >= 0)) {
            return false;
        }
    }
    return true;
}

void product_agent_memory_core_init(product_agent_memory_core_state_t *state)
{
    if (state) {
        memset(state, 0, sizeof(*state));
    }
}

product_agent_memory_core_result_t product_agent_memory_core_encode(
    const product_agent_memory_core_state_t *state,
    uint8_t *output,
    size_t output_capacity,
    size_t *output_size)
{
    if (!output_size || !state_valid(state, true)) {
        return PRODUCT_AGENT_MEMORY_CORE_INVALID;
    }
    size_t required = HEADER_SIZE;
    for (uint8_t i = 0; i < state->count; ++i) {
        required += ITEM_HEADER_SIZE + strlen(state->items[i].key) +
                    strlen(state->items[i].value);
    }
    if (required > PRODUCT_AGENT_MEMORY_BLOB_MAX || required > UINT16_MAX) {
        return PRODUCT_AGENT_MEMORY_CORE_INVALID;
    }
    *output_size = required;
    if (!output || output_capacity < required) {
        return PRODUCT_AGENT_MEMORY_CORE_BUFFER_TOO_SMALL;
    }
    memset(output, 0, required);
    memcpy(output, FORMAT_MAGIC, sizeof(FORMAT_MAGIC));
    output[4] = FORMAT_VERSION;
    output[5] = state->count;
    write_u32_le(output + 8, state->generation);
    write_u16_le(output + 12, (uint16_t)(required - HEADER_SIZE));
    write_u64_le(output + 20, state->binding_revision);
    if (product_agent_memory_core_is_bound(state)) {
        memcpy(output + 28, state->binding_id,
               PRODUCT_AGENT_MEMORY_BINDING_ID_MAX);
    }

    size_t offset = HEADER_SIZE;
    for (uint8_t i = 0; i < state->count; ++i) {
        const product_agent_memory_core_item_t *item = &state->items[i];
        const size_t key_size = strlen(item->key);
        const size_t value_size = strlen(item->value);
        output[offset] = (uint8_t)item->category;
        output[offset + 1] = (uint8_t)key_size;
        write_u16_le(output + offset + 2, (uint16_t)value_size);
        write_u32_le(output + offset + 4, item->revision);
        offset += ITEM_HEADER_SIZE;
        memcpy(output + offset, item->key, key_size);
        offset += key_size;
        memcpy(output + offset, item->value, value_size);
        offset += value_size;
    }
    write_u32_le(output + CHECKSUM_OFFSET,
                 crc32_with_zeroed_checksum(output, required));
    return PRODUCT_AGENT_MEMORY_CORE_OK;
}

product_agent_memory_core_result_t product_agent_memory_core_decode(
    const uint8_t *input,
    size_t input_size,
    product_agent_memory_core_state_t *state)
{
    product_agent_memory_core_state_t decoded;
    if (input && state && input_size >= 20 &&
        memcmp(input, LEGACY_FORMAT_MAGIC,
               sizeof(LEGACY_FORMAT_MAGIC)) == 0) {
        enum { LEGACY_HEADER_SIZE = 20 };
        if (input_size > PRODUCT_AGENT_MEMORY_BLOB_MAX || input[4] != 1 ||
            input[5] > PRODUCT_AGENT_MEMORY_MAX_ITEMS || input[6] != 0 ||
            input[7] != 0 || input[14] != 0 || input[15] != 0 ||
            read_u32_le(input + 8) == 0 ||
            (size_t)read_u16_le(input + 12) !=
                input_size - LEGACY_HEADER_SIZE ||
            read_u32_le(input + CHECKSUM_OFFSET) !=
                crc32_with_zeroed_checksum(input, input_size)) {
            return PRODUCT_AGENT_MEMORY_CORE_CORRUPT;
        }
        product_agent_memory_core_state_t legacy;
        product_agent_memory_core_init(&legacy);
        legacy.generation = read_u32_le(input + 8);
        legacy.count = input[5];
        size_t offset = LEGACY_HEADER_SIZE;
        for (uint8_t i = 0; i < legacy.count; ++i) {
            if (input_size - offset < ITEM_HEADER_SIZE) {
                return PRODUCT_AGENT_MEMORY_CORE_CORRUPT;
            }
            product_agent_memory_core_item_t *item = &legacy.items[i];
            item->category =
                (product_agent_memory_core_category_t)input[offset];
            const size_t key_size = input[offset + 1];
            const size_t value_size = read_u16_le(input + offset + 2);
            item->revision = read_u32_le(input + offset + 4);
            offset += ITEM_HEADER_SIZE;
            if (key_size == 0 || key_size > PRODUCT_AGENT_MEMORY_KEY_MAX ||
                value_size == 0 ||
                value_size > PRODUCT_AGENT_MEMORY_VALUE_MAX ||
                key_size + value_size > input_size - offset) {
                return PRODUCT_AGENT_MEMORY_CORE_CORRUPT;
            }
            memcpy(item->key, input + offset, key_size);
            item->key[key_size] = '\0';
            offset += key_size;
            memcpy(item->value, input + offset, value_size);
            item->value[value_size] = '\0';
            offset += value_size;
            if (!category_valid(item->category) ||
                !product_agent_memory_core_key_allowed(item->key) ||
                !product_agent_memory_core_value_allowed(item->value) ||
                item->revision == 0 ||
                item->revision > legacy.generation ||
                (i > 0 && strcmp(legacy.items[i - 1].key,
                                 item->key) >= 0)) {
                return PRODUCT_AGENT_MEMORY_CORE_CORRUPT;
            }
        }
        if (offset != input_size) {
            return PRODUCT_AGENT_MEMORY_CORE_CORRUPT;
        }
        /* XAM1 predates cloud ownership binding. Preserve only its monotonic
         * generation and discard all unscoped values. The next authenticated
         * reconcile writes XAM2 atomically before memory can be used. */
        product_agent_memory_core_init(&decoded);
        decoded.generation = legacy.generation;
        *state = decoded;
        return PRODUCT_AGENT_MEMORY_CORE_OK;
    }
    if (!input || !state || input_size < HEADER_SIZE ||
        input_size > PRODUCT_AGENT_MEMORY_BLOB_MAX ||
        memcmp(input, FORMAT_MAGIC, sizeof(FORMAT_MAGIC)) != 0 ||
        input[4] != FORMAT_VERSION || input[5] > PRODUCT_AGENT_MEMORY_MAX_ITEMS ||
        input[6] != 0 || input[7] != 0 || input[14] != 0 || input[15] != 0 ||
        input[50] != 0 || input[51] != 0 ||
        read_u32_le(input + 8) == 0 ||
        (size_t)read_u16_le(input + 12) != input_size - HEADER_SIZE ||
        read_u32_le(input + CHECKSUM_OFFSET) !=
            crc32_with_zeroed_checksum(input, input_size)) {
        return PRODUCT_AGENT_MEMORY_CORE_CORRUPT;
    }
    product_agent_memory_core_init(&decoded);
    decoded.generation = read_u32_le(input + 8);
    decoded.count = input[5];
    decoded.binding_revision = read_u64_le(input + 20);
    if (decoded.binding_revision > 0) {
        memcpy(decoded.binding_id, input + 28,
               PRODUCT_AGENT_MEMORY_BINDING_ID_MAX);
        decoded.binding_id[PRODUCT_AGENT_MEMORY_BINDING_ID_MAX] = '\0';
    } else {
        for (size_t index = 28; index < 50; ++index) {
            if (input[index] != 0) {
                return PRODUCT_AGENT_MEMORY_CORE_CORRUPT;
            }
        }
    }
    size_t offset = HEADER_SIZE;
    for (uint8_t i = 0; i < decoded.count; ++i) {
        if (input_size - offset < ITEM_HEADER_SIZE) {
            return PRODUCT_AGENT_MEMORY_CORE_CORRUPT;
        }
        product_agent_memory_core_item_t *item = &decoded.items[i];
        item->category = (product_agent_memory_core_category_t)input[offset];
        const size_t key_size = input[offset + 1];
        const size_t value_size = read_u16_le(input + offset + 2);
        item->revision = read_u32_le(input + offset + 4);
        offset += ITEM_HEADER_SIZE;
        if (key_size == 0 || key_size > PRODUCT_AGENT_MEMORY_KEY_MAX ||
            value_size == 0 || value_size > PRODUCT_AGENT_MEMORY_VALUE_MAX ||
            key_size + value_size > input_size - offset) {
            return PRODUCT_AGENT_MEMORY_CORE_CORRUPT;
        }
        memcpy(item->key, input + offset, key_size);
        item->key[key_size] = '\0';
        offset += key_size;
        memcpy(item->value, input + offset, value_size);
        item->value[value_size] = '\0';
        offset += value_size;
    }
    /* Every encoded field has one representation: fixed little-endian
     * integers, zero reserved bytes, exact lengths, strict key ordering, and
     * no trailing data. Those checks make re-encoding here redundant and
     * avoid a 2 KiB stack buffer on the ESP main task. */
    if (offset != input_size || !state_valid(&decoded, true)) {
        return PRODUCT_AGENT_MEMORY_CORE_CORRUPT;
    }
    *state = decoded;
    return PRODUCT_AGENT_MEMORY_CORE_OK;
}

product_agent_memory_core_result_t product_agent_memory_core_select(
    const uint8_t *slot0,
    size_t slot0_size,
    const uint8_t *slot1,
    size_t slot1_size,
    product_agent_memory_core_state_t *state,
    product_agent_memory_core_selection_t *selection)
{
    product_agent_memory_core_state_t decoded[2];
    const uint8_t *slots[2] = {slot0, slot1};
    const size_t sizes[2] = {slot0_size, slot1_size};
    bool valid[2] = {false, false};
    if (!state || !selection || (slot0_size > 0 && !slot0) ||
        (slot1_size > 0 && !slot1)) {
        return PRODUCT_AGENT_MEMORY_CORE_INVALID;
    }
    memset(selection, 0, sizeof(*selection));
    selection->selected_slot = -1;
    for (int i = 0; i < 2; ++i) {
        selection->slot_present[i] = sizes[i] > 0;
        if (sizes[i] > 0 &&
            product_agent_memory_core_decode(slots[i], sizes[i],
                                             &decoded[i]) ==
                PRODUCT_AGENT_MEMORY_CORE_OK) {
            valid[i] = true;
            selection->slot_valid[i] = true;
        }
    }
    if (!valid[0] && !valid[1]) {
        if (!selection->slot_present[0] && !selection->slot_present[1]) {
            product_agent_memory_core_init(state);
            return PRODUCT_AGENT_MEMORY_CORE_OK;
        }
        return PRODUCT_AGENT_MEMORY_CORE_CORRUPT;
    }
    if (valid[0] && valid[1] &&
        decoded[0].generation == decoded[1].generation) {
        if (sizes[0] != sizes[1] ||
            memcmp(slots[0], slots[1], sizes[0]) != 0) {
            return PRODUCT_AGENT_MEMORY_CORE_DIVERGED;
        }
        *state = decoded[0];
        selection->selected_slot = 0;
        return PRODUCT_AGENT_MEMORY_CORE_OK;
    }
    selection->degraded = true;
    int selected = valid[0] && valid[1]
                       ? (decoded[1].generation > decoded[0].generation ? 1 : 0)
                       : (valid[0] ? 0 : 1);
    *state = decoded[selected];
    selection->selected_slot = selected;
    return PRODUCT_AGENT_MEMORY_CORE_OK;
}

const product_agent_memory_core_item_t *product_agent_memory_core_find(
    const product_agent_memory_core_state_t *state,
    const char *key)
{
    if (!state || !product_agent_memory_core_key_allowed(key)) {
        return NULL;
    }
    for (uint8_t i = 0; i < state->count; ++i) {
        const int comparison = strcmp(state->items[i].key, key);
        if (comparison == 0) {
            return &state->items[i];
        }
        if (comparison > 0) {
            break;
        }
    }
    return NULL;
}

static product_agent_memory_core_result_t next_generation(
    product_agent_memory_core_state_t *state,
    uint32_t *generation)
{
    if (!state || !generation || state->generation == UINT32_MAX) {
        return PRODUCT_AGENT_MEMORY_CORE_GENERATION_EXHAUSTED;
    }
    *generation = state->generation + 1;
    return PRODUCT_AGENT_MEMORY_CORE_OK;
}

product_agent_memory_core_result_t product_agent_memory_core_reconcile_binding(
    product_agent_memory_core_state_t *state,
    const char *binding_id,
    uint64_t binding_revision)
{
    if (!state || !state_valid(state, false) ||
        !product_agent_memory_core_binding_id_allowed(binding_id) ||
        binding_revision == 0 || binding_revision > UINT32_MAX) {
        return PRODUCT_AGENT_MEMORY_CORE_INVALID;
    }
    if (product_agent_memory_core_is_bound(state)) {
        if (state->binding_revision > binding_revision ||
            (state->binding_revision == binding_revision &&
             strcmp(state->binding_id, binding_id) != 0)) {
            return PRODUCT_AGENT_MEMORY_CORE_BINDING_STALE;
        }
        if (state->binding_revision == binding_revision) {
            return PRODUCT_AGENT_MEMORY_CORE_OK;
        }
    }
    uint32_t generation = 0;
    product_agent_memory_core_result_t result =
        next_generation(state, &generation);
    if (result != PRODUCT_AGENT_MEMORY_CORE_OK) {
        return result;
    }
    memset(state->items, 0, sizeof(state->items));
    state->count = 0;
    strcpy(state->binding_id, binding_id);
    state->binding_revision = binding_revision;
    state->generation = generation;
    return PRODUCT_AGENT_MEMORY_CORE_OK;
}

product_agent_memory_core_result_t product_agent_memory_core_put(
    product_agent_memory_core_state_t *state,
    product_agent_memory_core_category_t category,
    const char *key,
    const char *value)
{
    uint32_t generation;
    if (!state || !state_valid(state, false) ||
        !product_agent_memory_core_is_bound(state) || !category_valid(category) ||
        !product_agent_memory_core_key_allowed(key) ||
        !product_agent_memory_core_value_allowed(value)) {
        return PRODUCT_AGENT_MEMORY_CORE_INVALID;
    }
    product_agent_memory_core_result_t result =
        next_generation(state, &generation);
    if (result != PRODUCT_AGENT_MEMORY_CORE_OK) {
        return result;
    }
    uint8_t index = 0;
    while (index < state->count && strcmp(state->items[index].key, key) < 0) {
        ++index;
    }
    if (index < state->count && strcmp(state->items[index].key, key) == 0) {
        product_agent_memory_core_item_t *item = &state->items[index];
        item->category = category;
        strcpy(item->value, value);
        item->revision = generation;
    } else {
        if (state->count == PRODUCT_AGENT_MEMORY_MAX_ITEMS) {
            return PRODUCT_AGENT_MEMORY_CORE_FULL;
        }
        memmove(&state->items[index + 1], &state->items[index],
                (size_t)(state->count - index) * sizeof(state->items[0]));
        product_agent_memory_core_item_t *item = &state->items[index];
        memset(item, 0, sizeof(*item));
        item->category = category;
        strcpy(item->key, key);
        strcpy(item->value, value);
        item->revision = generation;
        ++state->count;
    }
    state->generation = generation;
    return PRODUCT_AGENT_MEMORY_CORE_OK;
}

product_agent_memory_core_result_t product_agent_memory_core_forget(
    product_agent_memory_core_state_t *state,
    const char *key)
{
    uint32_t generation;
    if (!state || !state_valid(state, false) ||
        !product_agent_memory_core_is_bound(state) ||
        !product_agent_memory_core_key_allowed(key)) {
        return PRODUCT_AGENT_MEMORY_CORE_INVALID;
    }
    uint8_t index = 0;
    while (index < state->count && strcmp(state->items[index].key, key) != 0) {
        ++index;
    }
    if (index == state->count) {
        return PRODUCT_AGENT_MEMORY_CORE_NOT_FOUND;
    }
    product_agent_memory_core_result_t result =
        next_generation(state, &generation);
    if (result != PRODUCT_AGENT_MEMORY_CORE_OK) {
        return result;
    }
    memmove(&state->items[index], &state->items[index + 1],
            (size_t)(state->count - index - 1) * sizeof(state->items[0]));
    --state->count;
    memset(&state->items[state->count], 0, sizeof(state->items[0]));
    state->generation = generation;
    return PRODUCT_AGENT_MEMORY_CORE_OK;
}

product_agent_memory_core_result_t product_agent_memory_core_clear(
    product_agent_memory_core_state_t *state)
{
    uint32_t generation;
    if (!state || !state_valid(state, false) ||
        !product_agent_memory_core_is_bound(state)) {
        return PRODUCT_AGENT_MEMORY_CORE_INVALID;
    }
    product_agent_memory_core_result_t result =
        next_generation(state, &generation);
    if (result != PRODUCT_AGENT_MEMORY_CORE_OK) {
        return result;
    }
    memset(state->items, 0, sizeof(state->items));
    state->count = 0;
    state->generation = generation;
    return PRODUCT_AGENT_MEMORY_CORE_OK;
}
