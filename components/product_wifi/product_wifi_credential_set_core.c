#include "product_wifi_credential_set_core.h"

#include <string.h>

enum {
    SET_VERSION = 1,
    COUNT_OFFSET = 5,
    ACTIVE_OFFSET = 6,
    RESERVED_OFFSET = 7,
    CREDENTIALS_OFFSET = 8,
    CHECKSUM_OFFSET = PRODUCT_WIFI_CREDENTIAL_SET_BLOB_SIZE - 4,
};

static const uint8_t SET_MAGIC[4] = {'P', 'W', 'L', '1'};

static void secure_zero(void *memory, size_t size)
{
    volatile uint8_t *bytes = memory;
    while (bytes && size > 0) {
        *bytes++ = 0;
        --size;
    }
}

static uint32_t crc32(const uint8_t *data, size_t size)
{
    uint32_t crc = UINT32_MAX;
    for (size_t index = 0; index < size; ++index) {
        crc ^= data[index];
        for (unsigned bit = 0; bit < 8; ++bit) {
            const uint32_t mask = (uint32_t)-(int32_t)(crc & 1U);
            crc = (crc >> 1) ^ (0xedb88320U & mask);
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
    return (uint32_t)input[0] | ((uint32_t)input[1] << 8) |
           ((uint32_t)input[2] << 16) | ((uint32_t)input[3] << 24);
}

static bool entries_are_unique(const product_wifi_credential_set_t *set)
{
    for (uint8_t left = 0; left < set->count; ++left) {
        if (!product_wifi_credentials_valid(set->entries[left].ssid,
                                            set->entries[left].password)) {
            return false;
        }
        for (uint8_t right = (uint8_t)(left + 1); right < set->count;
             ++right) {
            if (strcmp(set->entries[left].ssid,
                       set->entries[right].ssid) == 0) {
                return false;
            }
        }
    }
    return true;
}

bool product_wifi_credential_set_encode(
    const product_wifi_credential_set_t *set,
    uint8_t output[PRODUCT_WIFI_CREDENTIAL_SET_BLOB_SIZE])
{
    if (!set || !output || set->count == 0 ||
        set->count > PRODUCT_WIFI_CREDENTIAL_SET_LIMIT ||
        set->active_index >= set->count || !entries_are_unique(set)) {
        return false;
    }
    memset(output, 0, PRODUCT_WIFI_CREDENTIAL_SET_BLOB_SIZE);
    memcpy(output, SET_MAGIC, sizeof(SET_MAGIC));
    output[4] = SET_VERSION;
    output[COUNT_OFFSET] = set->count;
    output[ACTIVE_OFFSET] = set->active_index;
    for (uint8_t index = 0; index < set->count; ++index) {
        if (!product_wifi_credentials_encode(
                &set->entries[index],
                output + CREDENTIALS_OFFSET +
                    (size_t)index * PRODUCT_WIFI_CREDENTIAL_BLOB_SIZE)) {
            secure_zero(output, PRODUCT_WIFI_CREDENTIAL_SET_BLOB_SIZE);
            return false;
        }
    }
    write_u32_le(output + CHECKSUM_OFFSET, crc32(output, CHECKSUM_OFFSET));
    return true;
}

bool product_wifi_credential_set_decode(
    const uint8_t *input,
    size_t input_size,
    product_wifi_credential_set_t *set)
{
    if (!input || !set || input_size != PRODUCT_WIFI_CREDENTIAL_SET_BLOB_SIZE ||
        memcmp(input, SET_MAGIC, sizeof(SET_MAGIC)) != 0 ||
        input[4] != SET_VERSION || input[COUNT_OFFSET] == 0 ||
        input[COUNT_OFFSET] > PRODUCT_WIFI_CREDENTIAL_SET_LIMIT ||
        input[ACTIVE_OFFSET] >= input[COUNT_OFFSET] ||
        input[RESERVED_OFFSET] != 0 ||
        read_u32_le(input + CHECKSUM_OFFSET) !=
            crc32(input, CHECKSUM_OFFSET)) {
        return false;
    }
    product_wifi_credential_set_t decoded = {
        .count = input[COUNT_OFFSET],
        .active_index = input[ACTIVE_OFFSET],
    };
    for (uint8_t index = 0; index < decoded.count; ++index) {
        if (!product_wifi_credentials_decode(
                input + CREDENTIALS_OFFSET +
                    (size_t)index * PRODUCT_WIFI_CREDENTIAL_BLOB_SIZE,
                PRODUCT_WIFI_CREDENTIAL_BLOB_SIZE,
                &decoded.entries[index])) {
            secure_zero(&decoded, sizeof(decoded));
            return false;
        }
    }
    const size_t unused_start =
        CREDENTIALS_OFFSET +
        (size_t)decoded.count * PRODUCT_WIFI_CREDENTIAL_BLOB_SIZE;
    for (size_t index = unused_start; index < CHECKSUM_OFFSET; ++index) {
        if (input[index] != 0) {
            secure_zero(&decoded, sizeof(decoded));
            return false;
        }
    }
    if (!entries_are_unique(&decoded)) {
        secure_zero(&decoded, sizeof(decoded));
        return false;
    }
    *set = decoded;
    secure_zero(&decoded, sizeof(decoded));
    return true;
}

bool product_wifi_credential_set_upsert(
    product_wifi_credential_set_t *set,
    const product_wifi_credentials_t *credentials)
{
    if (!set || !credentials ||
        !product_wifi_credentials_valid(credentials->ssid,
                                        credentials->password) ||
        set->count > PRODUCT_WIFI_CREDENTIAL_SET_LIMIT ||
        (set->count > 0 &&
         (set->active_index >= set->count || !entries_are_unique(set)))) {
        return false;
    }
    uint8_t source = set->count;
    for (uint8_t index = 0; index < set->count; ++index) {
        if (strcmp(set->entries[index].ssid, credentials->ssid) == 0) {
            source = index;
            break;
        }
    }
    uint8_t new_count = set->count;
    uint8_t shift_from = source;
    if (source == set->count) {
        if (new_count < PRODUCT_WIFI_CREDENTIAL_SET_LIMIT) {
            ++new_count;
        }
        shift_from = (uint8_t)(new_count - 1);
    }
    for (uint8_t index = shift_from; index > 0; --index) {
        set->entries[index] = set->entries[index - 1];
    }
    set->entries[0] = *credentials;
    set->count = new_count;
    set->active_index = 0;
    for (uint8_t index = new_count;
         index < PRODUCT_WIFI_CREDENTIAL_SET_LIMIT; ++index) {
        secure_zero(&set->entries[index], sizeof(set->entries[index]));
    }
    return true;
}

bool product_wifi_credential_set_select_next(
    product_wifi_credential_set_t *set,
    product_wifi_credentials_t *credentials)
{
    if (!set || !credentials || set->count < 2 ||
        set->count > PRODUCT_WIFI_CREDENTIAL_SET_LIMIT ||
        set->active_index >= set->count || !entries_are_unique(set)) {
        return false;
    }
    set->active_index = (uint8_t)((set->active_index + 1) % set->count);
    *credentials = set->entries[set->active_index];
    return true;
}
