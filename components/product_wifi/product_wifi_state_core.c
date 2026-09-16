#include "product_wifi_state_core.h"

#include <string.h>

enum {
    STATE_VERSION = 1,
    FLAGS_OFFSET = 5,
    RESERVED_OFFSET = 6,
    CREDENTIAL_OFFSET = 8,
    CLAIM_OFFSET = CREDENTIAL_OFFSET + PRODUCT_WIFI_CREDENTIAL_BLOB_SIZE,
    CHECKSUM_OFFSET = PRODUCT_WIFI_STATE_BLOB_SIZE - 4,
    CLAIM_PENDING = 1U << 0,
};

static const uint8_t STATE_MAGIC[4] = {'P', 'W', 'S', '1'};

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

static int base64url_value(unsigned char value)
{
    if (value >= 'A' && value <= 'Z') {
        return (int)(value - 'A');
    }
    if (value >= 'a' && value <= 'z') {
        return 26 + (int)(value - 'a');
    }
    if (value >= '0' && value <= '9') {
        return 52 + (int)(value - '0');
    }
    if (value == '-') {
        return 62;
    }
    if (value == '_') {
        return 63;
    }
    return -1;
}

bool product_wifi_device_claim_is_canonical(const char *claim)
{
    if (!claim || strnlen(claim, PRODUCT_WIFI_DEVICE_CLAIM_SIZE + 1) !=
                      PRODUCT_WIFI_DEVICE_CLAIM_SIZE) {
        return false;
    }
    for (size_t index = 0; index < PRODUCT_WIFI_DEVICE_CLAIM_SIZE; ++index) {
        const int value = base64url_value((unsigned char)claim[index]);
        if (value < 0 ||
            (index == PRODUCT_WIFI_DEVICE_CLAIM_SIZE - 1 &&
             (value & 0x03) != 0)) {
            return false;
        }
    }
    return true;
}

bool product_wifi_state_encode(
    const product_wifi_persisted_state_t *state,
    uint8_t output[PRODUCT_WIFI_STATE_BLOB_SIZE])
{
    uint8_t credential[PRODUCT_WIFI_CREDENTIAL_BLOB_SIZE] = {0};
    if (!state || !output ||
        !product_wifi_credentials_encode(&state->credentials, credential) ||
        (state->claim_pending &&
         !product_wifi_device_claim_is_canonical(state->device_claim)) ||
        (!state->claim_pending && state->device_claim[0] != '\0')) {
        secure_zero(credential, sizeof(credential));
        return false;
    }

    memset(output, 0, PRODUCT_WIFI_STATE_BLOB_SIZE);
    memcpy(output, STATE_MAGIC, sizeof(STATE_MAGIC));
    output[4] = STATE_VERSION;
    output[FLAGS_OFFSET] = state->claim_pending ? CLAIM_PENDING : 0;
    memcpy(output + CREDENTIAL_OFFSET, credential, sizeof(credential));
    if (state->claim_pending) {
        memcpy(output + CLAIM_OFFSET, state->device_claim,
               PRODUCT_WIFI_DEVICE_CLAIM_SIZE);
    }
    write_u32_le(output + CHECKSUM_OFFSET, crc32(output, CHECKSUM_OFFSET));
    secure_zero(credential, sizeof(credential));
    return true;
}

bool product_wifi_state_decode(
    const uint8_t *input,
    size_t input_size,
    product_wifi_persisted_state_t *state)
{
    if (!input || !state || input_size != PRODUCT_WIFI_STATE_BLOB_SIZE ||
        memcmp(input, STATE_MAGIC, sizeof(STATE_MAGIC)) != 0 ||
        input[4] != STATE_VERSION ||
        (input[FLAGS_OFFSET] & (uint8_t)~CLAIM_PENDING) != 0 ||
        input[RESERVED_OFFSET] != 0 || input[RESERVED_OFFSET + 1] != 0 ||
        read_u32_le(input + CHECKSUM_OFFSET) !=
            crc32(input, CHECKSUM_OFFSET)) {
        return false;
    }

    product_wifi_persisted_state_t decoded = {0};
    if (!product_wifi_credentials_decode(
            input + CREDENTIAL_OFFSET, PRODUCT_WIFI_CREDENTIAL_BLOB_SIZE,
            &decoded.credentials)) {
        secure_zero(&decoded, sizeof(decoded));
        return false;
    }
    decoded.claim_pending =
        (input[FLAGS_OFFSET] & CLAIM_PENDING) != 0;
    if (decoded.claim_pending) {
        memcpy(decoded.device_claim, input + CLAIM_OFFSET,
               PRODUCT_WIFI_DEVICE_CLAIM_SIZE);
        if (!product_wifi_device_claim_is_canonical(decoded.device_claim)) {
            secure_zero(&decoded, sizeof(decoded));
            return false;
        }
    } else {
        for (size_t index = CLAIM_OFFSET; index < CHECKSUM_OFFSET; ++index) {
            if (input[index] != 0) {
                secure_zero(&decoded, sizeof(decoded));
                return false;
            }
        }
    }
    *state = decoded;
    secure_zero(&decoded, sizeof(decoded));
    return true;
}
