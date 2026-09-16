#include "product_wifi_credentials_core.h"

#include <string.h>

enum {
    CREDENTIAL_VERSION = 1,
    SSID_OFFSET = 8,
    PASSWORD_OFFSET = SSID_OFFSET + PRODUCT_WIFI_SSID_MAX,
    CHECKSUM_OFFSET = PRODUCT_WIFI_CREDENTIAL_BLOB_SIZE - 4,
};

static const uint8_t CREDENTIAL_MAGIC[4] = {'P', 'W', 'F', '1'};

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

bool product_wifi_credentials_valid(const char *ssid, const char *password)
{
    if (!ssid || !password) {
        return false;
    }
    const size_t ssid_size = strnlen(ssid, PRODUCT_WIFI_SSID_MAX + 1);
    const size_t password_size =
        strnlen(password, PRODUCT_WIFI_PASSWORD_MAX + 1);
    if (ssid_size == 0 || ssid_size > PRODUCT_WIFI_SSID_MAX ||
        password_size < PRODUCT_WIFI_PASSWORD_MIN ||
        password_size > PRODUCT_WIFI_PASSWORD_MAX) {
        return false;
    }
    for (size_t index = 0; index < ssid_size; ++index) {
        const unsigned char c = (unsigned char)ssid[index];
        if (c < 0x20 || c == 0x7f) {
            return false;
        }
    }
    for (size_t index = 0; index < password_size; ++index) {
        const unsigned char c = (unsigned char)password[index];
        if (c < 0x20 || c > 0x7e) {
            return false;
        }
    }
    return true;
}

bool product_wifi_credentials_encode(
    const product_wifi_credentials_t *credentials,
    uint8_t output[PRODUCT_WIFI_CREDENTIAL_BLOB_SIZE])
{
    if (!credentials || !output ||
        !product_wifi_credentials_valid(credentials->ssid,
                                        credentials->password)) {
        return false;
    }
    const size_t ssid_size = strlen(credentials->ssid);
    const size_t password_size = strlen(credentials->password);
    memset(output, 0, PRODUCT_WIFI_CREDENTIAL_BLOB_SIZE);
    memcpy(output, CREDENTIAL_MAGIC, sizeof(CREDENTIAL_MAGIC));
    output[4] = CREDENTIAL_VERSION;
    output[5] = (uint8_t)ssid_size;
    output[6] = (uint8_t)password_size;
    output[7] = 0;
    memcpy(output + SSID_OFFSET, credentials->ssid, ssid_size);
    memcpy(output + PASSWORD_OFFSET, credentials->password, password_size);
    write_u32_le(output + CHECKSUM_OFFSET,
                 crc32(output, CHECKSUM_OFFSET));
    return true;
}

bool product_wifi_credentials_decode(
    const uint8_t *input,
    size_t input_size,
    product_wifi_credentials_t *credentials)
{
    if (!input || !credentials ||
        input_size != PRODUCT_WIFI_CREDENTIAL_BLOB_SIZE ||
        memcmp(input, CREDENTIAL_MAGIC, sizeof(CREDENTIAL_MAGIC)) != 0 ||
        input[4] != CREDENTIAL_VERSION || input[7] != 0 ||
        input[5] == 0 || input[5] > PRODUCT_WIFI_SSID_MAX ||
        input[6] < PRODUCT_WIFI_PASSWORD_MIN ||
        input[6] > PRODUCT_WIFI_PASSWORD_MAX ||
        read_u32_le(input + CHECKSUM_OFFSET) !=
            crc32(input, CHECKSUM_OFFSET)) {
        return false;
    }
    for (size_t index = SSID_OFFSET + input[5];
         index < PASSWORD_OFFSET; ++index) {
        if (input[index] != 0) {
            return false;
        }
    }
    for (size_t index = PASSWORD_OFFSET + input[6];
         index < CHECKSUM_OFFSET; ++index) {
        if (input[index] != 0) {
            return false;
        }
    }

    product_wifi_credentials_t decoded = {0};
    memcpy(decoded.ssid, input + SSID_OFFSET, input[5]);
    memcpy(decoded.password, input + PASSWORD_OFFSET, input[6]);
    if (!product_wifi_credentials_valid(decoded.ssid, decoded.password)) {
        secure_zero(&decoded, sizeof(decoded));
        return false;
    }
    *credentials = decoded;
    secure_zero(&decoded, sizeof(decoded));
    return true;
}
