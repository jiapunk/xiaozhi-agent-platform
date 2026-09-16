#include "product_provisioning_material_core.h"

#include <stdio.h>
#include <string.h>

enum {
    MATERIAL_VERSION = 1,
    SALT_OFFSET = 8,
    VERIFIER_OFFSET = SALT_OFFSET + PRODUCT_PROVISIONING_SALT_MAX,
    CHECKSUM_OFFSET = PRODUCT_PROVISIONING_MATERIAL_AUTHENTICATED_SIZE - 4,
    AUTH_TAG_OFFSET = PRODUCT_PROVISIONING_MATERIAL_AUTHENTICATED_SIZE,
};

static const uint8_t MATERIAL_MAGIC[4] = {'P', 'S', '2', '1'};
static const char BASE32[] = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

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

static void write_u16_le(uint8_t *output, uint16_t value)
{
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
}

static uint16_t read_u16_le(const uint8_t *input)
{
    return (uint16_t)((uint16_t)input[0] | ((uint16_t)input[1] << 8));
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

static bool material_valid(const product_provisioning_material_t *material)
{
    if (!material ||
        material->salt_size < PRODUCT_PROVISIONING_SALT_MIN ||
        material->salt_size > PRODUCT_PROVISIONING_SALT_MAX) {
        return false;
    }
    uint8_t verifier_or = 0;
    for (size_t index = 0; index < sizeof(material->verifier); ++index) {
        verifier_or |= material->verifier[index];
    }
    return verifier_or != 0;
}

bool product_provisioning_material_encode(
    const product_provisioning_material_t *material,
    uint8_t output[PRODUCT_PROVISIONING_MATERIAL_BLOB_SIZE])
{
    if (!material_valid(material) || !output) {
        return false;
    }
    memset(output, 0, PRODUCT_PROVISIONING_MATERIAL_BLOB_SIZE);
    memcpy(output, MATERIAL_MAGIC, sizeof(MATERIAL_MAGIC));
    output[4] = MATERIAL_VERSION;
    output[5] = (uint8_t)material->salt_size;
    write_u16_le(output + 6, PRODUCT_PROVISIONING_VERIFIER_SIZE);
    memcpy(output + SALT_OFFSET, material->salt, material->salt_size);
    memcpy(output + VERIFIER_OFFSET, material->verifier,
           sizeof(material->verifier));
    write_u32_le(output + CHECKSUM_OFFSET,
                 crc32(output, CHECKSUM_OFFSET));
    memcpy(output + AUTH_TAG_OFFSET, material->auth_tag,
           sizeof(material->auth_tag));
    return true;
}

bool product_provisioning_material_decode(
    const uint8_t *input,
    size_t input_size,
    product_provisioning_material_t *material)
{
    if (!input || !material ||
        input_size != PRODUCT_PROVISIONING_MATERIAL_BLOB_SIZE ||
        memcmp(input, MATERIAL_MAGIC, sizeof(MATERIAL_MAGIC)) != 0 ||
        input[4] != MATERIAL_VERSION ||
        input[5] < PRODUCT_PROVISIONING_SALT_MIN ||
        input[5] > PRODUCT_PROVISIONING_SALT_MAX ||
        read_u16_le(input + 6) != PRODUCT_PROVISIONING_VERIFIER_SIZE ||
        read_u32_le(input + CHECKSUM_OFFSET) !=
            crc32(input, CHECKSUM_OFFSET)) {
        return false;
    }
    for (size_t index = SALT_OFFSET + input[5];
         index < VERIFIER_OFFSET; ++index) {
        if (input[index] != 0) {
            return false;
        }
    }
    product_provisioning_material_t decoded = {0};
    decoded.salt_size = input[5];
    memcpy(decoded.salt, input + SALT_OFFSET, decoded.salt_size);
    memcpy(decoded.verifier, input + VERIFIER_OFFSET,
           sizeof(decoded.verifier));
    memcpy(decoded.auth_tag, input + AUTH_TAG_OFFSET,
           sizeof(decoded.auth_tag));
    if (!material_valid(&decoded)) {
        memset(&decoded, 0, sizeof(decoded));
        return false;
    }
    *material = decoded;
    memset(&decoded, 0, sizeof(decoded));
    return true;
}

bool product_provisioning_format_service_name(
    const uint8_t mac[6],
    char output[PRODUCT_PROVISIONING_SERVICE_NAME_SIZE])
{
    if (!mac || !output) {
        return false;
    }
    return snprintf(output, PRODUCT_PROVISIONING_SERVICE_NAME_SIZE,
                    "XA-%02X%02X%02X", mac[3], mac[4], mac[5]) ==
           PRODUCT_PROVISIONING_SERVICE_NAME_SIZE - 1;
}

bool product_provisioning_format_ap_secret(
    const uint8_t derived_key[32],
    char output[PRODUCT_PROVISIONING_AP_SECRET_SIZE + 1])
{
    if (!derived_key || !output) {
        return false;
    }
    uint32_t accumulator = 0;
    unsigned bits = 0;
    size_t input_index = 0;
    for (size_t output_index = 0;
         output_index < PRODUCT_PROVISIONING_AP_SECRET_SIZE;
         ++output_index) {
        while (bits < 5) {
            accumulator = (accumulator << 8) | derived_key[input_index++];
            bits += 8;
        }
        bits -= 5;
        output[output_index] = BASE32[(accumulator >> bits) & 31U];
    }
    output[PRODUCT_PROVISIONING_AP_SECRET_SIZE] = '\0';
    return true;
}
