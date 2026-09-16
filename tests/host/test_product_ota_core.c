#include "product_ota_core.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static const char *VALID_MANIFEST =
    "{"
    "\"schema\":2,"
    "\"release_id\":\"release-0015\","
    "\"project\":\"xiaozhi_agent_platform\","
    "\"board\":\"esp32s3-box3\","
    "\"channel\":\"stable\","
    "\"version\":\"1.2.3\","
    "\"release_sequence\":15,"
    "\"secure_version\":2,"
    "\"image_url\":\"https://updates.example.com/firmware/r15.bin\","
    "\"image_size\":1342032,"
    "\"image_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
    "\"reset_qualification_sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\","
    "\"not_before\":1786276800,"
    "\"expires_at\":1786881600,"
    "\"signing_key_id\":\"release-key-2026\","
    "\"signature_algorithm\":\"ECDSA_P256_SHA256\","
    "\"signature_b64url\":\"AQIDBAUGBwg\""
    "}";

static product_ota_manifest_t parse_valid(void)
{
    product_ota_manifest_t manifest = {0};
    assert(product_ota_manifest_parse(VALID_MANIFEST,
                                      strlen(VALID_MANIFEST), &manifest));
    return manifest;
}

static void test_parse_and_canonical_contract(void)
{
    const product_ota_manifest_t manifest = parse_valid();
    assert(manifest.release_sequence == 15);
    assert(manifest.secure_version == 2);
    assert(manifest.image_size == 1342032);
    assert(manifest.signature_size == 8);
    assert(manifest.image_sha256[0] == 0xaa);
    assert(manifest.reset_qualification_sha256[0] == 0xbb);

    char canonical[PRODUCT_OTA_CANONICAL_MAX_BYTES];
    size_t written = 0;
    assert(product_ota_manifest_canonicalize(
        &manifest, canonical, sizeof(canonical), &written));
    assert(written == strlen(canonical));
    assert(strcmp(
               canonical,
               "xiaozhi-product-ota-v2\n"
               "board=esp32s3-box3\n"
               "channel=stable\n"
               "expires_at=1786881600\n"
               "image_sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
               "image_size=1342032\n"
               "image_url=https://updates.example.com/firmware/r15.bin\n"
               "not_before=1786276800\n"
               "project=xiaozhi_agent_platform\n"
               "release_id=release-0015\n"
               "release_sequence=15\n"
               "reset_qualification_sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
               "schema=2\n"
               "secure_version=2\n"
               "signature_algorithm=ECDSA_P256_SHA256\n"
               "signing_key_id=release-key-2026\n"
               "version=1.2.3\n") == 0);
}

static void test_policy_accepts_only_new_bounded_target(void)
{
    product_ota_manifest_t manifest = parse_valid();
    product_ota_policy_t policy = {
        .project = "xiaozhi_agent_platform",
        .board = "esp32s3-box3",
        .channel = "stable",
        .allowed_image_authority = "updates.example.com",
        .current_release_sequence = 14,
        .current_secure_version = 1,
        .authenticated_time = 1786276801,
        .maximum_image_size = 5 * 1024 * 1024,
    };
    assert(product_ota_manifest_validate_policy(&manifest, &policy));
    manifest.release_sequence = 14;
    assert(!product_ota_manifest_validate_policy(&manifest, &policy));
    manifest = parse_valid();
    manifest.secure_version = 0;
    assert(!product_ota_manifest_validate_policy(&manifest, &policy));
    manifest = parse_valid();
    policy.board = "esp32s3-n32r16";
    assert(!product_ota_manifest_validate_policy(&manifest, &policy));
    policy.board = "esp32s3-box3";
    policy.authenticated_time = manifest.expires_at + 1;
    assert(!product_ota_manifest_validate_policy(&manifest, &policy));
    policy.authenticated_time = manifest.not_before;
    policy.maximum_image_size = manifest.image_size - 1;
    assert(!product_ota_manifest_validate_policy(&manifest, &policy));
}

static void test_url_policy(void)
{
    assert(product_ota_url_has_authority(
        "https://updates.example.com/path/image.bin", "UPDATES.example.com"));
    assert(!product_ota_url_has_authority(
        "http://updates.example.com/path/image.bin", "updates.example.com"));
    assert(!product_ota_url_has_authority(
        "https://updates.example.com.evil/path/image.bin",
        "updates.example.com"));
    assert(!product_ota_url_has_authority(
        "https://updates.example.com/path/image.bin?token=secret",
        "updates.example.com"));
    assert(!product_ota_url_has_authority(
        "https://user@updates.example.com/path/image.bin",
        "updates.example.com"));
    assert(!product_ota_url_has_authority(
        "https://updates.example.com\\evil/path/image.bin",
        "updates.example.com"));
    assert(product_ota_url_has_authority(
        "https://updates.example.com:8443/path/image.bin",
        "updates.example.com:8443"));
    assert(!product_ota_url_has_authority(
        "https://updates..example.com/path/image.bin", NULL));
    assert(!product_ota_url_has_authority(
        "https://-updates.example.com/path/image.bin", NULL));
    assert(!product_ota_url_has_authority(
        "https://updates.example.com:/path/image.bin", NULL));
    assert(!product_ota_url_has_authority(
        "https://updates.example.com:0/path/image.bin", NULL));
    assert(!product_ota_url_has_authority(
        "https://updates.example.com:65536/path/image.bin", NULL));
    assert(!product_ota_url_has_authority(
        "https://updates.example.com:443:9/path/image.bin", NULL));
}

static void test_malformed_json_fails_closed(void)
{
    product_ota_manifest_t manifest = {0};
    const char *unknown =
        "{\"schema\":2,\"unknown\":true}";
    assert(!product_ota_manifest_parse(unknown, strlen(unknown), &manifest));

    char duplicate[9000];
    const int duplicate_size = snprintf(
        duplicate, sizeof(duplicate), "%.*s,\"schema\":2}",
        (int)strlen(VALID_MANIFEST) - 1, VALID_MANIFEST);
    assert(duplicate_size > 0);
    assert(!product_ota_manifest_parse(duplicate, (size_t)duplicate_size,
                                       &manifest));

    char trailing[9000];
    const int trailing_size = snprintf(trailing, sizeof(trailing), "%s x",
                                       VALID_MANIFEST);
    assert(trailing_size > 0);
    assert(!product_ota_manifest_parse(trailing, (size_t)trailing_size,
                                       &manifest));

    const char *escaped_nul =
        "{\"schema\":2,\"release_id\":\"good\\u0000bad\"}";
    assert(!product_ota_manifest_parse(escaped_nul, strlen(escaped_nul),
                                       &manifest));

    char legacy[9000];
    memcpy(legacy, VALID_MANIFEST, strlen(VALID_MANIFEST) + 1);
    char *schema = strstr(legacy, "\"schema\":2");
    assert(schema);
    schema[strlen("\"schema\":")] = '1';
    assert(!product_ota_manifest_parse(legacy, strlen(legacy), &manifest));
}

static void test_health_gate(void)
{
    const uint32_t storage = 1U << 0;
    const uint32_t network = 1U << 1;
    const uint32_t agent = 1U << 3;
    const uint32_t audio = 1U << 4;
    const uint32_t required = storage | network | agent;
    assert(product_ota_health_satisfied(required, required));
    assert(product_ota_health_satisfied(required | audio, required));
    assert(!product_ota_health_satisfied(storage, required));
    assert(!product_ota_health_satisfied(required, 0));
    assert(!product_ota_health_satisfied(UINT32_MAX, UINT32_MAX));
}

int main(void)
{
    test_parse_and_canonical_contract();
    test_policy_accepts_only_new_bounded_target();
    test_url_policy();
    test_malformed_json_fails_closed();
    test_health_gate();
    puts("product_ota_core: all tests passed");
    return 0;
}
