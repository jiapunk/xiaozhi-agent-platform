#include "product_ota_client_protocol.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_endpoint_and_canonical(void)
{
    assert(product_ota_client_endpoint_valid(
        "https://control.example/v1/ota/offer"));
    assert(product_ota_client_endpoint_valid(
        "https://control.example:8443/v1/ota/offer"));
    assert(!product_ota_client_endpoint_valid(
        "http://control.example/v1/ota/offer"));
    assert(!product_ota_client_endpoint_valid(
        "https://user@control.example/v1/ota/offer"));
    assert(!product_ota_client_endpoint_valid(
        "https://control..example/v1/ota/offer"));
    assert(!product_ota_client_endpoint_valid(
        "https://control.example/v1/ota/offer?secret=x"));

    char canonical[PRODUCT_OTA_CLIENT_CANONICAL_MAX];
    assert(product_ota_client_build_canonical(
        "device-1", "client-1", "1800000000",
        "AAECAwQFBgcICQoLDA0ODw", "esp32s3-box3", "development",
        14, "0.14.0-dev", canonical, sizeof(canonical)));
    assert(strcmp(
               canonical,
               "xiaozhi-ota-offer-proof-v1\nPOST\n/v1/ota/offer\n"
               "device-1\nclient-1\n1800000000\n"
               "AAECAwQFBgcICQoLDA0ODw\n"
               "esp32s3-box3\ndevelopment\n14\n0.14.0-dev") == 0);
    assert(!product_ota_client_build_canonical(
        "device-1", "client-1", "1800000000", "nonce",
        "esp32s3/box3", "development", 14, "0.14.0-dev",
        canonical, sizeof(canonical)));
}

static void test_available_offer(void)
{
    const char manifest_json[] = "{\"schema\":1}";
    char encoded[64];
    assert(product_ota_client_base64url_encode(
        (const uint8_t *)manifest_json, strlen(manifest_json),
        encoded, sizeof(encoded)));
    char response[512];
    const int response_size = snprintf(
        response, sizeof(response),
        "{\"version\":1,\"status\":\"available\","
        "\"device_id\":\"device-1\",\"manifest_b64url\":\"%s\","
        "\"download_token\":\"v1.payload.signature\","
        "\"expires_in_seconds\":300}", encoded);
    assert(response_size > 0 && (size_t)response_size < sizeof(response));
    product_ota_client_offer_status_t status = 0;
    char manifest[128];
    size_t manifest_size = 0;
    char token[128];
    uint32_t ttl = 0;
    uint32_t retry = 0;
    assert(product_ota_client_parse_offer(
        response, (size_t)response_size, "device-1", &status,
        manifest, sizeof(manifest), &manifest_size,
        token, sizeof(token), &ttl, &retry));
    assert(status == PRODUCT_OTA_CLIENT_OFFER_AVAILABLE);
    assert(manifest_size == strlen(manifest_json));
    assert(strcmp(manifest, manifest_json) == 0);
    assert(strcmp(token, "v1.payload.signature") == 0);
    assert(ttl == 300 && retry == 0);
}

static void test_wait_offers_and_exact_schema(void)
{
    char current[] =
        "{\"version\":1,\"status\":\"up_to_date\","
        "\"device_id\":\"device-1\",\"retry_after_seconds\":900}";
    product_ota_client_offer_status_t status = 0;
    char manifest[32];
    size_t manifest_size = 0;
    char token[32];
    uint32_t ttl = 0;
    uint32_t retry = 0;
    assert(product_ota_client_parse_offer(
        current, strlen(current), "device-1", &status,
        manifest, sizeof(manifest), &manifest_size,
        token, sizeof(token), &ttl, &retry));
    assert(status == PRODUCT_OTA_CLIENT_OFFER_UP_TO_DATE && retry == 900);
    assert(manifest_size == 0 && manifest[0] == '\0' && token[0] == '\0');

    char deferred[] =
        "{\"version\":1,\"status\":\"deferred\","
        "\"device_id\":\"device-1\",\"retry_after_seconds\":3600}";
    assert(product_ota_client_parse_offer(
        deferred, strlen(deferred), "device-1", &status,
        manifest, sizeof(manifest), &manifest_size,
        token, sizeof(token), &ttl, &retry));
    assert(status == PRODUCT_OTA_CLIENT_OFFER_DEFERRED && retry == 3600);

    char extra[] =
        "{\"version\":1,\"status\":\"deferred\","
        "\"device_id\":\"device-1\",\"retry_after_seconds\":3600,"
        "\"extra\":true}";
    assert(!product_ota_client_parse_offer(
        extra, strlen(extra), "device-1", &status,
        manifest, sizeof(manifest), &manifest_size,
        token, sizeof(token), &ttl, &retry));

    char duplicate[] =
        "{\"version\":1,\"version\":1,\"status\":\"deferred\","
        "\"device_id\":\"device-1\",\"retry_after_seconds\":3600}";
    assert(!product_ota_client_parse_offer(
        duplicate, strlen(duplicate), "device-1", &status,
        manifest, sizeof(manifest), &manifest_size,
        token, sizeof(token), &ttl, &retry));
}

static void test_protocol_limits_override_larger_caller_buffers(void)
{
    char oversized_token[PRODUCT_OTA_CLIENT_TOKEN_MAX + 2];
    memset(oversized_token, 'a', sizeof(oversized_token) - 1);
    oversized_token[sizeof(oversized_token) - 1] = '\0';
    char response[PRODUCT_OTA_CLIENT_TOKEN_MAX + 256];
    const int response_size = snprintf(
        response, sizeof(response),
        "{\"version\":1,\"status\":\"available\","
        "\"device_id\":\"device-1\",\"manifest_b64url\":\"e30\","
        "\"download_token\":\"%s\",\"expires_in_seconds\":300}",
        oversized_token);
    assert(response_size > 0 && (size_t)response_size < sizeof(response));
    product_ota_client_offer_status_t status = 0;
    char manifest[PRODUCT_OTA_CLIENT_MANIFEST_MAX + 64];
    size_t manifest_size = 0;
    char token[PRODUCT_OTA_CLIENT_TOKEN_MAX + 64];
    uint32_t ttl = 0;
    uint32_t retry = 0;
    assert(!product_ota_client_parse_offer(
        response, (size_t)response_size, "device-1", &status,
        manifest, sizeof(manifest), &manifest_size,
        token, sizeof(token), &ttl, &retry));
}

int main(void)
{
    test_endpoint_and_canonical();
    test_available_offer();
    test_wait_offers_and_exact_schema();
    test_protocol_limits_override_larger_caller_buffers();
    puts("product_ota_client_protocol: all tests passed");
    return 0;
}
