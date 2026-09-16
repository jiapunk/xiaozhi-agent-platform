#include "box3_agent_credentials_protocol.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_base64url_vectors(void)
{
    char output[64];
    assert(box3_agent_credentials_base64url(
        (const uint8_t *)"", 0, output, sizeof(output)));
    assert(strcmp(output, "") == 0);
    assert(box3_agent_credentials_base64url(
        (const uint8_t *)"f", 1, output, sizeof(output)));
    assert(strcmp(output, "Zg") == 0);
    assert(box3_agent_credentials_base64url(
        (const uint8_t *)"fo", 2, output, sizeof(output)));
    assert(strcmp(output, "Zm8") == 0);
    assert(box3_agent_credentials_base64url(
        (const uint8_t *)"foo", 3, output, sizeof(output)));
    assert(strcmp(output, "Zm9v") == 0);
    assert(!box3_agent_credentials_base64url(
        (const uint8_t *)"foo", 3, output, 4));
}

static void test_endpoint_identifier_and_canonical(void)
{
    assert(box3_agent_credentials_validate_endpoint(
        "https://control.example/v1/session"));
    assert(box3_agent_credentials_validate_endpoint(
        "https://control.example:8443/v1/session"));
    assert(!box3_agent_credentials_validate_endpoint(
        "http://control.example/v1/session"));
    assert(!box3_agent_credentials_validate_endpoint(
        "https://user@control.example/v1/session"));
    assert(!box3_agent_credentials_validate_endpoint(
        "https://control%2eexample/v1/session"));
    assert(!box3_agent_credentials_validate_endpoint(
        "https://control\\example/v1/session"));
    assert(!box3_agent_credentials_validate_endpoint(
        "https://control.example/v1/session?x=1"));
    assert(box3_agent_credentials_safe_identifier("box3-demo_1"));
    assert(!box3_agent_credentials_safe_identifier("box3/demo"));

    char canonical[BOX3_AGENT_CREDENTIALS_CANONICAL_MAX];
    assert(box3_agent_credentials_build_canonical(
        "device-1", "client-1", "1800000000", "nonce-value",
        canonical, sizeof(canonical)));
    assert(strcmp(canonical,
                  "xiaozhi-session-proof-v1\nPOST\n/v1/session\n"
                  "device-1\nclient-1\n1800000000\nnonce-value") == 0);
}

static bool parse(const char *input,
                  const char *device_id,
                  box3_agent_voice_credentials_t *credentials)
{
    char buffer[BOX3_AGENT_CREDENTIALS_RESPONSE_MAX + 1];
    const size_t size = strlen(input);
    assert(size <= BOX3_AGENT_CREDENTIALS_RESPONSE_MAX);
    memcpy(buffer, input, size);
    return box3_agent_credentials_parse_voice_response(
        buffer, size, device_id, credentials);
}

static void test_voice_response(void)
{
    const char *valid =
        "{\"version\":2,\"device_id\":\"device-1\","
        "\"binding_id\":\"AAECAwQFBgcICQoLDA0ODw\","
        "\"binding_revision\":7,\"voice\":{"
        "\"uri\":\"wss://voice.example/v1/device\","
        "\"bearer_token\":\"v1.payload.signature\","
        "\"expires_in_seconds\":900}}";
    box3_agent_voice_credentials_t credentials = {0};
    assert(parse(valid, "device-1", &credentials));
    assert(strcmp(credentials.uri, "wss://voice.example/v1/device") == 0);
    assert(strcmp(credentials.bearer_token, "v1.payload.signature") == 0);
    assert(credentials.ttl_seconds == 900);
    assert(strcmp(credentials.binding_id,
                  "AAECAwQFBgcICQoLDA0ODw") == 0);
    assert(credentials.binding_revision == 7);

    assert(!parse(valid, "device-2", &credentials));
    assert(!parse(
        "{\"version\":2,\"version\":2,\"device_id\":\"device-1\","
        "\"binding_id\":\"AAECAwQFBgcICQoLDA0ODw\","
        "\"binding_revision\":7,"
        "\"voice\":{\"uri\":\"wss://voice.example/v1/device\","
        "\"bearer_token\":\"token\",\"expires_in_seconds\":900}}",
        "device-1", &credentials));
    assert(!parse(
        "{\"version\":2,\"device_id\":\"device-1\","
        "\"binding_id\":\"AAECAwQFBgcICQoLDA0ODw\","
        "\"binding_revision\":7,\"voice\":{"
        "\"uri\":\"ws://voice.example/v1/device\","
        "\"bearer_token\":\"token\",\"expires_in_seconds\":900}}",
        "device-1", &credentials));
    assert(!parse(
        "{\"version\":2,\"device_id\":\"device-1\","
        "\"binding_id\":\"AAECAwQFBgcICQoLDA0ODw\","
        "\"binding_revision\":7,\"voice\":{"
        "\"uri\":\"wss://voice.example/v1/device\","
        "\"bearer_token\":\"token\",\"expires_in_seconds\":59}}",
        "device-1", &credentials));
    assert(!parse(
        "{\"version\":2,\"device_id\":\"device-1\","
        "\"binding_id\":\"AAECAwQFBgcICQoLDA0ODw\","
        "\"binding_revision\":7,\"extra\":true,"
        "\"voice\":{\"uri\":\"wss://voice.example/v1/device\","
        "\"bearer_token\":\"token\",\"expires_in_seconds\":900}}",
        "device-1", &credentials));
    assert(!parse(
        "{\"version\":2,\"device_id\":\"device-1\","
        "\"binding_id\":\"AAECAwQFBgcICQoLDA0ODw\","
        "\"binding_revision\":7,\"voice\":{"
        "\"uri\":\"wss://voice.example/v1/device\","
        "\"bearer_token\":\"token\",\"expires_in_seconds\":900,"
        "\"extra\":true}}",
        "device-1", &credentials));
    assert(!parse("{} trailing", "device-1", &credentials));
    assert(box3_agent_credentials_binding_id_is_canonical(
        "AAECAwQFBgcICQoLDA0ODw"));
    assert(!box3_agent_credentials_binding_id_is_canonical(
        "AAECAwQFBgcICQoLDA0ODx"));
}

static void test_agent_token_validation(void)
{
    assert(box3_agent_credentials_validate_agent_token(
        "agent-token", 32, 60));
    assert(!box3_agent_credentials_validate_agent_token(
        "agent token", 32, 60));
    assert(!box3_agent_credentials_validate_agent_token(
        "agent-token", 32, 3601));
    assert(box3_agent_credentials_tokens_are_separate(
        "voice-token", 32, "agent-token", 32));
    assert(!box3_agent_credentials_tokens_are_separate(
        "same-token", 32, "same-token", 32));
    assert(!box3_agent_credentials_tokens_are_separate(
        "voice token", 32, "agent-token", 32));
}

int main(void)
{
    test_base64url_vectors();
    test_endpoint_identifier_and_canonical();
    test_voice_response();
    test_agent_token_validation();
    puts("box3_agent_credentials_protocol: all host tests passed");
    return 0;
}
