#include "device_voice_client_protocol.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                    \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,          \
                    #condition);                                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static int test_hello_contract(void)
{
    char output[1024];
    char small[16] = "dirty";
    size_t output_size = 0;
    cJSON *root;
    const cJSON *features;
    const cJSON *agent;
    const cJSON *audio;

    CHECK(device_voice_client_build_hello(
              2, 16000, 60, output, sizeof(output), &output_size) ==
          AGENT_BRIDGE_OK);
    CHECK(output_size == strlen(output));
    root = cJSON_Parse(output);
    CHECK(root != NULL);
    CHECK(cJSON_GetObjectItemCaseSensitive(root, "version")->valueint == 2);
    CHECK(strcmp(cJSON_GetObjectItemCaseSensitive(root, "transport")->valuestring,
                 "websocket") == 0);
    features = cJSON_GetObjectItemCaseSensitive(root, "features");
    agent = cJSON_GetObjectItemCaseSensitive(features, "device_agent");
    audio = cJSON_GetObjectItemCaseSensitive(root, "audio_params");
    CHECK(cJSON_IsObject(agent));
    CHECK(cJSON_GetObjectItemCaseSensitive(agent, "version")->valueint == 1);
    CHECK(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(
        agent, "request_correlation")));
    CHECK(cJSON_GetObjectItemCaseSensitive(audio, "sample_rate")->valueint ==
          16000);
    CHECK(cJSON_GetObjectItemCaseSensitive(audio, "frame_duration")->valueint ==
          60);
    cJSON_Delete(root);

    CHECK(device_voice_client_build_hello(
              2, 16000, 60, small, sizeof(small), &output_size) ==
          AGENT_BRIDGE_ERR_OPERATION);
    CHECK(small[0] == '\0' && output_size == 0);
    CHECK(device_voice_client_build_hello(
              4, 16000, 60, output, sizeof(output), &output_size) ==
          AGENT_BRIDGE_ERR_INVALID_ARG);
    return 0;
}

static int test_strict_json_parser(void)
{
    const uint8_t valid[] = "{\"type\":\"hello\"} \n\t";
    const uint8_t trailing[] = "{\"type\":\"hello\"}junk";
    const uint8_t embedded_nul[] = {
        '{', '"', 'x', '"', ':', '1', '}', 0, '{', '}'
    };
    cJSON *root = device_voice_client_parse_json_strict(
        valid, sizeof(valid) - 1);
    CHECK(root != NULL);
    cJSON_Delete(root);
    CHECK(device_voice_client_parse_json_strict(
              trailing, sizeof(trailing) - 1) == NULL);
    CHECK(device_voice_client_parse_json_strict(
              embedded_nul, sizeof(embedded_nul)) == NULL);
    CHECK(device_voice_client_parse_json_strict(NULL, 1) == NULL);
    return 0;
}

int main(void)
{
    CHECK(test_hello_contract() == 0);
    CHECK(test_strict_json_parser() == 0);
    puts("device_voice_client_protocol: all host tests passed");
    return 0;
}
