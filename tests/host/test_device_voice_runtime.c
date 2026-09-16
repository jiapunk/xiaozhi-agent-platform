#include "device_voice_runtime.h"

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

typedef struct {
    int submit_calls;
    int cancel_calls;
    int send_calls;
    int binary_calls;
    int fail_binary;
    int playback_begin;
    int playback_drain;
    int playback_flush;
    uint32_t request_id;
    char session_id[AGENT_BRIDGE_SESSION_ID_MAX];
    char text[128];
    char json[512];
} mock_t;

static int submit_agent(void *ctx, uint32_t request_id,
                        const char *session_id, const char *text)
{
    mock_t *mock = ctx;
    mock->submit_calls++;
    mock->request_id = request_id;
    snprintf(mock->session_id, sizeof(mock->session_id), "%s", session_id);
    snprintf(mock->text, sizeof(mock->text), "%s", text);
    return 0;
}

static int cancel_agent(void *ctx, uint32_t request_id)
{
    mock_t *mock = ctx;
    mock->cancel_calls++;
    mock->request_id = request_id;
    return 0;
}

static int send_json(void *ctx, const char *json, size_t length)
{
    mock_t *mock = ctx;
    mock->send_calls++;
    if (length >= sizeof(mock->json)) {
        return -1;
    }
    memcpy(mock->json, json, length);
    mock->json[length] = '\0';
    return 0;
}

static int receive_binary(void *ctx, const uint8_t *packet, size_t size)
{
    mock_t *mock = ctx;
    if (!packet || size == 0) {
        return -1;
    }
    mock->binary_calls++;
    return mock->fail_binary ? -1 : 0;
}

static void playback(void *ctx, voice_agent_playback_event_t event,
                     uint32_t request_id)
{
    mock_t *mock = ctx;
    mock->request_id = request_id;
    if (event == VOICE_AGENT_PLAYBACK_BEGIN) {
        mock->playback_begin++;
    } else if (event == VOICE_AGENT_PLAYBACK_DRAIN) {
        mock->playback_drain++;
    } else if (event == VOICE_AGENT_PLAYBACK_FLUSH) {
        mock->playback_flush++;
    }
}

static device_voice_runtime_config_t config(mock_t *mock,
                                            char *tx_buffer,
                                            size_t tx_size)
{
    device_voice_runtime_config_t result = {
        .ops = {
            .submit_agent = submit_agent,
            .cancel_agent = cancel_agent,
            .send_json = send_json,
            .receive_binary = receive_binary,
            .playback_event = playback,
        },
        .ops_ctx = mock,
        .tx_buffer = tx_buffer,
        .tx_buffer_size = tx_size,
        .downlink_sample_rate = 24000,
        .frame_duration_ms = 60,
    };
    return result;
}

static cJSON *server_hello(const char *session_id, int sample_rate)
{
    cJSON *root = cJSON_CreateObject();
    cJSON *features = cJSON_CreateObject();
    cJSON *agent = cJSON_CreateObject();
    cJSON *audio = cJSON_CreateObject();
    if (!root || !features || !agent || !audio) {
        cJSON_Delete(root);
        cJSON_Delete(features);
        cJSON_Delete(agent);
        cJSON_Delete(audio);
        return NULL;
    }
    cJSON_AddStringToObject(root, "type", "hello");
    cJSON_AddStringToObject(root, "transport", "websocket");
    cJSON_AddStringToObject(root, "session_id", session_id);
    cJSON_AddNumberToObject(agent, "version", 1);
    cJSON_AddBoolToObject(agent, "request_correlation", true);
    cJSON_AddItemToObject(features, "device_agent", agent);
    cJSON_AddItemToObject(root, "features", features);
    cJSON_AddStringToObject(audio, "format", "opus");
    cJSON_AddNumberToObject(audio, "sample_rate", sample_rate);
    cJSON_AddNumberToObject(audio, "channels", 1);
    cJSON_AddNumberToObject(audio, "frame_duration", 60);
    cJSON_AddItemToObject(root, "audio_params", audio);
    return root;
}

static int test_full_device_control_and_audio_sequence(void)
{
    device_voice_runtime_t runtime;
    mock_t mock = {0};
    char tx_buffer[512];
    device_voice_runtime_config_t runtime_config =
        config(&mock, tx_buffer, sizeof(tx_buffer));
    xiaozhi_agent_message_outcome_t outcome;
    cJSON *hello = server_hello("voice:device-1", 24000);
    cJSON *client_hello = cJSON_CreateObject();
    cJSON *client_hello_features = cJSON_CreateObject();
    const cJSON *client_features;
    const cJSON *client_agent;
    const cJSON *client_version;
    cJSON *message;
    uint8_t binary[] = {1, 2, 3};

    CHECK(hello != NULL && client_hello != NULL &&
          client_hello_features != NULL);
    CHECK(cJSON_AddItemToObject(client_hello, "features",
                                client_hello_features));
    CHECK(device_voice_runtime_init(&runtime, &runtime_config) ==
          AGENT_BRIDGE_OK);
    CHECK(device_voice_runtime_add_client_hello(&runtime, client_hello) ==
          AGENT_BRIDGE_OK);
    client_features = cJSON_GetObjectItemCaseSensitive(client_hello,
                                                        "features");
    client_agent = cJSON_GetObjectItemCaseSensitive(client_features,
                                                     "device_agent");
    CHECK(cJSON_IsObject(client_agent));
    client_version = cJSON_GetObjectItemCaseSensitive(client_agent, "version");
    CHECK(cJSON_IsNumber(client_version) && client_version->valueint == 1);
    CHECK(device_voice_runtime_accept_server_hello(&runtime, hello) ==
          AGENT_BRIDGE_OK);
    CHECK(device_voice_runtime_ready(&runtime));
    CHECK(strcmp(device_voice_runtime_session_id(&runtime),
                 "voice:device-1") == 0);

    message = cJSON_Parse(
        "{\"type\":\"stt\",\"session_id\":\"voice:device-1\","
        "\"text\":\"turn on\"}");
    CHECK(message != NULL);
    CHECK(device_voice_runtime_on_json(&runtime, message, &outcome) ==
          AGENT_BRIDGE_OK);
    cJSON_Delete(message);
    CHECK(outcome.handled && outcome.accepted_request_id == 1);
    CHECK(mock.submit_calls == 1 && strcmp(mock.text, "turn on") == 0);

    CHECK(device_voice_runtime_on_agent_final(&runtime, 1, "Done") ==
          AGENT_BRIDGE_OK);
    CHECK(strstr(mock.json, "\"type\":\"tts_request\"") != NULL);
    message = cJSON_Parse(
        "{\"type\":\"tts\",\"state\":\"start\","
        "\"session_id\":\"voice:device-1\",\"request_id\":1}");
    CHECK(device_voice_runtime_on_json(&runtime, message, &outcome) ==
          AGENT_BRIDGE_OK);
    cJSON_Delete(message);
    CHECK(mock.playback_begin == 1);
    CHECK(device_voice_runtime_on_binary(&runtime, binary, sizeof(binary)) ==
          AGENT_BRIDGE_OK);
    CHECK(mock.binary_calls == 1);
    mock.fail_binary = 1;
    CHECK(device_voice_runtime_on_binary(&runtime, binary, sizeof(binary)) ==
          AGENT_BRIDGE_ERR_OPERATION);
    CHECK(mock.binary_calls == 2);
    mock.fail_binary = 0;

    message = cJSON_Parse(
        "{\"type\":\"tts\",\"state\":\"stop\","
        "\"session_id\":\"voice:device-1\",\"request_id\":1}");
    CHECK(device_voice_runtime_on_json(&runtime, message, &outcome) ==
          AGENT_BRIDGE_OK);
    cJSON_Delete(message);
    CHECK(mock.playback_drain == 1);
    CHECK(device_voice_runtime_on_binary(&runtime, binary, sizeof(binary)) ==
          AGENT_BRIDGE_ERR_INVALID_STATE);

    CHECK(device_voice_runtime_on_disconnected(&runtime) == AGENT_BRIDGE_OK);
    CHECK(!device_voice_runtime_ready(&runtime));
    CHECK(strcmp(device_voice_runtime_session_id(&runtime), "") == 0);
    cJSON_Delete(client_hello);
    cJSON_Delete(hello);
    return 0;
}

static int test_fail_closed_negotiation_and_disconnect_flush(void)
{
    device_voice_runtime_t runtime;
    mock_t mock = {0};
    char tx_buffer[512];
    device_voice_runtime_config_t runtime_config =
        config(&mock, tx_buffer, sizeof(tx_buffer));
    xiaozhi_agent_message_outcome_t outcome;
    cJSON *bad = server_hello("voice:bad", 16000);
    cJSON *good = server_hello("voice:good", 24000);
    cJSON *message;

    CHECK(device_voice_runtime_init(&runtime, &runtime_config) ==
          AGENT_BRIDGE_OK);
    CHECK(device_voice_runtime_accept_server_hello(&runtime, bad) ==
          AGENT_BRIDGE_ERR_INVALID_STATE);
    CHECK(!device_voice_runtime_ready(&runtime));
    CHECK(device_voice_runtime_accept_server_hello(&runtime, good) ==
          AGENT_BRIDGE_OK);
    message = cJSON_Parse(
        "{\"type\":\"stt\",\"text\":\"one\"}");
    CHECK(device_voice_runtime_on_json(&runtime, message, &outcome) ==
          AGENT_BRIDGE_OK);
    cJSON_Delete(message);
    CHECK(device_voice_runtime_on_agent_final(&runtime, 1, "reply") ==
          AGENT_BRIDGE_OK);
    message = cJSON_Parse(
        "{\"type\":\"tts\",\"state\":\"start\",\"request_id\":1}");
    CHECK(device_voice_runtime_on_json(&runtime, message, &outcome) ==
          AGENT_BRIDGE_OK);
    cJSON_Delete(message);
    CHECK(device_voice_runtime_on_disconnected(&runtime) == AGENT_BRIDGE_OK);
    CHECK(mock.playback_flush == 1);
    CHECK(strstr(mock.json, "\"reason\":\"network_lost\"") != NULL);
    cJSON_Delete(bad);
    cJSON_Delete(good);
    return 0;
}

static int test_speech_budget_error_resets_pending_tts(void)
{
    device_voice_runtime_t runtime;
    mock_t mock = {0};
    char tx_buffer[512];
    device_voice_runtime_config_t runtime_config =
        config(&mock, tx_buffer, sizeof(tx_buffer));
    xiaozhi_agent_message_outcome_t outcome;
    cJSON *hello = server_hello("voice:budget", 24000);
    cJSON *message;

    CHECK(device_voice_runtime_init(&runtime, &runtime_config) ==
          AGENT_BRIDGE_OK);
    CHECK(device_voice_runtime_accept_server_hello(&runtime, hello) ==
          AGENT_BRIDGE_OK);
    message = cJSON_Parse("{\"type\":\"stt\",\"text\":\"one\"}");
    CHECK(device_voice_runtime_on_json(&runtime, message, &outcome) ==
          AGENT_BRIDGE_OK);
    cJSON_Delete(message);
    CHECK(device_voice_runtime_on_agent_final(&runtime, 1, "reply") ==
          AGENT_BRIDGE_OK);
    message = cJSON_Parse(
        "{\"type\":\"error\",\"code\":\"speech_budget_exceeded\"}");
    CHECK(device_voice_runtime_on_json(&runtime, message, &outcome) ==
          AGENT_BRIDGE_OK);
    cJSON_Delete(message);
    CHECK(outcome.handled && outcome.service_error ==
          XIAOZHI_AGENT_SERVICE_ERROR_SPEECH_BUDGET_EXCEEDED);
    CHECK(voice_agent_controller_state(&runtime.controller) ==
          AGENT_BRIDGE_STATE_IDLE);
    CHECK(mock.playback_flush == 1);
    CHECK(mock.send_calls == 1);
    cJSON_Delete(hello);
    return 0;
}

int main(void)
{
    CHECK(test_full_device_control_and_audio_sequence() == 0);
    CHECK(test_fail_closed_negotiation_and_disconnect_flush() == 0);
    CHECK(test_speech_budget_error_resets_pending_tts() == 0);
    puts("device_voice_runtime: all host tests passed");
    return 0;
}
