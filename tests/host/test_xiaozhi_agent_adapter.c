#include "xiaozhi_agent_adapter.h"

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
    char last_json[256];
} mock_t;

static int submit_agent(void *ctx,
                        uint32_t request_id,
                        const char *session_id,
                        const char *text)
{
    mock_t *mock = ctx;
    (void)request_id;
    (void)session_id;
    (void)text;
    mock->submit_calls++;
    return 0;
}

static int cancel_agent(void *ctx, uint32_t request_id)
{
    mock_t *mock = ctx;
    (void)request_id;
    mock->cancel_calls++;
    return 0;
}

static int send_json(void *ctx, const char *json, size_t json_length)
{
    mock_t *mock = ctx;
    if (json_length >= sizeof(mock->last_json)) {
        return -1;
    }
    memcpy(mock->last_json, json, json_length);
    mock->last_json[json_length] = '\0';
    mock->send_calls++;
    return 0;
}

static int handle(voice_agent_controller_t *controller,
                  const char *json,
                  const char *session_id,
                  xiaozhi_agent_message_outcome_t *outcome,
                  agent_bridge_result_t expected)
{
    cJSON *root = cJSON_Parse(json);
    agent_bridge_result_t result;

    CHECK(root != NULL);
    result = xiaozhi_agent_adapter_handle_json(controller,
                                               root,
                                               session_id,
                                               outcome);
    cJSON_Delete(root);
    CHECK(result == expected);
    return 0;
}

static voice_agent_controller_config_t config_for(mock_t *mock,
                                                  char *tx_buffer,
                                                  size_t tx_buffer_size)
{
    voice_agent_controller_config_t config = {
        .ops = {
            .submit_agent = submit_agent,
            .cancel_agent = cancel_agent,
            .send_json = send_json,
        },
        .ops_ctx = mock,
        .tx_buffer = tx_buffer,
        .tx_buffer_size = tx_buffer_size,
    };
    return config;
}

static int test_current_stt_and_extended_tts(void)
{
    voice_agent_controller_t controller;
    mock_t mock = {0};
    char tx_buffer[256];
    voice_agent_controller_config_t config =
        config_for(&mock, tx_buffer, sizeof(tx_buffer));
    xiaozhi_agent_message_outcome_t outcome;
    uint32_t request_id;

    CHECK(voice_agent_controller_init(&controller, &config) == AGENT_BRIDGE_OK);
    CHECK(handle(&controller,
                 "{\"session_id\":\"s1\",\"type\":\"stt\","
                 "\"text\":\"hello\"}",
                 "s1", &outcome, AGENT_BRIDGE_OK) == 0);
    CHECK(outcome.handled);
    CHECK(outcome.accepted_request_id == 1);
    CHECK(mock.submit_calls == 1);
    request_id = outcome.accepted_request_id;

    CHECK(voice_agent_controller_on_agent_final(
              &controller, request_id, "reply") == AGENT_BRIDGE_OK);
    CHECK(handle(&controller,
                 "{\"session_id\":\"s1\",\"type\":\"tts\","
                 "\"state\":\"sentence_start\",\"text\":\"reply\"}",
                 "s1", &outcome, AGENT_BRIDGE_OK) == 0);
    CHECK(!outcome.handled);
    CHECK(handle(&controller,
                 "{\"session_id\":\"s1\",\"type\":\"tts\","
                 "\"state\":\"start\",\"request_id\":1}",
                 "s1", &outcome, AGENT_BRIDGE_OK) == 0);
    CHECK(outcome.handled && outcome.accepted_request_id == request_id);
    CHECK(handle(&controller,
                 "{\"session_id\":\"s1\",\"type\":\"tts\","
                 "\"state\":\"stop\",\"request_id\":1}",
                 "s1", &outcome, AGENT_BRIDGE_OK) == 0);
    CHECK(voice_agent_controller_state(&controller) == AGENT_BRIDGE_STATE_IDLE);
    return 0;
}

static int test_hello_feature_negotiation(void)
{
    cJSON *client_hello = cJSON_Parse(
        "{\"type\":\"hello\",\"features\":{\"mcp\":true}}");
    cJSON *server_hello = cJSON_Parse(
        "{\"type\":\"hello\",\"features\":{\"device_agent\":{"
        "\"version\":1,\"request_correlation\":true}}}");
    cJSON *legacy_hello = cJSON_Parse(
        "{\"type\":\"hello\",\"features\":{\"mcp\":true}}");
    cJSON *device_agent;

    CHECK(client_hello != NULL && server_hello != NULL && legacy_hello != NULL);
    CHECK(xiaozhi_agent_adapter_add_client_hello_feature(client_hello) ==
          AGENT_BRIDGE_OK);
    device_agent = cJSON_GetObjectItemCaseSensitive(
        cJSON_GetObjectItemCaseSensitive(client_hello, "features"),
        "device_agent");
    CHECK(cJSON_IsObject(device_agent));
    CHECK(cJSON_GetObjectItemCaseSensitive(device_agent, "version")->valueint == 1);
    CHECK(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(
        device_agent, "request_correlation")));
    CHECK(xiaozhi_agent_adapter_validate_server_hello(server_hello) ==
          AGENT_BRIDGE_OK);
    CHECK(xiaozhi_agent_adapter_validate_server_hello(legacy_hello) ==
          AGENT_BRIDGE_ERR_INVALID_STATE);

    cJSON_Delete(client_hello);
    cJSON_Delete(server_hello);
    cJSON_Delete(legacy_hello);
    return 0;
}

static int test_contract_rejects_legacy_and_stale_events(void)
{
    voice_agent_controller_t controller;
    mock_t mock = {0};
    char tx_buffer[256];
    voice_agent_controller_config_t config =
        config_for(&mock, tx_buffer, sizeof(tx_buffer));
    xiaozhi_agent_message_outcome_t outcome;
    uint32_t request_id = 0;

    CHECK(voice_agent_controller_init(&controller, &config) == AGENT_BRIDGE_OK);
    CHECK(voice_agent_controller_on_stt_final(
              &controller, "s1", "hello", &request_id) == AGENT_BRIDGE_OK);
    CHECK(voice_agent_controller_on_agent_final(
              &controller, request_id, "reply") == AGENT_BRIDGE_OK);

    CHECK(handle(&controller,
                 "{\"session_id\":\"s1\",\"type\":\"tts\","
                 "\"state\":\"start\"}",
                 "s1", &outcome, AGENT_BRIDGE_ERR_INVALID_ARG) == 0);
    CHECK(handle(&controller,
                 "{\"session_id\":\"old\",\"type\":\"tts\","
                 "\"state\":\"start\",\"request_id\":1}",
                 "s1", &outcome, AGENT_BRIDGE_ERR_STALE_EVENT) == 0);
    CHECK(handle(&controller,
                 "{\"session_id\":\"s1\",\"type\":\"tts\","
                 "\"state\":\"start\",\"request_id\":1.5}",
                 "s1", &outcome, AGENT_BRIDGE_ERR_INVALID_ARG) == 0);
    CHECK(handle(&controller,
                 "{\"session_id\":\"s1\",\"type\":\"tts\","
                 "\"state\":\"start\",\"request_id\":4294967296}",
                 "s1", &outcome, AGENT_BRIDGE_ERR_INVALID_ARG) == 0);
    CHECK(voice_agent_controller_state(&controller) ==
          AGENT_BRIDGE_STATE_TTS_PENDING);
    return 0;
}

static int test_unknown_messages_remain_available(void)
{
    voice_agent_controller_t controller;
    mock_t mock = {0};
    char tx_buffer[256];
    voice_agent_controller_config_t config =
        config_for(&mock, tx_buffer, sizeof(tx_buffer));
    xiaozhi_agent_message_outcome_t outcome;

    CHECK(voice_agent_controller_init(&controller, &config) == AGENT_BRIDGE_OK);
    CHECK(handle(&controller,
                 "{\"session_id\":\"s1\",\"type\":\"mcp\","
                 "\"payload\":{}}",
                 "s1", &outcome, AGENT_BRIDGE_OK) == 0);
    CHECK(!outcome.handled);
    CHECK(mock.submit_calls == 0 && mock.send_calls == 0);
    return 0;
}

static int test_speech_budget_errors_are_typed_and_reset_tts(void)
{
    voice_agent_controller_t controller;
    mock_t mock = {0};
    char tx_buffer[256];
    voice_agent_controller_config_t config =
        config_for(&mock, tx_buffer, sizeof(tx_buffer));
    xiaozhi_agent_message_outcome_t outcome;
    uint32_t request_id = 0;

    CHECK(voice_agent_controller_init(&controller, &config) == AGENT_BRIDGE_OK);
    CHECK(voice_agent_controller_on_stt_final(
              &controller, "s1", "hello", &request_id) == AGENT_BRIDGE_OK);
    CHECK(voice_agent_controller_on_agent_final(
              &controller, request_id, "reply") == AGENT_BRIDGE_OK);
    CHECK(voice_agent_controller_state(&controller) ==
          AGENT_BRIDGE_STATE_TTS_PENDING);
    CHECK(handle(&controller,
                 "{\"type\":\"error\","
                 "\"code\":\"speech_budget_exceeded\"}",
                 "s1", &outcome, AGENT_BRIDGE_OK) == 0);
    CHECK(outcome.handled && outcome.accepted_request_id == request_id);
    CHECK(outcome.service_error ==
          XIAOZHI_AGENT_SERVICE_ERROR_SPEECH_BUDGET_EXCEEDED);
    CHECK(voice_agent_controller_state(&controller) == AGENT_BRIDGE_STATE_IDLE);
    CHECK(mock.send_calls == 1);

    CHECK(handle(&controller,
                 "{\"type\":\"error\","
                 "\"code\":\"speech_budget_unavailable\"}",
                 "s1", &outcome, AGENT_BRIDGE_OK) == 0);
    CHECK(outcome.handled && outcome.accepted_request_id == 0);
    CHECK(outcome.service_error ==
          XIAOZHI_AGENT_SERVICE_ERROR_SPEECH_BUDGET_UNAVAILABLE);
    CHECK(handle(&controller,
                 "{\"type\":\"error\",\"code\":\"other\"}",
                 "s1", &outcome, AGENT_BRIDGE_OK) == 0);
    CHECK(!outcome.handled &&
          outcome.service_error == XIAOZHI_AGENT_SERVICE_ERROR_NONE);
    CHECK(handle(&controller,
                 "{\"type\":\"error\"}",
                 "s1", &outcome, AGENT_BRIDGE_ERR_INVALID_ARG) == 0);
    return 0;
}

int main(void)
{
    CHECK(test_hello_feature_negotiation() == 0);
    CHECK(test_current_stt_and_extended_tts() == 0);
    CHECK(test_contract_rejects_legacy_and_stale_events() == 0);
    CHECK(test_unknown_messages_remain_available() == 0);
    CHECK(test_speech_budget_errors_are_typed_and_reset_tts() == 0);
    puts("xiaozhi_agent_adapter: all host tests passed");
    return 0;
}
