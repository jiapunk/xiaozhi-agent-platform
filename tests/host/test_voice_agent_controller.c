#include "voice_agent_controller.h"
#include "voice_agent_protocol.h"

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

enum {
    OP_SUBMIT = 1,
    OP_CANCEL_AGENT,
    OP_SEND_JSON,
    OP_PLAYBACK_BEGIN,
    OP_PLAYBACK_DRAIN,
    OP_PLAYBACK_FLUSH,
};

typedef struct {
    int submit_calls;
    int cancel_agent_calls;
    int send_json_calls;
    int fail_send_json;
    uint32_t last_request_id;
    char last_session_id[AGENT_BRIDGE_SESSION_ID_MAX];
    char last_text[128];
    char last_json[512];
    size_t last_json_length;
    int operations[16];
    size_t operation_count;
    int playback_begin_calls;
    int playback_drain_calls;
    int playback_flush_calls;
} mock_t;

static void record_operation(mock_t *mock, int operation)
{
    if (mock->operation_count < sizeof(mock->operations) /
                                    sizeof(mock->operations[0])) {
        mock->operations[mock->operation_count++] = operation;
    }
}

static int mock_submit(void *ctx,
                       uint32_t request_id,
                       const char *session_id,
                       const char *text)
{
    mock_t *mock = ctx;
    record_operation(mock, OP_SUBMIT);
    mock->submit_calls++;
    mock->last_request_id = request_id;
    snprintf(mock->last_session_id, sizeof(mock->last_session_id), "%s",
             session_id);
    snprintf(mock->last_text, sizeof(mock->last_text), "%s", text);
    return 0;
}

static int mock_cancel_agent(void *ctx, uint32_t request_id)
{
    mock_t *mock = ctx;
    record_operation(mock, OP_CANCEL_AGENT);
    mock->cancel_agent_calls++;
    mock->last_request_id = request_id;
    return 0;
}

static int mock_send_json(void *ctx, const char *json, size_t json_length)
{
    mock_t *mock = ctx;
    record_operation(mock, OP_SEND_JSON);
    mock->send_json_calls++;
    mock->last_json_length = json_length;
    if (json_length >= sizeof(mock->last_json)) {
        return -1;
    }
    memcpy(mock->last_json, json, json_length);
    mock->last_json[json_length] = '\0';
    return mock->fail_send_json;
}

static void mock_playback_event(void *ctx,
                                voice_agent_playback_event_t event,
                                uint32_t request_id)
{
    mock_t *mock = ctx;
    mock->last_request_id = request_id;
    switch (event) {
    case VOICE_AGENT_PLAYBACK_BEGIN:
        mock->playback_begin_calls++;
        record_operation(mock, OP_PLAYBACK_BEGIN);
        break;
    case VOICE_AGENT_PLAYBACK_DRAIN:
        mock->playback_drain_calls++;
        record_operation(mock, OP_PLAYBACK_DRAIN);
        break;
    case VOICE_AGENT_PLAYBACK_FLUSH:
        mock->playback_flush_calls++;
        record_operation(mock, OP_PLAYBACK_FLUSH);
        break;
    }
}

static voice_agent_controller_config_t mock_config(mock_t *mock,
                                                   char *tx_buffer,
                                                   size_t tx_buffer_size)
{
    voice_agent_controller_config_t config = {
        .ops = {
            .submit_agent = mock_submit,
            .cancel_agent = mock_cancel_agent,
            .send_json = mock_send_json,
            .playback_event = mock_playback_event,
        },
        .ops_ctx = mock,
        .tx_buffer = tx_buffer,
        .tx_buffer_size = tx_buffer_size,
    };
    return config;
}

static int test_protocol_contract_and_escaping(void)
{
    char output[256];
    char small[8] = "dirty";
    size_t required_size = 0;

    CHECK(voice_agent_build_tts_request(
              output, sizeof(output), "s\"\\", UINT32_MAX, "line\n\t\x01",
              &required_size) == VOICE_AGENT_PROTOCOL_OK);
    CHECK(strcmp(output,
                 "{\"session_id\":\"s\\\"\\\\\",\"type\":\"tts_request\","
                 "\"request_id\":4294967295,\"text\":\"line\\n\\t\\u0001\"}") == 0);
    CHECK(required_size == strlen(output) + 1);

    CHECK(voice_agent_build_tts_request(
              small, sizeof(small), "session", 1, "response", &required_size) ==
          VOICE_AGENT_PROTOCOL_ERR_BUFFER_TOO_SMALL);
    CHECK(small[0] == '\0');
    CHECK(required_size > sizeof(small));
    CHECK(voice_agent_build_tts_request(
              output, sizeof(output), "session", 0, "response", &required_size) ==
          VOICE_AGENT_PROTOCOL_ERR_INVALID_ARG);
    return 0;
}

static int test_happy_path_wire_messages(void)
{
    voice_agent_controller_t controller;
    mock_t mock = {0};
    char tx_buffer[512];
    voice_agent_controller_config_t config =
        mock_config(&mock, tx_buffer, sizeof(tx_buffer));
    uint32_t request_id = 0;

    CHECK(voice_agent_controller_init(&controller, &config) == AGENT_BRIDGE_OK);
    CHECK(voice_agent_controller_on_stt_final(
              &controller, "voice:device-1", "turn on", &request_id) ==
          AGENT_BRIDGE_OK);
    CHECK(request_id == 1);
    CHECK(mock.submit_calls == 1);
    CHECK(strcmp(mock.last_session_id, "voice:device-1") == 0);

    CHECK(voice_agent_controller_on_agent_final(
              &controller, request_id, "Done \"now\"\n") == AGENT_BRIDGE_OK);
    CHECK(strcmp(mock.last_json,
                 "{\"session_id\":\"voice:device-1\",\"type\":\"tts_request\","
                 "\"request_id\":1,\"text\":\"Done \\\"now\\\"\\n\"}") == 0);
    CHECK(mock.last_json_length == strlen(mock.last_json));
    CHECK(voice_agent_controller_on_tts_event(
              &controller, "voice:device-1", request_id,
              VOICE_AGENT_TTS_STARTED) == AGENT_BRIDGE_OK);
    CHECK(mock.playback_begin_calls == 1);
    CHECK(voice_agent_controller_on_tts_event(
              &controller, "voice:device-1", request_id,
              VOICE_AGENT_TTS_STOPPED) == AGENT_BRIDGE_OK);
    CHECK(mock.playback_drain_calls == 1);
    CHECK(voice_agent_controller_state(&controller) == AGENT_BRIDGE_STATE_IDLE);
    return 0;
}

static int test_stale_tts_events_are_rejected(void)
{
    voice_agent_controller_t controller;
    mock_t mock = {0};
    char tx_buffer[256];
    voice_agent_controller_config_t config =
        mock_config(&mock, tx_buffer, sizeof(tx_buffer));
    uint32_t request_id = 0;

    CHECK(voice_agent_controller_init(&controller, &config) == AGENT_BRIDGE_OK);
    CHECK(voice_agent_controller_on_stt_final(
              &controller, "session-a", "hello", &request_id) == AGENT_BRIDGE_OK);
    CHECK(voice_agent_controller_on_agent_final(
              &controller, request_id, "reply") == AGENT_BRIDGE_OK);
    CHECK(voice_agent_controller_on_tts_event(
              &controller, "session-b", request_id,
              VOICE_AGENT_TTS_STARTED) == AGENT_BRIDGE_ERR_STALE_EVENT);
    CHECK(voice_agent_controller_on_tts_event(
              &controller, "session-a", request_id + 1,
              VOICE_AGENT_TTS_STARTED) == AGENT_BRIDGE_ERR_STALE_EVENT);
    CHECK(voice_agent_controller_state(&controller) ==
          AGENT_BRIDGE_STATE_TTS_PENDING);
    return 0;
}

static int test_barge_in_aborts_tts_before_new_submit(void)
{
    voice_agent_controller_t controller;
    mock_t mock = {0};
    char tx_buffer[256];
    voice_agent_controller_config_t config =
        mock_config(&mock, tx_buffer, sizeof(tx_buffer));
    uint32_t first = 0;
    uint32_t second = 0;

    CHECK(voice_agent_controller_init(&controller, &config) == AGENT_BRIDGE_OK);
    CHECK(voice_agent_controller_on_stt_final(
              &controller, "session", "first", &first) == AGENT_BRIDGE_OK);
    CHECK(voice_agent_controller_on_agent_final(
              &controller, first, "first reply") == AGENT_BRIDGE_OK);
    CHECK(voice_agent_controller_on_tts_event(
              &controller, "session", first, VOICE_AGENT_TTS_STARTED) ==
          AGENT_BRIDGE_OK);

    mock.operation_count = 0;
    CHECK(voice_agent_controller_on_stt_final(
              &controller, "session", "second", &second) == AGENT_BRIDGE_OK);
    CHECK(second == 2);
    CHECK(mock.operation_count == 3);
    CHECK(mock.operations[0] == OP_PLAYBACK_FLUSH);
    CHECK(mock.operations[1] == OP_SEND_JSON);
    CHECK(mock.operations[2] == OP_SUBMIT);
    CHECK(mock.playback_flush_calls == 1);
    CHECK(strcmp(mock.last_json,
                 "{\"session_id\":\"session\",\"type\":\"tts_abort\","
                 "\"request_id\":1,\"reason\":\"barge_in\"}") == 0);
    CHECK(voice_agent_controller_active_request_id(&controller) == second);
    return 0;
}

static int test_invalid_stt_does_not_flush_active_playback(void)
{
    voice_agent_controller_t controller;
    mock_t mock = {0};
    char tx_buffer[256];
    char oversized_session[AGENT_BRIDGE_SESSION_ID_MAX + 1];
    voice_agent_controller_config_t config =
        mock_config(&mock, tx_buffer, sizeof(tx_buffer));
    uint32_t request_id = 0;

    CHECK(voice_agent_controller_init(&controller, &config) == AGENT_BRIDGE_OK);
    CHECK(voice_agent_controller_on_stt_final(
              &controller, "session", "first", &request_id) ==
          AGENT_BRIDGE_OK);
    CHECK(voice_agent_controller_on_agent_final(
              &controller, request_id, "reply") == AGENT_BRIDGE_OK);
    CHECK(voice_agent_controller_on_tts_event(
              &controller, "session", request_id, VOICE_AGENT_TTS_STARTED) ==
          AGENT_BRIDGE_OK);

    memset(oversized_session, 'x', AGENT_BRIDGE_SESSION_ID_MAX);
    oversized_session[AGENT_BRIDGE_SESSION_ID_MAX] = '\0';
    CHECK(voice_agent_controller_on_stt_final(
              &controller, oversized_session, "invalid", NULL) ==
          AGENT_BRIDGE_ERR_INVALID_ARG);
    CHECK(voice_agent_controller_on_stt_final(
              &controller, "session", "", NULL) ==
          AGENT_BRIDGE_ERR_INVALID_ARG);
    CHECK(mock.playback_flush_calls == 0);
    CHECK(voice_agent_controller_state(&controller) ==
          AGENT_BRIDGE_STATE_TTS_PLAYING);
    CHECK(voice_agent_controller_active_request_id(&controller) == request_id);
    return 0;
}

static int test_explicit_interrupt_and_tts_error(void)
{
    voice_agent_controller_t controller;
    mock_t mock = {0};
    char tx_buffer[256];
    voice_agent_controller_config_t config =
        mock_config(&mock, tx_buffer, sizeof(tx_buffer));
    uint32_t request_id = 0;

    CHECK(voice_agent_controller_init(&controller, &config) == AGENT_BRIDGE_OK);
    CHECK(voice_agent_controller_on_stt_final(
              &controller, "session", "one", &request_id) == AGENT_BRIDGE_OK);
    CHECK(voice_agent_controller_on_agent_final(
              &controller, request_id, "reply") == AGENT_BRIDGE_OK);
    CHECK(voice_agent_controller_interrupt(
              &controller, AGENT_BRIDGE_INTERRUPT_NETWORK_LOST) ==
          AGENT_BRIDGE_OK);
    CHECK(strstr(mock.last_json, "\"reason\":\"network_lost\"") != NULL);
    CHECK(mock.playback_flush_calls == 1);
    CHECK(voice_agent_controller_state(&controller) == AGENT_BRIDGE_STATE_IDLE);

    CHECK(voice_agent_controller_on_stt_final(
              &controller, "session", "two", &request_id) == AGENT_BRIDGE_OK);
    CHECK(voice_agent_controller_on_agent_final(
              &controller, request_id, "reply") == AGENT_BRIDGE_OK);
    CHECK(voice_agent_controller_on_tts_event(
              &controller, "session", request_id, VOICE_AGENT_TTS_ERROR) ==
          AGENT_BRIDGE_OK);
    CHECK(mock.playback_flush_calls == 2);
    CHECK(voice_agent_controller_state(&controller) == AGENT_BRIDGE_STATE_IDLE);
    return 0;
}

static int test_transport_and_buffer_failures_recover(void)
{
    voice_agent_controller_t controller;
    mock_t mock = {.fail_send_json = 1};
    char tx_buffer[256];
    voice_agent_controller_config_t config =
        mock_config(&mock, tx_buffer, sizeof(tx_buffer));
    uint32_t request_id = 0;

    CHECK(voice_agent_controller_init(&controller, &config) == AGENT_BRIDGE_OK);
    CHECK(voice_agent_controller_on_stt_final(
              &controller, "session", "one", &request_id) == AGENT_BRIDGE_OK);
    CHECK(voice_agent_controller_on_agent_final(
              &controller, request_id, "reply") ==
          AGENT_BRIDGE_ERR_OPERATION);
    CHECK(voice_agent_controller_state(&controller) == AGENT_BRIDGE_STATE_IDLE);

    config.tx_buffer_size = 24;
    mock.fail_send_json = 0;
    CHECK(voice_agent_controller_init(&controller, &config) == AGENT_BRIDGE_OK);
    CHECK(voice_agent_controller_on_stt_final(
              &controller, "session", "two", &request_id) == AGENT_BRIDGE_OK);
    CHECK(voice_agent_controller_on_agent_final(
              &controller, request_id, "reply too large") ==
          AGENT_BRIDGE_ERR_OPERATION);
    CHECK(voice_agent_controller_state(&controller) == AGENT_BRIDGE_STATE_IDLE);
    return 0;
}

int main(void)
{
    CHECK(test_protocol_contract_and_escaping() == 0);
    CHECK(test_happy_path_wire_messages() == 0);
    CHECK(test_stale_tts_events_are_rejected() == 0);
    CHECK(test_barge_in_aborts_tts_before_new_submit() == 0);
    CHECK(test_invalid_stt_does_not_flush_active_playback() == 0);
    CHECK(test_explicit_interrupt_and_tts_error() == 0);
    CHECK(test_transport_and_buffer_failures_recover() == 0);
    puts("voice_agent_controller: all host tests passed");
    return 0;
}
