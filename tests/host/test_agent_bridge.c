#include "agent_bridge.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                     \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition); \
            return 1;                                                          \
        }                                                                      \
    } while (0)

typedef struct {
    int submit_calls;
    int cancel_agent_calls;
    int request_tts_calls;
    int cancel_tts_calls;
    int state_changes;
    int fail_submit;
    int fail_tts;
    uint32_t last_request_id;
    char last_session_id[AGENT_BRIDGE_SESSION_ID_MAX];
    char last_text[128];
} mock_t;

static int mock_submit(void *ctx,
                       uint32_t request_id,
                       const char *session_id,
                       const char *text)
{
    mock_t *mock = ctx;
    mock->submit_calls++;
    mock->last_request_id = request_id;
    snprintf(mock->last_session_id, sizeof(mock->last_session_id), "%s", session_id);
    snprintf(mock->last_text, sizeof(mock->last_text), "%s", text);
    return mock->fail_submit;
}

static int mock_cancel_agent(void *ctx, uint32_t request_id)
{
    mock_t *mock = ctx;
    mock->cancel_agent_calls++;
    mock->last_request_id = request_id;
    return 0;
}

static int mock_request_tts(void *ctx,
                            uint32_t request_id,
                            const char *session_id,
                            const char *text)
{
    mock_t *mock = ctx;
    mock->request_tts_calls++;
    mock->last_request_id = request_id;
    snprintf(mock->last_session_id, sizeof(mock->last_session_id), "%s", session_id);
    snprintf(mock->last_text, sizeof(mock->last_text), "%s", text);
    return mock->fail_tts;
}

static int mock_cancel_tts(void *ctx, uint32_t request_id)
{
    mock_t *mock = ctx;
    mock->cancel_tts_calls++;
    mock->last_request_id = request_id;
    return 0;
}

static void mock_state_changed(void *ctx,
                               agent_bridge_state_t from,
                               agent_bridge_state_t to,
                               uint32_t request_id)
{
    mock_t *mock = ctx;
    (void)from;
    (void)to;
    mock->state_changes++;
    mock->last_request_id = request_id;
}

static agent_bridge_ops_t mock_ops(void)
{
    agent_bridge_ops_t ops = {
        .submit_agent = mock_submit,
        .cancel_agent = mock_cancel_agent,
        .request_tts = mock_request_tts,
        .cancel_tts = mock_cancel_tts,
        .state_changed = mock_state_changed,
    };
    return ops;
}

static int test_happy_path(void)
{
    agent_bridge_t bridge;
    agent_bridge_ops_t ops = mock_ops();
    mock_t mock = {0};
    uint32_t request_id = 0;

    CHECK(agent_bridge_init(&bridge, &ops, &mock) == AGENT_BRIDGE_OK);
    CHECK(agent_bridge_on_stt_final(&bridge, "voice:device-1", "turn on the light",
                                    &request_id) == AGENT_BRIDGE_OK);
    CHECK(request_id == 1);
    CHECK(agent_bridge_state(&bridge) == AGENT_BRIDGE_STATE_AGENT_RUNNING);
    CHECK(strcmp(agent_bridge_active_session_id(&bridge), "voice:device-1") == 0);
    CHECK(mock.submit_calls == 1);
    CHECK(strcmp(mock.last_text, "turn on the light") == 0);

    CHECK(agent_bridge_on_agent_final(&bridge, request_id, "Done") == AGENT_BRIDGE_OK);
    CHECK(agent_bridge_state(&bridge) == AGENT_BRIDGE_STATE_TTS_PENDING);
    CHECK(mock.request_tts_calls == 1);
    CHECK(agent_bridge_on_tts_started(&bridge, request_id) == AGENT_BRIDGE_OK);
    CHECK(agent_bridge_state(&bridge) == AGENT_BRIDGE_STATE_TTS_PLAYING);
    CHECK(agent_bridge_on_tts_stopped(&bridge, request_id) == AGENT_BRIDGE_OK);
    CHECK(agent_bridge_state(&bridge) == AGENT_BRIDGE_STATE_IDLE);
    CHECK(agent_bridge_active_request_id(&bridge) == 0);
    CHECK(strcmp(agent_bridge_active_session_id(&bridge), "") == 0);
    return 0;
}

static int test_tts_error_recovers(void)
{
    agent_bridge_t bridge;
    agent_bridge_ops_t ops = mock_ops();
    mock_t mock = {0};
    uint32_t request_id = 0;

    CHECK(agent_bridge_init(&bridge, &ops, &mock) == AGENT_BRIDGE_OK);
    CHECK(agent_bridge_on_stt_final(&bridge, "s", "hello", &request_id) ==
          AGENT_BRIDGE_OK);
    CHECK(agent_bridge_on_agent_final(&bridge, request_id, "response") ==
          AGENT_BRIDGE_OK);
    CHECK(agent_bridge_on_tts_error(&bridge, request_id) == AGENT_BRIDGE_OK);
    CHECK(agent_bridge_state(&bridge) == AGENT_BRIDGE_STATE_IDLE);
    CHECK(agent_bridge_on_tts_error(&bridge, request_id) ==
          AGENT_BRIDGE_ERR_STALE_EVENT);
    return 0;
}

static int test_barge_in_rejects_stale_result(void)
{
    agent_bridge_t bridge;
    agent_bridge_ops_t ops = mock_ops();
    mock_t mock = {0};
    uint32_t first = 0;
    uint32_t second = 0;

    CHECK(agent_bridge_init(&bridge, &ops, &mock) == AGENT_BRIDGE_OK);
    CHECK(agent_bridge_on_stt_final(&bridge, "s", "first", &first) == AGENT_BRIDGE_OK);
    CHECK(agent_bridge_on_stt_final(&bridge, "s", "second", &second) == AGENT_BRIDGE_OK);
    CHECK(first == 1 && second == 2);
    CHECK(mock.cancel_agent_calls == 1);
    CHECK(mock.submit_calls == 2);
    CHECK(agent_bridge_active_request_id(&bridge) == second);
    CHECK(agent_bridge_on_agent_final(&bridge, first, "stale") ==
          AGENT_BRIDGE_ERR_STALE_EVENT);
    CHECK(mock.request_tts_calls == 0);
    CHECK(agent_bridge_on_agent_final(&bridge, second, "fresh") == AGENT_BRIDGE_OK);
    CHECK(mock.request_tts_calls == 1);
    return 0;
}

static int test_interrupt_during_tts(void)
{
    agent_bridge_t bridge;
    agent_bridge_ops_t ops = mock_ops();
    mock_t mock = {0};
    uint32_t request_id = 0;

    CHECK(agent_bridge_init(&bridge, &ops, &mock) == AGENT_BRIDGE_OK);
    CHECK(agent_bridge_on_stt_final(&bridge, "s", "hello", &request_id) == AGENT_BRIDGE_OK);
    CHECK(agent_bridge_on_agent_final(&bridge, request_id, "response") == AGENT_BRIDGE_OK);
    CHECK(agent_bridge_on_tts_started(&bridge, request_id) == AGENT_BRIDGE_OK);
    CHECK(agent_bridge_interrupt(&bridge, AGENT_BRIDGE_INTERRUPT_BUTTON) == AGENT_BRIDGE_OK);
    CHECK(mock.cancel_tts_calls == 1);
    CHECK(agent_bridge_state(&bridge) == AGENT_BRIDGE_STATE_IDLE);
    CHECK(agent_bridge_on_tts_stopped(&bridge, request_id) ==
          AGENT_BRIDGE_ERR_STALE_EVENT);
    return 0;
}

static int test_barge_in_during_tts_starts_new_agent_request(void)
{
    agent_bridge_t bridge;
    agent_bridge_ops_t ops = mock_ops();
    mock_t mock = {0};
    uint32_t first = 0;
    uint32_t second = 0;

    CHECK(agent_bridge_init(&bridge, &ops, &mock) == AGENT_BRIDGE_OK);
    CHECK(agent_bridge_on_stt_final(&bridge, "s", "first", &first) == AGENT_BRIDGE_OK);
    CHECK(agent_bridge_on_agent_final(&bridge, first, "first response") == AGENT_BRIDGE_OK);
    CHECK(agent_bridge_on_tts_started(&bridge, first) == AGENT_BRIDGE_OK);

    CHECK(agent_bridge_on_stt_final(&bridge, "s", "second", &second) == AGENT_BRIDGE_OK);
    CHECK(mock.cancel_tts_calls == 1);
    CHECK(mock.submit_calls == 2);
    CHECK(second != first);
    CHECK(agent_bridge_state(&bridge) == AGENT_BRIDGE_STATE_AGENT_RUNNING);
    CHECK(agent_bridge_on_tts_stopped(&bridge, first) == AGENT_BRIDGE_ERR_STALE_EVENT);
    return 0;
}

static int test_operation_failures_recover(void)
{
    agent_bridge_t bridge;
    agent_bridge_ops_t ops = mock_ops();
    mock_t mock = {.fail_submit = 1};
    uint32_t request_id = 0;

    CHECK(agent_bridge_init(&bridge, &ops, &mock) == AGENT_BRIDGE_OK);
    CHECK(agent_bridge_on_stt_final(&bridge, "s", "hello", &request_id) ==
          AGENT_BRIDGE_ERR_OPERATION);
    CHECK(agent_bridge_state(&bridge) == AGENT_BRIDGE_STATE_IDLE);

    mock.fail_submit = 0;
    mock.fail_tts = 1;
    CHECK(agent_bridge_on_stt_final(&bridge, "s", "hello", &request_id) == AGENT_BRIDGE_OK);
    CHECK(agent_bridge_on_agent_final(&bridge, request_id, "response") ==
          AGENT_BRIDGE_ERR_OPERATION);
    CHECK(agent_bridge_state(&bridge) == AGENT_BRIDGE_STATE_IDLE);
    return 0;
}

static int test_request_id_wrap_skips_zero(void)
{
    agent_bridge_t bridge;
    agent_bridge_ops_t ops = mock_ops();
    mock_t mock = {0};
    uint32_t first = 0;
    uint32_t second = 0;

    CHECK(agent_bridge_init(&bridge, &ops, &mock) == AGENT_BRIDGE_OK);
    bridge.next_request_id = UINT32_MAX;
    CHECK(agent_bridge_on_stt_final(&bridge, "s", "one", &first) == AGENT_BRIDGE_OK);
    CHECK(first == UINT32_MAX);
    CHECK(agent_bridge_on_agent_error(&bridge, first) == AGENT_BRIDGE_OK);
    CHECK(agent_bridge_on_stt_final(&bridge, "s", "two", &second) == AGENT_BRIDGE_OK);
    CHECK(second == 1);
    return 0;
}

int main(void)
{
    CHECK(test_happy_path() == 0);
    CHECK(test_tts_error_recovers() == 0);
    CHECK(test_barge_in_rejects_stale_result() == 0);
    CHECK(test_interrupt_during_tts() == 0);
    CHECK(test_barge_in_during_tts_starts_new_agent_request() == 0);
    CHECK(test_operation_failures_recover() == 0);
    CHECK(test_request_id_wrap_skips_zero() == 0);
    puts("agent_bridge: all host tests passed");
    return 0;
}
