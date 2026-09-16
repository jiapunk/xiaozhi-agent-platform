#include "voice_audio_session.h"

#include <stdio.h>

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                    \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,          \
                    #condition);                                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static int test_admission_drain_and_completion(void)
{
    voice_audio_session_t session;
    voice_audio_token_t token;
    uint32_t finished = 0;

    CHECK(voice_audio_session_init(&session) == VOICE_AUDIO_SESSION_OK);
    CHECK(voice_audio_session_admit(&session, &token) ==
          VOICE_AUDIO_SESSION_ERR_INVALID_STATE);
    CHECK(voice_audio_session_begin(&session, 42) == VOICE_AUDIO_SESSION_OK);
    CHECK(voice_audio_session_admit(&session, &token) == VOICE_AUDIO_SESSION_OK);
    CHECK(token.request_id == 42 && token.generation != 0);
    CHECK(voice_audio_session_set_inflight(&session, token, true) ==
          VOICE_AUDIO_SESSION_OK);
    CHECK(voice_audio_session_drain(&session, 42) == VOICE_AUDIO_SESSION_OK);
    CHECK(voice_audio_session_admit(&session, &token) ==
          VOICE_AUDIO_SESSION_ERR_INVALID_STATE);
    CHECK(voice_audio_session_finish_drain(&session, true, &finished) ==
          VOICE_AUDIO_SESSION_ERR_INVALID_STATE);
    CHECK(voice_audio_session_set_inflight(&session,
                                           session.inflight_token, false) ==
          VOICE_AUDIO_SESSION_OK);
    CHECK(voice_audio_session_finish_drain(&session, false, &finished) ==
          VOICE_AUDIO_SESSION_ERR_INVALID_STATE);
    CHECK(voice_audio_session_finish_drain(&session, true, &finished) ==
          VOICE_AUDIO_SESSION_OK);
    CHECK(finished == 42 && session.state == VOICE_AUDIO_SESSION_IDLE);
    return 0;
}

static int test_generation_rejects_dequeued_stale_packet(void)
{
    voice_audio_session_t session;
    voice_audio_token_t first;
    voice_audio_token_t second;

    CHECK(voice_audio_session_init(&session) == VOICE_AUDIO_SESSION_OK);
    CHECK(voice_audio_session_begin(&session, 1) == VOICE_AUDIO_SESSION_OK);
    CHECK(voice_audio_session_admit(&session, &first) == VOICE_AUDIO_SESSION_OK);
    CHECK(voice_audio_session_set_inflight(&session, first, true) ==
          VOICE_AUDIO_SESSION_OK);
    CHECK(voice_audio_session_flush(&session, 1) == VOICE_AUDIO_SESSION_OK);
    CHECK(!voice_audio_session_is_current(&session, first));

    CHECK(voice_audio_session_begin(&session, 2) == VOICE_AUDIO_SESSION_OK);
    CHECK(voice_audio_session_admit(&session, &second) == VOICE_AUDIO_SESSION_OK);
    CHECK(second.generation != first.generation);
    CHECK(!voice_audio_session_is_current(&session, first));
    CHECK(voice_audio_session_is_current(&session, second));
    CHECK(voice_audio_session_set_inflight(&session, first, false) ==
          VOICE_AUDIO_SESSION_OK);
    CHECK(voice_audio_session_set_inflight(&session, second, true) ==
          VOICE_AUDIO_SESSION_OK);
    CHECK(voice_audio_session_set_inflight(&session, second, false) ==
          VOICE_AUDIO_SESSION_OK);
    return 0;
}

static int test_stale_lifecycle_does_not_change_active_request(void)
{
    voice_audio_session_t session;
    voice_audio_token_t token;

    CHECK(voice_audio_session_init(&session) == VOICE_AUDIO_SESSION_OK);
    CHECK(voice_audio_session_begin(&session, 7) == VOICE_AUDIO_SESSION_OK);
    CHECK(voice_audio_session_flush(&session, 8) ==
          VOICE_AUDIO_SESSION_ERR_STALE);
    CHECK(voice_audio_session_drain(&session, 8) ==
          VOICE_AUDIO_SESSION_ERR_STALE);
    CHECK(voice_audio_session_admit(&session, &token) == VOICE_AUDIO_SESSION_OK);
    CHECK(token.request_id == 7);
    return 0;
}

int main(void)
{
    CHECK(test_admission_drain_and_completion() == 0);
    CHECK(test_generation_rejects_dequeued_stale_packet() == 0);
    CHECK(test_stale_lifecycle_does_not_change_active_request() == 0);
    puts("voice_audio_session: all host tests passed");
    return 0;
}
