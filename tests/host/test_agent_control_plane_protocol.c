#include "agent_control_plane_protocol.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_endpoints_and_canonical(void)
{
    assert(agent_control_plane_validate_endpoints(
        "https://control.example/v1/time",
        "https://control.example/v1/agent-token",
        "https://control.example/v1/device-claim/device",
        "https://control.example/v1/action-consents/device/challenge",
        "https://control.example/v1/action-consents/device/result"));
    assert(!agent_control_plane_validate_endpoints(
        "http://control.example/v1/time",
        "https://control.example/v1/agent-token",
        "https://control.example/v1/device-claim/device",
        "https://control.example/v1/action-consents/device/challenge",
        "https://control.example/v1/action-consents/device/result"));
    assert(!agent_control_plane_validate_endpoints(
        "https://control.example/v1/time",
        "https://other.example/v1/agent-token",
        "https://control.example/v1/device-claim/device",
        "https://control.example/v1/action-consents/device/challenge",
        "https://control.example/v1/action-consents/device/result"));
    assert(!agent_control_plane_validate_endpoints(
        "https://user@control.example/v1/time",
        "https://user@control.example/v1/agent-token",
        "https://user@control.example/v1/device-claim/device",
        "https://user@control.example/v1/action-consents/device/challenge",
        "https://user@control.example/v1/action-consents/device/result"));
    assert(!agent_control_plane_validate_endpoints(
        "https://control.example/v1/time",
        "https://control.example/v1/agent-token",
        "https://other.example/v1/device-claim/device",
        "https://control.example/v1/action-consents/device/challenge",
        "https://control.example/v1/action-consents/device/result"));
    assert(!agent_control_plane_validate_endpoints(
        "https://control.example/v1/time",
        "https://control.example/v1/agent-token",
        "https://control.example/v1/device-claim/device",
        "https://other.example/v1/action-consents/device/challenge",
        "https://control.example/v1/action-consents/device/result"));
    char canonical[256];
    assert(agent_control_plane_build_agent_canonical(
        "device-1", "client-1", "1800000000",
        "AAECAwQFBgcICQoLDA0ODw", canonical, sizeof(canonical)));
    assert(strcmp(canonical,
                  "xiaozhi-agent-token-proof-v1\nPOST\n"
                  "/v1/agent-token\ndevice-1\nclient-1\n1800000000\n"
                  "AAECAwQFBgcICQoLDA0ODw") == 0);
}

static void test_action_consent_protocol(void)
{
    const char *challenge_id = "AAECAwQFBgcICQoLDA0ODw";
    const char *digest =
        "0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef";
    char body[512];
    assert(agent_control_plane_action_challenge_id_is_canonical(
        challenge_id));
    assert(!agent_control_plane_action_challenge_id_is_canonical(
        "AAECAwQFBgcICQoLDA0ODx"));
    assert(agent_control_plane_build_action_challenge_body(
        challenge_id, "session-1", 42, true, 1800000020,
        body, sizeof(body)));
    assert(strcmp(
               body,
               "{\"version\":1,\"challenge_id\":"
               "\"AAECAwQFBgcICQoLDA0ODw\","
               "\"session_id\":\"session-1\",\"request_id\":42,"
               "\"capability\":\"device.set_indicator\","
               "\"arguments\":{\"on\":true},"
               "\"expires_at_unix\":1800000020}") == 0);
    assert(agent_control_plane_build_action_result_body(
        challenge_id, 7, "session-1", 42, true,
        body, sizeof(body)));
    assert(strcmp(
               body,
               "{\"version\":1,\"challenge_id\":"
               "\"AAECAwQFBgcICQoLDA0ODw\",\"owner_revision\":7,"
               "\"session_id\":\"session-1\",\"request_id\":42,"
               "\"capability\":\"device.set_indicator\","
               "\"arguments\":{\"on\":true}}") == 0);

    char canonical[512];
    assert(agent_control_plane_build_action_canonical(
        AGENT_CONTROL_PLANE_ACTION_PROOF_CHALLENGE,
        "device-1", "client-1", "1800000000",
        challenge_id, digest, canonical, sizeof(canonical)));
    assert(strcmp(
               canonical,
               "xiaozhi-action-consent-challenge-proof-v1\nPOST\n"
               "/v1/action-consents/device/challenge\n"
               "device-1\nclient-1\n1800000000\n"
               "AAECAwQFBgcICQoLDA0ODw\n"
               "0123456789abcdef0123456789abcdef"
               "0123456789abcdef0123456789abcdef") == 0);
    assert(!agent_control_plane_build_action_canonical(
        (agent_control_plane_action_proof_scope_t)99,
        "device-1", "client-1", "1800000000",
        challenge_id, digest, canonical, sizeof(canonical)));

    char challenge_response[] =
        "{\"version\":1,\"challenge_id\":"
        "\"AAECAwQFBgcICQoLDA0ODw\",\"device_id\":\"device-1\","
        "\"owner_revision\":7,\"session_id\":\"session-1\","
        "\"request_id\":42,\"capability\":\"device.set_indicator\","
        "\"arguments\":{\"on\":true},"
        "\"expires_at_unix\":1800000020}";
    uint64_t owner_revision = 0;
    assert(agent_control_plane_parse_action_challenge_response(
        challenge_response, strlen(challenge_response), challenge_id,
        "device-1", "session-1", 42, true, 1800000020,
        &owner_revision));
    assert(owner_revision == 7);
    char noncanonical_challenge[] =
        "{\"version\":1,\"challenge_id\":"
        "\"AAECAwQFBgcICQoLDA0ODw\",\"device_id\":\"device-1\","
        "\"owner_revision\":7,\"session_id\":\"session-1\","
        "\"request_id\":42,\"capability\":\"device.set_indicator\","
        "\"arguments\":{\"on\":true},"
        "\"expires_at_unix\":1800000020}\n";
    assert(!agent_control_plane_parse_action_challenge_response(
        noncanonical_challenge, strlen(noncanonical_challenge),
        challenge_id, "device-1", "session-1", 42, true,
        1800000020, &owner_revision));
    assert(owner_revision == 0);

    agent_control_plane_action_protocol_decision_t decision =
        AGENT_CONTROL_PLANE_ACTION_PROTOCOL_DENY;
    char pending[] =
        "{\"version\":1,\"challenge_id\":"
        "\"AAECAwQFBgcICQoLDA0ODw\",\"status\":\"pending\","
        "\"retry_after_seconds\":1}";
    assert(agent_control_plane_parse_action_result_response(
        pending, strlen(pending), 202, challenge_id, &decision));
    assert(decision == AGENT_CONTROL_PLANE_ACTION_PROTOCOL_PENDING);
    char approved[] =
        "{\"version\":1,\"challenge_id\":"
        "\"AAECAwQFBgcICQoLDA0ODw\",\"decision\":\"approve\"}";
    assert(agent_control_plane_parse_action_result_response(
        approved, strlen(approved), 200, challenge_id, &decision));
    assert(decision == AGENT_CONTROL_PLANE_ACTION_PROTOCOL_APPROVE);
    char invented[] =
        "{\"version\":1,\"challenge_id\":"
        "\"AAECAwQFBgcICQoLDA0ODw\",\"decision\":\"allow\"}";
    assert(!agent_control_plane_parse_action_result_response(
        invented, strlen(invented), 200, challenge_id, &decision));
    assert(decision == AGENT_CONTROL_PLANE_ACTION_PROTOCOL_PENDING);
}

static void test_device_claim_protocol(void)
{
    const char *claim =
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    char canonical[256];
    assert(agent_control_plane_device_claim_is_canonical(claim));
    assert(!agent_control_plane_device_claim_is_canonical(
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh9"));
    assert(!agent_control_plane_device_claim_is_canonical(
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh"));
    assert(agent_control_plane_device_claim_http_is_terminal(301));
    assert(agent_control_plane_device_claim_http_is_terminal(400));
    assert(agent_control_plane_device_claim_http_is_terminal(404));
    assert(agent_control_plane_device_claim_http_is_terminal(409));
    assert(agent_control_plane_device_claim_http_is_terminal(410));
    assert(!agent_control_plane_device_claim_http_is_terminal(200));
    assert(!agent_control_plane_device_claim_http_is_terminal(408));
    assert(!agent_control_plane_device_claim_http_is_terminal(429));
    assert(!agent_control_plane_device_claim_http_is_terminal(500));
    assert(agent_control_plane_build_device_claim_canonical(
        "device-1", "client-1", "1800000000",
        "AAECAwQFBgcICQoLDA0ODw", claim,
        canonical, sizeof(canonical)));
    assert(strcmp(canonical,
                  "xiaozhi-device-claim-proof-v1\nPOST\n"
                  "/v1/device-claim/device\ndevice-1\nclient-1\n"
                  "1800000000\nAAECAwQFBgcICQoLDA0ODw\n"
                  "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8") == 0);

    char valid[] =
        "{\"version\":1,\"device_id\":\"device-1\","
        "\"status\":\"bound\"}";
    assert(agent_control_plane_parse_device_claim_response(
        valid, strlen(valid), "device-1"));
    char pending[] =
        "{\"version\":1,\"device_id\":\"device-1\","
        "\"status\":\"pending\"}";
    assert(!agent_control_plane_parse_device_claim_response(
        pending, strlen(pending), "device-1"));
    char wrong[] =
        "{\"version\":1,\"device_id\":\"device-2\","
        "\"status\":\"bound\"}";
    assert(!agent_control_plane_parse_device_claim_response(
        wrong, strlen(wrong), "device-1"));
    char extra[] =
        "{\"version\":1,\"device_id\":\"device-1\","
        "\"status\":\"bound\",\"owner\":\"secret\"}";
    assert(!agent_control_plane_parse_device_claim_response(
        extra, strlen(extra), "device-1"));
}

static void test_time_response(void)
{
    char valid[] =
        "{\"version\":1,\"device_id\":\"device-1\","
        "\"client_id\":\"client-1\","
        "\"nonce\":\"AAECAwQFBgcICQoLDA0ODw\","
        "\"unix_seconds\":1800000000}";
    int64_t seconds = 0;
    assert(agent_control_plane_parse_time_response(
        valid, strlen(valid), "device-1", "client-1",
        "AAECAwQFBgcICQoLDA0ODw", &seconds));
    assert(seconds == INT64_C(1800000000));

    char extra[] =
        "{\"version\":1,\"device_id\":\"device-1\","
        "\"client_id\":\"client-1\","
        "\"nonce\":\"AAECAwQFBgcICQoLDA0ODw\","
        "\"unix_seconds\":1800000000,\"extra\":true}";
    assert(!agent_control_plane_parse_time_response(
        extra, strlen(extra), "device-1", "client-1",
        "AAECAwQFBgcICQoLDA0ODw", &seconds));

    char replayed[] =
        "{\"version\":1,\"device_id\":\"device-1\","
        "\"client_id\":\"client-1\",\"nonce\":\"wrong\","
        "\"unix_seconds\":1800000000}";
    assert(!agent_control_plane_parse_time_response(
        replayed, strlen(replayed), "device-1", "client-1",
        "AAECAwQFBgcICQoLDA0ODw", &seconds));
}

static void test_agent_token_response(void)
{
    char valid[] =
        "{\"version\":2,\"device_id\":\"device-1\","
        "\"audience\":\"xiaozhi-agent-proxy\","
        "\"binding_id\":\"AAECAwQFBgcICQoLDA0ODw\","
        "\"binding_revision\":7,"
        "\"bearer_token\":\"v3.payload.signature\","
        "\"expires_in_seconds\":600}";
    char token[128];
    char binding_id[23];
    uint32_t ttl = 0;
    uint64_t binding_revision = 0;
    assert(agent_control_plane_parse_agent_token_response(
        valid, strlen(valid), "device-1", token, sizeof(token), &ttl,
        binding_id, sizeof(binding_id), &binding_revision));
    assert(strcmp(token, "v3.payload.signature") == 0 && ttl == 600 &&
           strcmp(binding_id, "AAECAwQFBgcICQoLDA0ODw") == 0 &&
           binding_revision == 7);

    char wrong_audience[] =
        "{\"version\":2,\"device_id\":\"device-1\","
        "\"audience\":\"xiaozhi-agent-gateway\","
        "\"binding_id\":\"AAECAwQFBgcICQoLDA0ODw\","
        "\"binding_revision\":7,"
        "\"bearer_token\":\"v3.payload.signature\","
        "\"expires_in_seconds\":600}";
    assert(!agent_control_plane_parse_agent_token_response(
        wrong_audience, strlen(wrong_audience), "device-1",
        token, sizeof(token), &ttl, binding_id, sizeof(binding_id),
        &binding_revision));
    assert(token[0] == '\0' && ttl == 0 && binding_id[0] == '\0' &&
           binding_revision == 0);

    char duplicate[] =
        "{\"version\":2,\"version\":2,"
        "\"device_id\":\"device-1\","
        "\"audience\":\"xiaozhi-agent-proxy\","
        "\"binding_id\":\"AAECAwQFBgcICQoLDA0ODw\","
        "\"binding_revision\":7,"
        "\"bearer_token\":\"v3.payload.signature\","
        "\"expires_in_seconds\":600}";
    assert(!agent_control_plane_parse_agent_token_response(
        duplicate, strlen(duplicate), "device-1",
        token, sizeof(token), &ttl, binding_id, sizeof(binding_id),
        &binding_revision));

    char noncanonical_binding[] =
        "{\"version\":2,\"device_id\":\"device-1\","
        "\"audience\":\"xiaozhi-agent-proxy\","
        "\"binding_id\":\"AAECAwQFBgcICQoLDA0ODx\","
        "\"binding_revision\":7,"
        "\"bearer_token\":\"v3.payload.signature\","
        "\"expires_in_seconds\":600}";
    assert(!agent_control_plane_parse_agent_token_response(
        noncanonical_binding, strlen(noncanonical_binding), "device-1",
        token, sizeof(token), &ttl, binding_id, sizeof(binding_id),
        &binding_revision));
}

static void test_base64url(void)
{
    const uint8_t input[16] = {
        0, 1, 2, 3, 4, 5, 6, 7,
        8, 9, 10, 11, 12, 13, 14, 15,
    };
    char output[32];
    assert(agent_control_plane_base64url(
        input, sizeof(input), output, sizeof(output)));
    assert(strcmp(output, "AAECAwQFBgcICQoLDA0ODw") == 0);
    assert(!agent_control_plane_base64url(
        input, sizeof(input), output, 22));
}

int main(void)
{
    test_endpoints_and_canonical();
    test_time_response();
    test_agent_token_response();
    test_device_claim_protocol();
    test_base64url();
    test_action_consent_protocol();
    puts("agent_control_plane_protocol: all host tests passed");
    return 0;
}
