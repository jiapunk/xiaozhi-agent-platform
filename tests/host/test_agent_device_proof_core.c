#include "agent_device_proof_core.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static bool validate(const char *message,
                     const char *device,
                     int64_t *timestamp)
{
    return agent_device_proof_validate(
        (const uint8_t *)message, strlen(message), device, timestamp);
}

static bool validate_agent(const char *message,
                           const char *device,
                           int64_t *timestamp)
{
    return agent_device_proof_validate_scoped(
        (const uint8_t *)message, strlen(message), device,
        AGENT_DEVICE_PROOF_SCOPE_AGENT_TOKEN, timestamp);
}

static bool validate_ota(const char *message,
                         const char *device,
                         int64_t *timestamp)
{
    return agent_device_proof_validate_scoped(
        (const uint8_t *)message, strlen(message), device,
        AGENT_DEVICE_PROOF_SCOPE_OTA_OFFER, timestamp);
}

static bool validate_claim(const char *message,
                           const char *device,
                           int64_t *timestamp)
{
    return agent_device_proof_validate_scoped(
        (const uint8_t *)message, strlen(message), device,
        AGENT_DEVICE_PROOF_SCOPE_DEVICE_CLAIM, timestamp);
}

static bool validate_action_challenge(const char *message,
                                      const char *device,
                                      int64_t *timestamp)
{
    return agent_device_proof_validate_scoped(
        (const uint8_t *)message, strlen(message), device,
        AGENT_DEVICE_PROOF_SCOPE_ACTION_CONSENT_CHALLENGE, timestamp);
}

static bool validate_action_result(const char *message,
                                   const char *device,
                                   int64_t *timestamp)
{
    return agent_device_proof_validate_scoped(
        (const uint8_t *)message, strlen(message), device,
        AGENT_DEVICE_PROOF_SCOPE_ACTION_CONSENT_RESULT, timestamp);
}

static void test_valid_proof(void)
{
    const char *message =
        "xiaozhi-session-proof-v1\nPOST\n/v1/session\n"
        "device-1\nclient:boot-1\n1800000000\n"
        "AAECAwQFBgcICQoLDA0ODw";
    int64_t timestamp = 0;
    assert(validate(message, "device-1", &timestamp));
    assert(timestamp == 1800000000);
    assert(agent_device_proof_safe_identifier("device-1"));
}

static void test_identity_and_structure_are_bound(void)
{
    int64_t timestamp = 0;
    assert(!validate(
        "xiaozhi-session-proof-v1\nPOST\n/v1/session\n"
        "device-1\nclient-1\n1800000000\nAAECAwQFBgcICQoLDA0ODw",
        "device-2", &timestamp));
    assert(!validate(
        "xiaozhi-session-proof-v1\nGET\n/v1/session\n"
        "device-1\nclient-1\n1800000000\nAAECAwQFBgcICQoLDA0ODw",
        "device-1", &timestamp));
    assert(!validate(
        "xiaozhi-session-proof-v1\nPOST\n/v1/session\n"
        "device-1\nclient/1\n1800000000\nAAECAwQFBgcICQoLDA0ODw",
        "device-1", &timestamp));
}

static void test_timestamp_and_nonce_are_canonical(void)
{
    int64_t timestamp = 0;
    assert(!validate(
        "xiaozhi-session-proof-v1\nPOST\n/v1/session\n"
        "device-1\nclient-1\n01800000000\nAAECAwQFBgcICQoLDA0ODw",
        "device-1", &timestamp));
    assert(!validate(
        "xiaozhi-session-proof-v1\nPOST\n/v1/session\n"
        "device-1\nclient-1\n1800000000\nAAECAwQFBgcICQoLDA0ODx",
        "device-1", &timestamp));
    assert(!validate(
        "xiaozhi-session-proof-v1\nPOST\n/v1/session\n"
        "device-1\nclient-1\n1800000000\nAAECAwQFBgcICQoLDA0ODw\n",
        "device-1", &timestamp));
}

static void test_proof_time_window(void)
{
    assert(agent_device_proof_time_is_current(
        1800000000, 1800000002, 2));
    assert(agent_device_proof_time_is_current(
        1800000002, 1800000000, 2));
    assert(!agent_device_proof_time_is_current(
        1800000000, 1800000003, 2));
    assert(!agent_device_proof_time_is_current(
        1609459199, 1800000000, 2));
}

static void test_proof_scopes_are_isolated(void)
{
    const char *session =
        "xiaozhi-session-proof-v1\nPOST\n/v1/session\n"
        "device-1\nclient-1\n1800000000\n"
        "AAECAwQFBgcICQoLDA0ODw";
    const char *agent =
        "xiaozhi-agent-token-proof-v1\nPOST\n/v1/agent-token\n"
        "device-1\nclient-1\n1800000000\n"
        "AAECAwQFBgcICQoLDA0ODw";
    const char *ota =
        "xiaozhi-ota-offer-proof-v1\nPOST\n/v1/ota/offer\n"
        "device-1\nclient-1\n1800000000\n"
        "AAECAwQFBgcICQoLDA0ODw\n"
        "esp32s3-box3\ndevelopment\n14\n0.14.0-dev";
    const char *claim =
        "xiaozhi-device-claim-proof-v1\nPOST\n/v1/device-claim/device\n"
        "device-1\nclient-1\n1800000000\n"
        "AAECAwQFBgcICQoLDA0ODw\n"
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    int64_t timestamp = 0;
    assert(validate_agent(agent, "device-1", &timestamp));
    assert(timestamp == 1800000000);
    assert(!validate_agent(session, "device-1", &timestamp));
    assert(!validate(agent, "device-1", &timestamp));
    assert(validate_ota(ota, "device-1", &timestamp));
    assert(!validate_ota(agent, "device-1", &timestamp));
    assert(!validate_agent(ota, "device-1", &timestamp));
    assert(validate_claim(claim, "device-1", &timestamp));
    assert(!validate_claim(session, "device-1", &timestamp));
    assert(!validate_claim(ota, "device-1", &timestamp));
    assert(!validate(claim, "device-1", &timestamp));
    assert(!agent_device_proof_validate_scoped(
        (const uint8_t *)agent, strlen(agent), "device-1",
        (agent_device_proof_scope_t)99, &timestamp));
}

static void test_device_claim_proof_is_canonical_and_bound(void)
{
    int64_t timestamp = 0;
    const char *prefix =
        "xiaozhi-device-claim-proof-v1\nPOST\n/v1/device-claim/device\n"
        "device-1\nclient-1\n1800000000\n"
        "AAECAwQFBgcICQoLDA0ODw\n";
    char message[512];
    assert(snprintf(message, sizeof(message), "%s%s", prefix,
                    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8") > 0);
    assert(validate_claim(message, "device-1", &timestamp));
    assert(timestamp == 1800000000);

    /* A 32-byte raw Base64URL value is exactly 43 characters. */
    assert(snprintf(message, sizeof(message), "%s%s", prefix,
                    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh") > 0);
    assert(!validate_claim(message, "device-1", &timestamp));
    assert(snprintf(message, sizeof(message), "%s%s", prefix,
                    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh9") > 0);
    assert(!validate_claim(message, "device-1", &timestamp));
    assert(snprintf(message, sizeof(message), "%s%s", prefix,
                    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\n") > 0);
    assert(!validate_claim(message, "device-1", &timestamp));
    assert(snprintf(message, sizeof(message), "%s%s", prefix,
                    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh+") > 0);
    assert(!validate_claim(message, "device-1", &timestamp));
}

static void test_action_consent_proofs_bind_body_digest_and_scope(void)
{
    const char *digest =
        "0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef";
    char challenge[512];
    char result[512];
    int64_t timestamp = 0;
    assert(snprintf(
               challenge, sizeof(challenge),
               "xiaozhi-action-consent-challenge-proof-v1\nPOST\n"
               "/v1/action-consents/device/challenge\n"
               "device-1\nclient-1\n1800000000\n"
               "AAECAwQFBgcICQoLDA0ODw\n%s",
               digest) > 0);
    assert(snprintf(
               result, sizeof(result),
               "xiaozhi-action-consent-result-proof-v1\nPOST\n"
               "/v1/action-consents/device/result\n"
               "device-1\nclient-1\n1800000000\n"
               "AAECAwQFBgcICQoLDA0ODw\n%s",
               digest) > 0);
    assert(validate_action_challenge(challenge, "device-1", &timestamp));
    assert(timestamp == 1800000000);
    assert(validate_action_result(result, "device-1", &timestamp));
    assert(!validate_action_challenge(result, "device-1", &timestamp));
    assert(!validate_action_result(challenge, "device-1", &timestamp));

    challenge[strlen(challenge) - 1] = 'G';
    assert(!validate_action_challenge(challenge, "device-1", &timestamp));
    challenge[strlen(challenge) - 1] = 'F';
    assert(!validate_action_challenge(challenge, "device-1", &timestamp));
}

static void test_ota_proof_binds_compiled_release_state(void)
{
    int64_t timestamp = 0;
    const char *prefix =
        "xiaozhi-ota-offer-proof-v1\nPOST\n/v1/ota/offer\n"
        "device-1\nclient-1\n1800000000\n"
        "AAECAwQFBgcICQoLDA0ODw\n";
    char message[512];
    assert(snprintf(message, sizeof(message), "%s%s", prefix,
                    "esp32s3-box3\ndevelopment\n14\n0.14.0-dev") > 0);
    assert(validate_ota(message, "device-1", &timestamp));
    assert(snprintf(message, sizeof(message), "%s%s", prefix,
                    "esp32s3-box3\ndevelopment\n014\n0.14.0-dev") > 0);
    assert(!validate_ota(message, "device-1", &timestamp));
    assert(snprintf(message, sizeof(message), "%s%s", prefix,
                    "esp32s3/box3\ndevelopment\n14\n0.14.0-dev") > 0);
    assert(!validate_ota(message, "device-1", &timestamp));
    assert(snprintf(message, sizeof(message), "%s%s", prefix,
                    "esp32s3-box3\ndevelopment\n14\n0.14.0 dev") > 0);
    assert(!validate_ota(message, "device-1", &timestamp));
}

int main(void)
{
    test_valid_proof();
    test_identity_and_structure_are_bound();
    test_timestamp_and_nonce_are_canonical();
    test_proof_time_window();
    test_proof_scopes_are_isolated();
    test_ota_proof_binds_compiled_release_state();
    test_device_claim_proof_is_canonical_and_bound();
    test_action_consent_proofs_bind_body_digest_and_scope();
    puts("agent_device_proof_core: all host tests passed");
    return 0;
}
