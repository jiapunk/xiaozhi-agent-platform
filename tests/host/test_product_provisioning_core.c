#include "product_provisioning_core.h"
#include "product_provisioning_material_core.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static product_provisioning_core_t new_core(bool claim_required)
{
    product_provisioning_core_t core;
    const product_provisioning_core_config_t config = {
        .window_ms = 60000,
        .commit_delay_ms = 500,
        .success_grace_ms = 5000,
        .authentication_failure_limit = 3,
        .claim_required = claim_required,
    };
    assert(product_provisioning_core_init(&core, &config));
    return core;
}

static void test_material_round_trip(void)
{
    product_provisioning_material_t material = {
        .salt_size = 16,
    };
    for (size_t index = 0; index < material.salt_size; ++index) {
        material.salt[index] = (uint8_t)(index + 1);
    }
    for (size_t index = 0; index < sizeof(material.verifier); ++index) {
        material.verifier[index] = (uint8_t)(index * 17U + 3U);
    }
    memset(material.auth_tag, 0x5c, sizeof(material.auth_tag));
    uint8_t blob[PRODUCT_PROVISIONING_MATERIAL_BLOB_SIZE];
    assert(product_provisioning_material_encode(&material, blob));
    product_provisioning_material_t decoded = {0};
    assert(product_provisioning_material_decode(blob, sizeof(blob),
                                                &decoded));
    assert(decoded.salt_size == material.salt_size);
    assert(memcmp(decoded.salt, material.salt, sizeof(material.salt)) == 0);
    assert(memcmp(decoded.verifier, material.verifier,
                  sizeof(material.verifier)) == 0);
    assert(memcmp(decoded.auth_tag, material.auth_tag,
                  sizeof(material.auth_tag)) == 0);

    blob[20] ^= 1;
    assert(!product_provisioning_material_decode(blob, sizeof(blob),
                                                 &decoded));
    blob[20] ^= 1;
    assert(!product_provisioning_material_decode(blob, sizeof(blob) - 1,
                                                 &decoded));
}

static void test_label_formats(void)
{
    const uint8_t mac[6] = {0x02, 0, 0, 0x12, 0xab, 0xef};
    char service[PRODUCT_PROVISIONING_SERVICE_NAME_SIZE];
    assert(product_provisioning_format_service_name(mac, service));
    assert(strcmp(service, "XA-12ABEF") == 0);

    uint8_t key[32];
    memset(key, 0xa5, sizeof(key));
    char secret[PRODUCT_PROVISIONING_AP_SECRET_SIZE + 1];
    assert(product_provisioning_format_ap_secret(key, secret));
    assert(strlen(secret) == PRODUCT_PROVISIONING_AP_SECRET_SIZE);
    for (size_t index = 0; index < strlen(secret); ++index) {
        assert(strchr("ABCDEFGHJKLMNPQRSTUVWXYZ23456789",
                      secret[index]) != NULL);
    }
}

static void test_candidate_retry_and_success(void)
{
    product_provisioning_core_t core = new_core(false);
    assert(product_provisioning_core_open(&core, 1000) ==
           PRODUCT_PROVISIONING_ACTION_BEGIN_ONBOARDING);
    assert(product_provisioning_core_poll(
               &core, 1100, true, false, false, 0) ==
           PRODUCT_PROVISIONING_ACTION_START_SOFTAP);
    assert(product_provisioning_core_poll(
               &core, 1200, true, true, false, 0) ==
           PRODUCT_PROVISIONING_ACTION_START_TRANSPORT);
    assert(core.state == PRODUCT_PROVISIONING_STATE_SERVING);

    assert(product_provisioning_core_apply(&core, 2000, 0) ==
           PRODUCT_PROVISIONING_ACTION_NONE);
    assert(product_provisioning_core_poll(
               &core, 2499, true, true, false, 0) ==
           PRODUCT_PROVISIONING_ACTION_NONE);
    assert(product_provisioning_core_poll(
               &core, 2500, true, true, false, 0) ==
           PRODUCT_PROVISIONING_ACTION_SUBMIT_CANDIDATE);
    assert(product_provisioning_core_poll(
               &core, 2600, true, true, false, 1) ==
           PRODUCT_PROVISIONING_ACTION_NONE);
    assert(core.state == PRODUCT_PROVISIONING_STATE_SERVING);

    product_provisioning_core_apply(&core, 3000, 1);
    assert(product_provisioning_core_poll(
               &core, 3500, true, true, false, 1) ==
           PRODUCT_PROVISIONING_ACTION_SUBMIT_CANDIDATE);
    assert(product_provisioning_core_poll(
               &core, 4000, true, true, true, 1) ==
           PRODUCT_PROVISIONING_ACTION_NONE);
    assert(core.state == PRODUCT_PROVISIONING_STATE_SUCCESS_GRACE);
    product_provisioning_core_online_observed(&core, 4100);
    assert(product_provisioning_core_poll(
               &core, 4599, true, true, true, 1) ==
           PRODUCT_PROVISIONING_ACTION_NONE);
    const product_provisioning_action_t closed =
        product_provisioning_core_poll(
            &core, 4600, true, true, true, 1);
    assert((closed & PRODUCT_PROVISIONING_ACTION_STOP_TRANSPORT) != 0);
    assert((closed & PRODUCT_PROVISIONING_ACTION_FINISH_ONBOARDING) != 0);
    assert(core.state == PRODUCT_PROVISIONING_STATE_CLOSED);
}

static void test_timeout_and_lockout(void)
{
    product_provisioning_core_t core = new_core(false);
    product_provisioning_core_open(&core, 1000);
    const product_provisioning_action_t timeout =
        product_provisioning_core_poll(
            &core, 61000, false, false, false, 0);
    assert((timeout & PRODUCT_PROVISIONING_ACTION_STOP_TRANSPORT) != 0);
    assert(core.state == PRODUCT_PROVISIONING_STATE_CLOSED);

    core = new_core(false);
    product_provisioning_core_open(&core, 0);
    assert(product_provisioning_core_auth_failure(&core) ==
           PRODUCT_PROVISIONING_ACTION_NONE);
    assert(product_provisioning_core_auth_failure(&core) ==
           PRODUCT_PROVISIONING_ACTION_NONE);
    const product_provisioning_action_t locked =
        product_provisioning_core_auth_failure(&core);
    assert((locked & PRODUCT_PROVISIONING_ACTION_STOP_TRANSPORT) != 0);
    assert(core.state == PRODUCT_PROVISIONING_STATE_LOCKED_OUT);
}

static void test_claim_gates_success_and_retries(void)
{
    product_provisioning_core_t core = new_core(true);
    assert(product_provisioning_core_open(&core, 1000) ==
           PRODUCT_PROVISIONING_ACTION_BEGIN_ONBOARDING);
    assert(product_provisioning_core_poll(
               &core, 1100, true, false, false, 0) ==
           PRODUCT_PROVISIONING_ACTION_START_SOFTAP);
    assert(product_provisioning_core_poll(
               &core, 1200, true, true, false, 0) ==
           PRODUCT_PROVISIONING_ACTION_START_TRANSPORT);
    product_provisioning_core_apply(&core, 2000, 0);
    assert(product_provisioning_core_poll(
               &core, 2500, true, true, false, 0) ==
           PRODUCT_PROVISIONING_ACTION_SUBMIT_CANDIDATE);
    assert(product_provisioning_core_poll(
               &core, 3000, true, true, true, 0) ==
           PRODUCT_PROVISIONING_ACTION_PUBLISH_CLAIM);
    assert(core.state == PRODUCT_PROVISIONING_STATE_SUCCESS_GRACE);
    assert(!core.claim_published);

    product_provisioning_core_claim_result(&core, 3100, false);
    assert(product_provisioning_core_poll(
               &core, 5099, true, true, true, 0) ==
           PRODUCT_PROVISIONING_ACTION_NONE);
    assert(product_provisioning_core_poll(
               &core, 5100, true, true, true, 0) ==
           PRODUCT_PROVISIONING_ACTION_PUBLISH_CLAIM);
    product_provisioning_core_claim_result(&core, 5200, true);
    assert(core.claim_published);
    assert(product_provisioning_core_poll(
               &core, 5699, true, true, true, 0) ==
           PRODUCT_PROVISIONING_ACTION_NONE);
    const product_provisioning_action_t closed =
        product_provisioning_core_poll(
            &core, 5700, true, true, true, 0);
    assert((closed & PRODUCT_PROVISIONING_ACTION_STOP_TRANSPORT) != 0);
    assert((closed & PRODUCT_PROVISIONING_ACTION_FINISH_ONBOARDING) != 0);
}

static void test_unbound_claim_times_out(void)
{
    product_provisioning_core_t core = new_core(true);
    product_provisioning_core_open(&core, 1000);
    product_provisioning_core_poll(&core, 1100, true, false, false, 0);
    product_provisioning_core_poll(&core, 1200, true, true, false, 0);
    product_provisioning_core_apply(&core, 2000, 0);
    product_provisioning_core_poll(&core, 2500, true, true, false, 0);
    product_provisioning_core_poll(&core, 3000, true, true, true, 0);
    const product_provisioning_action_t timed_out =
        product_provisioning_core_poll(
            &core, 61000, true, true, true, 0);
    assert((timed_out & PRODUCT_PROVISIONING_ACTION_STOP_TRANSPORT) != 0);
    assert(!core.claim_published);
}

static void test_boot_claim_recovery_is_bounded_and_terminal(void)
{
    product_claim_recovery_core_t recovery;
    product_claim_recovery_core_init(&recovery);
    assert(!product_claim_recovery_core_should_attempt(
        &recovery, 1000, true, false, true));
    assert(!product_claim_recovery_core_should_attempt(
        &recovery, 1000, false, true, true));
    assert(product_claim_recovery_core_should_attempt(
        &recovery, 1000, true, true, true));

    product_claim_recovery_core_record(
        &recovery, 1000, PRODUCT_CLAIM_RECOVERY_RETRY);
    assert(recovery.retry_at_ms == 3000);
    assert(!product_claim_recovery_core_should_attempt(
        &recovery, 2999, true, true, true));
    assert(product_claim_recovery_core_should_attempt(
        &recovery, 3000, true, true, true));

    product_claim_recovery_core_record(
        &recovery, 3000, PRODUCT_CLAIM_RECOVERY_RECOVERED);
    assert(recovery.retry_at_ms == 0);
    recovery.retry_at_ms = 5000;
    assert(!product_claim_recovery_core_should_attempt(
        &recovery, 4000, true, true, false));
    assert(recovery.retry_at_ms == 0);

    product_claim_recovery_core_record(
        &recovery, UINT64_MAX, PRODUCT_CLAIM_RECOVERY_RETRY);
    assert(recovery.retry_at_ms == UINT64_MAX);
    product_claim_recovery_core_record(
        &recovery, UINT64_MAX, PRODUCT_CLAIM_RECOVERY_REJECTED);
    assert(recovery.retry_at_ms == 0);
}

int main(void)
{
    test_material_round_trip();
    test_label_formats();
    test_candidate_retry_and_success();
    test_timeout_and_lockout();
    test_claim_gates_success_and_retries();
    test_unbound_claim_times_out();
    test_boot_claim_recovery_is_bounded_and_terminal();
    puts("product_provisioning_core: all tests passed");
    return 0;
}
