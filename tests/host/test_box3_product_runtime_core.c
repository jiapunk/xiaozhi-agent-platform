#include "box3_product_runtime_core.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_identity_formatting(void)
{
    const uint8_t mac[6] = {0x02, 0xab, 0xcd, 0xef, 0x12, 0x34};
    char device_id[BOX3_PRODUCT_RUNTIME_DEVICE_ID_BYTES];
    assert(box3_product_runtime_format_device_id(mac, device_id));
    assert(strcmp(device_id, "xz-02abcdef1234") == 0);

    const uint8_t zero_mac[6] = {0};
    const uint8_t multicast_mac[6] = {0x03, 0, 0, 0, 0, 1};
    assert(!box3_product_runtime_format_device_id(zero_mac, device_id));
    assert(!box3_product_runtime_format_device_id(multicast_mac, device_id));
    assert(!box3_product_runtime_format_device_id(NULL, device_id));

    const uint8_t random_bytes[8] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    };
    char client_id[BOX3_PRODUCT_RUNTIME_CLIENT_ID_BYTES];
    assert(box3_product_runtime_format_client_id(random_bytes, client_id));
    assert(strcmp(client_id, "boot-0123456789abcdef") == 0);
    const uint8_t zero_random[8] = {0};
    assert(!box3_product_runtime_format_client_id(zero_random, client_id));
}

static void test_endpoint_construction(void)
{
    char endpoint[BOX3_PRODUCT_RUNTIME_ENDPOINT_BYTES];
    assert(box3_product_runtime_build_endpoint(
        "https://control.example:8443", "/v1/session", endpoint,
        sizeof(endpoint)));
    assert(strcmp(endpoint,
                  "https://control.example:8443/v1/session") == 0);
    assert(box3_product_runtime_build_endpoint(
        "https://[2001:db8::1]", "/v1/time", endpoint,
        sizeof(endpoint)));
    assert(!box3_product_runtime_build_endpoint(
        "http://control.example", "/v1/time", endpoint,
        sizeof(endpoint)));
    assert(!box3_product_runtime_build_endpoint(
        "https://user@control.example", "/v1/time", endpoint,
        sizeof(endpoint)));
    assert(!box3_product_runtime_build_endpoint(
        "https://control.example/path", "/v1/time", endpoint,
        sizeof(endpoint)));
    assert(!box3_product_runtime_build_endpoint(
        "https://control.example", "v1/time", endpoint,
        sizeof(endpoint)));
    assert(!box3_product_runtime_build_endpoint(
        "https://control.example", "/v1/time?x=1", endpoint,
        sizeof(endpoint)));
    assert(!box3_product_runtime_build_endpoint(
        "https://control.example", "/v1/session", endpoint, 8));
}

static void test_full_lifecycle_and_retry(void)
{
    box3_product_runtime_core_t core;
    box3_product_runtime_core_init(&core);
    assert(core.state == BOX3_PRODUCT_RUNTIME_CORE_STARTING);
    assert(!box3_product_runtime_core_acquire(
        &core, BOX3_PRODUCT_RUNTIME_RESOURCE_CONTROL));
    const box3_product_runtime_resource_t start_order[] = {
        BOX3_PRODUCT_RUNTIME_RESOURCE_IDENTITY,
        BOX3_PRODUCT_RUNTIME_RESOURCE_CONTROL,
        BOX3_PRODUCT_RUNTIME_RESOURCE_CREDENTIALS,
        BOX3_PRODUCT_RUNTIME_RESOURCE_SUPERVISOR,
        BOX3_PRODUCT_RUNTIME_RESOURCE_TIME_BOOTSTRAP,
        BOX3_PRODUCT_RUNTIME_RESOURCE_WIFI,
        BOX3_PRODUCT_RUNTIME_RESOURCE_PROVISIONING,
        BOX3_PRODUCT_RUNTIME_RESOURCE_LOCAL_ACTION,
    };
    for (size_t index = 0;
         index < sizeof(start_order) / sizeof(start_order[0]); ++index) {
        assert(box3_product_runtime_core_acquire(&core,
                                                 start_order[index]));
        assert(!box3_product_runtime_core_acquire(&core,
                                                  start_order[index]));
    }
    assert(box3_product_runtime_core_commit(&core));
    assert(core.state == BOX3_PRODUCT_RUNTIME_CORE_RUNNING);
    assert(!box3_product_runtime_core_commit(&core));

    box3_product_runtime_core_begin_stop(&core);
    assert(core.state == BOX3_PRODUCT_RUNTIME_CORE_STOPPING);
    box3_product_runtime_core_cleanup_failed(&core);
    assert(core.cleanup_retries == 1);
    const box3_product_runtime_resource_t stop_order[] = {
        BOX3_PRODUCT_RUNTIME_RESOURCE_LOCAL_ACTION,
        BOX3_PRODUCT_RUNTIME_RESOURCE_PROVISIONING,
        BOX3_PRODUCT_RUNTIME_RESOURCE_WIFI,
        BOX3_PRODUCT_RUNTIME_RESOURCE_TIME_BOOTSTRAP,
        BOX3_PRODUCT_RUNTIME_RESOURCE_SUPERVISOR,
        BOX3_PRODUCT_RUNTIME_RESOURCE_CREDENTIALS,
        BOX3_PRODUCT_RUNTIME_RESOURCE_CONTROL,
        BOX3_PRODUCT_RUNTIME_RESOURCE_IDENTITY,
    };
    for (size_t index = 0;
         index < sizeof(stop_order) / sizeof(stop_order[0]); ++index) {
        assert(box3_product_runtime_core_next_cleanup(&core) ==
               stop_order[index]);
        if (index + 1 < sizeof(stop_order) / sizeof(stop_order[0])) {
            assert(!box3_product_runtime_core_release(
                &core, stop_order[index + 1]));
        }
        assert(box3_product_runtime_core_release(&core,
                                                 stop_order[index]));
    }
    assert(core.state == BOX3_PRODUCT_RUNTIME_CORE_STOPPED);
    assert(box3_product_runtime_core_next_cleanup(&core) ==
           BOX3_PRODUCT_RUNTIME_RESOURCE_NONE);
}

static void test_partial_start_unwinds_exact_prefix(void)
{
    box3_product_runtime_core_t core;
    box3_product_runtime_core_init(&core);
    assert(box3_product_runtime_core_acquire(
        &core, BOX3_PRODUCT_RUNTIME_RESOURCE_IDENTITY));
    assert(box3_product_runtime_core_acquire(
        &core, BOX3_PRODUCT_RUNTIME_RESOURCE_CONTROL));
    assert(!box3_product_runtime_core_commit(&core));
    box3_product_runtime_core_begin_stop(&core);
    assert(box3_product_runtime_core_next_cleanup(&core) ==
           BOX3_PRODUCT_RUNTIME_RESOURCE_CONTROL);
    assert(box3_product_runtime_core_release(
        &core, BOX3_PRODUCT_RUNTIME_RESOURCE_CONTROL));
    assert(box3_product_runtime_core_next_cleanup(&core) ==
           BOX3_PRODUCT_RUNTIME_RESOURCE_IDENTITY);
    assert(box3_product_runtime_core_release(
        &core, BOX3_PRODUCT_RUNTIME_RESOURCE_IDENTITY));
    assert(core.state == BOX3_PRODUCT_RUNTIME_CORE_STOPPED);

    box3_product_runtime_core_init(&core);
    box3_product_runtime_core_begin_stop(&core);
    assert(core.state == BOX3_PRODUCT_RUNTIME_CORE_STOPPED);
}

typedef struct {
    uint64_t now_ms;
    bool available;
    bool register_ok;
    bool poll_ok;
    bool cancel_on_wait;
    uint32_t poll_count;
    uint32_t decide_on_poll;
    box3_action_consent_decision_t final_decision;
    uint32_t registered_request_id;
    bool registered_indicator_on;
    uint32_t registered_lifetime;
    uint32_t largest_request_timeout;
    char registered_session[65];
} consent_fake_t;

static bool consent_now(void *ctx, uint64_t *value)
{
    consent_fake_t *fake = ctx;
    if (!fake || !value) {
        return false;
    }
    *value = fake->now_ms;
    return true;
}

static bool consent_available(void *ctx)
{
    consent_fake_t *fake = ctx;
    return fake && fake->available;
}

static void record_request_timeout(consent_fake_t *fake, uint32_t timeout)
{
    if (fake && timeout > fake->largest_request_timeout) {
        fake->largest_request_timeout = timeout;
    }
}

static bool consent_register(void *ctx, const char *session_id,
                             uint32_t request_id, bool indicator_on,
                             uint32_t lifetime_seconds,
                             uint32_t request_timeout_ms,
                             void *consent_state)
{
    consent_fake_t *fake = ctx;
    if (!fake || !consent_state || !session_id) {
        return false;
    }
    strcpy(fake->registered_session, session_id);
    fake->registered_request_id = request_id;
    fake->registered_indicator_on = indicator_on;
    fake->registered_lifetime = lifetime_seconds;
    record_request_timeout(fake, request_timeout_ms);
    *(uint32_t *)consent_state = 0x434f4e53U;
    return fake->register_ok;
}

static bool consent_poll(void *ctx, void *consent_state,
                         uint32_t request_timeout_ms,
                         box3_action_consent_decision_t *decision)
{
    consent_fake_t *fake = ctx;
    if (!fake || !consent_state || !decision ||
        *(uint32_t *)consent_state != 0x434f4e53U) {
        return false;
    }
    record_request_timeout(fake, request_timeout_ms);
    ++fake->poll_count;
    if (!fake->poll_ok) {
        return false;
    }
    *decision = fake->decide_on_poll != 0 &&
                        fake->poll_count >= fake->decide_on_poll
                    ? fake->final_decision
                    : BOX3_ACTION_CONSENT_PENDING;
    return true;
}

static void consent_wait(void *ctx, uint32_t milliseconds)
{
    consent_fake_t *fake = ctx;
    assert(fake != NULL);
    fake->now_ms += milliseconds;
    if (fake->cancel_on_wait) {
        fake->available = false;
    }
}

static const box3_action_consent_core_config_t consent_config = {
    .timeout_ms = 20000,
    .poll_interval_ms = 500,
    .network_timeout_ms = 10000,
    .maximum_request_timeout_ms = 2000,
};

static const box3_action_consent_core_ops_t consent_ops = {
    .monotonic_ms = consent_now,
    .available = consent_available,
    .register_action = consent_register,
    .poll_action = consent_poll,
    .wait_ms = consent_wait,
};

static consent_fake_t valid_consent_fake(void)
{
    return (consent_fake_t){
        .now_ms = 1000,
        .available = true,
        .register_ok = true,
        .poll_ok = true,
        .decide_on_poll = 2,
        .final_decision = BOX3_ACTION_CONSENT_APPROVED,
    };
}

static void test_action_consent_exact_approval_and_denial(void)
{
    uint32_t state = 0;
    bool registered = false;
    consent_fake_t fake = valid_consent_fake();
    assert(box3_action_consent_core_run(
               &consent_config, &consent_ops, &fake, "voice:device-1", 42,
               true, &state, &registered) ==
           BOX3_ACTION_CONSENT_OUTCOME_APPROVED);
    assert(registered);
    assert(strcmp(fake.registered_session, "voice:device-1") == 0);
    assert(fake.registered_request_id == 42);
    assert(fake.registered_indicator_on);
    assert(fake.registered_lifetime == 21);
    assert(fake.poll_count == 2);
    assert(fake.largest_request_timeout == 2000);

    fake = valid_consent_fake();
    fake.decide_on_poll = 1;
    fake.final_decision = BOX3_ACTION_CONSENT_DENIED;
    state = 0;
    registered = false;
    assert(box3_action_consent_core_run(
               &consent_config, &consent_ops, &fake, "voice:device-1", 43,
               false, &state, &registered) ==
           BOX3_ACTION_CONSENT_OUTCOME_DENIED);
    assert(registered && !fake.registered_indicator_on);
}

static void test_action_consent_timeout_cancel_and_failure_fail_closed(void)
{
    uint32_t state = 0;
    bool registered = false;
    consent_fake_t fake = valid_consent_fake();
    fake.decide_on_poll = 0;
    assert(box3_action_consent_core_run(
               &consent_config, &consent_ops, &fake, "voice:device-1", 44,
               true, &state, &registered) ==
           BOX3_ACTION_CONSENT_OUTCOME_EXPIRED);
    assert(registered && fake.now_ms <= 21000);
    assert(fake.largest_request_timeout <= 2000);

    fake = valid_consent_fake();
    fake.cancel_on_wait = true;
    state = 0;
    registered = false;
    assert(box3_action_consent_core_run(
               &consent_config, &consent_ops, &fake, "voice:device-1", 45,
               true, &state, &registered) ==
           BOX3_ACTION_CONSENT_OUTCOME_CANCELED);
    assert(registered && fake.poll_count == 0);

    fake = valid_consent_fake();
    fake.register_ok = false;
    state = 0;
    registered = false;
    assert(box3_action_consent_core_run(
               &consent_config, &consent_ops, &fake, "voice:device-1", 46,
               true, &state, &registered) ==
           BOX3_ACTION_CONSENT_OUTCOME_FAILED);
    assert(!registered);

    fake = valid_consent_fake();
    fake.poll_ok = false;
    state = 0;
    registered = false;
    assert(box3_action_consent_core_run(
               &consent_config, &consent_ops, &fake, "voice:device-1", 47,
               true, &state, &registered) ==
           BOX3_ACTION_CONSENT_OUTCOME_FAILED);
    assert(registered);
}

static void test_action_consent_rejects_invalid_contract(void)
{
    uint32_t state = 0;
    bool registered = true;
    consent_fake_t fake = valid_consent_fake();
    box3_action_consent_core_config_t invalid = consent_config;
    invalid.timeout_ms = 30000;
    assert(box3_action_consent_core_run(
               &invalid, &consent_ops, &fake, "voice:device-1", 1,
               true, &state, &registered) ==
           BOX3_ACTION_CONSENT_OUTCOME_FAILED);
    assert(!registered);
    assert(box3_action_consent_core_run(
               &consent_config, &consent_ops, &fake, "bad/session", 1,
               true, &state, &registered) ==
           BOX3_ACTION_CONSENT_OUTCOME_FAILED);
}

int main(void)
{
    test_identity_formatting();
    test_endpoint_construction();
    test_full_lifecycle_and_retry();
    test_partial_start_unwinds_exact_prefix();
    test_action_consent_exact_approval_and_denial();
    test_action_consent_timeout_cancel_and_failure_fail_closed();
    test_action_consent_rejects_invalid_contract();
    puts("box3_product_runtime_core: all host tests passed");
    return 0;
}
