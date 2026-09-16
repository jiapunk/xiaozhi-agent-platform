#include "product_wifi_core.h"
#include "product_wifi_credential_set_core.h"
#include "product_wifi_credentials_core.h"
#include "product_wifi_state_core.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static product_wifi_core_t new_core(uint32_t auth_limit)
{
    product_wifi_core_t core;
    const product_wifi_core_config_t config = {
        .minimum_backoff_ms = 2000,
        .maximum_backoff_ms = 60000,
        .authentication_failure_limit = auth_limit,
    };
    assert(product_wifi_core_init(&core, &config));
    return core;
}

static void test_config_validation(void)
{
    product_wifi_core_t core;
    product_wifi_core_config_t config = {
        .minimum_backoff_ms = 0,
        .maximum_backoff_ms = 60000,
        .authentication_failure_limit = 3,
    };
    assert(!product_wifi_core_init(&core, &config));
    config.minimum_backoff_ms = 2000;
    config.maximum_backoff_ms = 1000;
    assert(!product_wifi_core_init(&core, &config));
    config.maximum_backoff_ms = 60000;
    config.authentication_failure_limit = 0;
    assert(!product_wifi_core_init(&core, &config));
}

static void test_unprovisioned_requires_physical_onboarding(void)
{
    product_wifi_core_t core = new_core(3);
    product_wifi_action_t action = product_wifi_core_start(&core, false);
    assert(core.state == PRODUCT_WIFI_STATE_UNPROVISIONED);
    assert(action == PRODUCT_WIFI_ACTION_REQUIRE_ONBOARDING);
    assert(product_wifi_core_candidate_submitted(&core) ==
           PRODUCT_WIFI_ACTION_NONE);

    action = product_wifi_core_begin_onboarding(&core);
    assert(core.state == PRODUCT_WIFI_STATE_ONBOARDING);
    assert(action == PRODUCT_WIFI_ACTION_REQUIRE_ONBOARDING);
    action = product_wifi_core_candidate_submitted(&core);
    assert(core.state == PRODUCT_WIFI_STATE_CONNECTING);
    assert(!core.has_credentials);
    assert(core.candidate_credentials);
    assert(core.station_started);
    assert(action == PRODUCT_WIFI_ACTION_START_CANDIDATE);
    assert(product_wifi_core_got_ip(&core) ==
           PRODUCT_WIFI_ACTION_NETWORK_UP);
    assert(core.state == PRODUCT_WIFI_STATE_ONLINE);
    assert(core.network_available);
    assert(core.has_credentials);
    assert(!core.candidate_credentials);
    assert(product_wifi_core_finish_onboarding(&core) ==
           PRODUCT_WIFI_ACTION_NONE);
    assert(!core.onboarding_active);
}

static void test_transient_disconnect_uses_bounded_backoff(void)
{
    product_wifi_core_t core = new_core(3);
    assert(product_wifi_core_start(&core, true) ==
           PRODUCT_WIFI_ACTION_START_STATION);
    assert(product_wifi_core_station_started(&core) ==
           PRODUCT_WIFI_ACTION_CONNECT);
    assert(product_wifi_core_got_ip(&core) ==
           PRODUCT_WIFI_ACTION_NETWORK_UP);

    product_wifi_action_t action = product_wifi_core_disconnected(
        &core, false, 10000, 0);
    assert(action == PRODUCT_WIFI_ACTION_NETWORK_DOWN);
    assert(core.state == PRODUCT_WIFI_STATE_BACKOFF);
    assert(core.retry_at_ms == 11000);
    assert(product_wifi_core_wait_ms(&core, 10000, 5000) == 1000);
    assert(product_wifi_core_poll(&core, 10999) ==
           PRODUCT_WIFI_ACTION_NONE);
    assert(product_wifi_core_poll(&core, 11000) ==
           PRODUCT_WIFI_ACTION_CONNECT);
    assert(core.state == PRODUCT_WIFI_STATE_CONNECTING);

    action = product_wifi_core_disconnected(&core, false, 12000, 3000);
    assert(action == PRODUCT_WIFI_ACTION_NONE);
    assert(core.state == PRODUCT_WIFI_STATE_BACKOFF);
    assert(core.retry_at_ms >= 14000 && core.retry_at_ms <= 16000);
}

static void test_rejected_credentials_stop_automatic_retry(void)
{
    product_wifi_core_t core = new_core(3);
    assert(product_wifi_core_start(&core, true) ==
           PRODUCT_WIFI_ACTION_START_STATION);
    assert(product_wifi_core_station_started(&core) ==
           PRODUCT_WIFI_ACTION_CONNECT);

    for (unsigned attempt = 0; attempt < 2; ++attempt) {
        assert(product_wifi_core_disconnected(
                   &core, true, 1000 + attempt * 10000, 0) ==
               PRODUCT_WIFI_ACTION_NONE);
        assert(core.state == PRODUCT_WIFI_STATE_BACKOFF);
        assert(product_wifi_core_poll(&core, core.retry_at_ms) ==
               PRODUCT_WIFI_ACTION_CONNECT);
    }
    const product_wifi_action_t action = product_wifi_core_disconnected(
        &core, true, 30000, 0);
    assert(core.state == PRODUCT_WIFI_STATE_CREDENTIAL_REJECTED);
    assert(!core.station_started);
    assert((action & PRODUCT_WIFI_ACTION_STOP_STATION) != 0);
    assert((action & PRODUCT_WIFI_ACTION_REQUIRE_ONBOARDING) != 0);
    assert(product_wifi_core_poll(&core, UINT64_MAX) ==
           PRODUCT_WIFI_ACTION_NONE);
}

static void test_prolonged_loss_can_restart_station_without_erasing_credentials(void)
{
    product_wifi_core_t core = new_core(3);
    product_wifi_core_start(&core, true);
    product_wifi_core_station_started(&core);
    product_wifi_core_got_ip(&core);
    product_wifi_core_disconnected(&core, false, 1000, 0);

    const product_wifi_action_t action =
        product_wifi_core_recover_station(&core);
    assert(core.state == PRODUCT_WIFI_STATE_CONNECTING);
    assert(core.has_credentials);
    assert(core.station_started);
    assert(core.retry_at_ms == 0);
    assert((action & PRODUCT_WIFI_ACTION_RESTART_STATION) != 0);
    assert(product_wifi_core_station_started(&core) ==
           PRODUCT_WIFI_ACTION_CONNECT);

    product_wifi_core_got_ip(&core);
    assert(product_wifi_core_recover_station(&core) ==
           PRODUCT_WIFI_ACTION_NONE);
    product_wifi_core_begin_onboarding(&core);
    assert(product_wifi_core_recover_station(&core) ==
           PRODUCT_WIFI_ACTION_NONE);
}

static void test_explicit_onboarding_gates_network(void)
{
    product_wifi_core_t core = new_core(3);
    product_wifi_core_start(&core, true);
    product_wifi_core_station_started(&core);
    product_wifi_core_got_ip(&core);
    const product_wifi_action_t action =
        product_wifi_core_begin_onboarding(&core);
    assert(core.state == PRODUCT_WIFI_STATE_ONBOARDING);
    assert(!core.network_available);
    assert(!core.station_started);
    assert((action & PRODUCT_WIFI_ACTION_NETWORK_DOWN) != 0);
    assert((action & PRODUCT_WIFI_ACTION_STOP_STATION) != 0);
    assert((action & PRODUCT_WIFI_ACTION_REQUIRE_ONBOARDING) != 0);

    assert(product_wifi_core_credentials_cleared(&core) ==
           PRODUCT_WIFI_ACTION_REQUIRE_ONBOARDING);
    assert(core.state == PRODUCT_WIFI_STATE_ONBOARDING);
    assert(!core.has_credentials);

    assert(product_wifi_core_finish_onboarding(&core) ==
           PRODUCT_WIFI_ACTION_REQUIRE_ONBOARDING);
    assert(core.state == PRODUCT_WIFI_STATE_UNPROVISIONED);
}

static void test_candidate_failure_preserves_active_credentials(void)
{
    product_wifi_core_t core = new_core(3);
    product_wifi_core_start(&core, true);
    product_wifi_core_station_started(&core);
    product_wifi_core_got_ip(&core);
    product_wifi_core_begin_onboarding(&core);
    assert(core.has_credentials);
    assert(core.onboarding_active);
    assert(product_wifi_core_candidate_submitted(&core) ==
           PRODUCT_WIFI_ACTION_START_CANDIDATE);

    const product_wifi_action_t rejected =
        product_wifi_core_disconnected(&core, true, 1000, 0);
    assert((rejected & PRODUCT_WIFI_ACTION_REJECT_CANDIDATE) != 0);
    assert(core.state == PRODUCT_WIFI_STATE_ONBOARDING);
    assert(core.has_credentials);
    assert(!core.candidate_credentials);
    assert(product_wifi_core_finish_onboarding(&core) ==
           PRODUCT_WIFI_ACTION_START_STATION);
    assert(core.state == PRODUCT_WIFI_STATE_CONNECTING);
}

static void test_stop_and_fatal_fail_closed(void)
{
    product_wifi_core_t core = new_core(3);
    product_wifi_core_start(&core, true);
    product_wifi_core_station_started(&core);
    product_wifi_core_got_ip(&core);
    product_wifi_action_t action = product_wifi_core_stop(&core);
    assert(core.state == PRODUCT_WIFI_STATE_STOPPED);
    assert((action & PRODUCT_WIFI_ACTION_NETWORK_DOWN) != 0);
    assert((action & PRODUCT_WIFI_ACTION_STOP_STATION) != 0);

    core = new_core(3);
    product_wifi_core_start(&core, true);
    action = product_wifi_core_fatal(&core);
    assert(core.state == PRODUCT_WIFI_STATE_FATAL);
    assert((action & PRODUCT_WIFI_ACTION_STOP_STATION) != 0);
}

static void test_credential_blob_round_trip_and_tamper_rejection(void)
{
    product_wifi_credentials_t credentials = {0};
    memcpy(credentials.ssid, "Product-Lab", sizeof("Product-Lab"));
    memcpy(credentials.password, "correct-horse-42",
           sizeof("correct-horse-42"));
    uint8_t blob[PRODUCT_WIFI_CREDENTIAL_BLOB_SIZE];
    assert(product_wifi_credentials_encode(&credentials, blob));

    product_wifi_credentials_t decoded = {0};
    assert(product_wifi_credentials_decode(blob, sizeof(blob), &decoded));
    assert(strcmp(decoded.ssid, credentials.ssid) == 0);
    assert(strcmp(decoded.password, credentials.password) == 0);

    blob[10] ^= 0x40;
    assert(!product_wifi_credentials_decode(blob, sizeof(blob), &decoded));
    blob[10] ^= 0x40;
    assert(!product_wifi_credentials_decode(blob, sizeof(blob) - 1,
                                            &decoded));
}

static void test_credential_validation(void)
{
    assert(product_wifi_credentials_valid("ssid", "12345678"));
    assert(!product_wifi_credentials_valid("", "12345678"));
    assert(!product_wifi_credentials_valid("ssid", "short"));
    assert(!product_wifi_credentials_valid("ssid", "line\nbreak"));

    char long_ssid[PRODUCT_WIFI_SSID_MAX + 2];
    memset(long_ssid, 'a', sizeof(long_ssid));
    long_ssid[sizeof(long_ssid) - 1] = '\0';
    assert(!product_wifi_credentials_valid(long_ssid, "12345678"));
}

static product_wifi_credentials_t test_network(const char *ssid,
                                               const char *password)
{
    product_wifi_credentials_t credentials = {0};
    memcpy(credentials.ssid, ssid, strlen(ssid) + 1);
    memcpy(credentials.password, password, strlen(password) + 1);
    return credentials;
}

static void test_multiple_wifi_round_trip_rotation_and_update(void)
{
    product_wifi_credential_set_t set = {0};
    const product_wifi_credentials_t home =
        test_network("Home", "home-pass-1");
    const product_wifi_credentials_t office =
        test_network("Office", "office-pass-2");
    const product_wifi_credentials_t mobile =
        test_network("Mobile", "mobile-pass-3");
    assert(product_wifi_credential_set_upsert(&set, &home));
    assert(product_wifi_credential_set_upsert(&set, &office));
    assert(product_wifi_credential_set_upsert(&set, &mobile));
    assert(set.count == 3 && set.active_index == 0);
    assert(strcmp(set.entries[0].ssid, "Mobile") == 0);

    uint8_t blob[PRODUCT_WIFI_CREDENTIAL_SET_BLOB_SIZE] = {0};
    assert(product_wifi_credential_set_encode(&set, blob));
    product_wifi_credential_set_t decoded = {0};
    assert(product_wifi_credential_set_decode(blob, sizeof(blob), &decoded));
    assert(decoded.count == 3 && decoded.active_index == 0);

    product_wifi_credentials_t selected = {0};
    assert(product_wifi_credential_set_select_next(&decoded, &selected));
    assert(strcmp(selected.ssid, "Office") == 0);
    assert(product_wifi_credential_set_select_next(&decoded, &selected));
    assert(strcmp(selected.ssid, "Home") == 0);
    assert(product_wifi_credential_set_select_next(&decoded, &selected));
    assert(strcmp(selected.ssid, "Mobile") == 0);

    const product_wifi_credentials_t office_updated =
        test_network("Office", "new-office-pass");
    assert(product_wifi_credential_set_upsert(&decoded, &office_updated));
    assert(decoded.count == 3 && decoded.active_index == 0);
    assert(strcmp(decoded.entries[0].ssid, "Office") == 0);
    assert(strcmp(decoded.entries[0].password, "new-office-pass") == 0);
    const product_wifi_credentials_t office_updated_again =
        test_network("Office", "newest-office-pass");
    assert(product_wifi_credential_set_upsert(&decoded,
                                              &office_updated_again));
    assert(decoded.count == 3 && decoded.active_index == 0);
    assert(strcmp(decoded.entries[0].password,
                  "newest-office-pass") == 0);
    assert(strcmp(decoded.entries[1].ssid, "Mobile") == 0);
    assert(strcmp(decoded.entries[2].ssid, "Home") == 0);

    blob[30] ^= 0x10;
    assert(!product_wifi_credential_set_decode(blob, sizeof(blob), &decoded));
}

static void test_multiple_wifi_limit_evicts_oldest(void)
{
    product_wifi_credential_set_t set = {0};
    for (unsigned index = 0; index < PRODUCT_WIFI_CREDENTIAL_SET_LIMIT + 1;
         ++index) {
        char ssid[16] = {0};
        snprintf(ssid, sizeof(ssid), "Network-%u", index);
        const product_wifi_credentials_t credentials =
            test_network(ssid, "password-123");
        assert(product_wifi_credential_set_upsert(&set, &credentials));
    }
    assert(set.count == PRODUCT_WIFI_CREDENTIAL_SET_LIMIT);
    assert(strcmp(set.entries[0].ssid, "Network-5") == 0);
    for (uint8_t index = 0; index < set.count; ++index) {
        assert(strcmp(set.entries[index].ssid, "Network-0") != 0);
    }
}

static void test_atomic_wifi_claim_state_round_trip(void)
{
    product_wifi_persisted_state_t state = {0};
    memcpy(state.credentials.ssid, "Product-Lab", sizeof("Product-Lab"));
    memcpy(state.credentials.password, "correct-horse-42",
           sizeof("correct-horse-42"));
    memset(state.device_claim, 'A', PRODUCT_WIFI_DEVICE_CLAIM_SIZE);
    state.claim_pending = true;
    assert(product_wifi_device_claim_is_canonical(state.device_claim));

    uint8_t blob[PRODUCT_WIFI_STATE_BLOB_SIZE];
    assert(product_wifi_state_encode(&state, blob));
    product_wifi_persisted_state_t decoded = {0};
    assert(product_wifi_state_decode(blob, sizeof(blob), &decoded));
    assert(strcmp(decoded.credentials.ssid, state.credentials.ssid) == 0);
    assert(strcmp(decoded.credentials.password,
                  state.credentials.password) == 0);
    assert(decoded.claim_pending);
    assert(strcmp(decoded.device_claim, state.device_claim) == 0);

    blob[120] ^= 0x20;
    assert(!product_wifi_state_decode(blob, sizeof(blob), &decoded));
    blob[120] ^= 0x20;
    assert(!product_wifi_state_decode(blob, sizeof(blob) - 1, &decoded));
}

static void test_device_claim_canonical_validation(void)
{
    char claim[PRODUCT_WIFI_DEVICE_CLAIM_SIZE + 1];
    memset(claim, 'A', PRODUCT_WIFI_DEVICE_CLAIM_SIZE);
    claim[PRODUCT_WIFI_DEVICE_CLAIM_SIZE] = '\0';
    assert(product_wifi_device_claim_is_canonical(claim));
    claim[PRODUCT_WIFI_DEVICE_CLAIM_SIZE - 1] = 'B';
    assert(!product_wifi_device_claim_is_canonical(claim));
    claim[PRODUCT_WIFI_DEVICE_CLAIM_SIZE - 1] = '=';
    assert(!product_wifi_device_claim_is_canonical(claim));
    claim[PRODUCT_WIFI_DEVICE_CLAIM_SIZE - 1] = '\0';
    assert(!product_wifi_device_claim_is_canonical(claim));

    product_wifi_persisted_state_t state = {0};
    memcpy(state.credentials.ssid, "Product-Lab", sizeof("Product-Lab"));
    memcpy(state.credentials.password, "correct-horse-42",
           sizeof("correct-horse-42"));
    uint8_t blob[PRODUCT_WIFI_STATE_BLOB_SIZE];
    assert(product_wifi_state_encode(&state, blob));
    product_wifi_persisted_state_t decoded = {0};
    assert(product_wifi_state_decode(blob, sizeof(blob), &decoded));
    assert(!decoded.claim_pending);
    assert(decoded.device_claim[0] == '\0');
}

int main(void)
{
    test_config_validation();
    test_unprovisioned_requires_physical_onboarding();
    test_transient_disconnect_uses_bounded_backoff();
    test_rejected_credentials_stop_automatic_retry();
    test_prolonged_loss_can_restart_station_without_erasing_credentials();
    test_explicit_onboarding_gates_network();
    test_candidate_failure_preserves_active_credentials();
    test_stop_and_fatal_fail_closed();
    test_credential_blob_round_trip_and_tamper_rejection();
    test_credential_validation();
    test_multiple_wifi_round_trip_rotation_and_update();
    test_multiple_wifi_limit_evicts_oldest();
    test_atomic_wifi_claim_state_round_trip();
    test_device_claim_canonical_validation();
    puts("product_wifi_core: all tests passed");
    return 0;
}
