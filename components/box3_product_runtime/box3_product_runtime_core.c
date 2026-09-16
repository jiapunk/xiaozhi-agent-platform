#include "box3_product_runtime_core.h"

#include <stdio.h>
#include <string.h>

enum {
    ALL_RESOURCES = BOX3_PRODUCT_RUNTIME_RESOURCE_IDENTITY |
                    BOX3_PRODUCT_RUNTIME_RESOURCE_CONTROL |
                    BOX3_PRODUCT_RUNTIME_RESOURCE_CREDENTIALS |
                    BOX3_PRODUCT_RUNTIME_RESOURCE_SUPERVISOR |
                    BOX3_PRODUCT_RUNTIME_RESOURCE_TIME_BOOTSTRAP |
                    BOX3_PRODUCT_RUNTIME_RESOURCE_WIFI |
                    BOX3_PRODUCT_RUNTIME_RESOURCE_PROVISIONING |
                    BOX3_PRODUCT_RUNTIME_RESOURCE_LOCAL_ACTION,
};

static bool all_zero(const uint8_t *bytes, size_t size)
{
    if (!bytes) {
        return true;
    }
    uint8_t combined = 0;
    for (size_t index = 0; index < size; ++index) {
        combined |= bytes[index];
    }
    return combined == 0;
}

static bool safe_identifier(const char *value)
{
    if (!value) {
        return false;
    }
    const size_t length = strnlen(value, 65);
    if (length == 0 || length > 64) {
        return false;
    }
    for (size_t index = 0; index < length; ++index) {
        const unsigned char character = (unsigned char)value[index];
        if (!((character >= 'a' && character <= 'z') ||
              (character >= 'A' && character <= 'Z') ||
              (character >= '0' && character <= '9') ||
              character == ':' || character == '-' || character == '_' ||
              character == '.')) {
            return false;
        }
    }
    return true;
}

static bool consent_config_valid(
    const box3_action_consent_core_config_t *config,
    const box3_action_consent_core_ops_t *ops)
{
    return config && ops && ops->monotonic_ms && ops->available &&
           ops->register_action && ops->poll_action && ops->wait_ms &&
           config->timeout_ms >= 1000 && config->timeout_ms <= 28000 &&
           config->poll_interval_ms >= 100 &&
           config->poll_interval_ms <= 2000 &&
           config->poll_interval_ms + 100 < config->timeout_ms &&
           config->network_timeout_ms >= 100 &&
           config->network_timeout_ms <= 30000 &&
           config->maximum_request_timeout_ms >= 100 &&
           config->maximum_request_timeout_ms <= 30000;
}

static uint32_t consent_remaining(uint64_t now, uint64_t deadline)
{
    if (now >= deadline) {
        return 0;
    }
    const uint64_t value = deadline - now;
    return value > UINT32_MAX ? UINT32_MAX : (uint32_t)value;
}

static uint32_t consent_request_timeout(
    const box3_action_consent_core_config_t *config,
    uint32_t remaining)
{
    if (remaining < 100) {
        return 0;
    }
    uint32_t result = remaining;
    if (result > config->network_timeout_ms) {
        result = config->network_timeout_ms;
    }
    if (result > config->maximum_request_timeout_ms) {
        result = config->maximum_request_timeout_ms;
    }
    return result;
}

box3_action_consent_outcome_t box3_action_consent_core_run(
    const box3_action_consent_core_config_t *config,
    const box3_action_consent_core_ops_t *ops,
    void *ctx,
    const char *session_id,
    uint32_t request_id,
    bool indicator_on,
    void *consent_state,
    bool *registered)
{
    if (registered) {
        *registered = false;
    }
    if (!consent_config_valid(config, ops) || !ctx || !consent_state ||
        !registered || request_id == 0 || !safe_identifier(session_id)) {
        return BOX3_ACTION_CONSENT_OUTCOME_FAILED;
    }
    if (!ops->available(ctx)) {
        return BOX3_ACTION_CONSENT_OUTCOME_CANCELED;
    }
    uint64_t now = 0;
    if (!ops->monotonic_ms(ctx, &now) ||
        now > UINT64_MAX - config->timeout_ms) {
        return BOX3_ACTION_CONSENT_OUTCOME_FAILED;
    }
    const uint64_t deadline = now + config->timeout_ms;
    uint32_t remaining = consent_remaining(now, deadline);
    uint32_t request_timeout = consent_request_timeout(config, remaining);
    const uint32_t lifetime_seconds =
        (config->timeout_ms + 999U) / 1000U + 1U;
    if (request_timeout == 0 || lifetime_seconds > 30 ||
        !ops->register_action(ctx, session_id, request_id, indicator_on,
                              lifetime_seconds, request_timeout,
                              consent_state)) {
        return ops->available(ctx)
                   ? BOX3_ACTION_CONSENT_OUTCOME_FAILED
                   : BOX3_ACTION_CONSENT_OUTCOME_CANCELED;
    }
    *registered = true;

    for (;;) {
        if (!ops->available(ctx)) {
            return BOX3_ACTION_CONSENT_OUTCOME_CANCELED;
        }
        if (!ops->monotonic_ms(ctx, &now)) {
            return BOX3_ACTION_CONSENT_OUTCOME_FAILED;
        }
        remaining = consent_remaining(now, deadline);
        if (remaining <= 100) {
            return BOX3_ACTION_CONSENT_OUTCOME_EXPIRED;
        }
        uint32_t delay = config->poll_interval_ms;
        if (delay > remaining - 100) {
            delay = remaining - 100;
        }
        ops->wait_ms(ctx, delay);
        if (!ops->available(ctx)) {
            return BOX3_ACTION_CONSENT_OUTCOME_CANCELED;
        }
        if (!ops->monotonic_ms(ctx, &now)) {
            return BOX3_ACTION_CONSENT_OUTCOME_FAILED;
        }
        remaining = consent_remaining(now, deadline);
        request_timeout = consent_request_timeout(config, remaining);
        if (request_timeout == 0) {
            return BOX3_ACTION_CONSENT_OUTCOME_EXPIRED;
        }
        box3_action_consent_decision_t decision =
            BOX3_ACTION_CONSENT_PENDING;
        if (!ops->poll_action(ctx, consent_state, request_timeout,
                              &decision)) {
            return ops->available(ctx)
                       ? BOX3_ACTION_CONSENT_OUTCOME_FAILED
                       : BOX3_ACTION_CONSENT_OUTCOME_CANCELED;
        }
        if (decision == BOX3_ACTION_CONSENT_APPROVED) {
            return BOX3_ACTION_CONSENT_OUTCOME_APPROVED;
        }
        if (decision == BOX3_ACTION_CONSENT_DENIED) {
            return BOX3_ACTION_CONSENT_OUTCOME_DENIED;
        }
        if (decision != BOX3_ACTION_CONSENT_PENDING) {
            return BOX3_ACTION_CONSENT_OUTCOME_FAILED;
        }
    }
}

bool box3_product_runtime_format_device_id(
    const uint8_t base_mac[6],
    char output[BOX3_PRODUCT_RUNTIME_DEVICE_ID_BYTES])
{
    if (!base_mac || !output || all_zero(base_mac, 6) ||
        (base_mac[0] & 1U) != 0) {
        return false;
    }
    const int written = snprintf(
        output, BOX3_PRODUCT_RUNTIME_DEVICE_ID_BYTES,
        "xz-%02x%02x%02x%02x%02x%02x",
        base_mac[0], base_mac[1], base_mac[2],
        base_mac[3], base_mac[4], base_mac[5]);
    return written == BOX3_PRODUCT_RUNTIME_DEVICE_ID_BYTES - 1;
}

bool box3_product_runtime_format_client_id(
    const uint8_t random_bytes[8],
    char output[BOX3_PRODUCT_RUNTIME_CLIENT_ID_BYTES])
{
    if (!random_bytes || !output || all_zero(random_bytes, 8)) {
        return false;
    }
    const int written = snprintf(
        output, BOX3_PRODUCT_RUNTIME_CLIENT_ID_BYTES,
        "boot-%02x%02x%02x%02x%02x%02x%02x%02x",
        random_bytes[0], random_bytes[1], random_bytes[2], random_bytes[3],
        random_bytes[4], random_bytes[5], random_bytes[6], random_bytes[7]);
    return written == BOX3_PRODUCT_RUNTIME_CLIENT_ID_BYTES - 1;
}

static bool safe_authority_character(unsigned char character)
{
    return (character >= 'a' && character <= 'z') ||
           (character >= 'A' && character <= 'Z') ||
           (character >= '0' && character <= '9') ||
           character == '.' || character == '-' || character == ':' ||
           character == '[' || character == ']';
}

bool box3_product_runtime_build_endpoint(
    const char *authority,
    const char *exact_path,
    char *output,
    size_t output_size)
{
    if (!authority || !exact_path || !output || output_size == 0 ||
        strncmp(authority, "https://", 8) != 0 || exact_path[0] != '/' ||
        exact_path[1] == '\0') {
        return false;
    }
    const size_t authority_size = strnlen(
        authority, BOX3_PRODUCT_RUNTIME_ENDPOINT_BYTES);
    const size_t path_size = strnlen(
        exact_path, BOX3_PRODUCT_RUNTIME_ENDPOINT_BYTES);
    if (authority_size <= 8 ||
        authority_size == BOX3_PRODUCT_RUNTIME_ENDPOINT_BYTES ||
        path_size == BOX3_PRODUCT_RUNTIME_ENDPOINT_BYTES ||
        authority_size + path_size + 1 > output_size) {
        return false;
    }
    for (size_t index = 8; index < authority_size; ++index) {
        if (!safe_authority_character((unsigned char)authority[index])) {
            return false;
        }
    }
    for (size_t index = 0; index < path_size; ++index) {
        const unsigned char character = (unsigned char)exact_path[index];
        if (character <= 0x20 || character >= 0x7f ||
            character == '?' || character == '#') {
            return false;
        }
    }
    memcpy(output, authority, authority_size);
    memcpy(output + authority_size, exact_path, path_size + 1);
    return true;
}

void box3_product_runtime_core_init(box3_product_runtime_core_t *core)
{
    if (core) {
        *core = (box3_product_runtime_core_t){
            .state = BOX3_PRODUCT_RUNTIME_CORE_STARTING,
        };
    }
}

static box3_product_runtime_resource_t expected_next(uint32_t resources)
{
    switch (resources) {
    case 0:
        return BOX3_PRODUCT_RUNTIME_RESOURCE_IDENTITY;
    case BOX3_PRODUCT_RUNTIME_RESOURCE_IDENTITY:
        return BOX3_PRODUCT_RUNTIME_RESOURCE_CONTROL;
    case BOX3_PRODUCT_RUNTIME_RESOURCE_IDENTITY |
             BOX3_PRODUCT_RUNTIME_RESOURCE_CONTROL:
        return BOX3_PRODUCT_RUNTIME_RESOURCE_CREDENTIALS;
    case BOX3_PRODUCT_RUNTIME_RESOURCE_IDENTITY |
             BOX3_PRODUCT_RUNTIME_RESOURCE_CONTROL |
             BOX3_PRODUCT_RUNTIME_RESOURCE_CREDENTIALS:
        return BOX3_PRODUCT_RUNTIME_RESOURCE_SUPERVISOR;
    case BOX3_PRODUCT_RUNTIME_RESOURCE_IDENTITY |
             BOX3_PRODUCT_RUNTIME_RESOURCE_CONTROL |
             BOX3_PRODUCT_RUNTIME_RESOURCE_CREDENTIALS |
             BOX3_PRODUCT_RUNTIME_RESOURCE_SUPERVISOR:
        return BOX3_PRODUCT_RUNTIME_RESOURCE_TIME_BOOTSTRAP;
    case BOX3_PRODUCT_RUNTIME_RESOURCE_IDENTITY |
             BOX3_PRODUCT_RUNTIME_RESOURCE_CONTROL |
             BOX3_PRODUCT_RUNTIME_RESOURCE_CREDENTIALS |
             BOX3_PRODUCT_RUNTIME_RESOURCE_SUPERVISOR |
             BOX3_PRODUCT_RUNTIME_RESOURCE_TIME_BOOTSTRAP:
        return BOX3_PRODUCT_RUNTIME_RESOURCE_WIFI;
    case BOX3_PRODUCT_RUNTIME_RESOURCE_IDENTITY |
             BOX3_PRODUCT_RUNTIME_RESOURCE_CONTROL |
             BOX3_PRODUCT_RUNTIME_RESOURCE_CREDENTIALS |
             BOX3_PRODUCT_RUNTIME_RESOURCE_SUPERVISOR |
             BOX3_PRODUCT_RUNTIME_RESOURCE_TIME_BOOTSTRAP |
             BOX3_PRODUCT_RUNTIME_RESOURCE_WIFI:
        return BOX3_PRODUCT_RUNTIME_RESOURCE_PROVISIONING;
    case BOX3_PRODUCT_RUNTIME_RESOURCE_IDENTITY |
             BOX3_PRODUCT_RUNTIME_RESOURCE_CONTROL |
             BOX3_PRODUCT_RUNTIME_RESOURCE_CREDENTIALS |
             BOX3_PRODUCT_RUNTIME_RESOURCE_SUPERVISOR |
             BOX3_PRODUCT_RUNTIME_RESOURCE_TIME_BOOTSTRAP |
             BOX3_PRODUCT_RUNTIME_RESOURCE_WIFI |
             BOX3_PRODUCT_RUNTIME_RESOURCE_PROVISIONING:
        return BOX3_PRODUCT_RUNTIME_RESOURCE_LOCAL_ACTION;
    default:
        return BOX3_PRODUCT_RUNTIME_RESOURCE_NONE;
    }
}

bool box3_product_runtime_core_acquire(
    box3_product_runtime_core_t *core,
    box3_product_runtime_resource_t resource)
{
    if (!core || core->state != BOX3_PRODUCT_RUNTIME_CORE_STARTING ||
        resource == BOX3_PRODUCT_RUNTIME_RESOURCE_NONE ||
        expected_next(core->resources) != resource) {
        return false;
    }
    core->resources |= (uint32_t)resource;
    return true;
}

bool box3_product_runtime_core_commit(box3_product_runtime_core_t *core)
{
    if (!core || core->state != BOX3_PRODUCT_RUNTIME_CORE_STARTING ||
        core->resources != ALL_RESOURCES) {
        return false;
    }
    core->state = BOX3_PRODUCT_RUNTIME_CORE_RUNNING;
    return true;
}

void box3_product_runtime_core_begin_stop(box3_product_runtime_core_t *core)
{
    if (!core || core->state == BOX3_PRODUCT_RUNTIME_CORE_STOPPED) {
        return;
    }
    core->state = core->resources == 0
                      ? BOX3_PRODUCT_RUNTIME_CORE_STOPPED
                      : BOX3_PRODUCT_RUNTIME_CORE_STOPPING;
}

box3_product_runtime_resource_t box3_product_runtime_core_next_cleanup(
    const box3_product_runtime_core_t *core)
{
    if (!core || core->state != BOX3_PRODUCT_RUNTIME_CORE_STOPPING) {
        return BOX3_PRODUCT_RUNTIME_RESOURCE_NONE;
    }
    static const box3_product_runtime_resource_t order[] = {
        BOX3_PRODUCT_RUNTIME_RESOURCE_LOCAL_ACTION,
        BOX3_PRODUCT_RUNTIME_RESOURCE_PROVISIONING,
        BOX3_PRODUCT_RUNTIME_RESOURCE_WIFI,
        BOX3_PRODUCT_RUNTIME_RESOURCE_TIME_BOOTSTRAP,
        BOX3_PRODUCT_RUNTIME_RESOURCE_SUPERVISOR,
        BOX3_PRODUCT_RUNTIME_RESOURCE_CREDENTIALS,
        BOX3_PRODUCT_RUNTIME_RESOURCE_CONTROL,
        BOX3_PRODUCT_RUNTIME_RESOURCE_IDENTITY,
    };
    for (size_t index = 0; index < sizeof(order) / sizeof(order[0]); ++index) {
        if ((core->resources & (uint32_t)order[index]) != 0) {
            return order[index];
        }
    }
    return BOX3_PRODUCT_RUNTIME_RESOURCE_NONE;
}

bool box3_product_runtime_core_release(
    box3_product_runtime_core_t *core,
    box3_product_runtime_resource_t resource)
{
    if (!core || resource == BOX3_PRODUCT_RUNTIME_RESOURCE_NONE ||
        box3_product_runtime_core_next_cleanup(core) != resource) {
        return false;
    }
    core->resources &= ~(uint32_t)resource;
    if (core->resources == 0) {
        core->state = BOX3_PRODUCT_RUNTIME_CORE_STOPPED;
    }
    return true;
}

void box3_product_runtime_core_cleanup_failed(
    box3_product_runtime_core_t *core)
{
    if (core && core->state == BOX3_PRODUCT_RUNTIME_CORE_STOPPING &&
        core->cleanup_retries != UINT32_MAX) {
        ++core->cleanup_retries;
    }
}
