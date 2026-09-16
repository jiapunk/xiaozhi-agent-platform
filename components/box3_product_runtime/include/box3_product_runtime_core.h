#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    BOX3_PRODUCT_RUNTIME_DEVICE_ID_BYTES = 16,
    BOX3_PRODUCT_RUNTIME_CLIENT_ID_BYTES = 22,
    BOX3_PRODUCT_RUNTIME_ENDPOINT_BYTES = 512,
};

typedef enum {
    BOX3_PRODUCT_RUNTIME_RESOURCE_NONE = 0,
    BOX3_PRODUCT_RUNTIME_RESOURCE_IDENTITY = 1U << 0,
    BOX3_PRODUCT_RUNTIME_RESOURCE_CONTROL = 1U << 1,
    BOX3_PRODUCT_RUNTIME_RESOURCE_CREDENTIALS = 1U << 2,
    BOX3_PRODUCT_RUNTIME_RESOURCE_SUPERVISOR = 1U << 3,
    BOX3_PRODUCT_RUNTIME_RESOURCE_TIME_BOOTSTRAP = 1U << 4,
    BOX3_PRODUCT_RUNTIME_RESOURCE_WIFI = 1U << 5,
    BOX3_PRODUCT_RUNTIME_RESOURCE_PROVISIONING = 1U << 6,
    BOX3_PRODUCT_RUNTIME_RESOURCE_LOCAL_ACTION = 1U << 7,
} box3_product_runtime_resource_t;

typedef enum {
    BOX3_PRODUCT_RUNTIME_CORE_STARTING = 0,
    BOX3_PRODUCT_RUNTIME_CORE_RUNNING,
    BOX3_PRODUCT_RUNTIME_CORE_STOPPING,
    BOX3_PRODUCT_RUNTIME_CORE_STOPPED,
} box3_product_runtime_core_state_t;

typedef struct {
    box3_product_runtime_core_state_t state;
    uint32_t resources;
    uint32_t cleanup_retries;
} box3_product_runtime_core_t;

typedef enum {
    BOX3_ACTION_CONSENT_PENDING = 0,
    BOX3_ACTION_CONSENT_APPROVED,
    BOX3_ACTION_CONSENT_DENIED,
} box3_action_consent_decision_t;

typedef enum {
    BOX3_ACTION_CONSENT_OUTCOME_APPROVED = 0,
    BOX3_ACTION_CONSENT_OUTCOME_DENIED,
    BOX3_ACTION_CONSENT_OUTCOME_EXPIRED,
    BOX3_ACTION_CONSENT_OUTCOME_CANCELED,
    BOX3_ACTION_CONSENT_OUTCOME_FAILED,
} box3_action_consent_outcome_t;

typedef struct {
    uint32_t timeout_ms;
    uint32_t poll_interval_ms;
    uint32_t network_timeout_ms;
    uint32_t maximum_request_timeout_ms;
} box3_action_consent_core_config_t;

typedef struct {
    bool (*monotonic_ms)(void *ctx, uint64_t *value);
    bool (*available)(void *ctx);
    bool (*register_action)(void *ctx, const char *session_id,
                            uint32_t request_id, bool indicator_on,
                            uint32_t lifetime_seconds,
                            uint32_t request_timeout_ms,
                            void *consent_state);
    bool (*poll_action)(void *ctx, void *consent_state,
                        uint32_t request_timeout_ms,
                        box3_action_consent_decision_t *decision);
    void (*wait_ms)(void *ctx, uint32_t milliseconds);
} box3_action_consent_core_ops_t;

/* Stable public registry identity: xz- followed by the base MAC in lowercase. */
bool box3_product_runtime_format_device_id(
    const uint8_t base_mac[6],
    char output[BOX3_PRODUCT_RUNTIME_DEVICE_ID_BYTES]);

/* Per-boot correlation identity. The random bytes are never a credential. */
bool box3_product_runtime_format_client_id(
    const uint8_t random_bytes[8],
    char output[BOX3_PRODUCT_RUNTIME_CLIENT_ID_BYTES]);

/* Accepts only https://authority with no path, query, fragment, or userinfo. */
bool box3_product_runtime_build_endpoint(
    const char *authority,
    const char *exact_path,
    char *output,
    size_t output_size);

void box3_product_runtime_core_init(box3_product_runtime_core_t *core);

/* Resources must be acquired in dependency order and form a strict prefix. */
bool box3_product_runtime_core_acquire(
    box3_product_runtime_core_t *core,
    box3_product_runtime_resource_t resource);

bool box3_product_runtime_core_commit(box3_product_runtime_core_t *core);

void box3_product_runtime_core_begin_stop(
    box3_product_runtime_core_t *core);

/* Returns the only resource that may be released next. */
box3_product_runtime_resource_t box3_product_runtime_core_next_cleanup(
    const box3_product_runtime_core_t *core);

bool box3_product_runtime_core_release(
    box3_product_runtime_core_t *core,
    box3_product_runtime_resource_t resource);

void box3_product_runtime_core_cleanup_failed(
    box3_product_runtime_core_t *core);

/*
 * Runs one exact action approval with a single monotonic deadline. Each
 * network request is sliced to the lesser of network, remaining, and maximum
 * request time so cancellation and stop cannot become an unbounded wait.
 * consent_state is opaque and remains caller-owned.
 */
box3_action_consent_outcome_t box3_action_consent_core_run(
    const box3_action_consent_core_config_t *config,
    const box3_action_consent_core_ops_t *ops,
    void *ctx,
    const char *session_id,
    uint32_t request_id,
    bool indicator_on,
    void *consent_state,
    bool *registered);

#ifdef __cplusplus
}
#endif
