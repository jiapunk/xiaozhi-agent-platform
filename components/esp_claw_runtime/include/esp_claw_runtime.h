#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "product_agent_memory.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct esp_claw_runtime *esp_claw_runtime_handle_t;

typedef struct {
  esp_err_t (*get_status_json)(void *ctx, char *output, size_t output_size);
  esp_err_t (*set_indicator)(void *ctx, bool on);
  esp_err_t (*set_volume)(void *ctx, uint8_t volume_percent);
  void *ctx;
} esp_claw_device_ops_t;

typedef enum {
  ESP_CLAW_CAPABILITY_NONE = 0,
  ESP_CLAW_CAPABILITY_DEVICE_GET_STATUS = 1U << 0,
  ESP_CLAW_CAPABILITY_DEVICE_SET_INDICATOR = 1U << 1,
  ESP_CLAW_CAPABILITY_DEVICE_SET_VOLUME = 1U << 2,
  ESP_CLAW_CAPABILITY_ALL = ESP_CLAW_CAPABILITY_DEVICE_GET_STATUS |
                            ESP_CLAW_CAPABILITY_DEVICE_SET_INDICATOR |
                            ESP_CLAW_CAPABILITY_DEVICE_SET_VOLUME,
} esp_claw_capability_flags_t;

typedef enum {
  ESP_CLAW_CAPABILITY_ACTION_SET_INDICATOR = 1,
  ESP_CLAW_CAPABILITY_ACTION_SET_VOLUME = 2,
} esp_claw_capability_action_type_t;

typedef struct {
  esp_claw_capability_action_type_t type;
  bool indicator_on;
  uint8_t volume_percent;
} esp_claw_capability_action_t;

typedef enum {
  ESP_CLAW_CAPABILITY_AUDIT_EXECUTED = 0,
  ESP_CLAW_CAPABILITY_AUDIT_DENIED_DISABLED,
  ESP_CLAW_CAPABILITY_AUDIT_DENIED_CONTEXT,
  ESP_CLAW_CAPABILITY_AUDIT_DENIED_CONSENT,
  ESP_CLAW_CAPABILITY_AUDIT_INVALID_INPUT,
  ESP_CLAW_CAPABILITY_AUDIT_EXECUTION_FAILED,
} esp_claw_capability_audit_decision_t;

typedef struct {
  const char *capability_id;
  uint32_t request_id;
  const char *session_id;
  esp_claw_capability_audit_decision_t decision;
  esp_err_t result;
} esp_claw_capability_audit_event_t;

/*
 * Called synchronously only after an action tool's exact input validates.
 * Voice text is never passed and is never proof of consent. The callback must
 * consult trusted App/physical-UI state for this exact action. A true result
 * becomes one one-use request/session/argument-bound grant and must not be
 * cached by the callback. Keep the wait bounded so Agent cancellation works.
 */
typedef bool (*esp_claw_capability_consent_fn)(
    void *ctx, uint32_t request_id, const char *session_id,
    const esp_claw_capability_action_t *action);

/* Metadata only: input/output JSON and memory values are never included. */
typedef void (*esp_claw_capability_audit_fn)(
    void *ctx, const esp_claw_capability_audit_event_t *event);

typedef void (*esp_claw_response_fn)(uint32_t request_id, bool success,
                                     const char *text,
                                     const char *error_message, void *user_ctx);

typedef enum {
  ESP_CLAW_MEMORY_CONSENT_NONE = 0,
  ESP_CLAW_MEMORY_CONSENT_PUT = 1U << 0,
  ESP_CLAW_MEMORY_CONSENT_FORGET = 1U << 1,
} esp_claw_memory_consent_flags_t;

/*
 * Called synchronously before request submission. The callback must consult
 * trusted App/physical-UI state; user_text alone is never proof of consent.
 * Returned bits become one-use grants bound to this request and session.
 */
typedef uint32_t (*esp_claw_memory_consent_fn)(void *ctx, uint32_t request_id,
                                               const char *session_id,
                                               const char *user_text);

typedef struct {
  /*
   * Product builds should supply a short-lived, per-device token obtained
   * from the product gateway. Do not embed a provider master key.
   */
  const char *api_key;
  const char *backend_type;
  const char *model;
  const char *base_url;
  const char *auth_type;
  const char *max_tokens_field;
  const char *system_prompt;
  uint32_t timeout_ms;
  uint32_t max_tokens;
  uint32_t max_tool_iterations;
  uint32_t enabled_capabilities;
  esp_claw_device_ops_t device_ops;
  esp_claw_capability_consent_fn capability_consent;
  void *capability_consent_ctx;
  esp_claw_capability_audit_fn capability_audit;
  void *capability_audit_ctx;
  product_agent_memory_handle_t memory;
  esp_claw_memory_consent_fn memory_consent;
  void *memory_consent_ctx;
  esp_claw_response_fn response_cb;
  void *response_user_ctx;
} esp_claw_runtime_config_t;

/*
 * Development-only local capability harness. It starts the same typed
 * ESP-Claw capability registry used by the networked Agent runtime, without
 * starting an LLM backend. This exists for first-board bring-up and must not
 * be used as a production command channel.
 */
typedef struct {
  uint32_t enabled_capabilities;
  esp_claw_device_ops_t device_ops;
  esp_claw_capability_consent_fn capability_consent;
  void *capability_consent_ctx;
  esp_claw_capability_audit_fn capability_audit;
  void *capability_audit_ctx;
} esp_claw_local_capability_config_t;

/*
 * Configuration strings and device callback context must outlive the handle.
 * On an ordinary failure out_runtime is NULL. If fail-safe cleanup itself
 * times out, a retained handle is returned and must be passed to stop().
 */
esp_err_t esp_claw_runtime_start(const esp_claw_runtime_config_t *config,
                                 esp_claw_runtime_handle_t *out_runtime);

esp_err_t esp_claw_runtime_start_local_capabilities(
    const esp_claw_local_capability_config_t *config,
    esp_claw_runtime_handle_t *out_runtime);

/*
 * Calls one registered capability as a root Agent request. Only handles
 * created by esp_claw_runtime_start_local_capabilities() are accepted.
 */
esp_err_t esp_claw_runtime_call_local_capability(
    esp_claw_runtime_handle_t runtime, uint32_t request_id,
    const char *session_id, const char *capability_id, const char *input_json,
    char *output, size_t output_size);

esp_err_t esp_claw_runtime_submit(esp_claw_runtime_handle_t runtime,
                                  uint32_t request_id, const char *session_id,
                                  const char *text);

esp_err_t esp_claw_runtime_cancel(esp_claw_runtime_handle_t runtime,
                                  uint32_t request_id);

/*
 * Do not call from response_cb. ESP_OK consumes the handle. On any failure
 * the runtime and callback context remain retained so the caller can retry
 * with the same handle.
 */
esp_err_t esp_claw_runtime_stop(esp_claw_runtime_handle_t runtime,
                                uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif
