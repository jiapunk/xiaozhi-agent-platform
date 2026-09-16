#include "product_agent_observability.h"

#include <limits.h>
#include <string.h>

typedef enum {
  CAPABILITY_CLASS_INVALID = 0,
  CAPABILITY_CLASS_DEVICE_READ,
  CAPABILITY_CLASS_DEVICE_ACTION,
  CAPABILITY_CLASS_MEMORY_READ,
  CAPABILITY_CLASS_MEMORY_WRITE,
} capability_class_t;

static void saturating_increment(atomic_uint *counter) {
  unsigned current = atomic_load_explicit(counter, memory_order_relaxed);
  while (current != UINT_MAX &&
         !atomic_compare_exchange_weak_explicit(counter, &current, current + 1U,
                                                memory_order_relaxed,
                                                memory_order_relaxed)) {
  }
}

static capability_class_t classify_capability(const char *capability_id) {
  if (!capability_id) {
    return CAPABILITY_CLASS_INVALID;
  }
  if (strcmp(capability_id, "device.get_status") == 0) {
    return CAPABILITY_CLASS_DEVICE_READ;
  }
  if (strcmp(capability_id, "device.set_indicator") == 0 ||
      strcmp(capability_id, "device.set_volume") == 0) {
    return CAPABILITY_CLASS_DEVICE_ACTION;
  }
  if (strcmp(capability_id, "memory.list") == 0 ||
      strcmp(capability_id, "memory.get") == 0) {
    return CAPABILITY_CLASS_MEMORY_READ;
  }
  if (strcmp(capability_id, "memory.put") == 0 ||
      strcmp(capability_id, "memory.forget") == 0) {
    return CAPABILITY_CLASS_MEMORY_WRITE;
  }
  return CAPABILITY_CLASS_INVALID;
}

bool product_agent_observability_init(
    product_agent_observability_t *observability) {
  if (!observability) {
    return false;
  }
  atomic_init(&observability->total, 0);
  atomic_init(&observability->invalid_events, 0);
  atomic_init(&observability->executed, 0);
  atomic_init(&observability->denied_disabled, 0);
  atomic_init(&observability->denied_context, 0);
  atomic_init(&observability->denied_consent, 0);
  atomic_init(&observability->invalid_input, 0);
  atomic_init(&observability->execution_failed, 0);
  atomic_init(&observability->device_reads, 0);
  atomic_init(&observability->device_actions, 0);
  atomic_init(&observability->memory_reads, 0);
  atomic_init(&observability->memory_writes, 0);
  return true;
}

void product_agent_observability_record(
    void *ctx, const esp_claw_capability_audit_event_t *event) {
  product_agent_observability_t *observability = ctx;
  if (!observability) {
    return;
  }
  const capability_class_t capability =
      event ? classify_capability(event->capability_id)
            : CAPABILITY_CLASS_INVALID;
  const bool context_is_valid =
      event &&
      ((event->request_id != 0 && event->session_id && event->session_id[0]) ||
       event->decision == ESP_CLAW_CAPABILITY_AUDIT_DENIED_CONTEXT);
  if (!event || capability == CAPABILITY_CLASS_INVALID || !context_is_valid ||
      event->decision < ESP_CLAW_CAPABILITY_AUDIT_EXECUTED ||
      event->decision > ESP_CLAW_CAPABILITY_AUDIT_EXECUTION_FAILED) {
    saturating_increment(&observability->invalid_events);
    return;
  }

  saturating_increment(&observability->total);
  switch (event->decision) {
  case ESP_CLAW_CAPABILITY_AUDIT_EXECUTED:
    saturating_increment(&observability->executed);
    break;
  case ESP_CLAW_CAPABILITY_AUDIT_DENIED_DISABLED:
    saturating_increment(&observability->denied_disabled);
    break;
  case ESP_CLAW_CAPABILITY_AUDIT_DENIED_CONTEXT:
    saturating_increment(&observability->denied_context);
    break;
  case ESP_CLAW_CAPABILITY_AUDIT_DENIED_CONSENT:
    saturating_increment(&observability->denied_consent);
    break;
  case ESP_CLAW_CAPABILITY_AUDIT_INVALID_INPUT:
    saturating_increment(&observability->invalid_input);
    break;
  case ESP_CLAW_CAPABILITY_AUDIT_EXECUTION_FAILED:
    saturating_increment(&observability->execution_failed);
    break;
  default:
    /* The validated closed enum makes this unreachable. */
    return;
  }

  switch (capability) {
  case CAPABILITY_CLASS_DEVICE_READ:
    saturating_increment(&observability->device_reads);
    break;
  case CAPABILITY_CLASS_DEVICE_ACTION:
    saturating_increment(&observability->device_actions);
    break;
  case CAPABILITY_CLASS_MEMORY_READ:
    saturating_increment(&observability->memory_reads);
    break;
  case CAPABILITY_CLASS_MEMORY_WRITE:
    saturating_increment(&observability->memory_writes);
    break;
  case CAPABILITY_CLASS_INVALID:
  default:
    return;
  }
}

bool product_agent_observability_snapshot(
    const product_agent_observability_t *observability,
    product_agent_observability_stats_t *stats) {
  if (!observability || !stats) {
    return false;
  }
#define SNAPSHOT(field)                                                        \
  stats->field =                                                               \
      atomic_load_explicit(&observability->field, memory_order_relaxed)
  SNAPSHOT(total);
  SNAPSHOT(invalid_events);
  SNAPSHOT(executed);
  SNAPSHOT(denied_disabled);
  SNAPSHOT(denied_context);
  SNAPSHOT(denied_consent);
  SNAPSHOT(invalid_input);
  SNAPSHOT(execution_failed);
  SNAPSHOT(device_reads);
  SNAPSHOT(device_actions);
  SNAPSHOT(memory_reads);
  SNAPSHOT(memory_writes);
#undef SNAPSHOT
  return true;
}
