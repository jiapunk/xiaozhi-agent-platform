#include "product_agent_observability.h"

#include <assert.h>
#include <limits.h>
#include <stdio.h>

static void record(product_agent_observability_t *observability,
                   const char *capability,
                   uint32_t request_id,
                   const char *session_id,
                   esp_claw_capability_audit_decision_t decision,
                   esp_err_t result)
{
    const esp_claw_capability_audit_event_t event = {
        .capability_id = capability,
        .request_id = request_id,
        .session_id = session_id,
        .decision = decision,
        .result = result,
    };
    product_agent_observability_record(observability, &event);
}

int main(void)
{
    product_agent_observability_t observability;
    product_agent_observability_stats_t stats;
    assert(!product_agent_observability_init(NULL));
    assert(product_agent_observability_init(&observability));
    assert(!product_agent_observability_snapshot(NULL, &stats));
    assert(!product_agent_observability_snapshot(&observability, NULL));

    record(&observability, "device.get_status", 1, "session-a",
           ESP_CLAW_CAPABILITY_AUDIT_EXECUTED, ESP_OK);
    record(&observability, "device.set_indicator", 0, NULL,
           ESP_CLAW_CAPABILITY_AUDIT_DENIED_CONTEXT,
           ESP_ERR_INVALID_STATE);
    record(&observability, "device.set_indicator", 2, "session-a",
           ESP_CLAW_CAPABILITY_AUDIT_DENIED_DISABLED,
           ESP_ERR_NOT_ALLOWED);
    record(&observability, "memory.list", 3, "session-a",
           ESP_CLAW_CAPABILITY_AUDIT_INVALID_INPUT,
           ESP_ERR_INVALID_ARG);
    record(&observability, "memory.get", 4, "session-a",
           ESP_CLAW_CAPABILITY_AUDIT_EXECUTION_FAILED, ESP_FAIL);
    record(&observability, "memory.put", 5, "session-a",
           ESP_CLAW_CAPABILITY_AUDIT_DENIED_CONSENT,
           ESP_ERR_NOT_ALLOWED);
    record(&observability, "memory.forget", 6, "session-a",
           ESP_CLAW_CAPABILITY_AUDIT_EXECUTED, ESP_OK);

    product_agent_observability_record(&observability, NULL);
    record(&observability, "unknown.capability", 7, "session-a",
           ESP_CLAW_CAPABILITY_AUDIT_EXECUTED, ESP_OK);
    record(&observability, "device.get_status", 8, NULL,
           ESP_CLAW_CAPABILITY_AUDIT_EXECUTED, ESP_OK);
    record(&observability, "device.get_status", 9, "session-a",
           (esp_claw_capability_audit_decision_t)99, ESP_FAIL);
    product_agent_observability_record(NULL, NULL);

    assert(product_agent_observability_snapshot(&observability, &stats));
    assert(stats.total == 7);
    assert(stats.invalid_events == 4);
    assert(stats.executed == 2);
    assert(stats.denied_disabled == 1);
    assert(stats.denied_context == 1);
    assert(stats.denied_consent == 1);
    assert(stats.invalid_input == 1);
    assert(stats.execution_failed == 1);
    assert(stats.device_reads == 1);
    assert(stats.device_actions == 2);
    assert(stats.memory_reads == 2);
    assert(stats.memory_writes == 2);

    atomic_store_explicit(&observability.total, UINT_MAX,
                          memory_order_relaxed);
    record(&observability, "device.get_status", 10, "session-a",
           ESP_CLAW_CAPABILITY_AUDIT_EXECUTED, ESP_OK);
    assert(product_agent_observability_snapshot(&observability, &stats));
    assert(stats.total == UINT_MAX);

    puts("product_agent_observability: all tests passed");
    return 0;
}
