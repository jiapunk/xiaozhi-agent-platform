#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "product_factory_reset_core.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool pending_at_boot;
    bool completed;
    product_factory_reset_phase_t starting_phase;
    product_factory_reset_phase_t final_phase;
    uint32_t wifi_erase_commits;
    uint32_t memory_erase_commits;
} product_factory_reset_result_t;

/*
 * Durably records reset intent before the caller restarts the device. This is
 * idempotent and never moves an already-pending journal backwards.
 */
esp_err_t product_factory_reset_prepare(void);

/*
 * Call immediately after product_storage_initialize() and before opening
 * Agent memory or starting Wi-Fi. A pending reset is completed in the strict
 * order Wi-Fi -> Agent memory -> journal. Every step is separately committed,
 * so interruption only causes an idempotent retry on the next boot.
 *
 * This erases only the prod_wifi and agent_mem namespaces in the encrypted
 * product NVS partition. It never touches nvs_factory, OTA partitions, secure
 * boot state, flash-encryption keys, or device-identity eFuse material.
 */
esp_err_t product_factory_reset_resume(
    product_factory_reset_result_t *result);

#ifdef __cplusplus
}
#endif
