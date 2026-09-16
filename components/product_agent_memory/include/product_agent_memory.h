#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    PRODUCT_AGENT_MEMORY_ITEM_LIMIT = 8,
    PRODUCT_AGENT_MEMORY_KEY_BYTES = 33,
    PRODUCT_AGENT_MEMORY_VALUE_BYTES = 161,
    PRODUCT_AGENT_MEMORY_MUTATIONS_PER_BOOT_LIMIT = 128,
    PRODUCT_AGENT_MEMORY_BINDING_ID_BYTES = 23,
};

typedef struct product_agent_memory *product_agent_memory_handle_t;

typedef enum {
    PRODUCT_AGENT_MEMORY_PREFERENCE = 1,
    PRODUCT_AGENT_MEMORY_PROFILE = 2,
} product_agent_memory_category_t;

typedef struct {
    product_agent_memory_category_t category;
    char key[PRODUCT_AGENT_MEMORY_KEY_BYTES];
    uint32_t revision;
} product_agent_memory_entry_t;

typedef struct {
    uint32_t generation;
    uint32_t mutations_this_boot;
    uint32_t mirror_failures;
    size_t item_count;
    uint64_t binding_revision;
    bool binding_active;
    bool storage_encrypted;
    bool degraded_redundancy;
} product_agent_memory_stats_t;

/*
 * Unlocks memory for the authenticated cloud ownership binding. The first
 * binding and every strictly newer binding atomically clear all prior items;
 * the same binding is idempotent, and stale/conflicting epochs fail closed.
 */
esp_err_t product_agent_memory_reconcile_binding(
    product_agent_memory_handle_t memory,
    const char *binding_id,
    uint64_t binding_revision);

/*
 * Opens the product-owned, bounded Agent memory namespace in the already
 * initialized product NVS partition. Production confidentiality depends on
 * product_storage's factory-provisioned encrypted-NVS profile.
 */
esp_err_t product_agent_memory_open(product_agent_memory_handle_t *out_memory);

esp_err_t product_agent_memory_list(product_agent_memory_handle_t memory,
                                    product_agent_memory_entry_t *entries,
                                    size_t entry_capacity,
                                    size_t *entry_count);

esp_err_t product_agent_memory_get(product_agent_memory_handle_t memory,
                                   const char *key,
                                   product_agent_memory_category_t *category,
                                   char *value,
                                   size_t value_size,
                                   uint32_t *revision);

/* These mutation APIs are for trusted product code. LLM adapters must gate
 * every call with product-owned, request-bound user consent. */
esp_err_t product_agent_memory_put(product_agent_memory_handle_t memory,
                                   product_agent_memory_category_t category,
                                   const char *key,
                                   const char *value);

esp_err_t product_agent_memory_forget(product_agent_memory_handle_t memory,
                                      const char *key);

/* Logical clear only. Physical remnants require encrypted NVS and the
 * product's separately reviewed factory-reset/partition-erase procedure. */
esp_err_t product_agent_memory_clear(product_agent_memory_handle_t memory);

esp_err_t product_agent_memory_get_stats(
    product_agent_memory_handle_t memory,
    product_agent_memory_stats_t *stats);

/* The lifecycle owner must exclude concurrent calls before closing. */
esp_err_t product_agent_memory_close(product_agent_memory_handle_t memory);

#ifdef __cplusplus
}
#endif
