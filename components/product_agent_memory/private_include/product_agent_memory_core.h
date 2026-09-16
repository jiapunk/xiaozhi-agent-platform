#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    PRODUCT_AGENT_MEMORY_MAX_ITEMS = 8,
    PRODUCT_AGENT_MEMORY_KEY_MAX = 32,
    PRODUCT_AGENT_MEMORY_VALUE_MAX = 160,
    PRODUCT_AGENT_MEMORY_BLOB_MAX = 2048,
    PRODUCT_AGENT_MEMORY_BINDING_ID_MAX = 22,
};

typedef enum {
    PRODUCT_AGENT_MEMORY_CATEGORY_PREFERENCE = 1,
    PRODUCT_AGENT_MEMORY_CATEGORY_PROFILE = 2,
} product_agent_memory_core_category_t;

typedef enum {
    PRODUCT_AGENT_MEMORY_CORE_OK = 0,
    PRODUCT_AGENT_MEMORY_CORE_INVALID,
    PRODUCT_AGENT_MEMORY_CORE_NOT_FOUND,
    PRODUCT_AGENT_MEMORY_CORE_FULL,
    PRODUCT_AGENT_MEMORY_CORE_CORRUPT,
    PRODUCT_AGENT_MEMORY_CORE_DIVERGED,
    PRODUCT_AGENT_MEMORY_CORE_GENERATION_EXHAUSTED,
    PRODUCT_AGENT_MEMORY_CORE_BUFFER_TOO_SMALL,
    PRODUCT_AGENT_MEMORY_CORE_BINDING_STALE,
} product_agent_memory_core_result_t;

typedef struct {
    product_agent_memory_core_category_t category;
    char key[PRODUCT_AGENT_MEMORY_KEY_MAX + 1];
    char value[PRODUCT_AGENT_MEMORY_VALUE_MAX + 1];
    uint32_t revision;
} product_agent_memory_core_item_t;

typedef struct {
    uint32_t generation;
    uint8_t count;
    char binding_id[PRODUCT_AGENT_MEMORY_BINDING_ID_MAX + 1];
    uint64_t binding_revision;
    product_agent_memory_core_item_t items[PRODUCT_AGENT_MEMORY_MAX_ITEMS];
} product_agent_memory_core_state_t;

typedef struct {
    bool degraded;
    bool slot_present[2];
    bool slot_valid[2];
    int selected_slot;
} product_agent_memory_core_selection_t;

void product_agent_memory_core_init(product_agent_memory_core_state_t *state);

bool product_agent_memory_core_key_allowed(const char *key);
bool product_agent_memory_core_value_allowed(const char *value);
bool product_agent_memory_core_binding_id_allowed(const char *value);
bool product_agent_memory_core_is_bound(
    const product_agent_memory_core_state_t *state);

product_agent_memory_core_result_t product_agent_memory_core_reconcile_binding(
    product_agent_memory_core_state_t *state,
    const char *binding_id,
    uint64_t binding_revision);

product_agent_memory_core_result_t product_agent_memory_core_encode(
    const product_agent_memory_core_state_t *state,
    uint8_t *output,
    size_t output_capacity,
    size_t *output_size);

product_agent_memory_core_result_t product_agent_memory_core_decode(
    const uint8_t *input,
    size_t input_size,
    product_agent_memory_core_state_t *state);

product_agent_memory_core_result_t product_agent_memory_core_select(
    const uint8_t *slot0,
    size_t slot0_size,
    const uint8_t *slot1,
    size_t slot1_size,
    product_agent_memory_core_state_t *state,
    product_agent_memory_core_selection_t *selection);

product_agent_memory_core_result_t product_agent_memory_core_put(
    product_agent_memory_core_state_t *state,
    product_agent_memory_core_category_t category,
    const char *key,
    const char *value);

product_agent_memory_core_result_t product_agent_memory_core_forget(
    product_agent_memory_core_state_t *state,
    const char *key);

product_agent_memory_core_result_t product_agent_memory_core_clear(
    product_agent_memory_core_state_t *state);

const product_agent_memory_core_item_t *product_agent_memory_core_find(
    const product_agent_memory_core_state_t *state,
    const char *key);

#ifdef __cplusplus
}
#endif
