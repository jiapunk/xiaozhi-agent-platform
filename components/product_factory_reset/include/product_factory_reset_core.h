#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    PRODUCT_FACTORY_RESET_JOURNAL_BYTES = 12,
};

typedef enum {
    PRODUCT_FACTORY_RESET_PHASE_NONE = 0,
    PRODUCT_FACTORY_RESET_PHASE_PREPARED = 1,
    PRODUCT_FACTORY_RESET_PHASE_WIFI_CLEARED = 2,
    PRODUCT_FACTORY_RESET_PHASE_MEMORY_CLEARED = 3,
} product_factory_reset_phase_t;

typedef enum {
    PRODUCT_FACTORY_RESET_ACTION_NONE = 0,
    PRODUCT_FACTORY_RESET_ACTION_ERASE_WIFI,
    PRODUCT_FACTORY_RESET_ACTION_ERASE_MEMORY,
    PRODUCT_FACTORY_RESET_ACTION_CLEAR_JOURNAL,
} product_factory_reset_action_t;

bool product_factory_reset_core_encode(
    product_factory_reset_phase_t phase,
    uint8_t output[PRODUCT_FACTORY_RESET_JOURNAL_BYTES]);

bool product_factory_reset_core_decode(
    const uint8_t *input,
    size_t input_size,
    product_factory_reset_phase_t *phase);

product_factory_reset_action_t product_factory_reset_core_next_action(
    product_factory_reset_phase_t phase);

bool product_factory_reset_core_advance(
    product_factory_reset_phase_t phase,
    product_factory_reset_action_t completed_action,
    product_factory_reset_phase_t *next_phase);

#ifdef __cplusplus
}
#endif
