#include "product_factory_reset_core.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_journal_round_trip_and_corruption(void)
{
    const product_factory_reset_phase_t phases[] = {
        PRODUCT_FACTORY_RESET_PHASE_PREPARED,
        PRODUCT_FACTORY_RESET_PHASE_WIFI_CLEARED,
        PRODUCT_FACTORY_RESET_PHASE_MEMORY_CLEARED,
    };
    for (size_t index = 0; index < sizeof(phases) / sizeof(phases[0]);
         ++index) {
        uint8_t blob[PRODUCT_FACTORY_RESET_JOURNAL_BYTES] = {0};
        product_factory_reset_phase_t decoded =
            PRODUCT_FACTORY_RESET_PHASE_NONE;
        assert(product_factory_reset_core_encode(phases[index], blob));
        assert(product_factory_reset_core_decode(blob, sizeof(blob),
                                                 &decoded));
        assert(decoded == phases[index]);
        blob[index] ^= UINT8_C(0x40);
        assert(!product_factory_reset_core_decode(blob, sizeof(blob),
                                                  &decoded));
    }
    uint8_t blob[PRODUCT_FACTORY_RESET_JOURNAL_BYTES] = {0};
    assert(!product_factory_reset_core_encode(
        PRODUCT_FACTORY_RESET_PHASE_NONE, blob));
    assert(!product_factory_reset_core_decode(NULL, sizeof(blob), NULL));
}

static void test_exact_erase_order(void)
{
    product_factory_reset_phase_t phase =
        PRODUCT_FACTORY_RESET_PHASE_PREPARED;
    product_factory_reset_phase_t next =
        PRODUCT_FACTORY_RESET_PHASE_NONE;
    assert(product_factory_reset_core_next_action(phase) ==
           PRODUCT_FACTORY_RESET_ACTION_ERASE_WIFI);
    assert(product_factory_reset_core_advance(
        phase, PRODUCT_FACTORY_RESET_ACTION_ERASE_WIFI, &next));
    phase = next;
    assert(product_factory_reset_core_next_action(phase) ==
           PRODUCT_FACTORY_RESET_ACTION_ERASE_MEMORY);
    assert(product_factory_reset_core_advance(
        phase, PRODUCT_FACTORY_RESET_ACTION_ERASE_MEMORY, &next));
    phase = next;
    assert(product_factory_reset_core_next_action(phase) ==
           PRODUCT_FACTORY_RESET_ACTION_CLEAR_JOURNAL);
    assert(product_factory_reset_core_advance(
        phase, PRODUCT_FACTORY_RESET_ACTION_CLEAR_JOURNAL, &next));
    assert(next == PRODUCT_FACTORY_RESET_PHASE_NONE);
    assert(!product_factory_reset_core_advance(
        PRODUCT_FACTORY_RESET_PHASE_PREPARED,
        PRODUCT_FACTORY_RESET_ACTION_ERASE_MEMORY, &next));
}

static void simulate_one_power_cut(unsigned cut_checkpoint)
{
    product_factory_reset_phase_t persisted =
        PRODUCT_FACTORY_RESET_PHASE_PREPARED;
    bool journal_present = true;
    bool wifi_present = true;
    bool memory_present = true;
    bool cut_used = false;
    unsigned checkpoint = 0;
    unsigned boots = 0;

    while (journal_present) {
        assert(++boots < 16);
        const product_factory_reset_action_t action =
            product_factory_reset_core_next_action(persisted);
        if (action == PRODUCT_FACTORY_RESET_ACTION_ERASE_WIFI) {
            wifi_present = false;
        } else if (action == PRODUCT_FACTORY_RESET_ACTION_ERASE_MEMORY) {
            assert(!wifi_present);
            memory_present = false;
        } else {
            assert(action == PRODUCT_FACTORY_RESET_ACTION_CLEAR_JOURNAL);
            assert(!wifi_present && !memory_present);
        }

        /* Cut after the idempotent erase but before its journal commit. */
        if (!cut_used && checkpoint++ == cut_checkpoint) {
            cut_used = true;
            continue;
        }

        product_factory_reset_phase_t next = persisted;
        assert(product_factory_reset_core_advance(persisted, action,
                                                  &next));
        if (next == PRODUCT_FACTORY_RESET_PHASE_NONE) {
            journal_present = false;
        } else {
            persisted = next;
        }

        /* Cut after the journal commit; the next boot resumes the next step. */
        if (!cut_used && checkpoint++ == cut_checkpoint) {
            cut_used = true;
            continue;
        }
    }
    assert(!wifi_present);
    assert(!memory_present);
    assert(!journal_present);
}

static void test_every_power_cut_boundary_converges(void)
{
    for (unsigned checkpoint = 0; checkpoint < 6; ++checkpoint) {
        simulate_one_power_cut(checkpoint);
    }
}

int main(void)
{
    test_journal_round_trip_and_corruption();
    test_exact_erase_order();
    test_every_power_cut_boundary_converges();
    puts("product_factory_reset_core: all tests passed");
    return 0;
}
