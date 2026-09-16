#include "product_agent_memory_core.h"

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

static const char BINDING_A[] = "AAECAwQFBgcICQoLDA0ODw";
static const char BINDING_B[] = "EBAQEBAQEBAQEBAQEBAQEA";

static uint32_t crc32_zero_checksum(const uint8_t *data, size_t size)
{
    uint32_t crc = UINT32_MAX;
    for (size_t i = 0; i < size; ++i) {
        uint8_t value = i >= 16 && i < 20 ? 0 : data[i];
        crc ^= value;
        for (unsigned bit = 0; bit < 8; ++bit) {
            uint32_t mask = (uint32_t)-(int32_t)(crc & 1U);
            crc = (crc >> 1) ^ (0xedb88320U & mask);
        }
    }
    return ~crc;
}

static void write_u32_le(uint8_t *output, uint32_t value)
{
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
    output[2] = (uint8_t)(value >> 16);
    output[3] = (uint8_t)(value >> 24);
}

static void write_u16_le(uint8_t *output, uint16_t value)
{
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
}

static size_t encode(const product_agent_memory_core_state_t *state,
                     uint8_t *blob)
{
    size_t size = 0;
    assert(product_agent_memory_core_encode(
               state, blob, PRODUCT_AGENT_MEMORY_BLOB_MAX, &size) ==
           PRODUCT_AGENT_MEMORY_CORE_OK);
    return size;
}

static void test_inputs_and_mutations(void)
{
    product_agent_memory_core_state_t state;
    product_agent_memory_core_init(&state);
	assert(!product_agent_memory_core_is_bound(&state));
	assert(product_agent_memory_core_put(
	           &state, PRODUCT_AGENT_MEMORY_CATEGORY_PREFERENCE,
	           "language", "English") == PRODUCT_AGENT_MEMORY_CORE_INVALID);
	assert(product_agent_memory_core_reconcile_binding(
	           &state, BINDING_A, 1) == PRODUCT_AGENT_MEMORY_CORE_OK);
	assert(product_agent_memory_core_is_bound(&state));
    assert(product_agent_memory_core_key_allowed("language"));
    assert(product_agent_memory_core_key_allowed("favorite.color"));
    assert(!product_agent_memory_core_key_allowed("Language"));
    assert(!product_agent_memory_core_key_allowed("api_token"));
    assert(!product_agent_memory_core_key_allowed("home_address"));
    assert(!product_agent_memory_core_key_allowed("medical_notes"));
    assert(product_agent_memory_core_value_allowed("繁體中文"));
    assert(!product_agent_memory_core_value_allowed("two\nlines"));
    assert(!product_agent_memory_core_value_allowed("Bearer abc"));
    assert(!product_agent_memory_core_value_allowed("password=hunter2"));
    const char invalid_utf8[] = {(char)0xc0, (char)0xaf, '\0'};
    assert(!product_agent_memory_core_value_allowed(invalid_utf8));

    assert(product_agent_memory_core_put(
               &state, PRODUCT_AGENT_MEMORY_CATEGORY_PREFERENCE,
               "language", "繁體中文") == PRODUCT_AGENT_MEMORY_CORE_OK);
    assert(product_agent_memory_core_put(
               &state, PRODUCT_AGENT_MEMORY_CATEGORY_PROFILE,
               "display_name", "小智") == PRODUCT_AGENT_MEMORY_CORE_OK);
    assert(state.generation == 3 && state.count == 2);
    assert(strcmp(state.items[0].key, "display_name") == 0);
    const product_agent_memory_core_item_t *item =
        product_agent_memory_core_find(&state, "language");
    assert(item && strcmp(item->value, "繁體中文") == 0 &&
           item->revision == 2);
    assert(product_agent_memory_core_put(
               &state, PRODUCT_AGENT_MEMORY_CATEGORY_PREFERENCE,
               "language", "English") == PRODUCT_AGENT_MEMORY_CORE_OK);
    item = product_agent_memory_core_find(&state, "language");
    assert(item && strcmp(item->value, "English") == 0 &&
           item->revision == 4);
    assert(product_agent_memory_core_forget(&state, "missing") ==
           PRODUCT_AGENT_MEMORY_CORE_NOT_FOUND);
    assert(product_agent_memory_core_forget(&state, "display_name") ==
           PRODUCT_AGENT_MEMORY_CORE_OK);
    assert(state.generation == 5 && state.count == 1);
    assert(product_agent_memory_core_clear(&state) ==
           PRODUCT_AGENT_MEMORY_CORE_OK);
    assert(state.generation == 6 && state.count == 0);
}

static void test_round_trip_and_canonical_rejection(void)
{
    product_agent_memory_core_state_t state;
    product_agent_memory_core_state_t decoded;
    uint8_t blob[PRODUCT_AGENT_MEMORY_BLOB_MAX];
    uint8_t second[PRODUCT_AGENT_MEMORY_BLOB_MAX];
    product_agent_memory_core_init(&state);
    assert(product_agent_memory_core_reconcile_binding(
               &state, BINDING_A, 1) == PRODUCT_AGENT_MEMORY_CORE_OK);
    assert(product_agent_memory_core_put(
               &state, PRODUCT_AGENT_MEMORY_CATEGORY_PREFERENCE,
               "voice_speed", "normal") == PRODUCT_AGENT_MEMORY_CORE_OK);
    const size_t size = encode(&state, blob);
    assert(product_agent_memory_core_decode(blob, size, &decoded) ==
           PRODUCT_AGENT_MEMORY_CORE_OK);
    const size_t second_size = encode(&decoded, second);
    assert(size == second_size && memcmp(blob, second, size) == 0);

    second[52 + 4] = 0; /* item revision zero, then repair CRC */
    second[52 + 5] = 0;
    second[52 + 6] = 0;
    second[52 + 7] = 0;
    write_u32_le(second + 16, crc32_zero_checksum(second, second_size));
    assert(product_agent_memory_core_decode(second, second_size, &decoded) ==
           PRODUCT_AGENT_MEMORY_CORE_CORRUPT);

    memcpy(second, blob, size);
    second[size - 1] ^= 1U;
    assert(product_agent_memory_core_decode(second, size, &decoded) ==
           PRODUCT_AGENT_MEMORY_CORE_CORRUPT);
    assert(product_agent_memory_core_decode(blob, size - 1, &decoded) ==
           PRODUCT_AGENT_MEMORY_CORE_CORRUPT);
}

static void test_power_loss_selection(void)
{
    product_agent_memory_core_state_t old_state;
    product_agent_memory_core_state_t new_state;
    product_agent_memory_core_state_t selected;
    product_agent_memory_core_selection_t selection;
    uint8_t old_blob[PRODUCT_AGENT_MEMORY_BLOB_MAX];
    uint8_t new_blob[PRODUCT_AGENT_MEMORY_BLOB_MAX];
    size_t old_size;
    size_t new_size;
    product_agent_memory_core_init(&old_state);
    assert(product_agent_memory_core_reconcile_binding(
               &old_state, BINDING_A, 1) == PRODUCT_AGENT_MEMORY_CORE_OK);
    assert(product_agent_memory_core_put(
               &old_state, PRODUCT_AGENT_MEMORY_CATEGORY_PREFERENCE,
               "language", "English") == PRODUCT_AGENT_MEMORY_CORE_OK);
    new_state = old_state;
    assert(product_agent_memory_core_put(
               &new_state, PRODUCT_AGENT_MEMORY_CATEGORY_PREFERENCE,
               "language", "繁體中文") == PRODUCT_AGENT_MEMORY_CORE_OK);
    old_size = encode(&old_state, old_blob);
    new_size = encode(&new_state, new_blob);

    assert(product_agent_memory_core_select(
               old_blob, old_size, new_blob, new_size, &selected,
               &selection) == PRODUCT_AGENT_MEMORY_CORE_OK);
    assert(selection.degraded && selection.selected_slot == 1 &&
           selected.generation == 3);
    assert(strcmp(product_agent_memory_core_find(&selected, "language")->value,
                  "繁體中文") == 0);

    assert(product_agent_memory_core_select(
               new_blob, new_size, new_blob, new_size, &selected,
               &selection) == PRODUCT_AGENT_MEMORY_CORE_OK);
    assert(!selection.degraded && selected.generation == 3);

    old_blob[old_size - 1] ^= 1U;
    assert(product_agent_memory_core_select(
               old_blob, old_size, new_blob, new_size, &selected,
               &selection) == PRODUCT_AGENT_MEMORY_CORE_OK);
    assert(selection.degraded && selection.slot_valid[1] &&
           !selection.slot_valid[0]);

    assert(product_agent_memory_core_select(
               NULL, 0, NULL, 0, &selected, &selection) ==
           PRODUCT_AGENT_MEMORY_CORE_OK);
    assert(selected.generation == 0 && selected.count == 0 &&
           selection.selected_slot == -1);
}

static void test_divergence_capacity_and_wrap(void)
{
    product_agent_memory_core_state_t left;
    product_agent_memory_core_state_t right;
    product_agent_memory_core_state_t selected;
    product_agent_memory_core_selection_t selection;
    uint8_t left_blob[PRODUCT_AGENT_MEMORY_BLOB_MAX];
    uint8_t right_blob[PRODUCT_AGENT_MEMORY_BLOB_MAX];
    product_agent_memory_core_init(&left);
    product_agent_memory_core_init(&right);
    assert(product_agent_memory_core_reconcile_binding(
               &left, BINDING_A, 1) == PRODUCT_AGENT_MEMORY_CORE_OK);
    assert(product_agent_memory_core_reconcile_binding(
               &right, BINDING_A, 1) == PRODUCT_AGENT_MEMORY_CORE_OK);
    assert(product_agent_memory_core_put(
               &left, PRODUCT_AGENT_MEMORY_CATEGORY_PROFILE,
               "display_name", "A") == PRODUCT_AGENT_MEMORY_CORE_OK);
    assert(product_agent_memory_core_put(
               &right, PRODUCT_AGENT_MEMORY_CATEGORY_PROFILE,
               "display_name", "B") == PRODUCT_AGENT_MEMORY_CORE_OK);
    size_t left_size = encode(&left, left_blob);
    size_t right_size = encode(&right, right_blob);
    assert(product_agent_memory_core_select(
               left_blob, left_size, right_blob, right_size, &selected,
               &selection) == PRODUCT_AGENT_MEMORY_CORE_DIVERGED);

    product_agent_memory_core_init(&left);
    assert(product_agent_memory_core_reconcile_binding(
               &left, BINDING_A, 1) == PRODUCT_AGENT_MEMORY_CORE_OK);
    for (unsigned i = 0; i < PRODUCT_AGENT_MEMORY_MAX_ITEMS; ++i) {
        char key[8];
        snprintf(key, sizeof(key), "item%u", i);
        assert(product_agent_memory_core_put(
                   &left, PRODUCT_AGENT_MEMORY_CATEGORY_PREFERENCE,
                   key, "value") == PRODUCT_AGENT_MEMORY_CORE_OK);
    }
    assert(product_agent_memory_core_put(
               &left, PRODUCT_AGENT_MEMORY_CATEGORY_PREFERENCE,
               "overflow", "value") == PRODUCT_AGENT_MEMORY_CORE_FULL);
    assert(left.count == PRODUCT_AGENT_MEMORY_MAX_ITEMS &&
           left.generation == PRODUCT_AGENT_MEMORY_MAX_ITEMS + 1);

    product_agent_memory_core_init(&left);
    assert(product_agent_memory_core_reconcile_binding(
               &left, BINDING_A, 1) == PRODUCT_AGENT_MEMORY_CORE_OK);
    left.generation = UINT32_MAX;
    assert(product_agent_memory_core_clear(&left) ==
           PRODUCT_AGENT_MEMORY_CORE_GENERATION_EXHAUSTED);
}

static void test_binding_epoch_reconciliation(void)
{
    product_agent_memory_core_state_t state;
    product_agent_memory_core_init(&state);
    assert(product_agent_memory_core_binding_id_allowed(BINDING_A));
    assert(!product_agent_memory_core_binding_id_allowed("bad"));
    assert(product_agent_memory_core_reconcile_binding(
               &state, BINDING_A, (uint64_t)UINT32_MAX + 1) ==
           PRODUCT_AGENT_MEMORY_CORE_INVALID);
    assert(product_agent_memory_core_reconcile_binding(
               &state, BINDING_A, 7) == PRODUCT_AGENT_MEMORY_CORE_OK);
    assert(state.generation == 1 && state.binding_revision == 7);
    assert(product_agent_memory_core_put(
               &state, PRODUCT_AGENT_MEMORY_CATEGORY_PROFILE,
               "display_name", "Alice") == PRODUCT_AGENT_MEMORY_CORE_OK);
    assert(product_agent_memory_core_reconcile_binding(
               &state, BINDING_A, 7) == PRODUCT_AGENT_MEMORY_CORE_OK);
    assert(state.generation == 2 && state.count == 1);
    assert(product_agent_memory_core_reconcile_binding(
               &state, BINDING_B, 7) ==
           PRODUCT_AGENT_MEMORY_CORE_BINDING_STALE);
    assert(product_agent_memory_core_reconcile_binding(
               &state, BINDING_A, 6) ==
           PRODUCT_AGENT_MEMORY_CORE_BINDING_STALE);
    assert(product_agent_memory_core_reconcile_binding(
               &state, BINDING_B, 8) == PRODUCT_AGENT_MEMORY_CORE_OK);
    assert(state.generation == 3 && state.count == 0 &&
           state.binding_revision == 8 &&
           strcmp(state.binding_id, BINDING_B) == 0);
}

static void test_legacy_xam1_migrates_locked_and_empty(void)
{
    const char key[] = "language";
    const char value[] = "English";
    uint8_t blob[64] = {0};
    const size_t size = 20 + 8 + sizeof(key) - 1 + sizeof(value) - 1;
    memcpy(blob, "XAM1", 4);
    blob[4] = 1;
    blob[5] = 1;
    write_u32_le(blob + 8, 5);
    write_u16_le(blob + 12, (uint16_t)(size - 20));
    blob[20] = PRODUCT_AGENT_MEMORY_CATEGORY_PREFERENCE;
    blob[21] = (uint8_t)(sizeof(key) - 1);
    write_u16_le(blob + 22, (uint16_t)(sizeof(value) - 1));
    write_u32_le(blob + 24, 4);
    memcpy(blob + 28, key, sizeof(key) - 1);
    memcpy(blob + 28 + sizeof(key) - 1, value, sizeof(value) - 1);
    write_u32_le(blob + 16, crc32_zero_checksum(blob, size));

    product_agent_memory_core_state_t decoded;
    assert(product_agent_memory_core_decode(blob, size, &decoded) ==
           PRODUCT_AGENT_MEMORY_CORE_OK);
    assert(decoded.generation == 5 && decoded.count == 0 &&
           !product_agent_memory_core_is_bound(&decoded));
    assert(product_agent_memory_core_reconcile_binding(
               &decoded, BINDING_A, 9) == PRODUCT_AGENT_MEMORY_CORE_OK);
    assert(decoded.generation == 6 && decoded.count == 0 &&
           decoded.binding_revision == 9);

    blob[size - 1] ^= 1U;
    assert(product_agent_memory_core_decode(blob, size, &decoded) ==
           PRODUCT_AGENT_MEMORY_CORE_CORRUPT);
}

int main(void)
{
    test_inputs_and_mutations();
    test_round_trip_and_canonical_rejection();
    test_power_loss_selection();
    test_divergence_capacity_and_wrap();
    test_binding_epoch_reconciliation();
    test_legacy_xam1_migrates_locked_and_empty();
    puts("product_agent_memory_core: all tests passed");
    return 0;
}
