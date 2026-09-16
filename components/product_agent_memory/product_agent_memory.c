#include "product_agent_memory.h"

#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "nvs.h"
#include "product_agent_memory_core.h"
#include "product_storage.h"

static const char *TAG = "agent_memory";
static const char *PARTITION = "nvs";
static const char *NAMESPACE = "agent_mem";
static const char *SLOT_KEYS[2] = {"slot0", "slot1"};

_Static_assert((int)PRODUCT_AGENT_MEMORY_ITEM_LIMIT ==
                   (int)PRODUCT_AGENT_MEMORY_MAX_ITEMS,
               "public and core item limits must match");
_Static_assert(PRODUCT_AGENT_MEMORY_KEY_BYTES ==
                   PRODUCT_AGENT_MEMORY_KEY_MAX + 1,
               "public and core key sizes must match");
_Static_assert(PRODUCT_AGENT_MEMORY_VALUE_BYTES ==
                   PRODUCT_AGENT_MEMORY_VALUE_MAX + 1,
               "public and core value sizes must match");
_Static_assert((int)PRODUCT_AGENT_MEMORY_PREFERENCE ==
                   (int)PRODUCT_AGENT_MEMORY_CATEGORY_PREFERENCE &&
                   (int)PRODUCT_AGENT_MEMORY_PROFILE ==
                       (int)PRODUCT_AGENT_MEMORY_CATEGORY_PROFILE,
               "public and core categories must match");

struct product_agent_memory {
    nvs_handle_t nvs;
    SemaphoreHandle_t mutex;
    product_agent_memory_core_state_t state;
    uint32_t mutations_this_boot;
    uint32_t mirror_failures;
    bool storage_encrypted;
    bool degraded;
};

static void secure_zero(void *memory, size_t size)
{
    volatile uint8_t *bytes = memory;
    while (bytes && size > 0) {
        *bytes++ = 0;
        --size;
    }
}

static esp_err_t core_error(product_agent_memory_core_result_t result)
{
    switch (result) {
    case PRODUCT_AGENT_MEMORY_CORE_OK:
        return ESP_OK;
    case PRODUCT_AGENT_MEMORY_CORE_NOT_FOUND:
        return ESP_ERR_NOT_FOUND;
    case PRODUCT_AGENT_MEMORY_CORE_FULL:
        return ESP_ERR_NO_MEM;
    case PRODUCT_AGENT_MEMORY_CORE_CORRUPT:
        return ESP_ERR_INVALID_CRC;
    case PRODUCT_AGENT_MEMORY_CORE_BUFFER_TOO_SMALL:
        return ESP_ERR_INVALID_SIZE;
    case PRODUCT_AGENT_MEMORY_CORE_DIVERGED:
    case PRODUCT_AGENT_MEMORY_CORE_GENERATION_EXHAUSTED:
    case PRODUCT_AGENT_MEMORY_CORE_BINDING_STALE:
        return ESP_ERR_INVALID_STATE;
    case PRODUCT_AGENT_MEMORY_CORE_INVALID:
    default:
        return ESP_ERR_INVALID_ARG;
    }
}

static esp_err_t load_slot(nvs_handle_t nvs,
                           const char *key,
                           uint8_t **blob,
                           size_t *blob_size)
{
    *blob = NULL;
    *blob_size = 0;
    size_t size = 0;
    esp_err_t error = nvs_get_blob(nvs, key, NULL, &size);
    if (error == ESP_ERR_NVS_NOT_FOUND) {
        return ESP_OK;
    }
    if (error == ESP_ERR_NVS_TYPE_MISMATCH ||
        error == ESP_ERR_NVS_INVALID_LENGTH) {
        size = 0;
    } else if (error != ESP_OK) {
        return error;
    }
    if (error != ESP_OK || size == 0 ||
        size > PRODUCT_AGENT_MEMORY_BLOB_MAX) {
        /* Preserve slot presence without allocating or reading an unbounded
         * value. The core decoder will mark this one-byte sentinel invalid,
         * allowing the other slot to recover independently. */
        uint8_t *invalid = calloc(1, 1);
        if (!invalid) {
            return ESP_ERR_NO_MEM;
        }
        *blob = invalid;
        *blob_size = 1;
        return ESP_OK;
    }
    uint8_t *loaded = malloc(size);
    if (!loaded) {
        return ESP_ERR_NO_MEM;
    }
    size_t actual = size;
    error = nvs_get_blob(nvs, key, loaded, &actual);
    if (error == ESP_ERR_NVS_TYPE_MISMATCH ||
        error == ESP_ERR_NVS_INVALID_LENGTH || actual != size) {
        secure_zero(loaded, size);
        free(loaded);
        loaded = calloc(1, 1);
        if (!loaded) {
            return ESP_ERR_NO_MEM;
        }
        *blob = loaded;
        *blob_size = 1;
        return ESP_OK;
    }
    if (error != ESP_OK) {
        secure_zero(loaded, size);
        free(loaded);
        return error;
    }
    *blob = loaded;
    *blob_size = size;
    return ESP_OK;
}

esp_err_t product_agent_memory_open(product_agent_memory_handle_t *out_memory)
{
    product_agent_memory_handle_t memory = NULL;
    uint8_t *slots[2] = {NULL, NULL};
    size_t sizes[2] = {0, 0};
    product_agent_memory_core_selection_t selection;
    product_storage_status_t storage;
    esp_err_t error;
    if (!out_memory) {
        return ESP_ERR_INVALID_ARG;
    }
    *out_memory = NULL;
    error = product_storage_require_ready();
    if (error != ESP_OK) {
        return error;
    }
    error = product_storage_get_status(&storage);
    if (error != ESP_OK) {
        return error;
    }
    memory = calloc(1, sizeof(*memory));
    if (!memory) {
        return ESP_ERR_NO_MEM;
    }
    memory->mutex = xSemaphoreCreateMutex();
    if (!memory->mutex) {
        free(memory);
        return ESP_ERR_NO_MEM;
    }
    error = nvs_open_from_partition(PARTITION, NAMESPACE, NVS_READWRITE,
                                    &memory->nvs);
    if (error != ESP_OK) {
        vSemaphoreDelete(memory->mutex);
        free(memory);
        return error;
    }
    for (int i = 0; i < 2 && error == ESP_OK; ++i) {
        error = load_slot(memory->nvs, SLOT_KEYS[i], &slots[i], &sizes[i]);
    }
    if (error == ESP_OK) {
        error = core_error(product_agent_memory_core_select(
            slots[0], sizes[0], slots[1], sizes[1], &memory->state,
            &selection));
    }
    secure_zero(slots[0], sizes[0]);
    secure_zero(slots[1], sizes[1]);
    free(slots[0]);
    free(slots[1]);
    if (error != ESP_OK) {
        nvs_close(memory->nvs);
        vSemaphoreDelete(memory->mutex);
        memset(memory, 0, sizeof(*memory));
        free(memory);
        return error;
    }
    memory->storage_encrypted = storage.credentials_encrypted;
    memory->degraded = selection.degraded;
    if (!memory->storage_encrypted) {
        ESP_LOGW(TAG, "development profile: Agent memory NVS is plaintext");
    }
    if (memory->degraded) {
        ESP_LOGW(TAG, "opened from one valid/newer memory slot");
    }
    *out_memory = memory;
    return ESP_OK;
}

static bool lock_memory(product_agent_memory_handle_t memory)
{
    return memory && memory->mutex &&
           xSemaphoreTake(memory->mutex, portMAX_DELAY) == pdTRUE;
}

static esp_err_t persist_locked(
    product_agent_memory_handle_t memory,
    const product_agent_memory_core_state_t *candidate)
{
    uint8_t *blob = malloc(PRODUCT_AGENT_MEMORY_BLOB_MAX);
    if (!blob) {
        return ESP_ERR_NO_MEM;
    }
    size_t blob_size = 0;
    esp_err_t error = core_error(product_agent_memory_core_encode(
        candidate, blob, PRODUCT_AGENT_MEMORY_BLOB_MAX, &blob_size));
    if (error != ESP_OK) {
        secure_zero(blob, PRODUCT_AGENT_MEMORY_BLOB_MAX);
        free(blob);
        return error;
    }
    const int primary = (int)(candidate->generation & 1U);
    error = nvs_set_blob(memory->nvs, SLOT_KEYS[primary], blob, blob_size);
    if (error == ESP_OK) {
        error = nvs_commit(memory->nvs);
    }
    if (error != ESP_OK) {
        secure_zero(blob, PRODUCT_AGENT_MEMORY_BLOB_MAX);
        free(blob);
        return error;
    }

    memory->state = *candidate;
    ++memory->mutations_this_boot;
    error = nvs_set_blob(memory->nvs, SLOT_KEYS[1 - primary], blob, blob_size);
    if (error == ESP_OK) {
        error = nvs_commit(memory->nvs);
    }
    secure_zero(blob, PRODUCT_AGENT_MEMORY_BLOB_MAX);
    free(blob);
    if (error != ESP_OK) {
        ++memory->mirror_failures;
        memory->degraded = true;
        ESP_LOGE(TAG, "memory primary committed but mirror failed: %s",
                 esp_err_to_name(error));
        /* The primary commit is already durable; report the mutation as
         * accepted and expose reduced redundancy through stats. */
        return ESP_OK;
    }
    memory->degraded = false;
    return ESP_OK;
}

esp_err_t product_agent_memory_reconcile_binding(
    product_agent_memory_handle_t memory,
    const char *binding_id,
    uint64_t binding_revision)
{
    if (!binding_id || !lock_memory(memory)) {
        return ESP_ERR_INVALID_ARG;
    }
    product_agent_memory_core_state_t *candidate =
        malloc(sizeof(*candidate));
    if (!candidate) {
        xSemaphoreGive(memory->mutex);
        return ESP_ERR_NO_MEM;
    }
    *candidate = memory->state;
    const uint32_t previous_generation = candidate->generation;
    esp_err_t error = core_error(product_agent_memory_core_reconcile_binding(
        candidate, binding_id, binding_revision));
    if (error == ESP_OK && candidate->generation != previous_generation) {
        error = persist_locked(memory, candidate);
    }
    secure_zero(candidate, sizeof(*candidate));
    free(candidate);
    xSemaphoreGive(memory->mutex);
    return error;
}

esp_err_t product_agent_memory_list(product_agent_memory_handle_t memory,
                                    product_agent_memory_entry_t *entries,
                                    size_t entry_capacity,
                                    size_t *entry_count)
{
    if (!entry_count || (entry_capacity > 0 && !entries) ||
        !lock_memory(memory)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!product_agent_memory_core_is_bound(&memory->state)) {
        xSemaphoreGive(memory->mutex);
        return ESP_ERR_INVALID_STATE;
    }
    const size_t count = memory->state.count;
    *entry_count = count;
    if (entry_capacity < count) {
        xSemaphoreGive(memory->mutex);
        return ESP_ERR_INVALID_SIZE;
    }
    for (size_t i = 0; i < count; ++i) {
        entries[i].category =
            (product_agent_memory_category_t)memory->state.items[i].category;
        strcpy(entries[i].key, memory->state.items[i].key);
        entries[i].revision = memory->state.items[i].revision;
    }
    xSemaphoreGive(memory->mutex);
    return ESP_OK;
}

esp_err_t product_agent_memory_get(product_agent_memory_handle_t memory,
                                   const char *key,
                                   product_agent_memory_category_t *category,
                                   char *value,
                                   size_t value_size,
                                   uint32_t *revision)
{
    if (!key || !category || !value || value_size == 0 || !revision ||
        !lock_memory(memory)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!product_agent_memory_core_is_bound(&memory->state)) {
        xSemaphoreGive(memory->mutex);
        return ESP_ERR_INVALID_STATE;
    }
    const product_agent_memory_core_item_t *item =
        product_agent_memory_core_find(&memory->state, key);
    if (!item) {
        xSemaphoreGive(memory->mutex);
        return product_agent_memory_core_key_allowed(key)
                   ? ESP_ERR_NOT_FOUND
                   : ESP_ERR_INVALID_ARG;
    }
    const size_t required = strlen(item->value) + 1;
    if (value_size < required) {
        xSemaphoreGive(memory->mutex);
        return ESP_ERR_INVALID_SIZE;
    }
    *category = (product_agent_memory_category_t)item->category;
    strcpy(value, item->value);
    *revision = item->revision;
    xSemaphoreGive(memory->mutex);
    return ESP_OK;
}

static esp_err_t begin_mutation(product_agent_memory_handle_t memory,
                                product_agent_memory_core_state_t **candidate)
{
    if (!memory || !candidate) {
        return ESP_ERR_INVALID_ARG;
    }
    if (memory->mutations_this_boot >=
        PRODUCT_AGENT_MEMORY_MUTATIONS_PER_BOOT_LIMIT) {
        return ESP_ERR_INVALID_STATE;
    }
    *candidate = malloc(sizeof(**candidate));
    if (!*candidate) {
        return ESP_ERR_NO_MEM;
    }
    **candidate = memory->state;
    return ESP_OK;
}

esp_err_t product_agent_memory_put(product_agent_memory_handle_t memory,
                                   product_agent_memory_category_t category,
                                   const char *key,
                                   const char *value)
{
    if (!key || !value || !lock_memory(memory)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!product_agent_memory_core_is_bound(&memory->state)) {
        xSemaphoreGive(memory->mutex);
        return ESP_ERR_INVALID_STATE;
    }
    product_agent_memory_core_state_t *candidate = NULL;
    esp_err_t error = begin_mutation(memory, &candidate);
    if (error == ESP_OK) {
        error = core_error(product_agent_memory_core_put(
            candidate, (product_agent_memory_core_category_t)category,
            key, value));
    }
    if (error == ESP_OK) {
        error = persist_locked(memory, candidate);
    }
    secure_zero(candidate, candidate ? sizeof(*candidate) : 0);
    free(candidate);
    xSemaphoreGive(memory->mutex);
    return error;
}

esp_err_t product_agent_memory_forget(product_agent_memory_handle_t memory,
                                      const char *key)
{
    if (!key || !lock_memory(memory)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!product_agent_memory_core_is_bound(&memory->state)) {
        xSemaphoreGive(memory->mutex);
        return ESP_ERR_INVALID_STATE;
    }
    product_agent_memory_core_state_t *candidate = NULL;
    esp_err_t error = begin_mutation(memory, &candidate);
    if (error == ESP_OK) {
        error = core_error(product_agent_memory_core_forget(candidate, key));
    }
    if (error == ESP_OK) {
        error = persist_locked(memory, candidate);
    }
    secure_zero(candidate, candidate ? sizeof(*candidate) : 0);
    free(candidate);
    xSemaphoreGive(memory->mutex);
    return error;
}

esp_err_t product_agent_memory_clear(product_agent_memory_handle_t memory)
{
    if (!lock_memory(memory)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!product_agent_memory_core_is_bound(&memory->state)) {
        xSemaphoreGive(memory->mutex);
        return ESP_ERR_INVALID_STATE;
    }
    product_agent_memory_core_state_t *candidate = NULL;
    esp_err_t error = begin_mutation(memory, &candidate);
    if (error == ESP_OK) {
        error = core_error(product_agent_memory_core_clear(candidate));
    }
    if (error == ESP_OK) {
        error = persist_locked(memory, candidate);
    }
    secure_zero(candidate, candidate ? sizeof(*candidate) : 0);
    free(candidate);
    xSemaphoreGive(memory->mutex);
    return error;
}

esp_err_t product_agent_memory_get_stats(
    product_agent_memory_handle_t memory,
    product_agent_memory_stats_t *stats)
{
    if (!stats || !lock_memory(memory)) {
        return ESP_ERR_INVALID_ARG;
    }
    *stats = (product_agent_memory_stats_t){
        .generation = memory->state.generation,
        .mutations_this_boot = memory->mutations_this_boot,
        .mirror_failures = memory->mirror_failures,
        .item_count = memory->state.count,
        .binding_revision = memory->state.binding_revision,
        .binding_active = product_agent_memory_core_is_bound(&memory->state),
        .storage_encrypted = memory->storage_encrypted,
        .degraded_redundancy = memory->degraded,
    };
    xSemaphoreGive(memory->mutex);
    return ESP_OK;
}

esp_err_t product_agent_memory_close(product_agent_memory_handle_t memory)
{
    if (!memory || !memory->mutex) {
        return ESP_ERR_INVALID_ARG;
    }
    if (xSemaphoreTake(memory->mutex, portMAX_DELAY) != pdTRUE) {
        return ESP_ERR_INVALID_STATE;
    }
    nvs_close(memory->nvs);
    memset(&memory->state, 0, sizeof(memory->state));
    SemaphoreHandle_t mutex = memory->mutex;
    memory->mutex = NULL;
    xSemaphoreGive(mutex);
    vSemaphoreDelete(mutex);
    memset(memory, 0, sizeof(*memory));
    free(memory);
    return ESP_OK;
}
