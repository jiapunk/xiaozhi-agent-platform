#include "product_factory_reset.h"

#include <string.h>

#include "nvs.h"
#include "product_storage.h"

static const char *PARTITION = "nvs";
static const char *JOURNAL_NAMESPACE = "factory_rst";
static const char *JOURNAL_KEY = "intent";
static const char *WIFI_NAMESPACE = "prod_wifi";
static const char *MEMORY_NAMESPACE = "agent_mem";

static esp_err_t read_phase(nvs_handle_t journal,
                            product_factory_reset_phase_t *phase,
                            bool *present)
{
    if (!phase || !present) {
        return ESP_ERR_INVALID_ARG;
    }
    *phase = PRODUCT_FACTORY_RESET_PHASE_NONE;
    *present = false;
    size_t size = 0;
    esp_err_t error = nvs_get_blob(journal, JOURNAL_KEY, NULL, &size);
    if (error == ESP_ERR_NVS_NOT_FOUND) {
        return ESP_OK;
    }
    if (error != ESP_OK) {
        return error;
    }
    if (size != PRODUCT_FACTORY_RESET_JOURNAL_BYTES) {
        return ESP_ERR_INVALID_CRC;
    }
    uint8_t blob[PRODUCT_FACTORY_RESET_JOURNAL_BYTES] = {0};
    error = nvs_get_blob(journal, JOURNAL_KEY, blob, &size);
    if (error != ESP_OK) {
        return error;
    }
    if (!product_factory_reset_core_decode(blob, size, phase)) {
        return ESP_ERR_INVALID_CRC;
    }
    *present = true;
    return ESP_OK;
}

static esp_err_t write_phase(nvs_handle_t journal,
                             product_factory_reset_phase_t phase)
{
    uint8_t blob[PRODUCT_FACTORY_RESET_JOURNAL_BYTES] = {0};
    if (!product_factory_reset_core_encode(phase, blob)) {
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t error = nvs_set_blob(journal, JOURNAL_KEY, blob,
                                   sizeof(blob));
    if (error == ESP_OK) {
        error = nvs_commit(journal);
    }
    memset(blob, 0, sizeof(blob));
    return error;
}

static esp_err_t erase_namespace(const char *name)
{
    nvs_handle_t nvs = 0;
    esp_err_t error = nvs_open_from_partition(
        PARTITION, name, NVS_READWRITE, &nvs);
    if (error == ESP_OK) {
        error = nvs_erase_all(nvs);
    }
    if (error == ESP_OK) {
        error = nvs_commit(nvs);
    }
    if (nvs != 0) {
        nvs_close(nvs);
    }
    return error;
}

esp_err_t product_factory_reset_prepare(void)
{
    esp_err_t error = product_storage_require_ready();
    if (error != ESP_OK) {
        return error;
    }
    nvs_handle_t journal = 0;
    error = nvs_open_from_partition(PARTITION, JOURNAL_NAMESPACE,
                                    NVS_READWRITE, &journal);
    product_factory_reset_phase_t phase =
        PRODUCT_FACTORY_RESET_PHASE_NONE;
    bool present = false;
    if (error == ESP_OK) {
        error = read_phase(journal, &phase, &present);
    }
    if (error == ESP_OK && !present) {
        error = write_phase(journal,
                            PRODUCT_FACTORY_RESET_PHASE_PREPARED);
    }
    if (journal != 0) {
        nvs_close(journal);
    }
    return error;
}

esp_err_t product_factory_reset_resume(
    product_factory_reset_result_t *result)
{
    if (!result) {
        return ESP_ERR_INVALID_ARG;
    }
    memset(result, 0, sizeof(*result));
    esp_err_t error = product_storage_require_ready();
    if (error != ESP_OK) {
        return error;
    }

    nvs_handle_t journal = 0;
    error = nvs_open_from_partition(PARTITION, JOURNAL_NAMESPACE,
                                    NVS_READWRITE, &journal);
    product_factory_reset_phase_t phase =
        PRODUCT_FACTORY_RESET_PHASE_NONE;
    bool present = false;
    if (error == ESP_OK) {
        error = read_phase(journal, &phase, &present);
    }
    if (error != ESP_OK || !present) {
        if (journal != 0) {
            nvs_close(journal);
        }
        return error;
    }

    result->pending_at_boot = true;
    result->starting_phase = phase;
    result->final_phase = phase;
    while (error == ESP_OK && present) {
        const product_factory_reset_action_t action =
            product_factory_reset_core_next_action(phase);
        product_factory_reset_phase_t next_phase = phase;
        if (action == PRODUCT_FACTORY_RESET_ACTION_ERASE_WIFI) {
            error = erase_namespace(WIFI_NAMESPACE);
            if (error == ESP_OK) {
                ++result->wifi_erase_commits;
            }
        } else if (action == PRODUCT_FACTORY_RESET_ACTION_ERASE_MEMORY) {
            error = erase_namespace(MEMORY_NAMESPACE);
            if (error == ESP_OK) {
                ++result->memory_erase_commits;
            }
        } else if (action == PRODUCT_FACTORY_RESET_ACTION_CLEAR_JOURNAL) {
            error = nvs_erase_key(journal, JOURNAL_KEY);
            if (error == ESP_ERR_NVS_NOT_FOUND) {
                error = ESP_OK;
            }
            if (error == ESP_OK) {
                error = nvs_commit(journal);
            }
        } else {
            error = ESP_ERR_INVALID_STATE;
        }
        if (error != ESP_OK ||
            !product_factory_reset_core_advance(
                phase, action, &next_phase)) {
            if (error == ESP_OK) {
                error = ESP_ERR_INVALID_STATE;
            }
            break;
        }
        if (next_phase == PRODUCT_FACTORY_RESET_PHASE_NONE) {
            phase = next_phase;
            present = false;
            result->completed = true;
            result->final_phase = phase;
            break;
        }
        error = write_phase(journal, next_phase);
        if (error == ESP_OK) {
            phase = next_phase;
            result->final_phase = phase;
        }
    }
    nvs_close(journal);
    return error;
}
