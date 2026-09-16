#include "esp_claw_memory_grant_core.h"

#include <string.h>

static size_t bounded_length(const char *text, size_t maximum)
{
    size_t size = 0;
    if (!text) {
        return maximum + 1;
    }
    while (size <= maximum && text[size] != '\0') {
        ++size;
    }
    return size;
}

void esp_claw_memory_grant_core_init(esp_claw_memory_grant_core_t *grants)
{
    if (grants) {
        memset(grants, 0, sizeof(*grants));
    }
}

bool esp_claw_memory_grant_core_issue(esp_claw_memory_grant_core_t *grants,
                                      uint32_t request_id,
                                      const char *session_id,
                                      uint32_t flags)
{
    if (!grants || request_id == 0 || flags == 0 ||
        (flags & ~ESP_CLAW_MEMORY_GRANT_ALL) != 0) {
        return false;
    }
    const size_t session_size =
        bounded_length(session_id, ESP_CLAW_MEMORY_SESSION_MAX);
    if (session_size == 0 || session_size > ESP_CLAW_MEMORY_SESSION_MAX) {
        return false;
    }
    int free_index = -1;
    for (int i = 0; i < ESP_CLAW_MEMORY_GRANT_LIMIT; ++i) {
        if (grants->entries[i].request_id == request_id) {
            return false;
        }
        if (free_index < 0 && grants->entries[i].request_id == 0) {
            free_index = i;
        }
    }
    if (free_index < 0) {
        return false;
    }
    esp_claw_memory_grant_entry_t *entry = &grants->entries[free_index];
    entry->request_id = request_id;
    entry->flags = flags;
    memcpy(entry->session_id, session_id, session_size + 1);
    return true;
}

bool esp_claw_memory_grant_core_consume(
    esp_claw_memory_grant_core_t *grants,
    uint32_t request_id,
    const char *session_id,
    uint32_t flag)
{
    if (!grants || request_id == 0 || !session_id ||
        (flag != ESP_CLAW_MEMORY_GRANT_PUT &&
         flag != ESP_CLAW_MEMORY_GRANT_FORGET)) {
        return false;
    }
    for (int i = 0; i < ESP_CLAW_MEMORY_GRANT_LIMIT; ++i) {
        esp_claw_memory_grant_entry_t *entry = &grants->entries[i];
        if (entry->request_id == request_id &&
            strcmp(entry->session_id, session_id) == 0) {
            if ((entry->flags & flag) == 0) {
                return false;
            }
            entry->flags &= ~flag;
            if (entry->flags == 0) {
                memset(entry, 0, sizeof(*entry));
            }
            return true;
        }
    }
    return false;
}

void esp_claw_memory_grant_core_revoke(esp_claw_memory_grant_core_t *grants,
                                       uint32_t request_id)
{
    if (!grants || request_id == 0) {
        return;
    }
    for (int i = 0; i < ESP_CLAW_MEMORY_GRANT_LIMIT; ++i) {
        if (grants->entries[i].request_id == request_id) {
            memset(&grants->entries[i], 0, sizeof(grants->entries[i]));
        }
    }
}

void esp_claw_memory_grant_core_clear(esp_claw_memory_grant_core_t *grants)
{
    if (grants) {
        volatile uint8_t *bytes = (volatile uint8_t *)grants;
        for (size_t i = 0; i < sizeof(*grants); ++i) {
            bytes[i] = 0;
        }
    }
}
