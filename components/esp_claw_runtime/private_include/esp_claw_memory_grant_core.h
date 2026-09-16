#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum {
    ESP_CLAW_MEMORY_GRANT_LIMIT = 4,
    ESP_CLAW_MEMORY_SESSION_MAX = 64,
    ESP_CLAW_MEMORY_GRANT_PUT = 1U << 0,
    ESP_CLAW_MEMORY_GRANT_FORGET = 1U << 1,
    ESP_CLAW_MEMORY_GRANT_ALL = ESP_CLAW_MEMORY_GRANT_PUT |
                                ESP_CLAW_MEMORY_GRANT_FORGET,
};

typedef struct {
    uint32_t request_id;
    uint32_t flags;
    char session_id[ESP_CLAW_MEMORY_SESSION_MAX + 1];
} esp_claw_memory_grant_entry_t;

typedef struct {
    esp_claw_memory_grant_entry_t entries[ESP_CLAW_MEMORY_GRANT_LIMIT];
} esp_claw_memory_grant_core_t;

void esp_claw_memory_grant_core_init(esp_claw_memory_grant_core_t *grants);

bool esp_claw_memory_grant_core_issue(esp_claw_memory_grant_core_t *grants,
                                      uint32_t request_id,
                                      const char *session_id,
                                      uint32_t flags);

bool esp_claw_memory_grant_core_consume(
    esp_claw_memory_grant_core_t *grants,
    uint32_t request_id,
    const char *session_id,
    uint32_t flag);

void esp_claw_memory_grant_core_revoke(esp_claw_memory_grant_core_t *grants,
                                       uint32_t request_id);

void esp_claw_memory_grant_core_clear(esp_claw_memory_grant_core_t *grants);

#ifdef __cplusplus
}
#endif
