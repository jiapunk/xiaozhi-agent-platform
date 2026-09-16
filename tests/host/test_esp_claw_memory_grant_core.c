#include "esp_claw_memory_grant_core.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    esp_claw_memory_grant_core_t grants;
    esp_claw_memory_grant_core_init(&grants);
    assert(!esp_claw_memory_grant_core_issue(NULL, 1, "session", 1));
    assert(!esp_claw_memory_grant_core_issue(&grants, 0, "session", 1));
    assert(!esp_claw_memory_grant_core_issue(&grants, 1, "", 1));
    assert(!esp_claw_memory_grant_core_issue(&grants, 1, "session", 4));
    assert(esp_claw_memory_grant_core_issue(
        &grants, 1, "session-a",
        ESP_CLAW_MEMORY_GRANT_PUT | ESP_CLAW_MEMORY_GRANT_FORGET));
    assert(!esp_claw_memory_grant_core_issue(
        &grants, 1, "session-a", ESP_CLAW_MEMORY_GRANT_PUT));
    assert(!esp_claw_memory_grant_core_consume(
        &grants, 1, "session-b", ESP_CLAW_MEMORY_GRANT_PUT));
    assert(esp_claw_memory_grant_core_consume(
        &grants, 1, "session-a", ESP_CLAW_MEMORY_GRANT_PUT));
    assert(!esp_claw_memory_grant_core_consume(
        &grants, 1, "session-a", ESP_CLAW_MEMORY_GRANT_PUT));
    assert(esp_claw_memory_grant_core_consume(
        &grants, 1, "session-a", ESP_CLAW_MEMORY_GRANT_FORGET));
    assert(!esp_claw_memory_grant_core_consume(
        &grants, 1, "session-a", ESP_CLAW_MEMORY_GRANT_FORGET));

    for (uint32_t i = 0; i < ESP_CLAW_MEMORY_GRANT_LIMIT; ++i) {
        assert(esp_claw_memory_grant_core_issue(
            &grants, 10 + i, "bounded", ESP_CLAW_MEMORY_GRANT_PUT));
    }
    assert(!esp_claw_memory_grant_core_issue(
        &grants, 99, "overflow", ESP_CLAW_MEMORY_GRANT_PUT));
    esp_claw_memory_grant_core_revoke(&grants, 11);
    assert(esp_claw_memory_grant_core_issue(
        &grants, 99, "replacement", ESP_CLAW_MEMORY_GRANT_FORGET));
    esp_claw_memory_grant_core_clear(&grants);
    const uint8_t zeros[sizeof(grants)] = {0};
    assert(memcmp(&grants, zeros, sizeof(grants)) == 0);

    char too_long[ESP_CLAW_MEMORY_SESSION_MAX + 2];
    memset(too_long, 'a', sizeof(too_long) - 1);
    too_long[sizeof(too_long) - 1] = '\0';
    assert(!esp_claw_memory_grant_core_issue(
        &grants, 1, too_long, ESP_CLAW_MEMORY_GRANT_PUT));
    puts("esp_claw_memory_grant_core: all tests passed");
    return 0;
}
