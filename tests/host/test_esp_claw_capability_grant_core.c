#include "esp_claw_capability_grant_core.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  esp_claw_capability_grant_core_t grants;
  esp_claw_capability_grant_core_init(&grants);
  assert(!esp_claw_capability_grant_core_issue(NULL, 1, "session", 1, 0));
  assert(!esp_claw_capability_grant_core_issue(&grants, 0, "session", 1, 0));
  assert(!esp_claw_capability_grant_core_issue(&grants, 1, "", 1, 0));
  assert(!esp_claw_capability_grant_core_issue(&grants, 1, "session", 4, 0));
  assert(esp_claw_capability_grant_core_issue(
      &grants, 1, "session-a", ESP_CLAW_CAPABILITY_GRANT_SET_INDICATOR, 1));
  assert(!esp_claw_capability_grant_core_issue(
      &grants, 1, "session-a", ESP_CLAW_CAPABILITY_GRANT_SET_INDICATOR, 1));
  assert(!esp_claw_capability_grant_core_consume(
      &grants, 1, "session-b", ESP_CLAW_CAPABILITY_GRANT_SET_INDICATOR, 1));
  assert(!esp_claw_capability_grant_core_consume(
      &grants, 1, "session-a", ESP_CLAW_CAPABILITY_GRANT_SET_INDICATOR, 0));
  assert(esp_claw_capability_grant_core_consume(
      &grants, 1, "session-a", ESP_CLAW_CAPABILITY_GRANT_SET_INDICATOR, 1));
  assert(!esp_claw_capability_grant_core_consume(
      &grants, 1, "session-a", ESP_CLAW_CAPABILITY_GRANT_SET_INDICATOR, 1));

  assert(esp_claw_capability_grant_core_issue(
      &grants, 2, "session-volume", ESP_CLAW_CAPABILITY_GRANT_SET_VOLUME, 70));
  assert(!esp_claw_capability_grant_core_consume(
      &grants, 2, "session-volume", ESP_CLAW_CAPABILITY_GRANT_SET_VOLUME, 60));
  assert(esp_claw_capability_grant_core_consume(
      &grants, 2, "session-volume", ESP_CLAW_CAPABILITY_GRANT_SET_VOLUME, 70));

  for (uint32_t index = 0; index < ESP_CLAW_CAPABILITY_GRANT_LIMIT; ++index) {
    assert(esp_claw_capability_grant_core_issue(
        &grants, 10 + index, "bounded", ESP_CLAW_CAPABILITY_GRANT_SET_INDICATOR,
        index & 1U));
  }
  assert(!esp_claw_capability_grant_core_issue(
      &grants, 99, "overflow", ESP_CLAW_CAPABILITY_GRANT_SET_INDICATOR, 0));
  esp_claw_capability_grant_core_revoke(&grants, 11);
  assert(esp_claw_capability_grant_core_issue(
      &grants, 99, "replacement", ESP_CLAW_CAPABILITY_GRANT_SET_INDICATOR, 0));
  esp_claw_capability_grant_core_clear(&grants);
  const uint8_t zeros[sizeof(grants)] = {0};
  assert(memcmp(&grants, zeros, sizeof(grants)) == 0);

  char too_long[ESP_CLAW_CAPABILITY_SESSION_MAX + 2];
  memset(too_long, 'a', sizeof(too_long) - 1);
  too_long[sizeof(too_long) - 1] = '\0';
  assert(!esp_claw_capability_grant_core_issue(
      &grants, 1, too_long, ESP_CLAW_CAPABILITY_GRANT_SET_INDICATOR, 0));
  puts("esp_claw_capability_grant_core: all tests passed");
  return 0;
}
