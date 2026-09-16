#include "esp_claw_capability_grant_core.h"

#include <stddef.h>
#include <string.h>

static size_t bounded_length(const char *text, size_t maximum) {
  size_t size = 0;
  if (!text) {
    return maximum + 1;
  }
  while (size <= maximum && text[size] != '\0') {
    ++size;
  }
  return size;
}

void esp_claw_capability_grant_core_init(
    esp_claw_capability_grant_core_t *grants) {
  if (grants) {
    memset(grants, 0, sizeof(*grants));
  }
}

bool esp_claw_capability_grant_core_issue(
    esp_claw_capability_grant_core_t *grants, uint32_t request_id,
    const char *session_id, uint32_t flags, uint32_t argument_binding) {
  if (!grants || request_id == 0 || flags == 0 ||
      (flags & ~ESP_CLAW_CAPABILITY_GRANT_ALL) != 0) {
    return false;
  }
  const size_t session_size =
      bounded_length(session_id, ESP_CLAW_CAPABILITY_SESSION_MAX);
  if (session_size == 0 || session_size > ESP_CLAW_CAPABILITY_SESSION_MAX) {
    return false;
  }
  int free_index = -1;
  for (int index = 0; index < ESP_CLAW_CAPABILITY_GRANT_LIMIT; ++index) {
    if (grants->entries[index].request_id == request_id) {
      return false;
    }
    if (free_index < 0 && grants->entries[index].request_id == 0) {
      free_index = index;
    }
  }
  if (free_index < 0) {
    return false;
  }
  esp_claw_capability_grant_entry_t *entry = &grants->entries[free_index];
  entry->request_id = request_id;
  entry->flags = flags;
  entry->argument_binding = argument_binding;
  memcpy(entry->session_id, session_id, session_size + 1);
  return true;
}

bool esp_claw_capability_grant_core_consume(
    esp_claw_capability_grant_core_t *grants, uint32_t request_id,
    const char *session_id, uint32_t flag, uint32_t argument_binding) {
  if (!grants || request_id == 0 || !session_id ||
      (flag != ESP_CLAW_CAPABILITY_GRANT_SET_INDICATOR &&
       flag != ESP_CLAW_CAPABILITY_GRANT_SET_VOLUME)) {
    return false;
  }
  for (int index = 0; index < ESP_CLAW_CAPABILITY_GRANT_LIMIT; ++index) {
    esp_claw_capability_grant_entry_t *entry = &grants->entries[index];
    if (entry->request_id == request_id &&
        strcmp(entry->session_id, session_id) == 0) {
      if ((entry->flags & flag) == 0 ||
          entry->argument_binding != argument_binding) {
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

void esp_claw_capability_grant_core_revoke(
    esp_claw_capability_grant_core_t *grants, uint32_t request_id) {
  if (!grants || request_id == 0) {
    return;
  }
  for (int index = 0; index < ESP_CLAW_CAPABILITY_GRANT_LIMIT; ++index) {
    if (grants->entries[index].request_id == request_id) {
      memset(&grants->entries[index], 0, sizeof(grants->entries[index]));
    }
  }
}

void esp_claw_capability_grant_core_clear(
    esp_claw_capability_grant_core_t *grants) {
  if (grants) {
    volatile uint8_t *bytes = (volatile uint8_t *)grants;
    for (size_t index = 0; index < sizeof(*grants); ++index) {
      bytes[index] = 0;
    }
  }
}
