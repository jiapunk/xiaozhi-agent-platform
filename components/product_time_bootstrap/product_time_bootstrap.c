#include "product_time_bootstrap.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "esp_heap_caps.h"
#include "esp_netif_sntp.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "product_time_bootstrap_core.h"

enum {
    SIGNAL_WAKE = 1U << 0,
    SIGNAL_STOP = 1U << 1,
    SIGNAL_TASK_READY = 1U << 2,
    SIGNAL_TASK_STOPPED = 1U << 3,
    DEFAULT_SYNC_TIMEOUT_MS = 10000,
    DEFAULT_MINIMUM_BACKOFF_MS = 5000,
    DEFAULT_MAXIMUM_BACKOFF_MS = 5 * 60 * 1000,
    DEFAULT_TASK_STACK_SIZE = 4096,
    DEFAULT_TASK_PRIORITY = 4,
    MAXIMUM_TASK_STACK_SIZE = 16384,
    CREATE_TIMEOUT_MS = 5000,
    SYNC_POLL_MS = 1000,
    TIME_HEALTH_POLL_MS = 60 * 1000,
};

struct product_time_bootstrap {
    char servers[PRODUCT_TIME_BOOTSTRAP_SERVER_LIMIT]
                [PRODUCT_TIME_BOOTSTRAP_SERVER_BYTES];
    size_t server_count;
    product_time_bootstrap_event_fn event;
    void *event_ctx;
    uint32_t sync_timeout_ms;
    uint32_t minimum_backoff_ms;
    uint32_t maximum_backoff_ms;
    uint32_t task_stack_size;
    uint32_t task_priority;
    EventGroupHandle_t signals;
    TaskHandle_t worker;
    atomic_bool stopping;
    atomic_bool network_available;
    atomic_bool approximate_time_available;
    atomic_uint attempts;
    atomic_uint failures;
    atomic_uint retries;
    atomic_int last_error;
};

static void secure_zero(void *memory, size_t size)
{
    volatile unsigned char *bytes = memory;
    while (bytes && size > 0) {
        *bytes++ = 0;
        --size;
    }
}

static bool safe_server(const char *server)
{
    if (!server || !server[0]) {
        return false;
    }
    const size_t size = strnlen(server, PRODUCT_TIME_BOOTSTRAP_SERVER_BYTES);
    if (size == PRODUCT_TIME_BOOTSTRAP_SERVER_BYTES ||
        server[0] == '.' || server[size - 1] == '.') {
        return false;
    }
    for (size_t index = 0; index < size; ++index) {
        const unsigned char character = (unsigned char)server[index];
        if ((character >= 'a' && character <= 'z') ||
            (character >= 'A' && character <= 'Z') ||
            (character >= '0' && character <= '9') ||
            character == '.' || character == '-') {
            continue;
        }
        return false;
    }
    return true;
}

static bool network_available(product_time_bootstrap_handle_t bootstrap)
{
    return atomic_load_explicit(&bootstrap->network_available,
                                memory_order_acquire);
}

static bool stopping(product_time_bootstrap_handle_t bootstrap)
{
    return atomic_load_explicit(&bootstrap->stopping,
                                memory_order_acquire);
}

static bool system_time_plausible(void)
{
    return product_time_bootstrap_plausible((int64_t)time(NULL));
}

static void publish(product_time_bootstrap_handle_t bootstrap,
                    bool available,
                    esp_err_t error,
                    uint32_t retry_in_ms)
{
    const bool changed = atomic_exchange_explicit(
        &bootstrap->approximate_time_available, available,
        memory_order_acq_rel) != available;
    atomic_store_explicit(&bootstrap->last_error, error,
                          memory_order_release);
    if (bootstrap->event && (changed || error != ESP_OK)) {
        const product_time_bootstrap_event_t event = {
            .approximate_time_available = available,
            .error = error,
            .attempts = atomic_load_explicit(&bootstrap->attempts,
                                             memory_order_relaxed),
            .retry_in_ms = retry_in_ms,
        };
        bootstrap->event(bootstrap->event_ctx, &event);
    }
}

static esp_err_t attempt_sync(product_time_bootstrap_handle_t bootstrap)
{
    esp_sntp_config_t config = {
        .smooth_sync = false,
        .server_from_dhcp = false,
        .wait_for_sync = true,
        .start = true,
        .sync_cb = NULL,
        .renew_servers_after_new_IP = false,
        .ip_event_to_renew = IP_EVENT_STA_GOT_IP,
        .index_of_first_server = 0,
        .num_of_servers = bootstrap->server_count,
    };
    for (size_t index = 0; index < bootstrap->server_count; ++index) {
        config.servers[index] = bootstrap->servers[index];
    }
    atomic_fetch_add_explicit(&bootstrap->attempts, 1,
                              memory_order_relaxed);
    esp_err_t error = esp_netif_sntp_init(&config);
    if (error != ESP_OK) {
        return error;
    }
    const int64_t start_us = esp_timer_get_time();
    if (start_us < 0) {
        esp_netif_sntp_deinit();
        return ESP_ERR_INVALID_STATE;
    }
    const uint64_t deadline_us =
        (uint64_t)start_us + (uint64_t)bootstrap->sync_timeout_ms * 1000U;
    error = ESP_ERR_TIMEOUT;
    while (!stopping(bootstrap) && network_available(bootstrap) &&
           (uint64_t)esp_timer_get_time() < deadline_us) {
        const esp_err_t wait = esp_netif_sntp_sync_wait(
            pdMS_TO_TICKS(SYNC_POLL_MS));
        if (wait == ESP_OK && system_time_plausible()) {
            error = ESP_OK;
            break;
        }
        if (wait != ESP_ERR_TIMEOUT && wait != ESP_ERR_NOT_FINISHED) {
            error = wait;
            break;
        }
    }
    esp_netif_sntp_deinit();
    if (stopping(bootstrap) || !network_available(bootstrap)) {
        return ESP_ERR_INVALID_STATE;
    }
    if (error == ESP_OK && !system_time_plausible()) {
        return ESP_ERR_INVALID_RESPONSE;
    }
    return error;
}

static EventBits_t wait_for_input(product_time_bootstrap_handle_t bootstrap,
                                  uint32_t timeout_ms)
{
    return xEventGroupWaitBits(
        bootstrap->signals, SIGNAL_WAKE | SIGNAL_STOP, pdTRUE, pdFALSE,
        timeout_ms == UINT32_MAX ? portMAX_DELAY
                                 : pdMS_TO_TICKS(timeout_ms));
}

static void worker_entry(void *argument)
{
    product_time_bootstrap_handle_t bootstrap = argument;
    uint32_t consecutive_failures = 0;
    bool synchronized_on_network = false;
    xEventGroupSetBits(bootstrap->signals, SIGNAL_TASK_READY);

    while (!stopping(bootstrap)) {
        if (!network_available(bootstrap)) {
            consecutive_failures = 0;
            synchronized_on_network = false;
            publish(bootstrap, false, ESP_OK, 0);
            const EventBits_t bits = wait_for_input(bootstrap, UINT32_MAX);
            if ((bits & SIGNAL_STOP) != 0) {
                break;
            }
            continue;
        }
        if (synchronized_on_network) {
            if (system_time_plausible()) {
                consecutive_failures = 0;
                publish(bootstrap, true, ESP_OK, 0);
                const EventBits_t bits = wait_for_input(
                    bootstrap, TIME_HEALTH_POLL_MS);
                if ((bits & SIGNAL_STOP) != 0) {
                    break;
                }
                continue;
            }
            synchronized_on_network = false;
            publish(bootstrap, false, ESP_ERR_INVALID_STATE, 0);
        }

        /* A plausible retained clock may let TLS proceed immediately, but we
         * still refresh it once on each network attachment. */
        if (system_time_plausible()) {
            publish(bootstrap, true, ESP_OK, 0);
        }
        const esp_err_t error = attempt_sync(bootstrap);
        if (stopping(bootstrap)) {
            break;
        }
        if (!network_available(bootstrap)) {
            publish(bootstrap, false, ESP_OK, 0);
            continue;
        }
        if (error == ESP_OK && system_time_plausible()) {
            consecutive_failures = 0;
            synchronized_on_network = true;
            publish(bootstrap, true, ESP_OK, 0);
            continue;
        }
        atomic_fetch_add_explicit(&bootstrap->failures, 1,
                                  memory_order_relaxed);
        if (consecutive_failures != UINT32_MAX) {
            ++consecutive_failures;
        }
        const uint32_t retry_ms = product_time_bootstrap_retry_ms(
            consecutive_failures, bootstrap->minimum_backoff_ms,
            bootstrap->maximum_backoff_ms, esp_random());
        atomic_fetch_add_explicit(&bootstrap->retries, 1,
                                  memory_order_relaxed);
        const bool plausible = system_time_plausible();
        publish(bootstrap, plausible,
                error == ESP_OK ? ESP_ERR_INVALID_RESPONSE : error,
                retry_ms);
        const EventBits_t bits = wait_for_input(bootstrap, retry_ms);
        if ((bits & SIGNAL_STOP) != 0) {
            break;
        }
    }

    publish(bootstrap, false, ESP_OK, 0);
    bootstrap->worker = NULL;
    xEventGroupSetBits(bootstrap->signals, SIGNAL_TASK_STOPPED);
    vTaskDelete(NULL);
}

esp_err_t product_time_bootstrap_create(
    const product_time_bootstrap_config_t *config,
    product_time_bootstrap_handle_t *out_bootstrap)
{
    if (!config || !out_bootstrap || *out_bootstrap ||
        config->server_count == 0 ||
        config->server_count > PRODUCT_TIME_BOOTSTRAP_SERVER_LIMIT ||
        config->server_count > CONFIG_LWIP_SNTP_MAX_SERVERS) {
        return ESP_ERR_INVALID_ARG;
    }
    const uint32_t sync_timeout_ms = config->sync_timeout_ms
                                         ? config->sync_timeout_ms
                                         : DEFAULT_SYNC_TIMEOUT_MS;
    const uint32_t minimum_backoff_ms = config->minimum_backoff_ms
                                            ? config->minimum_backoff_ms
                                            : DEFAULT_MINIMUM_BACKOFF_MS;
    const uint32_t maximum_backoff_ms = config->maximum_backoff_ms
                                            ? config->maximum_backoff_ms
                                            : DEFAULT_MAXIMUM_BACKOFF_MS;
    const uint32_t task_stack_size = config->task_stack_size
                                         ? config->task_stack_size
                                         : DEFAULT_TASK_STACK_SIZE;
    const uint32_t task_priority = config->task_priority
                                       ? config->task_priority
                                       : DEFAULT_TASK_PRIORITY;
    if (sync_timeout_ms < 1000 || sync_timeout_ms > 60000 ||
        minimum_backoff_ms < 1000 ||
        maximum_backoff_ms < minimum_backoff_ms ||
        maximum_backoff_ms > 60U * 60U * 1000U ||
        task_stack_size < 3072 ||
        task_stack_size > MAXIMUM_TASK_STACK_SIZE || task_priority == 0 ||
        task_priority >= configMAX_PRIORITIES) {
        return ESP_ERR_INVALID_ARG;
    }
    for (size_t index = 0; index < config->server_count; ++index) {
        if (!safe_server(config->servers[index])) {
            return ESP_ERR_INVALID_ARG;
        }
    }

    product_time_bootstrap_handle_t bootstrap = heap_caps_calloc(
        1, sizeof(*bootstrap), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!bootstrap) {
        return ESP_ERR_NO_MEM;
    }
    bootstrap->server_count = config->server_count;
    for (size_t index = 0; index < config->server_count; ++index) {
        memcpy(bootstrap->servers[index], config->servers[index],
               strlen(config->servers[index]) + 1);
    }
    bootstrap->event = config->event;
    bootstrap->event_ctx = config->event_ctx;
    bootstrap->sync_timeout_ms = sync_timeout_ms;
    bootstrap->minimum_backoff_ms = minimum_backoff_ms;
    bootstrap->maximum_backoff_ms = maximum_backoff_ms;
    bootstrap->task_stack_size = task_stack_size;
    bootstrap->task_priority = task_priority;
    bootstrap->signals = xEventGroupCreate();
    atomic_init(&bootstrap->stopping, false);
    atomic_init(&bootstrap->network_available, false);
    atomic_init(&bootstrap->approximate_time_available, false);
    atomic_init(&bootstrap->attempts, 0);
    atomic_init(&bootstrap->failures, 0);
    atomic_init(&bootstrap->retries, 0);
    atomic_init(&bootstrap->last_error, ESP_OK);
    if (!bootstrap->signals ||
        xTaskCreate(worker_entry, "time_bootstrap", task_stack_size,
                    bootstrap, task_priority, &bootstrap->worker) != pdPASS) {
        if (bootstrap->signals) {
            vEventGroupDelete(bootstrap->signals);
        }
        secure_zero(bootstrap, sizeof(*bootstrap));
        heap_caps_free(bootstrap);
        return ESP_ERR_NO_MEM;
    }
    const EventBits_t ready = xEventGroupWaitBits(
        bootstrap->signals, SIGNAL_TASK_READY, pdFALSE, pdTRUE,
        pdMS_TO_TICKS(CREATE_TIMEOUT_MS));
    if ((ready & SIGNAL_TASK_READY) == 0) {
        atomic_store_explicit(&bootstrap->stopping, true,
                              memory_order_release);
        xEventGroupSetBits(bootstrap->signals, SIGNAL_STOP);
        const EventBits_t stopped = xEventGroupWaitBits(
            bootstrap->signals, SIGNAL_TASK_STOPPED, pdFALSE, pdTRUE,
            pdMS_TO_TICKS(CREATE_TIMEOUT_MS));
        if ((stopped & SIGNAL_TASK_STOPPED) == 0 && bootstrap->worker) {
            vTaskDelete(bootstrap->worker);
        }
        vEventGroupDelete(bootstrap->signals);
        secure_zero(bootstrap, sizeof(*bootstrap));
        heap_caps_free(bootstrap);
        return ESP_ERR_TIMEOUT;
    }
    *out_bootstrap = bootstrap;
    return ESP_OK;
}

esp_err_t product_time_bootstrap_set_network_available(
    product_time_bootstrap_handle_t bootstrap,
    bool available)
{
    if (!bootstrap || stopping(bootstrap)) {
        return ESP_ERR_INVALID_STATE;
    }
    atomic_store_explicit(&bootstrap->network_available, available,
                          memory_order_release);
    xEventGroupSetBits(bootstrap->signals, SIGNAL_WAKE);
    return ESP_OK;
}

esp_err_t product_time_bootstrap_get_stats(
    product_time_bootstrap_handle_t bootstrap,
    product_time_bootstrap_stats_t *stats)
{
    if (!bootstrap || !stats || stopping(bootstrap)) {
        return ESP_ERR_INVALID_ARG;
    }
    *stats = (product_time_bootstrap_stats_t){
        .network_available = network_available(bootstrap),
        .approximate_time_available = atomic_load_explicit(
            &bootstrap->approximate_time_available, memory_order_acquire),
        .attempts = atomic_load_explicit(&bootstrap->attempts,
                                         memory_order_relaxed),
        .failures = atomic_load_explicit(&bootstrap->failures,
                                         memory_order_relaxed),
        .retries = atomic_load_explicit(&bootstrap->retries,
                                        memory_order_relaxed),
        .last_error = (esp_err_t)atomic_load_explicit(
            &bootstrap->last_error, memory_order_acquire),
    };
    return ESP_OK;
}

esp_err_t product_time_bootstrap_destroy(
    product_time_bootstrap_handle_t bootstrap,
    uint32_t timeout_ms)
{
    if (!bootstrap || timeout_ms == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    atomic_store_explicit(&bootstrap->stopping, true,
                          memory_order_release);
    atomic_store_explicit(&bootstrap->network_available, false,
                          memory_order_release);
    xEventGroupSetBits(bootstrap->signals, SIGNAL_STOP | SIGNAL_WAKE);
    const EventBits_t stopped = xEventGroupWaitBits(
        bootstrap->signals, SIGNAL_TASK_STOPPED, pdFALSE, pdTRUE,
        pdMS_TO_TICKS(timeout_ms));
    if ((stopped & SIGNAL_TASK_STOPPED) == 0) {
        return ESP_ERR_TIMEOUT;
    }
    vEventGroupDelete(bootstrap->signals);
    secure_zero(bootstrap, sizeof(*bootstrap));
    heap_caps_free(bootstrap);
    return ESP_OK;
}
